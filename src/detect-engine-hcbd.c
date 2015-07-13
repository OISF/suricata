/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup httplayer
 *
 * @{
 */


/** \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * \brief Handle HTTP request body match corresponding to http_client_body
 * keyword.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#define BUFFER_STEP 50

static inline int HCBDCreateSpace(DetectEngineThreadCtx *det_ctx, uint64_t size)
{
    if (size >= (USHRT_MAX - BUFFER_STEP))
        return -1;

    void *ptmp;
    if (size > det_ctx->hcbd_buffers_size) {
        ptmp = SCRealloc(det_ctx->hcbd,
                         (det_ctx->hcbd_buffers_size + BUFFER_STEP) * sizeof(HttpReassembledBody));
        if (ptmp == NULL) {
            SCFree(det_ctx->hcbd);
            det_ctx->hcbd = NULL;
            det_ctx->hcbd_buffers_size = 0;
            det_ctx->hcbd_buffers_list_len = 0;
            return -1;
        }
        det_ctx->hcbd = ptmp;

        memset(det_ctx->hcbd + det_ctx->hcbd_buffers_size, 0, BUFFER_STEP * sizeof(HttpReassembledBody));
        det_ctx->hcbd_buffers_size += BUFFER_STEP;

        uint16_t i;
        for (i = det_ctx->hcbd_buffers_list_len; i < ((uint16_t)size); i++) {
            det_ctx->hcbd[i].buffer_len = 0;
            det_ctx->hcbd[i].offset = 0;
        }
    }

    return 0;
}

/**
 */
static uint8_t *DetectEngineHCBDGetBufferForTX(htp_tx_t *tx, uint64_t tx_id,
                                               DetectEngineCtx *de_ctx,
                                               DetectEngineThreadCtx *det_ctx,
                                               Flow *f, HtpState *htp_state,
                                               uint8_t flags,
                                               uint32_t *buffer_len,
                                               uint32_t *stream_start_offset)
{
    int index = 0;
    uint8_t *buffer = NULL;
    *buffer_len = 0;
    *stream_start_offset = 0;

    if (det_ctx->hcbd_buffers_list_len == 0) {
        /* get the inspect id to use as a 'base id' */
        uint64_t base_inspect_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        BUG_ON(base_inspect_id > tx_id);
        /* see how many space we need for the current tx_id */
        uint64_t txs = (tx_id - base_inspect_id) + 1;
        if (HCBDCreateSpace(det_ctx, txs) < 0)
            goto end;

        index = (tx_id - base_inspect_id);
        det_ctx->hcbd_start_tx_id = base_inspect_id;
        det_ctx->hcbd_buffers_list_len = txs;
    } else {
        if ((tx_id - det_ctx->hcbd_start_tx_id) < det_ctx->hcbd_buffers_list_len) {
            if (det_ctx->hcbd[(tx_id - det_ctx->hcbd_start_tx_id)].buffer_len != 0) {
                *buffer_len = det_ctx->hcbd[(tx_id - det_ctx->hcbd_start_tx_id)].buffer_len;
                *stream_start_offset = det_ctx->hcbd[(tx_id - det_ctx->hcbd_start_tx_id)].offset;
                return det_ctx->hcbd[(tx_id - det_ctx->hcbd_start_tx_id)].buffer;
            }
        } else {
            uint64_t txs = (tx_id - det_ctx->hcbd_start_tx_id) + 1;
            if (HCBDCreateSpace(det_ctx, txs) < 0)
                goto end; /* let's consider it as stage not done for now */

            det_ctx->hcbd_buffers_list_len = txs;
        }
        index = (tx_id - det_ctx->hcbd_start_tx_id);
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        SCLogDebug("no htud");
        goto end;
    }

    /* no new data */
    if (htud->request_body.body_inspected == htud->request_body.content_len_so_far) {
        SCLogDebug("no new data");
        goto end;
    }

    HtpBodyChunk *cur = htud->request_body.first;
    if (cur == NULL) {
        SCLogDebug("No http chunks to inspect for this transacation");
        goto end;
    }

    /* inspect the body if the transfer is complete or we have hit
     * our body size limit */
    if ((htp_state->cfg->request_body_limit == 0 ||
         htud->request_body.content_len_so_far < htp_state->cfg->request_body_limit) &&
        htud->request_body.content_len_so_far < htp_state->cfg->request_inspect_min_size &&
        !(AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_BODY) &&
        !(flags & STREAM_EOF)) {
        SCLogDebug("we still haven't seen the entire request body.  "
                   "Let's defer body inspection till we see the "
                   "entire body.");
        goto end;
    }

    int first = 1;
    while (cur != NULL) {
        /* see if we can filter out chunks */
        if (htud->request_body.body_inspected > 0) {
            if (cur->stream_offset < htud->request_body.body_inspected) {
                if ((htud->request_body.body_inspected - cur->stream_offset) > htp_state->cfg->request_inspect_min_size) {
                    cur = cur->next;
                    continue;
                } else {
                    /* include this one */
                }
            } else {
                /* include this one */
            }
        }

        if (first) {
            det_ctx->hcbd[index].offset = cur->stream_offset;
            first = 0;
        }

        /* see if we need to grow the buffer */
        if (det_ctx->hcbd[index].buffer == NULL || (det_ctx->hcbd[index].buffer_len + cur->len) > det_ctx->hcbd[index].buffer_size) {
            void *ptmp;
            det_ctx->hcbd[index].buffer_size += cur->len * 2;

            if ((ptmp = SCRealloc(det_ctx->hcbd[index].buffer, det_ctx->hcbd[index].buffer_size)) == NULL) {
                SCFree(det_ctx->hcbd[index].buffer);
                det_ctx->hcbd[index].buffer = NULL;
                det_ctx->hcbd[index].buffer_size = 0;
                det_ctx->hcbd[index].buffer_len = 0;
                goto end;
            }
            det_ctx->hcbd[index].buffer = ptmp;
        }
        memcpy(det_ctx->hcbd[index].buffer + det_ctx->hcbd[index].buffer_len, cur->data, cur->len);
        det_ctx->hcbd[index].buffer_len += cur->len;

        cur = cur->next;
    }

    /* update inspected tracker */
    htud->request_body.body_inspected = htud->request_body.last->stream_offset + htud->request_body.last->len;

    buffer = det_ctx->hcbd[index].buffer;
    *buffer_len = det_ctx->hcbd[index].buffer_len;
    *stream_start_offset = det_ctx->hcbd[index].offset;
 end:
    return buffer;
}

int DetectEngineRunHttpClientBodyMpm(DetectEngineCtx *de_ctx,
                                     DetectEngineThreadCtx *det_ctx, Flow *f,
                                     HtpState *htp_state, uint8_t flags,
                                     void *tx, uint64_t idx)
{
    uint32_t cnt = 0;
    uint32_t buffer_len = 0;
    uint32_t stream_start_offset = 0;
    uint8_t *buffer = DetectEngineHCBDGetBufferForTX(tx, idx,
                                                     de_ctx, det_ctx,
                                                     f, htp_state,
                                                     flags,
                                                     &buffer_len,
                                                     &stream_start_offset);
    if (buffer_len == 0)
        goto end;

    cnt = HttpClientBodyPatternSearch(det_ctx, buffer, buffer_len, flags);

 end:
    return cnt;
}

int DetectEngineInspectHttpClientBody(ThreadVars *tv,
                                      DetectEngineCtx *de_ctx,
                                      DetectEngineThreadCtx *det_ctx,
                                      Signature *s, Flow *f, uint8_t flags,
                                      void *alstate, void *tx, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)alstate;
    uint32_t buffer_len = 0;
    uint32_t stream_start_offset = 0;
    uint8_t *buffer = DetectEngineHCBDGetBufferForTX(tx, tx_id,
                                                     de_ctx, det_ctx,
                                                     f, htp_state,
                                                     flags,
                                                     &buffer_len,
                                                     &stream_start_offset);
    if (buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_HCBDMATCH],
                                          f,
                                          buffer,
                                          buffer_len,
                                          stream_start_offset,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_HCBD, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;


 end:
    if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_BODY)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

void DetectEngineCleanHCBDBuffers(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->hcbd_buffers_list_len > 0) {
        for (int i = 0; i < det_ctx->hcbd_buffers_list_len; i++) {
            det_ctx->hcbd[i].buffer_len = 0;
            det_ctx->hcbd[i].offset = 0;
        }
    }
    det_ctx->hcbd_buffers_list_len = 0;
    det_ctx->hcbd_start_tx_id = 0;

    return;
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS

struct TestSteps {
    const uint8_t *input;
    size_t input_size;      /**< if 0 strlen will be used */
    int direction;          /**< STREAM_TOSERVER, STREAM_TOCLIENT */
    int expect;
};

static int RunTest (struct TestSteps *steps, const char *sig, const char *yaml)
{
    TcpSession ssn;
    Flow f;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    if (yaml) {
        ConfCreateContextBackup();
        ConfInit();
        HtpConfigCreateBackup();

        ConfYamlLoadString(yaml, strlen(yaml));
        HTPConfigure();
    }

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

    SCLogDebug("sig %s", sig);
    DetectEngineAppendSig(de_ctx, (char *)sig);

    de_ctx->flags |= DE_QUIET;

    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    struct TestSteps *b = steps;
    int i = 0;
    while (b->input != NULL) {
        SCLogDebug("chunk %p %d", b, i);
        p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
        if (p == NULL)
            goto end;
        p->flow = &f;
        p->flowflags = (b->direction == STREAM_TOSERVER) ? FLOW_PKT_TOSERVER : FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_ESTABLISHED;
        p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

        SCMutexLock(&f.m);
        int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, b->direction,
                (uint8_t *)b->input,
                b->input_size ? b->input_size : strlen((const char *)b->input));
        if (r != 0) {
            printf("toserver chunk %d returned %" PRId32 ", expected 0: ", i+1, r);
            result = 0;
            SCMutexUnlock(&f.m);
            goto end;
        }
        SCMutexUnlock(&f.m);

        /* do detect */
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

        int match = PacketAlertCheck(p, 1);
        if (b->expect != match) {
            printf("rule matching mismatch: ");
            goto end;
        }

        UTHFreePackets(&p, 1);
        p = NULL;
        b++;
        i++;
    }
    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);

    if (yaml) {
        HtpConfigRestoreBackup();
        ConfRestoreContextBackup();
    }
    return result;
}

static int DetectEngineHttpClientBodyTest01(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1This\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest02(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; offset:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest03(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; offset:16; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest04(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; offset:16; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest05(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; depth:25; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest06(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; depth:25; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest07(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; depth:15; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest08(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"This is dummy body1This is dummy message body2\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest09(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"This\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest10(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"boom\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest11(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"boom\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest12(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"This\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest13(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"dummy\"; http_client_body; distance:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest14(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"dummy\"; http_client_body; distance:10; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest15(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"dummy\"; http_client_body; distance:10; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest16(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"dummy\"; http_client_body; distance:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest17(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"bambu\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest18(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"bambu\"; http_client_body; fast_pattern; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest19(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bambu\"; http_client_body; content:\"is\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest20(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"is\"; http_client_body; fast_pattern; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest21(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; http_client_body; within:7; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest22(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; within:7; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest23(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; distance:3; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest24(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; distance:13; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest25(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; within:15; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest26(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; within:10; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest27(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; distance:8; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest28(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; distance:14; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest29(void)
{
    const char *request_buffer = "GET /one HTTP/1.0\r\n"
                                 "Host: localhost\r\n\r\n";
#define TOTAL_REQUESTS 45
    uint8_t *http_buf = SCMalloc(TOTAL_REQUESTS * strlen(request_buffer));
    if (unlikely(http_buf == NULL))
        return 0;
    for (int i = 0; i < TOTAL_REQUESTS; i++) {
        memcpy(http_buf + i * strlen(request_buffer), request_buffer,
               strlen(request_buffer));
    }
    uint32_t http_buf_len = TOTAL_REQUESTS * strlen(request_buffer);
#undef TOTAL_REQUESTS

    struct TestSteps steps[] = {
        {   (const uint8_t *)http_buf,
            (size_t)http_buf_len, STREAM_TOSERVER, 0 },

        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "dummy",
            0, STREAM_TOCLIENT, 0 },

        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"dummyone\"; fast_pattern:0,3; http_server_body; sid:1;)";
    int result = RunTest(steps, sig, NULL);
    SCFree(http_buf);
    return result;
}

static int DetectEngineHttpClientBodyTest30(void)
{
    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
\n\
    request-body-inspect-window: 0\n\
    response-body-inspect-window: 0\n\
    request-body-minimal-inspect-size: 0\n\
    response-body-minimal-inspect-size: 0\n\
";
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bags\"; within:4; http_client_body; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpClientBodyTest31(void)
{
    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
\n\
    request-body-inspect-window: 0\n\
    response-body-inspect-window: 0\n\
    request-body-minimal-inspect-size: 0\n\
    response-body-minimal-inspect-size: 0\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bags\"; depth:4; http_client_body; sid:1;)";
    return RunTest(steps, sig, yaml);
}

#endif /* UNITTESTS */

void DetectEngineHttpClientBodyRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("DetectEngineHttpClientBodyTest01",
                   DetectEngineHttpClientBodyTest01, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest02",
                   DetectEngineHttpClientBodyTest02, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest03",
                   DetectEngineHttpClientBodyTest03, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest04",
                   DetectEngineHttpClientBodyTest04, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest05",
                   DetectEngineHttpClientBodyTest05, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest06",
                   DetectEngineHttpClientBodyTest06, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest07",
                   DetectEngineHttpClientBodyTest07, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest08",
                   DetectEngineHttpClientBodyTest08, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest09",
                   DetectEngineHttpClientBodyTest09, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest10",
                   DetectEngineHttpClientBodyTest10, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest11",
                   DetectEngineHttpClientBodyTest11, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest12",
                   DetectEngineHttpClientBodyTest12, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest13",
                   DetectEngineHttpClientBodyTest13, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest14",
                   DetectEngineHttpClientBodyTest14, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest15",
                   DetectEngineHttpClientBodyTest15, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest16",
                   DetectEngineHttpClientBodyTest16, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest17",
                   DetectEngineHttpClientBodyTest17, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest18",
                   DetectEngineHttpClientBodyTest18, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest19",
                   DetectEngineHttpClientBodyTest19, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest20",
                   DetectEngineHttpClientBodyTest20, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest21",
                   DetectEngineHttpClientBodyTest21, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest22",
                   DetectEngineHttpClientBodyTest22, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest23",
                   DetectEngineHttpClientBodyTest23, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest24",
                   DetectEngineHttpClientBodyTest24, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest25",
                   DetectEngineHttpClientBodyTest25, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest26",
                   DetectEngineHttpClientBodyTest26, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest27",
                   DetectEngineHttpClientBodyTest27, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest28",
                   DetectEngineHttpClientBodyTest28, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest29",
                   DetectEngineHttpClientBodyTest29, 1);

    UtRegisterTest("DetectEngineHttpClientBodyTest30",
                   DetectEngineHttpClientBodyTest30, 1);
    UtRegisterTest("DetectEngineHttpClientBodyTest31",
                   DetectEngineHttpClientBodyTest31, 1);
#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
