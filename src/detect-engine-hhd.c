/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \brief Handle HTTP header match
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-hhd.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-memcmp.h"
#include "flow.h"

#include "stream-tcp.h"

#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

#define BUFFER_STEP 50

static inline int HHDCreateSpace(DetectEngineThreadCtx *det_ctx, uint64_t size)
{
    if (size >= (USHRT_MAX - BUFFER_STEP))
        return -1;

    void *ptmp;
    if (size > det_ctx->hhd_buffers_size) {
        ptmp = SCRealloc(det_ctx->hhd_buffers,
                         (det_ctx->hhd_buffers_size + BUFFER_STEP) * sizeof(uint8_t *));
        if (ptmp == NULL) {
            SCFree(det_ctx->hhd_buffers);
            det_ctx->hhd_buffers = NULL;
            det_ctx->hhd_buffers_size = 0;
            det_ctx->hhd_buffers_list_len = 0;
            return -1;
        }
        det_ctx->hhd_buffers = ptmp;

        memset(det_ctx->hhd_buffers + det_ctx->hhd_buffers_size, 0, BUFFER_STEP * sizeof(uint8_t *));
        ptmp = SCRealloc(det_ctx->hhd_buffers_len,
                         (det_ctx->hhd_buffers_size + BUFFER_STEP) * sizeof(uint32_t));
        if (ptmp == NULL) {
            SCFree(det_ctx->hhd_buffers_len);
            det_ctx->hhd_buffers_len = NULL;
            det_ctx->hhd_buffers_size = 0;
            det_ctx->hhd_buffers_list_len = 0;
            return -1;
        }
        det_ctx->hhd_buffers_len = ptmp;

        memset(det_ctx->hhd_buffers_len + det_ctx->hhd_buffers_size, 0, BUFFER_STEP * sizeof(uint32_t));
        det_ctx->hhd_buffers_size += BUFFER_STEP;
    }
    memset(det_ctx->hhd_buffers_len + det_ctx->hhd_buffers_list_len, 0, (size - det_ctx->hhd_buffers_list_len) * sizeof(uint32_t));

    return 0;
}

static uint8_t *DetectEngineHHDGetBufferForTX(htp_tx_t *tx, uint64_t tx_id,
                                              DetectEngineCtx *de_ctx,
                                              DetectEngineThreadCtx *det_ctx,
                                              Flow *f, HtpState *htp_state,
                                              uint8_t flags,
                                              uint32_t *buffer_len)
{
    uint8_t *headers_buffer = NULL;
    int index = 0;
    *buffer_len = 0;

    if (det_ctx->hhd_buffers_list_len == 0) {
        /* get the inspect id to use as a 'base id' */
        uint64_t base_inspect_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        BUG_ON(base_inspect_id > tx_id);
        /* see how many space we need for the current tx_id */
        uint64_t txs = (tx_id - base_inspect_id) + 1;
        if (HHDCreateSpace(det_ctx, txs) < 0)
            goto end;

        index = (tx_id - base_inspect_id);
        det_ctx->hhd_start_tx_id = base_inspect_id;
        det_ctx->hhd_buffers_list_len = txs;
    } else {
        /* tx fits in our current buffers */
        if ((tx_id - det_ctx->hhd_start_tx_id) < det_ctx->hhd_buffers_list_len) {
            /* if we previously reassembled, return that buffer */
            if (det_ctx->hhd_buffers_len[(tx_id - det_ctx->hhd_start_tx_id)] != 0) {
                *buffer_len = det_ctx->hhd_buffers_len[(tx_id - det_ctx->hhd_start_tx_id)];
                return det_ctx->hhd_buffers[(tx_id - det_ctx->hhd_start_tx_id)];
            }
            /* otherwise fall through */
        } else {
            /* not enough space, lets expand */
            uint64_t txs = (tx_id - det_ctx->hhd_start_tx_id) + 1;
            if (HHDCreateSpace(det_ctx, txs) < 0)
                goto end;

            det_ctx->hhd_buffers_list_len = txs;
        }
        index = (tx_id - det_ctx->hhd_start_tx_id);
    }

    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <= HTP_REQUEST_HEADERS)
            goto end;
        headers = tx->request_headers;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) <= HTP_RESPONSE_HEADERS)
            goto end;
        headers = tx->response_headers;
    }
    if (headers == NULL)
        goto end;

    htp_header_t *h = NULL;
    headers_buffer = det_ctx->hhd_buffers[index];
    size_t headers_buffer_len = 0;
    size_t i = 0;

    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        h = htp_table_get_index(headers, i, NULL);
        size_t size1 = bstr_size(h->name);
        size_t size2 = bstr_size(h->value);

        if (flags & STREAM_TOSERVER) {
            if (size1 == 6 &&
                SCMemcmpLowercase("cookie", bstr_ptr(h->name), 6) == 0) {
                continue;
            }
        } else {
            if (size1 == 10 &&
                SCMemcmpLowercase("set-cookie", bstr_ptr(h->name), 10) == 0) {
                continue;
            }
        }

        /* the extra 4 bytes if for ": " and "\r\n" */
        uint8_t *new_headers_buffer = SCRealloc(headers_buffer, headers_buffer_len + size1 + size2 + 4);
        if (unlikely(new_headers_buffer == NULL)) {
            if (headers_buffer != NULL) {
                SCFree(headers_buffer);
                headers_buffer = NULL;
            }
            det_ctx->hhd_buffers[index] = NULL;
            det_ctx->hhd_buffers_len[index] = 0;
            goto end;
        }
        headers_buffer = new_headers_buffer;

        memcpy(headers_buffer + headers_buffer_len, bstr_ptr(h->name), size1);
        headers_buffer_len += size1;
        headers_buffer[headers_buffer_len] = ':';
        headers_buffer[headers_buffer_len + 1] = ' ';
        headers_buffer_len += 2;
        memcpy(headers_buffer + headers_buffer_len, bstr_ptr(h->value), size2);
        headers_buffer_len += size2 + 2;
        /* \r */
        headers_buffer[headers_buffer_len - 2] = '\r';
        /* \n */
        headers_buffer[headers_buffer_len - 1] = '\n';
    }

    /* store the buffers.  We will need it for further inspection */
    det_ctx->hhd_buffers[index] = headers_buffer;
    det_ctx->hhd_buffers_len[index] = headers_buffer_len;

    *buffer_len = (uint32_t)headers_buffer_len;
 end:
    return headers_buffer;
}

int DetectEngineRunHttpHeaderMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                 HtpState *htp_state, uint8_t flags,
                                 void *tx, uint64_t idx)
{
    uint32_t cnt = 0;
    uint32_t buffer_len = 0;
    uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, idx,
                                                    NULL, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);
    if (buffer_len == 0)
        goto end;

    cnt = HttpHeaderPatternSearch(det_ctx, buffer, buffer_len, flags);

 end:
    return cnt;
}

int DetectEngineInspectHttpHeader(ThreadVars *tv,
                                  DetectEngineCtx *de_ctx,
                                  DetectEngineThreadCtx *det_ctx,
                                  Signature *s, Flow *f, uint8_t flags,
                                  void *alstate,
                                  void *tx, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)alstate;
    uint32_t buffer_len = 0;
    uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, tx_id,
                                                    de_ctx, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);
    if (buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_HHDMATCH],
                                          f,
                                          buffer,
                                          buffer_len,
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_HHD, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

void DetectEngineCleanHHDBuffers(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->hhd_buffers_list_len != 0) {
        int i;
        for (i = 0; i < det_ctx->hhd_buffers_list_len; i++) {
            det_ctx->hhd_buffers_len[i] = 0;
        }
        det_ctx->hhd_buffers_list_len = 0;
    }
    det_ctx->hhd_start_tx_id = 0;

    return;
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest01(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest02(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; depth:15; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest03(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:!\"one\"; depth:5; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest04(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; depth:5; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest05(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:!\"one\"; depth:15; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest06(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; offset:10; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest07(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:!\"one\"; offset:15; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest08(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; offset:15; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest09(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:!\"one\"; offset:10; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest10(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:\"three\"; http_header; within:10; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest11(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:!\"three\"; http_header; within:5; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest12(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:!\"three\"; http_header; within:10; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest13(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:\"three\"; http_header; within:5; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest14(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:\"five\"; http_header; distance:7; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest15(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:!\"five\"; http_header; distance:15; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest16(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:!\"five\"; http_header; distance:7; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest17(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:\"five\"; http_header; distance:15; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
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
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest18(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "Host: www.onetwothreefourfivesixsevenfive.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; content:\"five\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* start the search phase */
    det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    uint32_t r = HttpHeaderPatternSearch(det_ctx, http_buf, http_len, STREAM_TOSERVER);
    if (r != 2) {
        printf("expected result 2, got %"PRIu32": ", r);
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_header content matches against a http request
 *      which holds the content.
 */
static int DetectEngineHttpHeaderTest19(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "Host: www.onetwothreefourfivesixsevenfive.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"one\"; http_header; fast_pattern; content:\"five\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* start the search phase */
    det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    uint32_t r = HttpHeaderPatternSearch(det_ctx, http_buf, http_len, STREAM_TOSERVER);
    if (r != 1) {
        printf("expected result 1, got %"PRIu32": ", r);
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHeaderTest20(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:!\"dummy\"; http_header; within:7; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest21(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:!\"dummy\"; within:7; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest22(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:!\"dummy\"; distance:3; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest23(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:!\"dummy\"; distance:13; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest24(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:\"dummy\"; within:15; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest25(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:\"dummy\"; within:10; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest26(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:\"dummy\"; distance:8; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest27(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This_is_dummy_body1";
    uint8_t http2_buf[] =
        "This_is_dummy_message_body2\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "pcre:/body1/H; "
                               "content:\"dummy\"; distance:14; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest28(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"Content-Length: 6\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1,
                          http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpHeaderTest29(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"Content-Length: 7\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1,
                          http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

#if 0

static int DetectEngineHttpHeaderTest30(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"Content-Length: 6\"; http_header; "
                               "content:\"User-Agent: Mozilla\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list != NULL) {
        goto end;
    }

    result = 1;

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* #if 0 */

static int DetectEngineHttpHeaderTest30(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Set-Cookie: dummycookieset\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http header test\"; "
                               "content:\"dummycookieset\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1,
                          http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test reassembly bug where headers with names of length 6 were
  *       skipped
  */
static int DetectEngineHttpHeaderTest31(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Accept: blah\r\n"
        "Cookie: blah\r\n"
        "Crazy6: blah\r\n"
        "SixZix: blah\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(content:\"Accept|3a|\"; http_header; "
                               "content:!\"Cookie|3a|\"; http_header; "
                               "content:\"Crazy6|3a|\"; http_header; "
                               "content:\"SixZix|3a|\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    UTHFreePackets(&p1, 1);
    return result;
}

/**
 * \test Trailing headers.
 */
static int DetectEngineHttpHeaderTest32(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "host: boom\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "13\r\n"
        "This is dummy body1\r\n"
        "0\r\n"
        "Dummy-Header: kaboom\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(content:\"Dummy\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
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
    UTHFreePackets(&p1, 1);
    return result;
}

/**
 * \test Trailing headers.
 */
static int DetectEngineHttpHeaderTest33(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "host: boom\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "13\r\n"
        "This is dummy body1\r\n"
        "0\r\n";
    uint8_t http2_buf[] =
        "Dummy-Header: kaboom\r\n"
        "\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(content:\"Dummy\"; http_header; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have\n");
        goto end;
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
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

#endif /* UNITTESTS */

void DetectEngineHttpHeaderRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("DetectEngineHttpHeaderTest01",
                   DetectEngineHttpHeaderTest01, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest02",
                   DetectEngineHttpHeaderTest02, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest03",
                   DetectEngineHttpHeaderTest03, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest04",
                   DetectEngineHttpHeaderTest04, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest05",
                   DetectEngineHttpHeaderTest05, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest06",
                   DetectEngineHttpHeaderTest06, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest07",
                   DetectEngineHttpHeaderTest07, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest08",
                   DetectEngineHttpHeaderTest08, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest09",
                   DetectEngineHttpHeaderTest09, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest10",
                   DetectEngineHttpHeaderTest10, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest11",
                   DetectEngineHttpHeaderTest11, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest12",
                   DetectEngineHttpHeaderTest12, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest13",
                   DetectEngineHttpHeaderTest13, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest14",
                   DetectEngineHttpHeaderTest14, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest15",
                   DetectEngineHttpHeaderTest15, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest16",
                   DetectEngineHttpHeaderTest16, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest17",
                   DetectEngineHttpHeaderTest17, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest18",
                   DetectEngineHttpHeaderTest18, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest19",
                   DetectEngineHttpHeaderTest19, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest20",
                   DetectEngineHttpHeaderTest20, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest21",
                   DetectEngineHttpHeaderTest21, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest22",
                   DetectEngineHttpHeaderTest22, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest23",
                   DetectEngineHttpHeaderTest23, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest24",
                   DetectEngineHttpHeaderTest24, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest25",
                   DetectEngineHttpHeaderTest25, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest26",
                   DetectEngineHttpHeaderTest26, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest27",
                   DetectEngineHttpHeaderTest27, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest28",
                   DetectEngineHttpHeaderTest28, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest29",
                   DetectEngineHttpHeaderTest29, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest30",
                   DetectEngineHttpHeaderTest30, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest31",
                   DetectEngineHttpHeaderTest31, 1);
#if 0
    UtRegisterTest("DetectEngineHttpHeaderTest30",
                   DetectEngineHttpHeaderTest30, 1);
#endif
    UtRegisterTest("DetectEngineHttpHeaderTest32",
                   DetectEngineHttpHeaderTest32, 1);
    UtRegisterTest("DetectEngineHttpHeaderTest33",
                   DetectEngineHttpHeaderTest33, 1);

#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
