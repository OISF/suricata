/* Copyright (C) 2015-2016 Open Information Security Foundation
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


/** \file
 *
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
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
#include "detect-engine-prefilter.h"
#include "detect-engine-filedata-smtp.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "stream-tcp.h"

#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-smtp.h"
#include "app-layer-protos.h"

#include "util-validate.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#define BUFFER_STEP 50

static inline int SMTPCreateSpace(DetectEngineThreadCtx *det_ctx, uint16_t size)
{
    void *ptmp;
    if (size > det_ctx->smtp_buffers_size) {
        ptmp = SCRealloc(det_ctx->smtp,
                         (det_ctx->smtp_buffers_size + BUFFER_STEP) * sizeof(FiledataReassembledBody));
        if (ptmp == NULL) {
            SCFree(det_ctx->smtp);
            det_ctx->smtp = NULL;
            det_ctx->smtp_buffers_size = 0;
            det_ctx->smtp_buffers_list_len = 0;
            return -1;
        }
        det_ctx->smtp = ptmp;

        memset(det_ctx->smtp + det_ctx->smtp_buffers_size, 0, BUFFER_STEP * sizeof(FiledataReassembledBody));
        det_ctx->smtp_buffers_size += BUFFER_STEP;
    }
    for (int i = det_ctx->smtp_buffers_list_len; i < (size); i++) {
        det_ctx->smtp[i].buffer_len = 0;
        det_ctx->smtp[i].offset = 0;
    }

    return 0;
}

static const uint8_t *DetectEngineSMTPGetBufferForTX(uint64_t tx_id,
                                               DetectEngineCtx *de_ctx,
                                               DetectEngineThreadCtx *det_ctx,
                                               Flow *f, File *curr_file,
                                               uint8_t flags,
                                               uint32_t *buffer_len,
                                               uint32_t *stream_start_offset)
{
    SCEnter();
    int index = 0;
    const uint8_t *buffer = NULL;
    *buffer_len = 0;
    *stream_start_offset = 0;
    uint64_t file_size = FileDataSize(curr_file);

    if (det_ctx->smtp_buffers_list_len == 0) {
        if (SMTPCreateSpace(det_ctx, 1) < 0)
            goto end;
        index = 0;

        if (det_ctx->smtp_buffers_list_len == 0) {
            det_ctx->smtp_start_tx_id = tx_id;
        }
        det_ctx->smtp_buffers_list_len++;
    } else {
        if ((tx_id - det_ctx->smtp_start_tx_id) < det_ctx->smtp_buffers_list_len) {
            if (det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer_len != 0) {
                *buffer_len = det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer_len;
                *stream_start_offset = det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].offset;
                buffer = det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer;

                SCReturnPtr(buffer, "uint8_t");
            }
        } else {
            if (SMTPCreateSpace(det_ctx, (tx_id - det_ctx->smtp_start_tx_id) + 1) < 0)
                goto end;

            if (det_ctx->smtp_buffers_list_len == 0) {
                det_ctx->smtp_start_tx_id = tx_id;
            }
            det_ctx->smtp_buffers_list_len++;
        }
        index = (tx_id - det_ctx->smtp_start_tx_id);
    }

    SCLogDebug("smtp_config.content_limit %u, smtp_config.content_inspect_min_size %u",
                smtp_config.content_limit, smtp_config.content_inspect_min_size);

    SCLogDebug("file %p size %"PRIu64", state %d", curr_file, file_size, curr_file->state);

    /* no new data */
    if (curr_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        goto end;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        goto end;
    }

    if ((smtp_config.content_limit == 0 || file_size < smtp_config.content_limit) &&
        file_size < smtp_config.content_inspect_min_size &&
        !(flags & STREAM_EOF) && !(curr_file->state > FILE_STATE_OPENED)) {
        SCLogDebug("we still haven't seen the entire content. "
                   "Let's defer content inspection till we see the "
                   "entire content.");
        goto end;
    }

    StreamingBufferGetDataAtOffset(curr_file->sb,
            &det_ctx->smtp[index].buffer, &det_ctx->smtp[index].buffer_len,
            curr_file->content_inspected);

    det_ctx->smtp[index].offset = curr_file->content_inspected;

    /* updat inspected tracker */
    curr_file->content_inspected = FileDataSize(curr_file);

    SCLogDebug("content_inspected %"PRIu64", offset %"PRIu64,
            curr_file->content_inspected, det_ctx->smtp[index].offset);

    buffer = det_ctx->smtp[index].buffer;
    *buffer_len = det_ctx->smtp[index].buffer_len;
    *stream_start_offset = det_ctx->smtp[index].offset;

end:
    SCLogDebug("buffer %p, len %u", buffer, *buffer_len);
    SCReturnPtr(buffer, "uint8_t");
}

int DetectEngineInspectSMTPFiledata(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    SMTPState *smtp_state = (SMTPState *)alstate;
    FileContainer *ffc = smtp_state->files_ts;
    int r = 0;
    int match = 0;
    uint32_t buffer_len = 0;
    uint32_t stream_start_offset = 0;
    const uint8_t *buffer = 0;

    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            buffer = DetectEngineSMTPGetBufferForTX(tx_id,
                                                    de_ctx, det_ctx,
                                                    f, file,
                                                    flags,
                                                    &buffer_len,
                                                    &stream_start_offset);
        if (buffer_len == 0)
            goto end;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        match = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                              f,
                                              (uint8_t *)buffer,
                                              buffer_len,
                                              stream_start_offset,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
        if (match == 1)
            r = 1;
        }
    }

end:
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

void DetectEngineCleanSMTPBuffers(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->smtp_buffers_list_len > 0) {
        for (int i = 0; i < det_ctx->smtp_buffers_list_len; i++) {
            det_ctx->smtp[i].buffer_len = 0;
            det_ctx->smtp[i].offset = 0;
        }
    }
    det_ctx->smtp_buffers_list_len = 0;
    det_ctx->smtp_start_tx_id = 0;

    return;
}

/** \brief SMTP Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 *
 *  \todo check files against actual tx
 */
static void PrefilterTxSmtpFiledata(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    SMTPState *smtp_state = f->alstate;
    FileContainer *ffc = smtp_state->files_ts;
    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            uint32_t buffer_len = 0;
            uint32_t stream_start_offset = 0;

            const uint8_t *buffer = DetectEngineSMTPGetBufferForTX(idx,
                                                    NULL, det_ctx,
                                                    f, file,
                                                    flags,
                                                    &buffer_len,
                                                    &stream_start_offset);
            if (buffer != NULL && buffer_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
            }
        }
    }
}

int PrefilterTxSmtpFiledataRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxSmtpFiledata,
        ALPROTO_SMTP, 0,
        mpm_ctx, NULL, "file_data (smtp)");
}

#ifdef UNITTESTS

static int DetectEngineSMTPFiledataTest01(void)
{
    uint8_t mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,
                0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
                0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
                0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A,
                0x20, 0x74, 0x65, 0x78, 0x74, 0x2F, 0x70, 0x6C,
                0x61, 0x69, 0x6E, 0x3B, 0x20, 0x63, 0x68, 0x61,
                0x72, 0x73, 0x65, 0x74, 0x3D, 0x55, 0x54, 0x46,
                0x2D, 0x38, 0x3B, 0x0D, 0x0A, 0x43, 0x6F, 0x6E,
                0x74, 0x65, 0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61,
                0x6E, 0x73, 0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E,
                0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20,
                0x37, 0x62, 0x69, 0x74, 0x0D, 0x0A, 0x43, 0x6F,
                0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x44, 0x69,
                0x73, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x69, 0x6F,
                0x6E, 0x3A, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63,
                0x68, 0x6D, 0x65, 0x6E, 0x74, 0x3B, 0x20, 0x66,
                0x69, 0x6C, 0x65, 0x6E, 0x61, 0x6D, 0x65, 0x3D,
                0x22, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78,
                0x74, 0x22, 0x0D, 0x0A, 0x0D, 0x0A, 0x6d, 0x65,
                0x73, 0x73, 0x61, 0x67, 0x65,};
    uint32_t mimemsg_len = sizeof(mimemsg) - 1;
    TcpSession ssn;
    Packet *p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    SMTPState *smtp_state = NULL;
    Flow f;
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
    f.alstate = SMTPStateAlloc();

    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state) != 0)
        goto end;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST|PKT_STREAM_EOF;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert smtp any any -> any any "
                               "(msg:\"file_data smtp test\"; "
                               "file_data; content:\"message\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                mimemsg,
                                mimemsg_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineSMTPFiledataTest02(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert smtp any any -> any any "
                              "(msg:\"file_data smtp test\"; "
                              "file_data; content:\"message\"; sid:1;)");
    if (s == NULL)
        goto end;

    if (s->flags & SIG_FLAG_TOSERVER)
        result = 1;
    else if (s->flags & SIG_FLAG_TOCLIENT)
        printf("s->flags & SIG_FLAG_TOCLIENT");

end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;

}

static int DetectEngineSMTPFiledataTest03(void)
{
    uint8_t mimemsg1[] = {0x65, 0x76,};
    uint8_t mimemsg2[] = {0x69, 0x6C,};
    uint32_t mimemsg1_len = sizeof(mimemsg1) - 1;
    uint32_t mimemsg2_len = sizeof(mimemsg2) - 1;
    TcpSession ssn;
    Packet *p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    SMTPState *smtp_state = NULL;
    Flow f;
    int result = 1;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alstate = SMTPStateAlloc();

    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg1, sizeof(mimemsg1), state) != 0)
        goto end;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg2, sizeof(mimemsg2), state) != 0)
        goto end;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert smtp any any -> any any "
                               "(msg:\"file_data smtp test\"; "
                               "file_data; content:\"evil\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = 0;
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, mimemsg1, mimemsg1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, mimemsg2, mimemsg2_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    result = 0;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result == 0;
}

#endif /* UNITTESTS */

void DetectEngineSMTPFiledataRegisterTests(void)
{
    #ifdef UNITTESTS
    UtRegisterTest("DetectEngineSMTPFiledataTest01",
                   DetectEngineSMTPFiledataTest01);
    UtRegisterTest("DetectEngineSMTPFiledataTest02",
                   DetectEngineSMTPFiledataTest02);
    UtRegisterTest("DetectEngineSMTPFiledataTest03",
                   DetectEngineSMTPFiledataTest03);
    #endif /* UNITTESTS */

    return;
}
