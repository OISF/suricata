/* Copyright (C) 2023 Open Information Security Foundation
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
 * \file
 *
 * Detect keyword for DNS answer name: dns.answer.name
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-dns-answer-name.h"
#include "util-profiling.h"
#include "rust.h"

typedef struct PrefilterMpm {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpm;

static int detect_buffer_id = 0;

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, detect_buffer_id) < 0) {
        return -1;
    }
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0) {
        return -1;
    }

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx, uint8_t flags,
        const DetectEngineTransforms *transforms, void *txv, uint32_t index, int list_id)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, index);
    if (buffer == NULL) {
        return NULL;
    }
    if (buffer->initialized) {
        return buffer;
    }

    bool to_client = (flags & STREAM_TOSERVER) == 0;
    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (!SCDnsTxGetAnswerName(txv, to_client, index, &data, &data_len)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

static uint8_t DetectEngineInspectCb(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    if (f->alproto == ALPROTO_DOH2) {
        txv = SCDoH2GetDnsTx(txv, flags);
        if (txv == NULL) {
            return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
        }
    }
    for (uint32_t i = 0;; i++) {
        InspectionBuffer *buffer = GetBuffer(det_ctx, flags, transforms, txv, i, engine->sm_list);
        if (buffer == NULL || buffer->inspect == NULL) {
            break;
        }

        const bool match = DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd,
                NULL, f, buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static void PrefilterTx(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f,
        void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpm *ctx = (const PrefilterMpm *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    if (f->alproto == ALPROTO_DOH2) {
        txv = SCDoH2GetDnsTx(txv, flags);
        if (txv == NULL) {
            return;
        }
    }
    for (uint32_t i = 0;; i++) {
        InspectionBuffer *buffer = GetBuffer(det_ctx, flags, ctx->transforms, txv, i, list_id);
        if (buffer == NULL) {
            break;
        }

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }
    }
}

static void PrefilterMpmFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpm *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL) {
        return -1;
    }
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTx, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmFree, mpm_reg->pname);
}

void DetectDnsAnswerNameRegister(void)
{
    static const char *keyword = "dns.answer.name";
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].name = keyword;
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].desc = "DNS answer name sticky buffer";
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].url = "/rules/dns-keywords.html#dns-answer-name";
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].Setup = DetectSetup;
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_ANSWER_NAME].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register in the TO_SERVER direction, even though this is not
       normal, it could be provided as part of a request. */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectCb, NULL);
    DetectAppLayerMpmRegister(
            keyword, SIG_FLAG_TOSERVER, 2, PrefilterMpmRegister, NULL, ALPROTO_DNS, 1);

    /* Register in the TO_CLIENT direction. */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectCb, NULL);
    DetectAppLayerMpmRegister(
            keyword, SIG_FLAG_TOCLIENT, 2, PrefilterMpmRegister, NULL, ALPROTO_DNS, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "dns answer name");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);
}
