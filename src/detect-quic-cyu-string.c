/* Copyright (C) 2021 Open Information Security Foundation
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
 *
 * Implements the quic.cyu.string sticky buffer
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-quic-cyu-string.h"
#include "rust.h"

#define KEYWORD_NAME "quic.cyu.string"
#define KEYWORD_DOC  "quic-cyu.html#quic-cyu-string"
#define BUFFER_NAME  "quic.cyu.string"
#define BUFFER_DESC  "QUIC CYU String"
static int g_buffer_id = 0;

struct QuicStringGetDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

static int DetectQuicCyuStringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *QuicStringGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, struct QuicStringGetDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_quic_tx_get_cyu_string(cbdata->txv, cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }
    InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
    InspectionBufferApplyTransforms(buffer, transforms);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static int DetectEngineInspectQuicString(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct QuicStringGetDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                QuicStringGetData(det_ctx, transforms, f, &cbdata, engine->sm_list, false);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmQuicString {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmQuicString;

/** \brief QuicString Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxQuicString(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmQuicString *ctx = (const PrefilterMpmQuicString *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    while (1) {
        // loop until we get a NULL

        struct QuicStringGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                QuicStringGetData(det_ctx, ctx->transforms, f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmQuicStringFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmQuicStringRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmQuicString *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxQuicString, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmQuicStringFree, mpm_reg->pname);
}

void DetectQuicCyuStringRegister(void)
{
    /* quic.cyu.string sticky buffer */
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].desc =
            "sticky buffer to match on the QUIC CYU string";
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].Setup = DetectQuicCyuStringSetup;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterMpmQuicStringRegister,
            NULL, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2(
            BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOSERVER, 0, DetectEngineInspectQuicString, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
