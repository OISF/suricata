/* Copyright (C) 2020 Open Information Security Foundation
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
 * Implements the quic.cyu.hash sticky buffer
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-quic-cyu-hash.h"
#include "rust.h"

#define KEYWORD_NAME "quic.cyu.hash"
#define KEYWORD_DOC  "quic-cyu.html#quic-cyu-hash"
#define BUFFER_NAME  "quic.cyu.hash"
#define BUFFER_DESC  "QUIC CYU Hash"
static int g_buffer_id = 0;

struct QuicHashGetDataArgs {
    int local_id; /**< used as index into thread inspect array */
    void *txv;
};

static int DetectQuicCyuHashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *QuicHashGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, struct QuicHashGetDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBufferMultipleForList *fb = InspectionBufferGetMulti(det_ctx, list_id);
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(fb, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_quic_tx_get_cyu_hash(cbdata->txv, (uint16_t)cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }
    InspectionBufferSetup(buffer, data, data_len);
    InspectionBufferApplyTransforms(buffer, transforms);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static int DetectEngineInspectQuicHash(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    int local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct QuicHashGetDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                QuicHashGetData(det_ctx, transforms, f, &cbdata, engine->sm_list, false);
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

typedef struct PrefilterMpmQuicHash {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmQuicHash;

/** \brief QuicHash Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxQuicHash(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmQuicHash *ctx = (const PrefilterMpmQuicHash *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    int local_id = 0;
    while (1) {
        // loop until we get a NULL

        struct QuicHashGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                QuicHashGetData(det_ctx, ctx->transforms, f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmQuicHashFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmQuicHashRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmQuicHash *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxQuicHash, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmQuicHashFree, mpm_reg->pname);
}

static bool DetectQuicHashValidateCallback(const Signature *s, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_buffer_id];
    for (; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = BUFFER_NAME " should not be used together with "
                                    "nocase, since the rule is automatically "
                                    "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len != 32) {
            *sigerror = "Invalid length of the specified" BUFFER_NAME " (should "
                        "be 32 characters long). This rule will therefore "
                        "never match.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
            return FALSE;
        }
        for (size_t i = 0; i < cd->content_len; ++i) {
            if (!isxdigit(cd->content[i])) {
                *sigerror = "Invalid " BUFFER_NAME
                            " string (should be string of hexademical characters)."
                            "This rule will therefore never match.";
                SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
                return FALSE;
            }
        }
    }

    return TRUE;
}

void DetectQuicCyuHashRegister(void)
{
    /* quic.cyu.hash sticky buffer */
    sigmatch_table[DETECT_AL_QUIC_CYU_HASH].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_QUIC_CYU_HASH].desc = "sticky buffer to match on the QUIC CYU hash";
    sigmatch_table[DETECT_AL_QUIC_CYU_HASH].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_QUIC_CYU_HASH].Setup = DetectQuicCyuHashSetup;
    sigmatch_table[DETECT_AL_QUIC_CYU_HASH].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2(
            BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterMpmQuicHashRegister, NULL, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2(
            BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOSERVER, 0, DetectEngineInspectQuicHash, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME, DetectQuicHashValidateCallback);
}
