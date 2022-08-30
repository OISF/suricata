/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-ike-vendor.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"

static int DetectIkeVendorSetup(DetectEngineCtx *, Signature *, const char *);

typedef struct {
    char *vendor;
} DetectIkeVendorData;

struct IkeVendorGetDataArgs {
    uint32_t local_id;
    void *txv;
};

typedef struct PrefilterMpmIkeVendor {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmIkeVendor;

static int g_ike_vendor_buffer_id = 0;

static InspectionBuffer *IkeVendorGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, struct IkeVendorGetDataArgs *cbdata,
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
    if (rs_ike_tx_get_vendor(cbdata->txv, cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

/** \brief IkeVendor Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxIkeVendor(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmIkeVendor *ctx = (const PrefilterMpmIkeVendor *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    while (1) {
        struct IkeVendorGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                IkeVendorGetData(det_ctx, ctx->transforms, f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
        }
        local_id++;
    }

    SCReturn;
}

static void PrefilterMpmIkeVendorFree(void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

static int PrefilterMpmIkeVendorRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmIkeVendor *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxIkeVendor, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmIkeVendorFree, mpm_reg->pname);
}

static uint8_t DetectEngineInspectIkeVendor(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct IkeVendorGetDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                IkeVendorGetData(det_ctx, transforms, f, &cbdata, engine->sm_list, false);
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

/**
 * \brief Registration function for ike.vendor keyword.
 */
void DetectIkeVendorRegister(void)
{
    sigmatch_table[DETECT_AL_IKE_VENDOR].name = "ike.vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].desc = "match IKE Vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].url = "/rules/ike-keywords.html#ike-vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].Setup = DetectIkeVendorSetup;
    sigmatch_table[DETECT_AL_IKE_VENDOR].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_IKE_VENDOR].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2("ike.vendor", SIG_FLAG_TOSERVER, 1, PrefilterMpmIkeVendorRegister,
            NULL, ALPROTO_IKE, 1);

    DetectAppLayerInspectEngineRegister2(
            "ike.vendor", ALPROTO_IKE, SIG_FLAG_TOSERVER, 1, DetectEngineInspectIkeVendor, NULL);

    g_ike_vendor_buffer_id = DetectBufferTypeGetByName("ike.vendor");
}

/**
 * \brief setup the sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectIkeVendorSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_ike_vendor_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;
    return 0;
}
