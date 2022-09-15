/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-krb5-cname.h"

#include "rust.h"
#include "app-layer-krb5.h"
#include "util-profiling.h"

static int g_krb5_cname_buffer_id = 0;

struct Krb5PrincipalNameDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

static int DetectKrb5CNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_krb5_cname_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetKrb5CNameData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const struct Krb5PrincipalNameDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_krb5_tx_get_cname(cbdata->txv, cbdata->local_id, &b, &b_len) != 1)
        return NULL;
    if (b == NULL || b_len == 0)
        return NULL;

    InspectionBufferSetupMulti(buffer, transforms, b, b_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectKrb5CName(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct Krb5PrincipalNameDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = GetKrb5CNameData(det_ctx,
                transforms, f, &cbdata, engine->sm_list, false);

        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmKrb5Name {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmKrb5Name;

/** \brief Krb5CName Krb5CName Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxKrb5CName(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmKrb5Name *ctx = (const PrefilterMpmKrb5Name *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;

    while(1) {
        // loop until we get a NULL

        struct Krb5PrincipalNameDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = GetKrb5CNameData(det_ctx, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmKrb5NameFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmKrb5CNameRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmKrb5Name *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxKrb5CName,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmKrb5NameFree, mpm_reg->name);
}

void DetectKrb5CNameRegister(void)
{
    sigmatch_table[DETECT_AL_KRB5_CNAME].name = "krb5.cname";
    sigmatch_table[DETECT_AL_KRB5_CNAME].alias = "krb5_cname";
    sigmatch_table[DETECT_AL_KRB5_CNAME].url = "/rules/kerberos-keywords.html#krb5-cname";
    sigmatch_table[DETECT_AL_KRB5_CNAME].Setup = DetectKrb5CNameSetup;
    sigmatch_table[DETECT_AL_KRB5_CNAME].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[DETECT_AL_KRB5_CNAME].desc = "sticky buffer to match on Kerberos 5 client name";

    DetectAppLayerMpmRegister2("krb5_cname", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmKrb5CNameRegister, NULL,
            ALPROTO_KRB5, 1);

    DetectAppLayerInspectEngineRegister2("krb5_cname",
            ALPROTO_KRB5, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectKrb5CName, NULL);

    DetectBufferTypeSetDescriptionByName("krb5_cname",
            "Kerberos 5 ticket client name");

    g_krb5_cname_buffer_id = DetectBufferTypeGetByName("krb5_cname");
}
