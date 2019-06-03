/* Copyright (C) 2018 Open Information Security Foundation
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

#include "detect-krb5-sname.h"

#include "rust.h"
#include "app-layer-krb5.h"
#include "rust-krb-detect-gen.h"

static int g_krb5_sname_buffer_id = 0;

struct Krb5PrincipalNameDataArgs {
    int local_id;  /**< used as index into thread inspect array */
    void *txv;
};

static int DetectKrb5SNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_krb5_sname_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetKrb5SNameData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const struct Krb5PrincipalNameDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBufferMultipleForList *fb = InspectionBufferGetMulti(det_ctx, list_id);
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(fb, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_krb5_tx_get_sname(cbdata->txv, (uint16_t)cbdata->local_id, &b, &b_len) != 1)
        return NULL;
    if (b == NULL || b_len == 0)
        return NULL;

    InspectionBufferSetup(buffer, b, b_len);
    InspectionBufferApplyTransforms(buffer, transforms);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static int DetectEngineInspectKrb5SName(
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    int local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct Krb5PrincipalNameDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = GetKrb5SNameData(det_ctx,
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

/** \brief Krb5SName Krb5SName Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxKrb5SName(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmKrb5Name *ctx = (const PrefilterMpmKrb5Name *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    int local_id = 0;

    while(1) {
        // loop until we get a NULL

        struct Krb5PrincipalNameDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = GetKrb5SNameData(det_ctx, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmKrb5NameFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmKrb5SNameRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id)
{
    PrefilterMpmKrb5Name *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->v2.transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxKrb5SName,
            mpm_reg->v2.alproto, mpm_reg->v2.tx_min_progress,
            pectx, PrefilterMpmKrb5NameFree, mpm_reg->name);
}

void DetectKrb5SNameRegister(void)
{
    sigmatch_table[DETECT_AL_KRB5_SNAME].name = "krb5.sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].alias = "krb5_sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].Setup = DetectKrb5SNameSetup;
    sigmatch_table[DETECT_AL_KRB5_SNAME].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[DETECT_AL_KRB5_SNAME].desc = "sticky buffer to match on Kerberos 5 server name";

    DetectAppLayerMpmRegister2("krb5_sname", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmKrb5SNameRegister, NULL,
            ALPROTO_KRB5, 1);

    DetectAppLayerInspectEngineRegister2("krb5_sname",
            ALPROTO_KRB5, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectKrb5SName, NULL);

    DetectBufferTypeSetDescriptionByName("krb5_sname",
            "Kerberos 5 ticket server name");

    g_krb5_sname_buffer_id = DetectBufferTypeGetByName("krb5_sname");
}
