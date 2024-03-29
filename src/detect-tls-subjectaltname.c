/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 *
 * Implements support for tls.subjectaltname keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-subjectaltname.h"
#include "detect-engine-uint.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-profiling.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsSubjectAltNameSetup(DetectEngineCtx *, Signature *, const char *);
static uint8_t DetectEngineInspectTlsSubjectAltName(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static int PrefilterMpmTlsSubjectAltNameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id);

static int g_tls_subjectaltname_buffer_id = 0;

typedef struct PrefilterMpmTlsSubjectAltName {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmTlsSubjectAltName;

/**
 * \brief Registration function for keyword: tls.subjectaltname
 */
void DetectTlsSubjectAltNameRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].name = "tls.subjectaltname";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].desc =
            "sticky buffer to match the TLS Subject Alternative Name buffer";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].url =
            "/rules/tls-keywords.html#tls-subjectaltname";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].Setup = DetectTlsSubjectAltNameSetup;
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("tls.subjectaltname", ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_CERT_READY, DetectEngineInspectTlsSubjectAltName, NULL);

    DetectAppLayerMpmRegister("tls.subjectaltname", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmTlsSubjectAltNameRegister, NULL, ALPROTO_TLS, TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.subjectaltname", "TLS Subject Alternative Name");

    DetectBufferTypeSupportsMultiInstance("tls.subjectaltname");

    g_tls_subjectaltname_buffer_id = DetectBufferTypeGetByName("tls.subjectaltname");
}

/**
 * \brief This function setup the tls.subjectaltname sticky buffer keyword
 *
 * \param de_ctx Pointer to the Detect Engine Context
 * \param s      Pointer to the Signature to which the keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsSubjectAltNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_tls_subjectaltname_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *TlsSubjectAltNameGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flags, uint16_t idx, int list_id)
{
    SCEnter();
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL || buffer->initialized)
        return buffer;

    const SSLState *ssl_state = (SSLState *)f->alstate;
    const SSLStateConnp *connp;

    connp = &ssl_state->server_connp;

    if (connp->cert0_sans_len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    if (idx > 0 && idx >= connp->cert0_sans_len) {
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, (const uint8_t *)connp->cert0_sans[idx],
            strlen(connp->cert0_sans[idx]));

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectTlsSubjectAltName(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    for (uint16_t i = 0;; i++) {
        InspectionBuffer *buffer =
                TlsSubjectAltNameGetData(det_ctx, transforms, f, flags, i, engine->sm_list);
        if (buffer == NULL || buffer->inspect == NULL)
            break;
        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static void PrefilterTxTlsSubjectAltName(DetectEngineThreadCtx *det_ctx, const void *pectx,
        Packet *p, Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd,
        const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmTlsSubjectAltName *ctx = (const PrefilterMpmTlsSubjectAltName *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    for (uint16_t i = 0;; i++) {
        InspectionBuffer *buffer =
                TlsSubjectAltNameGetData(det_ctx, ctx->transforms, f, flags, i, list_id);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }
    }
}

static void PrefilterMpmTlsSubjectAltNameFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmTlsSubjectAltNameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmTlsSubjectAltName *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;

    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxTlsSubjectAltName,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress, pectx,
            PrefilterMpmTlsSubjectAltNameFree, mpm_reg->name);
}
