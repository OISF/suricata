/* Copyright (C) 2016 Open Information Security Foundation
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
 *  \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-ssl.h"
#include "detect-engine-tls.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

/** \brief TLS SNI Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxTlsSni(DetectEngineThreadCtx *det_ctx, const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    SSLState *ssl_state = f->alstate;

    if (ssl_state->client_connp.sni == NULL)
        return;

    const uint8_t *buffer = (uint8_t *)ssl_state->client_connp.sni;
    const uint32_t buffer_len = strlen(ssl_state->client_connp.sni);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

int PrefilterTxTlsSniRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxTlsSni,
        ALPROTO_TLS, 0, // TODO a special 'cert ready' state might be good to add
        mpm_ctx, NULL, "tls_sni");
}

/** \brief Do the content inspection and validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect
 *  \param sm       SigMatch to inspect
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param state    App layer state
 *
 *  \retval 0       No match
 *  \retval 1       Match
 */
int DetectEngineInspectTlsSni(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    int cnt = 0;

    SSLState *ssl_state = (SSLState *)alstate;

    if (ssl_state->client_connp.sni == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->client_connp.sni;
    buffer_len = strlen(ssl_state->client_connp.sni);

    cnt = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            f, buffer, buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);

    return cnt;
}

/** \brief TLS Issuer Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxTlsIssuer(DetectEngineThreadCtx *det_ctx, const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    SSLState *ssl_state = f->alstate;

    if (ssl_state->server_connp.cert0_issuerdn == NULL)
        return;

    const uint8_t *buffer = (const uint8_t *)ssl_state->server_connp.cert0_issuerdn;
    const uint32_t buffer_len = strlen(ssl_state->server_connp.cert0_issuerdn);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

int PrefilterTxTlsIssuerRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxTlsIssuer,
        ALPROTO_TLS, TLS_STATE_CERT_READY,
        mpm_ctx, NULL, "tls_cert_issuer");
}

/** \brief Do the content inspection and validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect
 *  \param sm       SigMatch to inspect
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param state    App layer state
 *
 *  \retval 0       No match
 *  \retval 1       Match
 */
int DetectEngineInspectTlsIssuer(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint8_t *buffer;
    uint32_t buffer_len;
    int cnt = 0;

    SSLState *ssl_state = (SSLState *)alstate;

    if (ssl_state->server_connp.cert0_issuerdn == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->server_connp.cert0_issuerdn;
    buffer_len = strlen(ssl_state->server_connp.cert0_issuerdn);

    cnt = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            f, buffer, buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);

    return cnt;
}

/** \brief TLS Subject Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxTlsSubject(DetectEngineThreadCtx *det_ctx, const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    SSLState *ssl_state = f->alstate;

    if (ssl_state->server_connp.cert0_subject == NULL)
        return;

    const uint8_t *buffer = (const uint8_t *)ssl_state->server_connp.cert0_subject;
    const uint32_t buffer_len = strlen(ssl_state->server_connp.cert0_subject);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

int PrefilterTxTlsSubjectRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxTlsSubject,
        ALPROTO_TLS, TLS_STATE_CERT_READY,
        mpm_ctx, NULL, "tls_cert_subject");
}

/** \brief Do the content inspection and validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect
 *  \param sm       SigMatch to inspect
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param state    App layer state
 *
 *  \retval 0       No match
 *  \retval 1       Match
 */
int DetectEngineInspectTlsSubject(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint8_t *buffer;
    uint32_t buffer_len;
    int cnt = 0;

    SSLState *ssl_state = (SSLState *)alstate;

    if (ssl_state->server_connp.cert0_subject == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->server_connp.cert0_subject;
    buffer_len = strlen(ssl_state->server_connp.cert0_subject);

    cnt = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            f, buffer, buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);

    return cnt;
}

/** \brief TLS Serial Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxTlsSerial(DetectEngineThreadCtx *det_ctx, const void *pectx,
                                 Packet *p, Flow *f, void *txv, const uint64_t idx,
                                 const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    SSLState *ssl_state = f->alstate;

    if (ssl_state->server_connp.cert0_serial == NULL)
        return;

    const uint8_t *buffer = (const uint8_t *)ssl_state->server_connp.cert0_serial;
    const uint32_t buffer_len = strlen(ssl_state->server_connp.cert0_serial);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtcu,
                &det_ctx->pmq, buffer, buffer_len);
    }
}

int PrefilterTxTlsSerialRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxTlsSerial, ALPROTO_TLS,
                                   TLS_STATE_CERT_READY, mpm_ctx, NULL,
                                   "tls_cert_serial");
}

/** \brief Do the content inspection and validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect
 *  \param sm       SigMatch to inspect
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param state    App layer state
 *
 *  \retval 0       No match
 *  \retval 1       Match
 */
int DetectEngineInspectTlsSerial(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                 DetectEngineThreadCtx *det_ctx, const Signature *s,
                                 const SigMatchData *smd, Flow *f,
                                 uint8_t flags, void *alstate, void *txv,
                                 uint64_t tx_id)
{
    uint8_t *buffer;
    uint32_t buffer_len;
    int cnt = 0;

    SSLState *ssl_state = (SSLState *)alstate;

    if (ssl_state->server_connp.cert0_serial == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->server_connp.cert0_serial;
    buffer_len = strlen(ssl_state->server_connp.cert0_serial);

    cnt = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
           f, buffer, buffer_len, 0,
           DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);

    return cnt;
}

int DetectEngineInspectTlsValidity(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}
