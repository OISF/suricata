/* Copyright (C) 2019-2022 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements support for tls.certs keyword.
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
#include "detect-tls-certs.h"
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

static int DetectTlsCertsSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsCertsRegisterTests(void);
#endif

static int g_tls_certs_buffer_id = 0;

static InspectionBuffer *TlsCertsGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL || buffer->initialized)
        return buffer;

    const SSLState *ssl_state = (SSLState *)f->alstate;
    const SSLStateConnp *connp;

    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (TAILQ_EMPTY(&connp->certs)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    SSLCertsChain *cert;
    if (local_id == 0) {
        cert = TAILQ_FIRST(&connp->certs);
    } else {
        // TODO optimize ?
        cert = TAILQ_FIRST(&connp->certs);
        for (uint32_t i = 0; i < local_id; i++) {
            cert = TAILQ_NEXT(cert, next);
        }
    }
    if (cert == NULL) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, cert->cert_data, cert->cert_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

/**
 * \brief Registration function for keyword: tls.certs
 */
void DetectTlsCertsRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERTS].name = "tls.certs";
    sigmatch_table[DETECT_AL_TLS_CERTS].desc = "sticky buffer to match the TLS certificate buffer";
    sigmatch_table[DETECT_AL_TLS_CERTS].url = "/rules/tls-keywords.html#tls-certs";
    sigmatch_table[DETECT_AL_TLS_CERTS].Setup = DetectTlsCertsSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_CERTS].RegisterTests = DetectTlsCertsRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_CERTS].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_CERTS].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister("tls.certs", ALPROTO_TLS, SIG_FLAG_TOCLIENT, TLS_STATE_CERT_READY,
            TlsCertsGetData, 2, 1);
    DetectAppLayerMultiRegister("tls.certs", ALPROTO_TLS, SIG_FLAG_TOSERVER, TLS_STATE_CERT_READY,
            TlsCertsGetData, 2, 1);

    DetectBufferTypeSetDescriptionByName("tls.certs", "TLS certificate");

    DetectBufferTypeSupportsMultiInstance("tls.certs");

    g_tls_certs_buffer_id = DetectBufferTypeGetByName("tls.certs");
}

/**
 * \brief This function setup the tls.certs modifier keyword
 *
 * \param de_ctx Pointer to the Detect Engine Context
 * \param s      Pointer to the Signature to which the keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsCertsSetup(DetectEngineCtx *de_ctx, Signature *s,
                               const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_tls_certs_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static int g_tls_cert_buffer_id = 0;
#define BUFFER_NAME  "tls_validity"
#define KEYWORD_ID   DETECT_AL_TLS_CHAIN_LEN
#define KEYWORD_NAME "tls.cert_chain_len"
#define KEYWORD_DESC "match TLS certificate chain length"
#define KEYWORD_URL  "/rules/tls-keywords.html#tls-cert-chain-len"

/**
 * \internal
 * \brief Function to match cert chain length in TLS
 *
 * \param t       Pointer to thread vars.
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param s       Pointer to the Signature.
 * \param m       Pointer to the sigmatch that we will cast into
 *                DetectU64Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectTLSCertChainLenMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    SSLState *ssl_state = state;
    if (flags & STREAM_TOCLIENT) {
        SSLStateConnp *connp = &ssl_state->server_connp;
        uint32_t cnt = 0;
        SSLCertsChain *cert;
        TAILQ_FOREACH (cert, &connp->certs, next) {
            cnt++;
        }
        SCLogDebug("%u certs in chain", cnt);

        const DetectU32Data *dd = (const DetectU32Data *)ctx;
        if (DetectU32Match(cnt, dd)) {
            SCReturnInt(1);
        }
    }
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU64Data.
 *
 * \param de_ptr Pointer to DetectU64Data.
 */
static void DetectTLSCertChainLenFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

/**
 * \brief Function to add the parsed tls cert chain len field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTLSCertChainLenSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) != 0)
        return -1;

    DetectU32Data *dd = DetectU32Parse(rawstr);
    if (dd == NULL) {
        SCLogError("Parsing \'%s\' failed for %s", rawstr, sigmatch_table[KEYWORD_ID].name);
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, KEYWORD_ID, (SigMatchCtx *)dd, g_tls_cert_buffer_id) ==
            NULL) {
        rs_detect_u32_free(dd);
        return -1;
    }
    return 0;
}

void DetectTlsCertChainLenRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].desc = KEYWORD_DESC;
    sigmatch_table[KEYWORD_ID].url = KEYWORD_URL;
    sigmatch_table[KEYWORD_ID].AppLayerTxMatch = DetectTLSCertChainLenMatch;
    sigmatch_table[KEYWORD_ID].Setup = DetectTLSCertChainLenSetup;
    sigmatch_table[KEYWORD_ID].Free = DetectTLSCertChainLenFree;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_CERT_READY, DetectEngineInspectGenericList, NULL);

    g_tls_cert_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

#ifdef UNITTESTS
#include "tests/detect-tls-certs.c"
#endif
