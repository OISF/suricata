/* Copyright (C) 2017 Open Information Security Foundation
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
 * Implements support for tls_cert_fingerprint keyword.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "flow-util.h"
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-cert-fingerprint.h"

#include "app-layer-ssl.h"

static int DetectTlsFingerprintSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsFingerprintRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);
static void DetectTlsFingerprintSetupCallback(const DetectEngineCtx *de_ctx,
        Signature *s);
static bool DetectTlsFingerprintValidateCallback(const Signature *s,
        const char **sigerror);
static int g_tls_cert_fingerprint_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.cert_fingerprint
 */
void DetectTlsFingerprintRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].name = "tls.cert_fingerprint";
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].alias = "tls_cert_fingerprint";
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].desc =
            "sticky byffer to match the TLS cert fingerprint buffer";
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].url = "/rules/tls-keywords.html#tls-cert-fingerprint";
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].Setup = DetectTlsFingerprintSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].RegisterTests = DetectTlsFingerprintRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_CERT_FINGERPRINT].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("tls.cert_fingerprint", ALPROTO_TLS,
            SIG_FLAG_TOCLIENT, TLS_STATE_CERT_READY,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("tls.cert_fingerprint", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS,
            TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.cert_fingerprint",
            "TLS certificate fingerprint");

    DetectBufferTypeRegisterSetupCallback("tls.cert_fingerprint",
            DetectTlsFingerprintSetupCallback);

    DetectBufferTypeRegisterValidateCallback("tls.cert_fingerprint",
            DetectTlsFingerprintValidateCallback);

    g_tls_cert_fingerprint_buffer_id = DetectBufferTypeGetByName("tls.cert_fingerprint");
}

/**
 * \brief this function setup the tls_cert_fingerprint modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsFingerprintSetup(DetectEngineCtx *de_ctx, Signature *s,
                                     const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_cert_fingerprint_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->server_connp.cert0_fingerprint == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->server_connp.cert0_fingerprint);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.cert0_fingerprint;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static bool DetectTlsFingerprintValidateCallback(const Signature *s,
                                                  const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_tls_cert_fingerprint_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->content_len != 59) {
            *sigerror = "Invalid length of the specified fingerprint. "
                        "This rule will therefore never match.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
            return false;
        }

        bool have_delimiters = false;
        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (cd->content[u] == ':') {
                have_delimiters = true;
                break;
            }
        }

        if (!have_delimiters) {
            *sigerror = "No colon delimiters ':' detected in content after "
                        "tls.cert_fingerprint. This rule will therefore "
                        "never match.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
            return false;
        }

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "tls.cert_fingerprint should not be used together "
                        "with nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }
    }

    return true;
}

static void DetectTlsFingerprintSetupCallback(const DetectEngineCtx *de_ctx,
                                              Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_tls_cert_fingerprint_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        bool changed = false;
        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (isupper(cd->content[u])) {
                cd->content[u] = u8_tolower(cd->content[u]);
                changed = true;
            }
        }

        /* recreate the context if changes were made */
        if (changed) {
            SpmDestroyCtx(cd->spm_ctx);
            cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
                                     de_ctx->spm_global_thread_ctx);
        }
    }
}

#ifdef UNITTESTS
#include "tests/detect-tls-cert-fingerprint.c"
#endif
