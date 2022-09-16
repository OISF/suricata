/* Copyright (C) 2019 Open Information Security Foundation
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
 * Implements support for ja3s.hash keyword.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "stream-tcp.h"
#include "util-ja3.h"
#include "util-print.h"
#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "conf-yaml-loader.h"
#include "conf.h"
#include "flow-var.h"
#include "flow-util.h"
#include "flow.h"
#include "detect-parse.h"
#include "detect.h"
#include "decode.h"
#include "debug.h"
#include "threads.h"
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-ja3s-hash.h"

#include "app-layer-ssl.h"

static int DetectTlsJa3SHashSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsJa3SHashRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static void DetectTlsJa3SHashSetupCallback(const DetectEngineCtx *de_ctx,
       Signature *s);
static bool DetectTlsJa3SHashValidateCallback(const Signature *s,
       const char **sigerror);
static int g_tls_ja3s_hash_buffer_id = 0;

/**
 * \brief Registration function for keyword: ja3s.hash
 */
void DetectTlsJa3SHashRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].name = "ja3s.hash";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].desc = "sticky buffer to match the JA3S hash buffer";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].url = "/rules/ja3-keywords.html#ja3s-hash";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].Setup = DetectTlsJa3SHashSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].RegisterTests = DetectTlsJa3SHashRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("ja3s.hash", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("ja3s.hash", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("ja3s.hash", "TLS JA3S hash");

    DetectBufferTypeRegisterSetupCallback("ja3s.hash",
            DetectTlsJa3SHashSetupCallback);

    DetectBufferTypeRegisterValidateCallback("ja3s.hash",
            DetectTlsJa3SHashValidateCallback);

    g_tls_ja3s_hash_buffer_id = DetectBufferTypeGetByName("ja3s.hash");
}

/**
 * \brief this function setup the ja3s.hash modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsJa3SHashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_ja3s_hash_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    /* try to enable JA3 */
    SSLEnableJA3();

    /* Check if JA3 is disabled */
    if (!RunmodeIsUnittests() && Ja3IsDisabled("rule")) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_TLS_JA3S_HASH)) {
            SCLogError(SC_WARN_JA3_DISABLED, "ja3(s) support is not enabled");
        }
        return -2;
    }

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->server_connp.ja3_hash == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->server_connp.ja3_hash);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.ja3_hash;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static bool DetectTlsJa3SHashValidateCallback(const Signature *s,
                                               const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_tls_ja3s_hash_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "ja3s.hash should not be used together with "
                        "nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len == 32)
            return true;

        *sigerror = "Invalid length of the specified JA3S hash (should "
                    "be 32 characters long). This rule will therefore "
                    "never match.";
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,  "rule %u: %s", s->id, *sigerror);
        return false;
    }

    return true;
}

static void DetectTlsJa3SHashSetupCallback(const DetectEngineCtx *de_ctx,
                                           Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_tls_ja3s_hash_buffer_id];
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
#include "tests/detect-tls-ja3s-hash.c"
#endif
