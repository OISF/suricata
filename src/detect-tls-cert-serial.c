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
 * Implements support for tls.cert_serial keyword.
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

#include "app-layer-ssl.h"
#include "detect-tls-cert-serial.h"

static int DetectTlsSerialSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsSerialRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);
static void DetectTlsSerialSetupCallback(const DetectEngineCtx *de_ctx,
        Signature *s);
static bool DetectTlsSerialValidateCallback(const Signature *s,
        const char **sigerror);
static int g_tls_cert_serial_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.cert_serial
 */
void DetectTlsSerialRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].name = "tls.cert_serial";
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].alias = "tls_cert_serial";
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].desc =
            "sticky buffer to match the TLS cert serial buffer";
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].url = "/rules/tls-keywords.html#tls-cert-serial";
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].Setup = DetectTlsSerialSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].RegisterTests = DetectTlsSerialRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_CERT_SERIAL].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("tls.cert_serial", ALPROTO_TLS,
            SIG_FLAG_TOCLIENT, TLS_STATE_CERT_READY,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("tls.cert_serial", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS,
            TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.cert_serial",
            "TLS certificate serial number");

    DetectBufferTypeRegisterSetupCallback("tls.cert_serial",
            DetectTlsSerialSetupCallback);

    DetectBufferTypeRegisterValidateCallback("tls.cert_serial",
            DetectTlsSerialValidateCallback);

    g_tls_cert_serial_buffer_id = DetectBufferTypeGetByName("tls.cert_serial");
}

/**
 * \brief this function setup the tls_cert_serial modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsSerialSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_cert_serial_buffer_id) < 0)
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

        if (ssl_state->server_connp.cert0_serial == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->server_connp.cert0_serial);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.cert0_serial;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static bool DetectTlsSerialValidateCallback(const Signature *s,
                                             const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_tls_cert_serial_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "tls.cert_serial should not be used together "
                        "with nocase, since the rule is automatically "
                        "uppercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        /* no need to worry about this if the content is short enough */
        if (cd->content_len <= 2)
            return true;

        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
            if (cd->content[u] == ':')
                return true;

        *sigerror = "No colon delimiters ':' detected in content after "
                    "tls.cert_serial. This rule will therefore never "
                    "match.";
        SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);

        return false;
    }

    return true;
}

static void DetectTlsSerialSetupCallback(const DetectEngineCtx *de_ctx,
                                         Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_tls_cert_serial_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        bool changed = false;
        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (islower(cd->content[u])) {
                cd->content[u] = u8_toupper(cd->content[u]);
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
#include "tests/detect-tls-cert-serial.c"
#endif
