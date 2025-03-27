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
 * Implements support for ja3s.string keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-ja3s-string.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"
#include "util-ja3.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifndef HAVE_JA3
static int DetectJA3SetupNoSupport(DetectEngineCtx *a, Signature *b, const char *c)
{
    SCLogError("no JA3 support built in");
    return -1;
}
#endif /* HAVE_JA3 */

#ifdef HAVE_JA3
static int DetectTlsJa3SStringSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static int g_tls_ja3s_str_buffer_id = 0;
#endif

/**
 * \brief Registration function for keyword: ja3s.string
 */
void DetectTlsJa3SStringRegister(void)
{
    sigmatch_table[DETECT_TLS_JA3S_STRING].name = "ja3s.string";
    sigmatch_table[DETECT_TLS_JA3S_STRING].desc = "sticky buffer to match the JA3S string buffer";
    sigmatch_table[DETECT_TLS_JA3S_STRING].url = "/rules/ja3-keywords.html#ja3s-string";
#ifdef HAVE_JA3
    sigmatch_table[DETECT_TLS_JA3S_STRING].Setup = DetectTlsJa3SStringSetup;
#else  /* HAVE_JA3 */
    sigmatch_table[DETECT_TLS_JA3S_STRING].Setup = DetectJA3SetupNoSupport;
#endif /* HAVE_JA3 */
    sigmatch_table[DETECT_TLS_JA3S_STRING].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_TLS_JA3S_STRING].flags |= SIGMATCH_INFO_STICKY_BUFFER;

#ifdef HAVE_JA3
    DetectAppLayerInspectEngineRegister("ja3s.string", ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_SERVER_HELLO, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister("ja3s.string", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_TLS, TLS_STATE_SERVER_HELLO);

    DetectAppLayerMpmRegister("ja3s.string", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            Ja3DetectGetString, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister("ja3s.string", ALPROTO_QUIC, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, Ja3DetectGetString);

    DetectBufferTypeSetDescriptionByName("ja3s.string", "TLS JA3S string");

    g_tls_ja3s_str_buffer_id = DetectBufferTypeGetByName("ja3s.string");
#endif /*  HAVE_JA3 */
}

#ifdef HAVE_JA3
/**
 * \brief this function setup the ja3s.string modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsJa3SStringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_tls_ja3s_str_buffer_id) < 0)
        return -1;

    AppProto alprotos[] = { ALPROTO_TLS, ALPROTO_QUIC, ALPROTO_UNKNOWN };
    if (DetectSignatureSetMultiAppProto(s, alprotos) < 0) {
        SCLogError("rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA3 */
    SSLEnableJA3();

    /* Check if JA3 is disabled */
    if (!RunmodeIsUnittests() && Ja3IsDisabled("rule")) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_TLS_JA3S_STRING)) {
            SCLogError("ja3(s) support is not enabled");
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

        if (ssl_state->server_connp.ja3_str == NULL ||
                ssl_state->server_connp.ja3_str->data == NULL) {
            return NULL;
        }

        const uint32_t data_len = (uint32_t)strlen(ssl_state->server_connp.ja3_str->data);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.ja3_str->data;

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    return buffer;
}
#endif
