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
 * Implements support for ja3.string keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-ja3-string.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"
#include "util-ja3.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsJa3StringSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static int g_tls_ja3_str_buffer_id = 0;

static InspectionBuffer *GetJa3Data(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ja3(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Registration function for keyword: ja3.string
 */
void DetectTlsJa3StringRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].name = "ja3.string";
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].alias = "ja3_string";
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].desc = "sticky buffer to match the JA3 string buffer";
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].url = "/rules/ja3-keywords.html#ja3-string";
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].Setup = DetectTlsJa3StringSetup;
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_JA3_STRING].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("ja3.string", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("ja3.string", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectAppLayerMpmRegister2("ja3.string", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetJa3Data, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2("ja3.string", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetJa3Data);

    DetectBufferTypeSetDescriptionByName("ja3.string", "TLS JA3 string");

    g_tls_ja3_str_buffer_id = DetectBufferTypeGetByName("ja3.string");
}

/**
 * \brief this function setup the ja3.string modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsJa3StringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_ja3_str_buffer_id) < 0)
        return -1;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS && s->alproto != ALPROTO_QUIC) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA3 */
    SSLEnableJA3();

    /* Check if JA3 is disabled */
    if (!RunmodeIsUnittests() && Ja3IsDisabled("rule")) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_TLS_JA3_STRING)) {
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

        if (ssl_state->client_connp.ja3_str == NULL ||
                ssl_state->client_connp.ja3_str->data == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->client_connp.ja3_str->data);
        const uint8_t *data = (uint8_t *)ssl_state->client_connp.ja3_str->data;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}
