/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 *
 * Implements support for ja4.r/ro keyworda.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-ja4-raw.h"

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

static int DetectJa4RSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *Ja4RGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *Ja4RDetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
static int DetectJa4ROSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *Ja4ROGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *Ja4RODetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

static int g_ja4_r_buffer_id = 0, g_ja4_ro_buffer_id = 0;

/**
 * \brief Registration function for keywords: ja4.r/ro
 */
void DetectJa4RawRegister(void)
{
    sigmatch_table[DETECT_AL_JA4_R].name = "ja4.r";
    sigmatch_table[DETECT_AL_JA4_R].alias = "ja4_r";
    sigmatch_table[DETECT_AL_JA4_R].desc = "sticky buffer to match the JA4_r raw string buffer";
    sigmatch_table[DETECT_AL_JA4_R].url = "/rules/ja4-keywords.html#ja4-r";
    sigmatch_table[DETECT_AL_JA4_R].Setup = DetectJa4RSetup;
    sigmatch_table[DETECT_AL_JA4_R].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_JA4_R].flags |= SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[DETECT_AL_JA4_RO].name = "ja4.ro";
    sigmatch_table[DETECT_AL_JA4_RO].alias = "ja4_ro";
    sigmatch_table[DETECT_AL_JA4_RO].desc = "sticky buffer to match the JA4_ro raw string buffer";
    sigmatch_table[DETECT_AL_JA4_RO].url = "/rules/ja4-keywords.html#ja4-ro";
    sigmatch_table[DETECT_AL_JA4_RO].Setup = DetectJa4ROSetup;
    sigmatch_table[DETECT_AL_JA4_RO].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_JA4_RO].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("ja4.r", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, Ja4RGetData);
    DetectAppLayerInspectEngineRegister("ja4.ro", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, Ja4ROGetData);

    DetectAppLayerMpmRegister("ja4.r", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            Ja4RGetData, ALPROTO_TLS, 0);
    DetectAppLayerMpmRegister("ja4.ro", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            Ja4ROGetData, ALPROTO_TLS, 0);

    DetectAppLayerMpmRegister("ja4.r", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            Ja4RDetectGetHash, ALPROTO_QUIC, 1);
    DetectAppLayerMpmRegister("ja4.ro", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            Ja4RODetectGetHash, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister("ja4.r", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, Ja4RDetectGetHash);
    DetectAppLayerInspectEngineRegister("ja4.ro", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, Ja4RODetectGetHash);

    DetectBufferTypeSetDescriptionByName("ja4.r", "TLS JA4_r raw string");
    DetectBufferTypeSetDescriptionByName("ja4.ro", "TLS JA4_ro raw string hash");

    g_ja4_r_buffer_id = DetectBufferTypeGetByName("ja4.r");
    g_ja4_ro_buffer_id = DetectBufferTypeGetByName("ja4.ro");
}

static int DetectJa4RawGenericSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str,
        const int buffer_id, const enum DetectKeywordId kwid)
{
    if (DetectBufferSetActiveList(de_ctx, s, buffer_id) < 0)
        return -1;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS && s->alproto != ALPROTO_QUIC) {
        SCLogError("rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA4 */
    SSLEnableJA4();

    /* check if JA4 enabling had an effect */
    if (!RunmodeIsUnittests() && !SSLJA4IsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, kwid)) {
            SCLogError("JA4 support is not enabled");
        }
        return -2;
    }
    s->init_data->init_flags |= SIG_FLAG_INIT_JA;

    return 0;
}

/**
 * \brief this function setup the ja4.r modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectJa4RSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectJa4RawGenericSetup(de_ctx, s, str, g_ja4_r_buffer_id, DETECT_AL_JA4_R);
}

/**
 * \brief this function setup the ja4.ro modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectJa4ROSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectJa4RawGenericSetup(de_ctx, s, str, g_ja4_ro_buffer_id, DETECT_AL_JA4_RO);
}

#define SC_JA4_HEX_LEN            36
#define SC_JA4_DETECT_RAW_BUFSIZE 4096

static InspectionBuffer *Ja4RGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        uint8_t data[SC_JA4_HEX_LEN], data_r[SC_JA4_DETECT_RAW_BUFSIZE],
                data_ro[SC_JA4_DETECT_RAW_BUFSIZE];

        if (ssl_state->client_connp.ja4 == NULL) {
            return NULL;
        }

        SCJA4GetHash(ssl_state->client_connp.ja4, (uint8_t(*)[SC_JA4_HEX_LEN])data, data_r,
                SC_JA4_DETECT_RAW_BUFSIZE, data_ro, SC_JA4_DETECT_RAW_BUFSIZE);

        InspectionBufferSetup(det_ctx, list_id, buffer, data_r, 0);
        InspectionBufferCopy(buffer, data_r, strlen((const char *)data_r));
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *Ja4RDetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ja4_r(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, NULL, 0);
        InspectionBufferCopy(buffer, (uint8_t *)b, strlen((const char *)b));
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

static InspectionBuffer *Ja4ROGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        uint8_t data[SC_JA4_HEX_LEN], data_r[SC_JA4_DETECT_RAW_BUFSIZE],
                data_ro[SC_JA4_DETECT_RAW_BUFSIZE];

        if (ssl_state->client_connp.ja4 == NULL) {
            return NULL;
        }

        SCJA4GetHash(ssl_state->client_connp.ja4, (uint8_t(*)[SC_JA4_HEX_LEN])data, data_r,
                SC_JA4_DETECT_RAW_BUFSIZE, data_ro, SC_JA4_DETECT_RAW_BUFSIZE);

        InspectionBufferSetup(det_ctx, list_id, buffer, data_ro, 0);
        InspectionBufferCopy(buffer, data_ro, strlen((const char *)data_ro));
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *Ja4RODetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ja4_ro(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, NULL, 0);
        InspectionBufferCopy(buffer, (uint8_t *)b, strlen((const char *)b));
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}
