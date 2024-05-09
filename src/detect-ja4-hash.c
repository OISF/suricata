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
 * Implements support for ja4.hash keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-ja4-hash.h"

#include "util-ja4.h"

#include "app-layer-ssl.h"

#ifndef HAVE_JA4
static int DetectJA4SetupNoSupport(DetectEngineCtx *a, Signature *b, const char *c)
{
    SCLogError("no JA4 support built in");
    return -1;
}
#endif /* HAVE_JA4 */

#ifdef HAVE_JA4
static int DetectJa4HashSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
int Ja4IsDisabled(const char *type);
static InspectionBuffer *Ja4DetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

static int g_ja4_hash_buffer_id = 0;
#endif

/**
 * \brief Registration function for keyword: ja4.hash
 */
void DetectJa4HashRegister(void)
{
    sigmatch_table[DETECT_AL_JA4_HASH].name = "ja4.hash";
    sigmatch_table[DETECT_AL_JA4_HASH].alias = "ja4_hash";
    sigmatch_table[DETECT_AL_JA4_HASH].desc = "sticky buffer to match the JA4 hash buffer";
    sigmatch_table[DETECT_AL_JA4_HASH].url = "/rules/ja4-keywords.html#ja4-hash";
#ifdef HAVE_JA4
    sigmatch_table[DETECT_AL_JA4_HASH].Setup = DetectJa4HashSetup;
#else  /* HAVE_JA4 */
    sigmatch_table[DETECT_AL_JA4_HASH].Setup = DetectJA4SetupNoSupport;
#endif /* HAVE_JA4 */
    sigmatch_table[DETECT_AL_JA4_HASH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_JA4_HASH].flags |= SIGMATCH_INFO_STICKY_BUFFER;

#ifdef HAVE_JA4
    DetectAppLayerInspectEngineRegister("ja4.hash", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(
            "ja4.hash", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectAppLayerMpmRegister("ja4.hash", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            Ja4DetectGetHash, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister("ja4.hash", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, Ja4DetectGetHash);

    DetectBufferTypeSetDescriptionByName("ja4.hash", "TLS JA4 hash");

    g_ja4_hash_buffer_id = DetectBufferTypeGetByName("ja4.hash");
#endif /* HAVE_JA4 */
}

#ifdef HAVE_JA4
/**
 * \brief this function setup the ja4.hash modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectJa4HashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_ja4_hash_buffer_id) < 0)
        return -1;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS && s->alproto != ALPROTO_QUIC) {
        SCLogError("rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA4 */
    SSLEnableJA4();

    /* check if JA4 enabling had an effect */
    if (!RunmodeIsUnittests() && !SSLJA4IsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_JA4_HASH)) {
            SCLogError("JA4 support is not enabled");
        }
        return -2;
    }
    s->init_data->init_flags |= SIG_FLAG_INIT_JA;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->client_connp.ja4 == NULL) {
            return NULL;
        }

        uint8_t data[JA4_HEX_LEN];
        SCJA4GetHash(ssl_state->client_connp.ja4, (uint8_t(*)[JA4_HEX_LEN])data);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, 0);
        InspectionBufferCopy(buffer, data, JA4_HEX_LEN);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *Ja4DetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ja4(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, NULL, 0);
        InspectionBufferCopy(buffer, (uint8_t *)b, JA4_HEX_LEN);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}
#endif
