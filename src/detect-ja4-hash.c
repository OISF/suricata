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
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-ja4-hash.h"

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
#ifdef UNITTESTS
static void DetectJa4RegisterTests(void);
#endif

static int g_ja4_hash_buffer_id = 0;
#endif

/**
 * \brief Registration function for keyword: ja4.hash
 */
void DetectJa4HashRegister(void)
{
    sigmatch_table[DETECT_JA4_HASH].name = "ja4.hash";
    sigmatch_table[DETECT_JA4_HASH].alias = "ja4_hash";
    sigmatch_table[DETECT_JA4_HASH].desc = "sticky buffer to match the JA4 hash buffer";
    sigmatch_table[DETECT_JA4_HASH].url = "/rules/ja4-keywords.html#ja4-hash";
#ifdef HAVE_JA4
    sigmatch_table[DETECT_JA4_HASH].Setup = DetectJa4HashSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_JA4_HASH].RegisterTests = DetectJa4RegisterTests;
#endif
#else  /* HAVE_JA4 */
    sigmatch_table[DETECT_JA4_HASH].Setup = DetectJA4SetupNoSupport;
#endif /* HAVE_JA4 */
    sigmatch_table[DETECT_JA4_HASH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_JA4_HASH].flags |= SIGMATCH_INFO_STICKY_BUFFER;

#ifdef HAVE_JA4
    DetectAppLayerInspectEngineRegister("ja4.hash", ALPROTO_TLS, SIG_FLAG_TOSERVER,
            TLS_STATE_CLIENT_HELLO_DONE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister("ja4.hash", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_TLS, TLS_STATE_CLIENT_HELLO_DONE);

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
    if (SCDetectBufferSetActiveList(de_ctx, s, g_ja4_hash_buffer_id) < 0)
        return -1;

    AppProto alprotos[] = { ALPROTO_TLS, ALPROTO_QUIC, ALPROTO_UNKNOWN };
    if (DetectSignatureSetMultiAppProto(s, alprotos) < 0) {
        SCLogError("rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA4 */
    SSLEnableJA4();

    /* check if JA4 enabling had an effect */
    if (!RunmodeIsUnittests() && !SSLJA4IsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_JA4_HASH)) {
            SCLogError("JA4 support is not enabled");
        }
        return -2;
    }

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->client_connp.hs == NULL) {
            return NULL;
        }

        uint8_t data[JA4_HEX_LEN];
        SCJA4GetHash(ssl_state->client_connp.hs, (uint8_t(*)[JA4_HEX_LEN])data);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, 0);
        InspectionBufferCopy(buffer, data, JA4_HEX_LEN);
        InspectionBufferApplyTransforms(det_ctx, buffer, transforms);
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

        if (SCQuicTxGetJa4(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, NULL, 0);
        InspectionBufferCopy(buffer, (uint8_t *)b, JA4_HEX_LEN);
        InspectionBufferApplyTransforms(det_ctx, buffer, transforms);
    }
    return buffer;
}

#ifdef UNITTESTS
static int DetectJa4TestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    // invalid tests
    Signature *s =
            SigInit(de_ctx, "alert ip any any -> any any (sid: 1; file.data; content: \"toto\"; "
                            "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // cannot have file.data with ja4.hash (quic or tls)
    FAIL_IF_NOT_NULL(s);
    s = SigInit(de_ctx, "alert ip any any -> any any (sid: 1; "
                        "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\"; file.data; "
                        "content: \"toto\";)");
    // cannot have file.data with ja4.hash (quic or tls)
    FAIL_IF_NOT_NULL(s);
    s = SigInit(de_ctx, "alert smb any any -> any any (sid: 1; "
                        "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // cannot have alproto=smb with ja4.hash (quic or tls)
    FAIL_IF_NOT_NULL(s);
    s = SigInit(de_ctx, "alert ip any any -> any any (sid: 1; "
                        "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\"; smb.share; "
                        "content:\"toto\";)");
    // cannot have a smb keyword with ja4.hash (quic or tls)
    FAIL_IF_NOT_NULL(s);
    s = SigInit(de_ctx, "alert ip any any -> any any (sid: 1; "
                        "smb.share; content:\"toto\"; ja4.hash; content: "
                        "\"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // cannot have a smb keyword with ja4.hash (quic or tls)
    FAIL_IF_NOT_NULL(s);

    // valid tests
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (sid: 1; "
            "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // just ja4.hash any proto
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert quic any any -> any any (sid: 2; "
            "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // just ja4.hash only quic
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tls any any -> any any (sid: 3; "
            "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\";)");
    // just ja4.hash only tls
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (sid: 4; "
            "ja4.hash; content: \"q13d0310h3_55b375c5d22e_cd85d2d88918\"; "
            "quic.version; content:\"|00|\";)");
    // ja4.hash and a quic keyword
    FAIL_IF_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectJa4RegisterTests(void)
{
    UtRegisterTest("DetectJa4TestParse01", DetectJa4TestParse01);
}
#endif

#endif // HAVE_JA4
