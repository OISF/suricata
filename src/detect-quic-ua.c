/* Copyright (C) 2022 Open Information Security Foundation
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
 *
 * Implements the quic.ua
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"
#include "detect-quic-ua.h"
#include "rust.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
#ifdef UNITTESTS
static void DetectQuicUaRegisterTests(void);
#endif

#define BUFFER_NAME  "quic_ua"
#define KEYWORD_NAME "quic.ua"
#define KEYWORD_ID   DETECT_AL_QUIC_UA

static int quic_ua_id = 0;

static int DetectQuicUaSetup(DetectEngineCtx *, Signature *, const char *);

static InspectionBuffer *GetUaData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ua(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Registration function for quic.ua: keyword
 */
void DetectQuicUaRegister(void)
{
    sigmatch_table[DETECT_AL_QUIC_UA].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_QUIC_UA].desc = "match Quic ua";
    sigmatch_table[DETECT_AL_QUIC_UA].url = "/rules/quic-keywords.html#quic-ua";
    sigmatch_table[DETECT_AL_QUIC_UA].Setup = DetectQuicUaSetup;
    sigmatch_table[DETECT_AL_QUIC_UA].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_QUIC_UA].RegisterTests = DetectQuicUaRegisterTests;
#endif

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetUaData, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetUaData);

    quic_ua_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

/**
 * \internal
 * \brief this function is used to add the parsed sigmatch  into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectQuicUaSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectBufferSetActiveList(s, quic_ua_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS

/**
 * \test QuicUaTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicUaTestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.ua; content:\"googe.com\"; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.ua; content:\"|00|\"; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicUaTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicUaTestParse03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig =
            DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (quic.ua:; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for QuicUa
 */
void DetectQuicUaRegisterTests(void)
{
    UtRegisterTest("QuicUaTestParse01", QuicUaTestParse01);
    UtRegisterTest("QuicUaTestParse03", QuicUaTestParse03);
}

#endif /* UNITTESTS */
