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
 * Implements the quic.ja3
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-uint.h"
#include "detect-quic-ja3.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "rust.h"

#ifdef UNITTESTS
static void DetectQuicJa3RegisterTests(void);
#endif

static int quic_ja3_id = 0;
static int quic_ja3s_id = 0;

static int DetectQuicJa3Setup(DetectEngineCtx *, Signature *, const char *);

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
 * \brief Registration function for quic.ja3: keyword
 */
void DetectQuicJa3Register(void)
{
    sigmatch_table[DETECT_AL_QUIC_JA3].name = "quic.ja3";
    sigmatch_table[DETECT_AL_QUIC_JA3].desc = "match Quic ja3 from client to server";
    sigmatch_table[DETECT_AL_QUIC_JA3].url = "/rules/quic-keywords.html#quic-ja3";
    sigmatch_table[DETECT_AL_QUIC_JA3].Setup = DetectQuicJa3Setup;
    sigmatch_table[DETECT_AL_QUIC_JA3].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_QUIC_JA3].RegisterTests = DetectQuicJa3RegisterTests;
#endif

    DetectAppLayerMpmRegister2("quic_ja3", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetJa3Data, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2("quic_ja3", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetJa3Data);

    quic_ja3_id = DetectBufferTypeGetByName("quic_ja3");

    sigmatch_table[DETECT_AL_QUIC_JA3S].name = "quic.ja3s";
    sigmatch_table[DETECT_AL_QUIC_JA3S].desc = "match Quic ja3 from server to client";
    sigmatch_table[DETECT_AL_QUIC_JA3S].url = "/rules/quic-keywords.html#quic-ja3";
    sigmatch_table[DETECT_AL_QUIC_JA3S].Setup = DetectQuicJa3Setup;
    sigmatch_table[DETECT_AL_QUIC_JA3S].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2("quic_ja3s", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetJa3Data, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2("quic_ja3s", ALPROTO_QUIC, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, GetJa3Data);

    quic_ja3s_id = DetectBufferTypeGetByName("quic_ja3s");
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
static int DetectQuicJa3Setup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectBufferSetActiveList(s, quic_ja3_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS

/**
 * \test QuicJa3TestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicJa3TestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.ja3; content:\"googe.com\"; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.ja3; content:\"|00|\"; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicJa3TestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicJa3TestParse03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig =
            DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (quic.ja3:; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for QuicJa3
 */
void DetectQuicJa3RegisterTests(void)
{
    UtRegisterTest("QuicJa3TestParse01", QuicJa3TestParse01);
    UtRegisterTest("QuicJa3TestParse03", QuicJa3TestParse03);
}

#endif /* UNITTESTS */
