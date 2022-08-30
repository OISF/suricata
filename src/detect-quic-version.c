/* Copyright (C) 2021-2022 Open Information Security Foundation
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
 * Implements the quic.version
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
#include "detect-quic-version.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "rust.h"

#ifdef UNITTESTS
static void DetectQuicVersionRegisterTests(void);
#endif

#define BUFFER_NAME  "quic_version"
#define KEYWORD_NAME "quic.version"
#define KEYWORD_ID   DETECT_AL_QUIC_VERSION

static int quic_version_id = 0;

static int DetectQuicVersionSetup(DetectEngineCtx *, Signature *, const char *);

static InspectionBuffer *GetVersionData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_version(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Registration function for quic.version: keyword
 */
void DetectQuicVersionRegister(void)
{
    sigmatch_table[DETECT_AL_QUIC_VERSION].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_QUIC_VERSION].desc = "match Quic version";
    sigmatch_table[DETECT_AL_QUIC_VERSION].url = "/rules/quic-keywords.html#quic-version";
    sigmatch_table[DETECT_AL_QUIC_VERSION].Setup = DetectQuicVersionSetup;
    sigmatch_table[DETECT_AL_QUIC_VERSION].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_QUIC_VERSION].RegisterTests = DetectQuicVersionRegisterTests;
#endif

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetVersionData, ALPROTO_QUIC, 1);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetVersionData, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetVersionData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, GetVersionData);

    quic_version_id = DetectBufferTypeGetByName(BUFFER_NAME);
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
static int DetectQuicVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectBufferSetActiveList(s, quic_version_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS

/**
 * \test QuicVersionTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version; content:\"Q046\"; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version; content:\"|00|\"; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicVersionTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for QuicVersion
 */
void DetectQuicVersionRegisterTests(void)
{
    UtRegisterTest("QuicVersionTestParse01", QuicVersionTestParse01);
    UtRegisterTest("QuicVersionTestParse03", QuicVersionTestParse03);
}

#endif /* UNITTESTS */
