/* Copyright (C) 2020 Open Information Security Foundation
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
 * This file contains the implementation of the xor_data keyword (sticky buffer)
 * which enables content matching on the data previously decrypted by the xor
 * keyword.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-parse.h"
#include "detect-xor-data.h"

static int DetectXorDataSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectXorDataRegisterTests(void);

static int g_xor_data_buffer_id = 0;

void DetectXorDataRegister(void)
{
    sigmatch_table[DETECT_XOR_DATA].name = "xor_data";
    sigmatch_table[DETECT_XOR_DATA].desc = "Content match xor decoded data.";
    sigmatch_table[DETECT_XOR_DATA].url = "/rules/xor-keywords.html#xor-data";
    sigmatch_table[DETECT_XOR_DATA].Setup = DetectXorDataSetup;
    sigmatch_table[DETECT_XOR_DATA].RegisterTests = DetectXorDataRegisterTests;

    sigmatch_table[DETECT_XOR_DATA].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    g_xor_data_buffer_id = DetectBufferTypeRegister("xor_data");
}

/**
 * \brief Do content inspection on the xor_data buffer.
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectXorDataDoMatch(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, g_xor_data_buffer_id);

    if (likely(buffer != NULL && buffer->inspect != NULL && buffer->inspect_len > 0)) {
        return DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_arrays[DETECT_SM_LIST_XOR_DATA], NULL, f, buffer->inspect,
            buffer->inspect_len, 0, DETECT_CI_FLAGS_SINGLE,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    }

    return 0;
}

/**
 * \brief Setup xor_data keyword match.
 *
 * \param de_ctx Detect engine context.
 * \param s Signature.
 * \param str Keyword arguments.
 *
 * \return 0 on success, -1 on failure
*/
static int DetectXorDataSetup(DetectEngineCtx *de_ctx, Signature *s,
        const char *str)
{
    /* Make sure this keyword is preceeded by an xor keyword */
    if (NULL == DetectGetLastSMFromLists(s, DETECT_XOR, -1)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "\"xor_data\" keyword seen without preceding xor keyword.");
        return -1;
    }

    /* Set the built-in xor_data as the active list */
    if (DetectBufferSetActiveList(s, DETECT_SM_LIST_XOR_DATA) < 0) {
        return -1;
    }

    return 0;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 * \brief Helper function for testing setup success.
 *
 * \param rule Rule to test.
 *
 * \return 1 on success, 0 on failure
 */
static int DetectXorDataTestSetupSuccessRun(const char *rule)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list == NULL);
    FAIL_IF(de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL);
    FAIL_IF(de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_XOR_DATA] == NULL);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief Helper function for testing setup failure.
 *
 * \param rule Rule to test.
 *
 * \return 1 on success, 0 on failure
 */
static int DetectXorDataTestSetupFailureRun(const char *rule)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list != NULL);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/** \test test cases for setup failures */
static int DetectXorDataTestSetupFailure(void)
{
    FAIL_IF_NOT(DetectXorDataTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"test no xor keyword\";"
            "xor_data;"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorDataTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"test no xor keyword before xor_data\";"
            "xor_data; xor key \"b2259a\";"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorDataTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"test no matches added to xor_data\";"
            "xor: key \"b2259a\"; xor_data;"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorDataTestSetupFailureRun(
            "alert tcp any any -> any any (msg:\"test xor_data twice\";"
            "xor: key \"b2259a\"; xor_data;"
            "content: \"|7c|\"; xor_data; content: \"|22|\";"
            "sid:1; rev:1;)"));

    PASS;
}

/** \test test cases for setup success */
static int DetectXorDataTestSetupSuccess(void)
{
    FAIL_IF_NOT(DetectXorDataTestSetupSuccessRun(
            "alert tcp any any -> any any ("
            "msg:\"test success\";"
            "xor: key \"b2259a\"; xor_data; content: \"|7c|\";"
            "sid:1; rev:1;)"));

    PASS;
}

/**
 * \brief Test helper for checking decoded xor_data buffer.
 *
 * \param rule Rule to test.
 * \param payload Data to decode.
 * \param payload_len Length of data to decode.
 * \param alert_cnt Alert count to expect.
 *
 * \return 1 on success, 0 on failure.
 */
static int DetectXorDataTestDecodeRun(
        const char *rule,
        uint8_t *payload, size_t payload_len,
        uint16_t alert_cnt)
{
    ThreadVars tv = {0};
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list == NULL);
    FAIL_IF(-1 == SigGroupBuild(de_ctx));
    FAIL_IF(TM_ECODE_OK !=
            DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx));

    p = UTHBuildPacket(payload, payload_len, IPPROTO_TCP);
    FAIL_IF(p == NULL);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(p->alerts.cnt == alert_cnt);

    /* cleanup */
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    StatsThreadCleanup(&tv);
    DetectEngineCtxFree(de_ctx);
    UTHFreePacket(p);

    PASS;
}

/** \test Test cases for decoding and matching on xor_data. */
static int DetectXorDataTestDecode(void)
{
    UTH_DECL_BUF(payload, 0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c);

    /* Show XOR result: res == (payload ^ key) */
    FAIL_IF_NOT(
            0x7c == (0xce ^ 0xb2) &&
            0x22 == (0x07 ^ 0x25) &&
            0x4e == (0xd4 ^ 0x9a) &&
            0xf5 == (0x47 ^ 0xb2) &&
            0x78 == (0x5d ^ 0x25) &&
            0xcb == (0x51 ^ 0x9a) &&
            0xf8 == (0x4a ^ 0xb2) &&
            0x69 == (0x4c ^ 0x25));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload match\";"
            "xor: key \"b2259a\"; xor_data; content: \"|7c 22 4e f5 78 cb f8 69|\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            1));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload match with content\";"
            "content: \"|ce 07|\"; xor: key \"b2259a\";"
            "xor_data; content: \"|7c 22 4e f5 78 cb f8 69|\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            1));

    /* Show XOR result: res == (payload ^ key) */
    FAIL_IF_NOT(
            0x66 == (0xd4 ^ 0xb2) &&
            0x62 == (0x47 ^ 0x25) &&
            0xc7 == (0x5d ^ 0x9a) &&
            0xe3 == (0x51 ^ 0xb2) &&
            0x6f == (0x4a ^ 0x25) &&
            0xd6 == (0x4c ^ 0x9a));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload relative match with content\";"
            "content: \"|ce 07|\"; xor: key \"b2259a\", relative;"
            "xor_data; content: \"|66 62 c7 e3 6f d6|\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            1));

    /* Show XOR result: res == (payload ^ key) */
    FAIL_IF_NOT(
            0xe3 == (0x51 ^ 0xb2) &&
            0x6f == (0x4a ^ 0x25) &&
            0xd6 == (0x4c ^ 0x9a));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload relative offset match with content\";"
            "content: \"|ce 07|\"; xor: key \"b2259a\", offset 3, relative;"
            "xor_data; content: \"|e3 6f d6|\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            1));

    /* Show XOR result: res == (payload ^ key) */
    FAIL_IF_NOT(0xe3 == (0x51 ^ 0xb2));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload relative offset match with bytes and content\";"
            "content: \"|ce 07|\"; xor: key \"b2259a\", bytes 1, offset 3, relative;"
            "xor_data; content: \"|e3|\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            1));

    UTH_DECL_BUF(payload1,
            /* random bytes to ignore */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            /* indicates xor key will follow */
            0xbe, 0xef,
            /* use this 3 byte extract as the xor key */
            0xb2, 0x25, 0x9a,
            /* use this data to decode */
            0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c,
            /* random bytes to ignore */
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04);

    /* Show XOR result: res == (payload ^ key) */
    FAIL_IF_NOT(
            0x7c == (0xce ^ 0xb2) &&
            0x22 == (0x07 ^ 0x25) &&
            0x4e == (0xd4 ^ 0x9a));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test byte_extract for key and content match\";"
            "content: \"|be ef|\";"
            "byte_extract: 3, 0, xor_key, relative;"
            "xor: key xor_key, bytes 3, relative;"
            "xor_data; content: \"|7c 22 4e|\";"
            "sid:1; rev:1;)",
            payload1, payload1_len,
            1));

    FAIL_IF_NOT(DetectXorDataTestDecodeRun(
        "alert tcp any any -> any any ("
        "msg:\"test empty payload no match\";"
        "xor: key \"b2259a\"; xor_data; content: \"|ff|\";"
        "sid:1; rev:1;)",
        NULL, 0,
        0));

    PASS;
}

#endif

static void DetectXorDataRegisterTests(void)
{

#ifdef UNITTESTS

    g_xor_data_buffer_id = DetectBufferTypeGetByName("xor_data");

    UtRegisterTest("DetectXorDataTestSetupFailure",
            DetectXorDataTestSetupFailure);
    UtRegisterTest("DetectXorDataTestSetupSuccess",
            DetectXorDataTestSetupSuccess);
    UtRegisterTest("DetectXorDataTestDecode",
            DetectXorDataTestDecode);

#endif /* UNITTESTS */

}
