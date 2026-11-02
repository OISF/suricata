/* Copyright (C) 2026 Open Information Security Foundation
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
 * Tests for plugin patterns.
 *
 * These tests exercise the API as it is used by plugins and by keywords
 * implemented in Rust, which can't see Suricata internals such as the
 * Signature and SigMatch structs. Some of these patterns are not used by
 * Suricata itself, so these tests may be their only in-tree user.
 *
 * Write the tests the way a plugin would: register through the public
 * helpers (e.g. SCDetectHelperKeywordRegister()) and only use SC-prefixed
 * API functions for keyword and signature access, never struct fields.
 * This file can see the internals, so nothing but this rule enforces that.
 */

#include "../detect-engine.h"
#include "../detect-engine-helper.h"
#include "../detect-parse.h"
#include "../util-byte.h"
#include "../util-unittest.h"

/*
 * Keyword setup: a packet keyword registered the way a plugin does it, whose
 * Setup callback records what it observed through the API so the tests can
 * check it after the rule is parsed. It is registered on first use, so it
 * only exists while running unit tests.
 */

#define UTIL_PLUGIN_TEST_KW "util-plugin-test"

typedef struct UtilPluginTestKwData_ {
    int value;
    /** result of SCDetectSignatureIsNegated() in Setup */
    bool negated;
    /** value of the previous instance found in Setup, or -1 if none */
    int prev_value;
} UtilPluginTestKwData;

static int g_util_plugin_test_kw_id = -1;

static void UtilPluginTestKwFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

static int UtilPluginTestKwSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    const uint16_t id = (uint16_t)g_util_plugin_test_kw_id;

    if (arg == NULL)
        return -1;
    int32_t value;
    if (StringParseInt32(&value, 10, strlen(arg), arg) <= 0)
        return -1;

    UtilPluginTestKwData *data = SCCalloc(1, sizeof(*data));
    if (data == NULL)
        return -1;
    data->value = value;
    data->negated = SCDetectSignatureIsNegated(s);
    data->prev_value = -1;

    const SigMatch *prev = SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_MATCH, id);
    if (prev != NULL) {
        data->prev_value = ((const UtilPluginTestKwData *)SCSigMatchGetCtx(prev))->value;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, id, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) ==
            NULL) {
        SCFree(data);
        return -1;
    }
    return 0;
}

static uint16_t UtilPluginTestKwRegister(void)
{
    if (g_util_plugin_test_kw_id < 0) {
        SCSigTableAppLiteElmt kw = {
            .name = UTIL_PLUGIN_TEST_KW,
            .desc = "unit test keyword for plugin patterns",
            .flags = SIGMATCH_HANDLE_NEGATION,
            .Setup = UtilPluginTestKwSetup,
            .Free = UtilPluginTestKwFree,
        };
        uint16_t id = SCDetectHelperKeywordRegister(&kw);
        BUG_ON(id == (uint16_t)-1);
        g_util_plugin_test_kw_id = id;
    }
    return (uint16_t)g_util_plugin_test_kw_id;
}

static const UtilPluginTestKwData *UtilPluginTestKwGetData(const SigMatch *sm)
{
    return (const UtilPluginTestKwData *)SCSigMatchGetCtx(sm);
}

/**
 * \test SCDetectSignatureIsNegated() reports the '!' that the rule parser
 *       stripped from a SIGMATCH_HANDLE_NEGATION keyword option.
 */
static int UtilPluginKeywordNegationTest(void)
{
    const uint16_t id = UtilPluginTestKwRegister();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (" UTIL_PLUGIN_TEST_KW
                                                 ":1; " UTIL_PLUGIN_TEST_KW ":!2; sid:1;)");
    FAIL_IF_NULL(s);

    const SigMatch *sm = SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_MATCH, id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->value == 2);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->negated);

    sm = SCSigMatchGetPrevByType(sm, id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->value == 1);
    FAIL_IF(UtilPluginTestKwGetData(sm)->negated);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test The SigMatch lookup walks only instances of the requested keyword,
 *       newest first, and still finds them from Setup once a sticky buffer
 *       is active.
 */
static int UtilPluginKeywordLookupTest(void)
{
    const uint16_t id = UtilPluginTestKwRegister();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (" UTIL_PLUGIN_TEST_KW ":1; ttl:10; " UTIL_PLUGIN_TEST_KW
            ":2; tcp.hdr; content:\"|00|\"; " UTIL_PLUGIN_TEST_KW ":3; sid:1;)");
    FAIL_IF_NULL(s);

    const SigMatch *sm = SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_MATCH, id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->value == 3);
    /* seen from Setup, after tcp.hdr made a sticky buffer active */
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->prev_value == 2);

    sm = SCSigMatchGetPrevByType(sm, id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->value == 2);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->prev_value == 1);

    /* skips the ttl SigMatch in between */
    sm = SCSigMatchGetPrevByType(sm, id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->value == 1);
    FAIL_IF_NOT(UtilPluginTestKwGetData(sm)->prev_value == -1);

    FAIL_IF_NOT_NULL(SCSigMatchGetPrevByType(sm, id));

    /* no instances in another static list */
    FAIL_IF_NOT_NULL(SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_POSTMATCH, id));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#ifndef DEBUG_VALIDATION
/**
 * \test Lists other than the static ones from DetectSigmatchListEnum are not
 *       supported and return NULL. Debug validation builds treat this as a
 *       bug instead.
 */
static int UtilPluginKeywordLookupDynamicListTest(void)
{
    const uint16_t id = UtilPluginTestKwRegister();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (" UTIL_PLUGIN_TEST_KW ":1; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_MATCH, id));
    FAIL_IF_NOT_NULL(SCDetectSignatureGetLastSMByType(s, DETECT_SM_LIST_MAX, id));
    FAIL_IF_NOT_NULL(SCDetectSignatureGetLastSMByType(s, -1, id));

    DetectEngineCtxFree(de_ctx);
    PASS;
}
#endif

void UtilPluginRegisterTests(void)
{
    UtRegisterTest("UtilPluginKeywordNegationTest", UtilPluginKeywordNegationTest);
    UtRegisterTest("UtilPluginKeywordLookupTest", UtilPluginKeywordLookupTest);
#ifndef DEBUG_VALIDATION
    UtRegisterTest(
            "UtilPluginKeywordLookupDynamicListTest", UtilPluginKeywordLookupDynamicListTest);
#endif
}
