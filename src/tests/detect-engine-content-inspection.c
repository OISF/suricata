/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Tests for the content inspection engine.
 */

#include "../suricata-common.h"
#include "../decode.h"
#include "../flow.h"
#include "../detect.h"
#include "detect-engine-build.h"

#define TEST_HEADER                                     \
    ThreadVars tv;                                      \
    memset(&tv, 0, sizeof(tv));                         \
    Flow f;                                             \
    memset(&f, 0, sizeof(f));

#define TEST_RUN(buf, buflen, sig, match, steps)                                            \
{                                                                                           \
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();                                        \
    FAIL_IF_NULL(de_ctx);                                                                   \
    DetectEngineThreadCtx *det_ctx = NULL;                                                  \
    char rule[2048];                                                                        \
    snprintf(rule, sizeof(rule), "alert tcp any any -> any any (%s sid:1; rev:1;)", (sig)); \
    Signature *s = DetectEngineAppendSig(de_ctx, rule);                                     \
    FAIL_IF_NULL(s);                                                                        \
    SigGroupBuild(de_ctx);                                                                  \
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);                       \
    FAIL_IF_NULL(det_ctx);                                                                  \
    int r = DetectEngineContentInspection(de_ctx, det_ctx,                                  \
                s, s->sm_arrays[DETECT_SM_LIST_PMATCH], NULL, &f,                           \
                (uint8_t *)(buf), (buflen), 0, DETECT_CI_FLAGS_SINGLE,                      \
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD);                             \
    FAIL_IF_NOT(r == (match));                                                              \
    FAIL_IF_NOT(det_ctx->inspection_recursion_counter == (steps));                          \
    DetectEngineThreadCtxDeinit(&tv, det_ctx);                                              \
    DetectEngineCtxFree(de_ctx);                                                            \
}
#define TEST_FOOTER     \
    PASS

/** \test simple match with distance */
static int DetectEngineContentInspectionTest01(void) {
    TEST_HEADER;
    TEST_RUN("ab", 2, "content:\"a\"; content:\"b\";", true, 2);
    TEST_RUN("ab", 2, "content:\"a\"; content:\"b\"; distance:0; ", true, 2);
    TEST_RUN("ba", 2, "content:\"a\"; content:\"b\"; distance:0; ", false, 2);
    TEST_FOOTER;
}

/** \test simple match with pcre/R */
static int DetectEngineContentInspectionTest02(void) {
    TEST_HEADER;
    TEST_RUN("ab", 2, "content:\"a\"; pcre:\"/b/\";", true, 2);
    TEST_RUN("ab", 2, "content:\"a\"; pcre:\"/b/R\";", true, 2);
    TEST_RUN("ba", 2, "content:\"a\"; pcre:\"/b/R\";", false, 2);
    TEST_FOOTER;
}

/** \test simple recursion logic */
static int DetectEngineContentInspectionTest03(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"c\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"d\";", false, 3);

    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0;", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; content:\"d\"; distance:0;", false, 3);

    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"d\"; distance:0; within:1;", false, 5);

    // 5 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1;", true, 5);
    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, (6) bab
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; content:\"bab\";", true, 6);
    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, (6) no not found
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; content:\"no\";", false, 6);

    // 5 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; pcre:\"/^c$/R\";", true, 5);
    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, (6) bab
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; pcre:\"/^c$/R\"; content:\"bab\";", true, 6);
    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, (6) no not found
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; pcre:\"/^c$/R\"; content:\"no\";", false, 6);

    TEST_FOOTER;
}

/** \test pcre recursion logic */
static int DetectEngineContentInspectionTest04(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"c\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"d\";", false, 3);

    // simple chain of pcre
    TEST_RUN("ababc", 5, "pcre:\"/^a/\"; pcre:\"/^b/R\"; pcre:\"/c/R\"; ", true, 3);
    TEST_RUN("ababc", 5, "pcre:\"/a/\"; pcre:\"/^b/R\"; pcre:\"/^c/R\"; ", true, 5);
    TEST_RUN("ababc", 5, "pcre:\"/^a/\"; pcre:\"/^b/R\"; pcre:\"/d/R\"; ", false, 3);
    TEST_RUN("ababc", 5, "pcre:\"/^a/\"; pcre:\"/^b/R\"; pcre:\"/c/R\"; pcre:\"/d/\"; ", false, 4);

    TEST_FOOTER;
}

/** \test multiple independent blocks recursion logic */
static int DetectEngineContentInspectionTest05(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"c\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"d\";", false, 3);

    // first block 2: (1) a, (2) b
    // second block 3: (1) b, (2) c not found, (x) b continues within loop, (3) c found
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"b\"; content:\"c\"; distance:0; within:1;", true, 5);

    TEST_FOOTER;
}

/** \test isdataat recursion logic */
static int DetectEngineContentInspectionTest06(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"c\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:\"d\";", false, 3);

    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, isdataat
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; isdataat:!1,relative;", true, 5);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; isdataat:1,relative;", false, 6);

    TEST_RUN("ababcabc", 8, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; isdataat:!1,relative;", true, 7);
    TEST_RUN("ababcabc", 8, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; isdataat:1,relative;", true, 6);

    TEST_RUN("abcXYZ", 6, "content:\"abc\"; content:\"XYZ\"; distance:0; within:3; isdataat:!1,relative;", true, 2);
    TEST_RUN("abcXYZ", 6, "content:\"XYZ\"; distance:3; within:3; isdataat:!1,relative;", true, 1);
    TEST_RUN("abcXYZ", 6, "content:\"cXY\"; distance:2; within:3; isdataat:!1,relative;", false, 1);

    TEST_RUN("xxxxxxxxxxxxxxxxxyYYYYYYYYYYYYYYYY", 34, "content:\"yYYYYYYYYYYYYYYYY\"; distance:9; within:29; isdataat:!1,relative;", true, 1);
    TEST_FOOTER;
}

/** \test extreme recursion */
static int DetectEngineContentInspectionTest07(void) {
    TEST_HEADER;
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcd", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; content:\"d\";", true, 4);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcd", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; content:\"d\"; within:1; distance:0; ", true, 31);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; content:\"d\"; within:1; distance:0; ", false, 31);

    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; content:\"d\"; distance:0; ", false, 4);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; pcre:\"/^d/R\"; ", false, 13);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; isdataat:!1,relative; ", false, 3);
    TEST_RUN("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdx", 41,
            "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; content:\"d\"; distance:0; content:\"e\"; distance:0; ", false, 5);
    TEST_RUN("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdx", 41,
            "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; content:\"d\"; distance:0; pcre:\"/^e/R\"; ", false, 14); // TODO should be 5?
    TEST_RUN("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdx", 41,
            "content:\"a\"; content:\"b\"; distance:0; content:\"c\"; distance:0; content:\"d\"; distance:0; isdataat:!1,relative; ", false, 4);

    TEST_RUN("abcabcabcabcabcabcabcabcabcabcd", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/d/\";", true, 4);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcd", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/d/R\";", true, 4);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcd", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/^d/R\";", true, 31);

    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/d/\";", false, 4);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/d/R\";", false, 31);
    TEST_RUN("abcabcabcabcabcabcabcabcabcabcx", 31, "content:\"a\"; content:\"b\"; within:1; distance:0; content:\"c\"; distance:0; within:1; pcre:\"/^d/R\";", false, 31);
    TEST_FOOTER;
}

/** \test mix in negation */
static int DetectEngineContentInspectionTest08(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:!\"d\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:!\"c\";", false, 3);

    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:!\"a\"; distance:0; within:1;", true, 5);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:!\"a\"; distance:0; ", true, 5);

    TEST_RUN("abcdefghy", 9, "content:\"a\"; content:!\"x\"; content:\"c\"; distance:0; within:2; ",
            true, 3);
    TEST_RUN("abcdefghx", 9, "content:\"a\"; content:!\"x\"; content:\"c\"; distance:0; within:2; ",
            false, 2);
    TEST_RUN("abcdefghy", 9,
            "content:\"a\"; content:!\"x\"; content:!\"c\"; distance:2; within:1; ", true, 3);

    TEST_FOOTER;
}

/** \test mix in byte_jump */
static int DetectEngineContentInspectionTest09(void) {
    TEST_HEADER;
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:!\"d\";", true, 3);
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; content:!\"c\";", false, 3);

    TEST_RUN("abc03abcxyz", 11, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3;", true, 3);
    TEST_RUN("abc03abc03abcxyz", 16, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3;", true, 5);
    TEST_RUN("abc03abc03abcxyz", 16, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3; isdataat:!1,relative;", true, 5);
    TEST_RUN("abc03abc03abcxyz", 16, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3; pcre:\"/klm$/R\";", false, 7);
    TEST_RUN("abc03abc03abcxyzklm", 19, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3; pcre:\"/klm$/R\";", true, 6);
    TEST_RUN("abc03abc03abcxyzklx", 19, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3; pcre:\"/^klm$/R\";", false, 7);
    TEST_RUN("abc03abc03abc03abcxyzklm", 24, "content:\"abc\"; byte_jump:2,0,relative,string,dec; content:\"xyz\"; within:3; pcre:\"/^klm$/R\";", true, 8);

    TEST_FOOTER;
}

/** \test mix in byte_extract */
static int DetectEngineContentInspectionTest10(void) {
    TEST_HEADER;
    /* extract first byte as length field and check with isdataat */
    TEST_RUN("9abcdefghi", 10, "byte_extract:1,0,data_size,string; isdataat:data_size;", true, 2);
    TEST_RUN("9abcdefgh", 9, "byte_extract:1,0,data_size,string; isdataat:!data_size;", true, 2);
    /* anchor len field to pattern 'x' to test recursion */
    TEST_RUN("x9x9abcdefghi", 13, "content:\"x\"; byte_extract:1,0,data_size,string,relative; isdataat:data_size,relative;", true, 3);
    TEST_RUN("x9x9abcdefgh", 12, "content:\"x\"; byte_extract:1,0,data_size,string,relative; isdataat:!data_size,relative;", true, 5);
    TEST_RUN("x9x9abcdefgh", 12, "content:\"x\"; depth:1; byte_extract:1,0,data_size,string,relative; isdataat:!data_size,relative;", false, 3);
    /* check for super high extracted values */
    TEST_RUN("100000000abcdefghi", 18, "byte_extract:0,0,data_size,string; isdataat:data_size;", false, 2);
    TEST_RUN("100000000abcdefghi", 18, "byte_extract:0,0,data_size,string; isdataat:!data_size;", true, 2);
    TEST_FOOTER;
}

static int DetectEngineContentInspectionTest11(void) {
    TEST_HEADER;
    TEST_RUN("ab", 2, "content:\"a\"; startswith; content:\"b\";", true, 2);
    TEST_RUN("ab", 2, "content:\"a\"; startswith; content:\"b\"; within:1; distance:0;", true, 2);
    TEST_RUN("ab", 2, "content:\"ab\"; startswith;", true, 1);
    TEST_RUN("ab", 2, "content:\"a\"; startswith;", true, 1);
    TEST_RUN("ab", 2, "content:\"b\"; startswith;", false, 1);
    TEST_FOOTER;
}

/** \test endswith (isdataat) recursion logic
 *        based on DetectEngineContentInspectionTest06 */
static int DetectEngineContentInspectionTest12(void) {
    TEST_HEADER;
    // 6 steps: (1) a, (2) 1st b, (3) c not found, (4) 2nd b, (5) c found, endswith
    TEST_RUN("ababc", 5, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; endswith;", true, 5);

    TEST_RUN("ababcabc", 8, "content:\"a\"; content:\"b\"; distance:0; within:1; content:\"c\"; distance:0; within:1; endswith;", true, 7);

    TEST_RUN("abcXYZ", 6, "content:\"abc\"; content:\"XYZ\"; distance:0; within:3; endswith;", true, 2);
    TEST_RUN("abcXYZ", 6, "content:\"XYZ\"; distance:3; within:3; endswith;", true, 1);
    TEST_RUN("abcXYZ", 6, "content:\"cXY\"; distance:2; within:3; endswith;", false, 1);

    TEST_RUN("xxxxxxxxxxxxxxxxxyYYYYYYYYYYYYYYYY", 34, "content:\"yYYYYYYYYYYYYYYYY\"; distance:9; within:29; endswith;", true, 1);
    TEST_FOOTER;
}

static int DetectEngineContentInspectionTest13(void) {
    TEST_HEADER;
    TEST_RUN("ab", 2, "content:\"a\"; startswith; content:\"b\"; endswith;", true, 2);
    TEST_RUN("ab", 2, "content:\"a\"; startswith; content:\"b\"; within:1; distance:0; endswith;", true, 2);
    TEST_RUN("ab", 2, "content:\"ab\"; startswith; endswith;", true, 1);
    TEST_RUN("ab", 2, "content:\"a\"; startswith; endswith;", false, 1);
    TEST_RUN("ab", 2, "content:\"b\"; startswith;", false, 1);
    TEST_RUN("ab", 2, "content:\"b\"; startswith; endswith;", false, 1);
    TEST_FOOTER;
}

void DetectEngineContentInspectionRegisterTests(void)
{
    UtRegisterTest("DetectEngineContentInspectionTest01",
                   DetectEngineContentInspectionTest01);
    UtRegisterTest("DetectEngineContentInspectionTest02",
                   DetectEngineContentInspectionTest02);
    UtRegisterTest("DetectEngineContentInspectionTest03",
                   DetectEngineContentInspectionTest03);
    UtRegisterTest("DetectEngineContentInspectionTest04",
                   DetectEngineContentInspectionTest04);
    UtRegisterTest("DetectEngineContentInspectionTest05",
                   DetectEngineContentInspectionTest05);
    UtRegisterTest("DetectEngineContentInspectionTest06",
                   DetectEngineContentInspectionTest06);
    UtRegisterTest("DetectEngineContentInspectionTest07",
                   DetectEngineContentInspectionTest07);
    UtRegisterTest("DetectEngineContentInspectionTest08",
                   DetectEngineContentInspectionTest08);
    UtRegisterTest("DetectEngineContentInspectionTest09",
                   DetectEngineContentInspectionTest09);
    UtRegisterTest("DetectEngineContentInspectionTest10",
                   DetectEngineContentInspectionTest10);
    UtRegisterTest("DetectEngineContentInspectionTest11 startswith",
                   DetectEngineContentInspectionTest11);
    UtRegisterTest("DetectEngineContentInspectionTest12 endswith",
                   DetectEngineContentInspectionTest12);
    UtRegisterTest("DetectEngineContentInspectionTest13 mix startswith/endswith",
                   DetectEngineContentInspectionTest13);
}

#undef TEST_HEADER
#undef TEST_RUN
#undef TEST_FOOTER
