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

#include "../util-unittest.h"

#define TEST_OK(str, m, lo, hi)                                                                    \
    {                                                                                              \
        DetectU64Data *bsz = DetectBsizeParse((str));                                              \
        FAIL_IF_NULL(bsz);                                                                         \
        FAIL_IF_NOT(bsz->mode == (m));                                                             \
        DetectBsizeFree(NULL, bsz);                                                                \
        SCLogDebug("str %s OK", (str));                                                            \
    }
#define TEST_FAIL(str)                                                                             \
    {                                                                                              \
        DetectU64Data *bsz = DetectBsizeParse((str));                                              \
        FAIL_IF_NOT_NULL(bsz);                                                                     \
    }

static int DetectBsizeTest01(void)
{
    TEST_OK("50", DETECT_UINT_EQ, 50, 0);
    TEST_OK(" 50", DETECT_UINT_EQ, 50, 0);
    TEST_OK("  50", DETECT_UINT_EQ, 50, 0);
    TEST_OK("  50 ", DETECT_UINT_EQ, 50, 0);
    TEST_OK("  50  ", DETECT_UINT_EQ, 50, 0);

    TEST_FAIL("AA");
    TEST_FAIL("5A");
    TEST_FAIL("A5");
    // bigger than UINT64_MAX
    TEST_FAIL("100000000000000000001");
    TEST_OK("  1000000001  ", DETECT_UINT_EQ, 1000000001, 0);
    PASS;
}

static int DetectBsizeTest02(void)
{
    TEST_OK(">50", DETECT_UINT_GT, 50, 0);
    TEST_OK("> 50", DETECT_UINT_GT, 50, 0);
    TEST_OK(">  50", DETECT_UINT_GT, 50, 0);
    TEST_OK(" >50", DETECT_UINT_GT, 50, 0);
    TEST_OK(" > 50", DETECT_UINT_GT, 50, 0);
    TEST_OK(" >  50", DETECT_UINT_GT, 50, 0);
    TEST_OK(" >50 ", DETECT_UINT_GT, 50, 0);
    TEST_OK(" > 50  ", DETECT_UINT_GT, 50, 0);
    TEST_OK(" >  50   ", DETECT_UINT_GT, 50, 0);

    TEST_FAIL(">>50");
    TEST_FAIL("<>50");
    TEST_FAIL(" > 50A");
    PASS;
}

static int DetectBsizeTest03(void)
{
    TEST_OK("<50", DETECT_UINT_LT, 50, 0);
    TEST_OK("< 50", DETECT_UINT_LT, 50, 0);
    TEST_OK("<  50", DETECT_UINT_LT, 50, 0);
    TEST_OK(" <50", DETECT_UINT_LT, 50, 0);
    TEST_OK(" < 50", DETECT_UINT_LT, 50, 0);
    TEST_OK(" <  50", DETECT_UINT_LT, 50, 0);
    TEST_OK(" <50 ", DETECT_UINT_LT, 50, 0);
    TEST_OK(" < 50  ", DETECT_UINT_LT, 50, 0);
    TEST_OK(" <  50   ", DETECT_UINT_LT, 50, 0);

    TEST_FAIL(">>50");
    TEST_FAIL(" < 50A");
    PASS;
}

static int DetectBsizeTest04(void)
{
    TEST_OK("50<>100", DETECT_UINT_RA, 50, 100);

    TEST_FAIL("50<$50");
    TEST_FAIL("100<>50");
    TEST_FAIL(">50<>100");
    PASS;
}

#undef TEST_OK
#undef TEST_FAIL

#define TEST_OK(rule)                                                                       \
{                                                                                           \
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();                                        \
    FAIL_IF_NULL(de_ctx);                                                                   \
    Signature *s = DetectEngineAppendSig(de_ctx, (rule));                                   \
    FAIL_IF_NULL(s);                                                                        \
    DetectEngineCtxFree(de_ctx);                                                            \
}

#define TEST_FAIL(rule)                                                                     \
{                                                                                           \
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();                                        \
    FAIL_IF_NULL(de_ctx);                                                                   \
    Signature *s = DetectEngineAppendSig(de_ctx, (rule));                                   \
    FAIL_IF_NOT_NULL(s);                                                                    \
    DetectEngineCtxFree(de_ctx);                                                            \
}

static int DetectBsizeSigTest01(void)
{
    TEST_OK("alert http any any -> any any (http_request_line; bsize:10; sid:1;)");
    TEST_OK("alert http any any -> any any (file_data; bsize:>1000; sid:2;)");

    TEST_FAIL("alert tcp any any -> any any (content:\"abc\"; bsize:10; sid:3;)");
    TEST_FAIL("alert http any any -> any any (content:\"GET\"; http_method; bsize:10; sid:4;)");
    TEST_FAIL("alert http any any -> any any (http_request_line; content:\"GET\"; bsize:<10>; sid:5;)");
    PASS;
}

#undef TEST_OK
#undef TEST_FAIL

static void DetectBsizeRegisterTests(void)
{
    UtRegisterTest("DetectBsizeTest01 EQ", DetectBsizeTest01);
    UtRegisterTest("DetectBsizeTest02 GT", DetectBsizeTest02);
    UtRegisterTest("DetectBsizeTest03 LT", DetectBsizeTest03);
    UtRegisterTest("DetectBsizeTest04 RA", DetectBsizeTest04);

    UtRegisterTest("DetectBsizeSigTest01", DetectBsizeSigTest01);
}
