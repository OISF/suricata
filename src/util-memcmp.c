/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Memcmp implementations.
 */

#include "suricata-common.h"
#include "util-memcmp.h"
#include "util-unittest.h"

/* code is implemented in util-memcmp.h as it's all inlined */

/* UNITTESTS */
#ifdef UNITTESTS
#include "util-debug.h"

static int MemcmpTest01 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcd";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest02 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcd";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest03 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcd";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest04 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcD";

    int r = SCMemcmp(a, b, sizeof(a)-1);
    FAIL_IF(r != 1);

    PASS;
}

static int MemcmpTest05 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcDabcdabcdabcd";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    PASS;
}

static int MemcmpTest06 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcDabcd";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    PASS;
}

static int MemcmpTest07 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest08 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest09 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    PASS;
}

static int MemcmpTest10 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "Zbcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    PASS;
}

static int MemcmpTest11 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "Zbcdabcdabcdabcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    PASS;
}

static int MemcmpTest12 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "Zbcdabcde";

    FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    PASS;
}

static int MemcmpTest13 (void)
{
    uint8_t a[] = "abcdefgh";
    uint8_t b[] = "AbCdEfGhIjK";

    FAIL_IF(SCMemcmpLowercase(a, b, sizeof(a) - 1) != 0);
    PASS;
}

#include "util-cpu.h"

static int MemcmpTest14 (void)
{
#ifdef PROFILING
#define TEST_RUNS 1000000
    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;
    const char *a[] = { "0123456789012345", "abc", "abcdefghij", "suricata", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };
    const char *b[] = { "1234567890123456", "abc", "abcdefghik", "suricatb", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };

    int t = 0;
    int i, j;
    int r1 = 0;

    printf("\n");

    ticks_start = UtilCpuGetTicks();
    for (t = 0; t < TEST_RUNS; t++) {
        for (i = 0; a[i] != NULL; i++) {
            // printf("a[%d] = %s\n", i, a[i]);
            size_t alen = strlen(a[i]) - 1;

            for (j = 0; b[j] != NULL; j++) {
                // printf("b[%d] = %s\n", j, b[j]);
                size_t blen = strlen(b[j]) - 1;

                r1 += (memcmp((uint8_t *)a[i], (uint8_t *)b[j], (alen < blen) ? alen : blen) ? 1 : 0);
            }
        }
    }
    ticks_end = UtilCpuGetTicks();
    printf("memcmp(%d) \t\t\t%"PRIu64"\n", TEST_RUNS, ((uint64_t)(ticks_end - ticks_start))/TEST_RUNS);
    SCLogInfo("ticks passed %"PRIu64, ticks_end - ticks_start);

    printf("r1 %d\n", r1);
    FAIL_IF(r1 != (51 * TEST_RUNS));
#endif
    PASS;
}

static int MemcmpTest15 (void)
{
#ifdef PROFILING
    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;
    const char *a[] = { "0123456789012345", "abc", "abcdefghij", "suricata", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };
    const char *b[] = { "1234567890123456", "abc", "abcdefghik", "suricatb", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };

    int t = 0;
    int i, j;
    int r2 = 0;

    printf("\n");

    ticks_start = UtilCpuGetTicks();
    for (t = 0; t < TEST_RUNS; t++) {
        for (i = 0; a[i] != NULL; i++) {
            // printf("a[%d] = %s\n", i, a[i]);
            size_t alen = strlen(a[i]) - 1;

            for (j = 0; b[j] != NULL; j++) {
                // printf("b[%d] = %s\n", j, b[j]);
                size_t blen = strlen(b[j]) - 1;

                r2 += MemcmpLowercase((uint8_t *)a[i], (uint8_t *)b[j], (alen < blen) ? alen : blen);
            }
        }
    }
    ticks_end = UtilCpuGetTicks();
    printf("MemcmpLowercase(%d) \t\t%"PRIu64"\n", TEST_RUNS, ((uint64_t)(ticks_end - ticks_start))/TEST_RUNS);
    SCLogInfo("ticks passed %"PRIu64, ticks_end - ticks_start);

    printf("r2 %d\n", r2);
    FAIL_IF(r2 != (51 * TEST_RUNS));
#endif
    PASS;
}

static int MemcmpTest16 (void)
{
#ifdef PROFILING
    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;
    const char *a[] = { "0123456789012345", "abc", "abcdefghij", "suricata", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };
    const char *b[] = { "1234567890123456", "abc", "abcdefghik", "suricatb", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };

    int t = 0;
    int i, j;
    int r3 = 0;

    printf("\n");

    ticks_start = UtilCpuGetTicks();
    for (t = 0; t < TEST_RUNS; t++) {
        for (i = 0; a[i] != NULL; i++) {
            // printf("a[%d] = %s\n", i, a[i]);
            size_t alen = strlen(a[i]) - 1;

            for (j = 0; b[j] != NULL; j++) {
                // printf("b[%d] = %s\n", j, b[j]);
                size_t blen = strlen(b[j]) - 1;

                r3 += SCMemcmp((uint8_t *)a[i], (uint8_t *)b[j], (alen < blen) ? alen : blen);
            }
        }
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMemcmp(%d) \t\t\t%"PRIu64"\n", TEST_RUNS, ((uint64_t)(ticks_end - ticks_start))/TEST_RUNS);
    SCLogInfo("ticks passed %"PRIu64, ticks_end - ticks_start);

    printf("r3 %d\n", r3);
    FAIL_IF(r3 != (51 * TEST_RUNS));
#endif
    PASS;
}

static int MemcmpTest17 (void)
{
#ifdef PROFILING
    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;
    const char *a[] = { "0123456789012345", "abc", "abcdefghij", "suricata", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };
    const char *b[] = { "1234567890123456", "abc", "abcdefghik", "suricatb", "test", "xyz", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "abcdefghijklmnopqrstuvwxyz", NULL };

    int t = 0;
    int i, j;
    int r4 = 0;

    printf("\n");

    ticks_start = UtilCpuGetTicks();
    for (t = 0; t < TEST_RUNS; t++) {
        for (i = 0; a[i] != NULL; i++) {
            // printf("a[%d] = %s\n", i, a[i]);
            size_t alen = strlen(a[i]) - 1;

            for (j = 0; b[j] != NULL; j++) {
                // printf("b[%d] = %s\n", j, b[j]);
                size_t blen = strlen(b[j]) - 1;

                r4 += SCMemcmpLowercase((uint8_t *)a[i], (uint8_t *)b[j], (alen < blen) ? alen : blen);
            }
        }
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMemcmpLowercase(%d) \t\t%"PRIu64"\n", TEST_RUNS, ((uint64_t)(ticks_end - ticks_start))/TEST_RUNS);
    SCLogInfo("ticks passed %"PRIu64, ticks_end - ticks_start);

    printf("r4 %d\n", r4);
    FAIL_IF(r4 != (51 * TEST_RUNS));
#endif
    PASS;
}

struct MemcmpTest18Tests {
    const char *a;
    const char *b;
    int result;
} memcmp_tests18_tests[] = {
        { "abcdefgh", "!bcdefgh", 1, },
        { "?bcdefgh", "!bcdefgh", 1, },
        { "!bcdefgh", "abcdefgh", 1, },
        { "!bcdefgh", "?bcdefgh", 1, },
        { "zbcdefgh", "bbcdefgh", 1, },

        { "abcdefgh12345678", "!bcdefgh12345678", 1, },
        { "?bcdefgh12345678", "!bcdefgh12345678", 1, },
        { "!bcdefgh12345678", "abcdefgh12345678", 1, },
        { "!bcdefgh12345678", "?bcdefgh12345678", 1, },
        { "bbcdefgh12345678", "zbcdefgh12345678", 1, },

        { "abcdefgh", "abcdefgh", 0, },
        { "abcdefgh", "Abcdefgh", 0, },
        { "abcdefgh12345678", "Abcdefgh12345678", 0, },

        { NULL, NULL, 0 },

    };

static int MemcmpTest18 (void)
{
    struct MemcmpTest18Tests *t = memcmp_tests18_tests;

    while (t && t->a != NULL) {

        FAIL_IF(SCMemcmpLowercase(t->a, t->b, strlen(t->a) - 1) != t->result);
        t++;
    }

    PASS;
}

#endif /* UNITTESTS */

void MemcmpRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MemcmpTest01", MemcmpTest01);
    UtRegisterTest("MemcmpTest02", MemcmpTest02);
    UtRegisterTest("MemcmpTest03", MemcmpTest03);
    UtRegisterTest("MemcmpTest04", MemcmpTest04);
    UtRegisterTest("MemcmpTest05", MemcmpTest05);
    UtRegisterTest("MemcmpTest06", MemcmpTest06);
    UtRegisterTest("MemcmpTest07", MemcmpTest07);
    UtRegisterTest("MemcmpTest08", MemcmpTest08);
    UtRegisterTest("MemcmpTest09", MemcmpTest09);
    UtRegisterTest("MemcmpTest10", MemcmpTest10);
    UtRegisterTest("MemcmpTest11", MemcmpTest11);
    UtRegisterTest("MemcmpTest12", MemcmpTest12);
    UtRegisterTest("MemcmpTest13", MemcmpTest13);
    UtRegisterTest("MemcmpTest14", MemcmpTest14);
    UtRegisterTest("MemcmpTest15", MemcmpTest15);
    UtRegisterTest("MemcmpTest16", MemcmpTest16);
    UtRegisterTest("MemcmpTest17", MemcmpTest17);
    UtRegisterTest("MemcmpTest18", MemcmpTest18);
#endif /* UNITTESTS */
}

