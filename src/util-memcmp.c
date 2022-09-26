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

#ifdef PROFILING
#include "util-cpu.h"
#endif
/* UNITTESTS */
#ifdef UNITTESTS

static int MemcmpTest01 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest02 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest03 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest04 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcD";

    int r = SCMemcmp(a, b, sizeof(a)-1);
    if (r != 1) {
        printf("%s != %s, but memcmp returned %d: ", a, b, r);
        return 0;
    }

    return 1;
}

static int MemcmpTest05 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcDabcdabcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest06 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcDabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest07 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest08 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest09 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest10 (void)
{
    uint8_t a[] = "abcd";
    uint8_t b[] = "Zbcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest11 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "Zbcdabcdabcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest12 (void)
{
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "Zbcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest13 (void)
{
    uint8_t a[] = "abcdefgh";
    uint8_t b[] = "AbCdEfGhIjK";

    if (SCMemcmpLowercase(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

#define TEST_RUNS 1000000

static int MemcmpTest14 (void)
{
#ifdef PROFILING
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
    if (r1 != (51 * TEST_RUNS))
        return 0;
#endif
    return 1;
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
    if (r2 != (51 * TEST_RUNS))
        return 0;
#endif
    return 1;
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
    if (r3 != (51 * TEST_RUNS))
        return 0;
#endif
    return 1;
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
    if (r4 != (51 * TEST_RUNS))
        return 0;
#endif
    return 1;
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

        if (SCMemcmpLowercase(t->a, t->b, strlen(t->a)-1) != t->result)
            return 0;
        SCLogInfo("ok");
        t++;
    }

    return 1;
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

