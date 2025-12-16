/* Copyright (C) 2007-2024 Open Information Security Foundation
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
    uint8_t a[] = "abcd            abcd";
    uint8_t b[] = "abcd            abcd";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest02 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd    ";
    uint8_t b[] = "abcdabcdabcdabcd    ";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest03 (void)
{
    uint8_t a[] = "abcdabcd         ";
    uint8_t b[] = "abcdabcd         ";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest04 (void)
{
    uint8_t a[] = "abcd             ";
    uint8_t b[] = "abcD             ";

    for (size_t x = 4; x < sizeof(a); x++) {
        int r = SCMemcmp(a, b, x);
        FAIL_IF(r != 1);
    }

    PASS;
}

static int MemcmpTest05 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd       ";
    uint8_t b[] = "abcDabcdabcdabcd       ";

    for (size_t x = 4; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    }

    PASS;
}

static int MemcmpTest06 (void)
{
    uint8_t a[] = "abcdabcd              ";
    uint8_t b[] = "abcDabcd              ";

    for (size_t x = 4; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    }

    PASS;
}

static int MemcmpTest07 (void)
{
    uint8_t a[] = "            abcd";
    uint8_t b[] = "            abcde";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest08 (void)
{
    uint8_t a[] = "  zyxvabcdabcdabcdabcd";
    uint8_t b[] = "  zyxvabcdabcdabcdabcde";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest09 (void)
{
    uint8_t a[] = "         abcdabcd";
    uint8_t b[] = "         abcdabcde";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

static int MemcmpTest10 (void)
{
    uint8_t a[] = "abcd                 ";
    uint8_t b[] = "Zbcde                ";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    }

    PASS;
}

static int MemcmpTest11 (void)
{
    uint8_t a[] = "abcdabcdabcdabcd     ";
    uint8_t b[] = "Zbcdabcdabcdabcde    ";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmp(a, b, sizeof(a) - 1) != 1);
    }

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
    uint8_t a[] = "        abcdefgh";
    uint8_t b[] = "        AbCdEfGhIjK";

    for (size_t x = 1; x < sizeof(a); x++) {
        FAIL_IF(SCMemcmpLowercase(a, b, sizeof(a) - 1) != 0);
    }

    PASS;
}

#include "util-cpu.h"

#ifdef PROFILING
/* patterns used with SCMemcmpLowercase throughout the engine */
const char *used[] = {
    "content-type:", // HTTP parsing
    "content-disposition:",
    "filename=",
    "boundary=",
    "cookie", // HTTP cookie keyword
    "set-cookie",
    ".tar.gz", // fileext likely patterns
    ".exe",
    ".doc",
    ".html",
    ".pdf.exe",
    ".pdf",
    "pipelining", // SMTP command parsing
    "starttls",
    "rset",
    "quit",
    "data",
    "bdat",
    "mail from",
    "rcpt to",
    "234 ", // FTP response codes
    "227 ",
    "229 ",
    NULL,
};

const char *syn[] = {
    "1",
    "2a",
    "4aaa",
    "8aaaaaaa",
    "16aaaaaaaaaaaaaa",
    "32aaaaaaaaaaaaaa32aaaaaaaaaaaaaa",
    "64aaaaaaaaaaaaaa64aaaaaaaaaaaaaa64aaaaaaaaaaaaaa64aaaaaaaaaaaaaa",
    "128aaaaaaaaaaaaaaaaaaaaaaaaaaaaa128aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "128aaaaaaaaaaaaaaaaaaaaaaaaaaaaa128aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa256aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa512aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa1024aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa2048aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa4096aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    NULL,
};

static inline int TestWrapMemcmp(const uint8_t *s1, const uint8_t *s2, size_t len)
{
    return (memcmp(s1, s2, len) == 0) ? 0 : 1;
}

#define BIGSZ 1024 * 1024
#define DRIVER(f)                                                                                  \
    uint8_t *big = SCCalloc(1, BIGSZ);                                                             \
    memset(big, 'a', BIGSZ);                                                                       \
    int res = 0;                                                                                   \
    uint64_t ticks_start = UtilCpuGetTicks();                                                      \
    for (int t = 0; t < TEST_RUNS; t++) {                                                          \
        for (int i = 0; used[i] != NULL; i++) {                                                    \
            size_t alen = strlen(used[i]) - 1;                                                     \
            for (int j = 0; used[j] != NULL; j++) {                                                \
                size_t blen = strlen(used[j]) - 1;                                                 \
                res += (f)((uint8_t *)used[i], (uint8_t *)used[j], (alen < blen) ? alen : blen);   \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    uint64_t ticks_end = UtilCpuGetTicks();                                                        \
    printf("real: %6" PRIu64 "k - ", ((uint64_t)(ticks_end - ticks_start)) / 1000);                \
    if (res != (504 * TEST_RUNS)) {                                                                \
        SCLogNotice("%d %" PRIu64 "k\n", res, ((uint64_t)(ticks_end - ticks_start)) / 1000);       \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < TEST_RUNS; t++) {                                                          \
        for (int i = 0; syn[i] != NULL; i++) {                                                     \
            size_t alen = strlen(syn[i]) - 1;                                                      \
            for (int j = 0; syn[j] != NULL; j++) {                                                 \
                size_t blen = strlen(syn[j]) - 1;                                                  \
                res += (f)((uint8_t *)syn[i], (uint8_t *)syn[j], (alen < blen) ? alen : blen);     \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("syn: %6" PRIu64 "k - ", ((uint64_t)(ticks_end - ticks_start)) / 1000);                 \
    if (res != (128 * TEST_RUNS)) {                                                                \
        SCLogNotice("%d %" PRIu64 "k\n", res, ((uint64_t)(ticks_end - ticks_start)) / 1000);       \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < 10; t++) {                                                                 \
        for (int i = 0; used[i] != NULL; i++) {                                                    \
            size_t alen = strlen(used[i]) - 1;                                                     \
            for (size_t j = 0; j < BIGSZ; j++) {                                                   \
                if (BIGSZ - j < alen)                                                              \
                    continue;                                                                      \
                uint8_t *b = big + j;                                                              \
                res += (f)((uint8_t *)used[i], b, alen);                                           \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("stream1: %6" PRIu64 "k - ", ((uint64_t)(ticks_end - ticks_start)) / 1000);             \
    if (res != 241171330) {                                                                        \
        SCLogNotice("%d %" PRIu64 "k\n", res, ((uint64_t)(ticks_end - ticks_start)) / 1000);       \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < 10; t++) {                                                                 \
        for (int i = 0; syn[i] != NULL; i++) {                                                     \
            size_t alen = strlen(syn[i]) - 1;                                                      \
                                                                                                   \
            for (size_t j = 0; j < BIGSZ; j++) {                                                   \
                if (BIGSZ - j < alen)                                                              \
                    continue;                                                                      \
                uint8_t *b = big + j;                                                              \
                res += (f)((uint8_t *)syn[i], b, alen);                                            \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("stream2: %6" PRIu64 "k - ", ((uint64_t)(ticks_end - ticks_start)) / 1000);             \
    if (res != 125747460) {                                                                        \
        SCLogNotice("%d %" PRIu64 "k\n", res, ((uint64_t)(ticks_end - ticks_start)) / 1000);       \
        return 0;                                                                                  \
    }                                                                                              \
    SCFree(big);
#endif
// #undef DRIVER
// #undef BIGSZ

#ifdef PROFILING
#define TEST_RUNS 1000000
#define PKT_SMALL 64
#define PKT_ETH   1418
#define PKT_JUMBO 9000

typedef int (*TestFunc)(const uint8_t *a, const uint8_t *b, size_t sz);
static int PktDriver(TestFunc FPtr, size_t size)
{
    uint8_t *pkt = SCCalloc(1, size);
    memset(pkt, 'a', size);
    uint8_t *seg_match = SCCalloc(1, size);
    memset(seg_match, 'a', size);
    uint8_t *seg_nomatch = SCCalloc(1, size);
    memset(seg_nomatch, 'a', size);
    seg_nomatch[size - 1] = 'b';
    uint64_t ticks_start = UtilCpuGetTicks();
    int res = 0;
    for (int t = 0; t < TEST_RUNS; t++) {
        cc_barrier();
        res += (FPtr)((uint8_t *)pkt, (uint8_t *)seg_match, size);
    }
    uint64_t ticks_end = UtilCpuGetTicks();
    printf("%u-m: %8" PRIu64 "k - ", (uint32_t)size,
            ((uint64_t)(ticks_end - ticks_start) / (uint64_t)1000));
    if (res != 0) {
        SCLogNotice("%d %" PRIu64 "\n", res, (uint64_t)(ticks_end - ticks_start));
        return 0;
    }
    ticks_start = UtilCpuGetTicks();
    res = 0;
    for (int t = 0; t < TEST_RUNS; t++) {
        cc_barrier();
        res += (FPtr)((uint8_t *)pkt, (uint8_t *)seg_nomatch, size);
    }
    ticks_end = UtilCpuGetTicks();
    printf("%u-nm: %8" PRIu64 "k - ", (uint32_t)size,
            ((uint64_t)(ticks_end - ticks_start) / (uint64_t)1000));
    if (res != TEST_RUNS) {
        SCLogNotice("%d %" PRIu64 "\n", res, (uint64_t)(ticks_end - ticks_start));
        return 0;
    }
    SCFree(pkt);
    SCFree(seg_match);
    SCFree(seg_nomatch);
    return 1;
}
#endif

#undef TEST_RUNS

#define TEST_RUNS 10000 // for DRIVER macro

static int MemcmpTestExactLibcMemcmp(void)
{
#ifdef PROFILING
    DRIVER(TestWrapMemcmp);
    PktDriver(TestWrapMemcmp, PKT_SMALL);
    PktDriver(TestWrapMemcmp, PKT_ETH);
    PktDriver(TestWrapMemcmp, PKT_JUMBO);
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmp(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmp);
    PktDriver(SCMemcmp, PKT_SMALL);
    PktDriver(SCMemcmp, PKT_ETH);
    PktDriver(SCMemcmp, PKT_JUMBO);
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmpSSE3(void)
{
#if defined(__SSE3__)
#ifdef PROFILING
    DRIVER(SCMemcmpSSE3);
    PktDriver(SCMemcmpSSE3, PKT_SMALL);
    PktDriver(SCMemcmpSSE3, PKT_ETH);
    PktDriver(SCMemcmpSSE3, PKT_JUMBO);
#endif
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmpSSE42(void)
{
#if defined(__SSE4_2__)
#ifdef PROFILING
    DRIVER(SCMemcmpSSE42);
    PktDriver(SCMemcmpSSE42, PKT_SMALL);
    PktDriver(SCMemcmpSSE42, PKT_ETH);
    PktDriver(SCMemcmpSSE42, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX2(void)
{
#ifdef PROFILING
#ifdef __AVX2__
    DRIVER(SCMemcmpAVX2);
    PktDriver(SCMemcmpAVX2, PKT_SMALL);
    PktDriver(SCMemcmpAVX2, PKT_ETH);
    PktDriver(SCMemcmpAVX2, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX2_512(void)
{
#ifdef PROFILING
#ifdef __AVX2__
    DRIVER(SCMemcmpAVX2_512);
    PktDriver(SCMemcmpAVX2_512, PKT_SMALL);
    PktDriver(SCMemcmpAVX2_512, PKT_ETH);
    PktDriver(SCMemcmpAVX2_512, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX2_1024(void)
{
#ifdef PROFILING
#ifdef __AVX2__
    DRIVER(SCMemcmpAVX2_1024);
    PktDriver(SCMemcmpAVX2_1024, PKT_SMALL);
    PktDriver(SCMemcmpAVX2_1024, PKT_ETH);
    PktDriver(SCMemcmpAVX2_1024, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_128(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_128);
    PktDriver(SCMemcmpAVX512_128, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_128, PKT_ETH);
    PktDriver(SCMemcmpAVX512_128, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_256(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_256);
    PktDriver(SCMemcmpAVX512_256, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_256, PKT_ETH);
    PktDriver(SCMemcmpAVX512_256, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_512(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_512);
    PktDriver(SCMemcmpAVX512_512, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_512, PKT_ETH);
    PktDriver(SCMemcmpAVX512_512, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_2048(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_2048);
    PktDriver(SCMemcmpAVX512_2048, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_2048, PKT_ETH);
    PktDriver(SCMemcmpAVX512_2048, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_4096(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_4096);
    PktDriver(SCMemcmpAVX512_4096, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_4096, PKT_ETH);
    PktDriver(SCMemcmpAVX512_4096, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_6144(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_6144);
    PktDriver(SCMemcmpAVX512_6144, PKT_SMALL);
    PktDriver(SCMemcmpAVX512_6144, PKT_ETH);
    PktDriver(SCMemcmpAVX512_6144, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpSVE(void)
{
#ifdef PROFILING
#if defined(__ARM_FEATURE_SVE)
    DRIVER(SCMemcmpSVE);
    PktDriver(SCMemcmpSVE, PKT_SMALL);
    PktDriver(SCMemcmpSVE, PKT_ETH);
    PktDriver(SCMemcmpSVE, PKT_JUMBO);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseDefault(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpLowercase);
#endif
    return 1;
}

static int MemcmpTestLowercaseNoSIMD(void)
{
#ifdef PROFILING
    DRIVER(MemcmpLowercase);
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE3(void)
{
#if defined(__SSE3__)
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE3and(void)
{
#if defined(__SSE3__)
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3and);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE3andload(void)
{
#if defined(__SSE3__)
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3andload);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE42(void)
{
#if defined(__SSE4_2__)
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE42);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseAVX2(void)
{
#ifdef PROFILING
#ifdef __AVX2__
    DRIVER(SCMemcmpLowercaseAVX2);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseAVX512_256(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpLowercaseAVX512_256);
#endif
#endif
    return 1;
}

static int MemcmpTestLowercaseAVX512_512(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpLowercaseAVX512_512);
#endif
#endif
    PASS;
}

static int MemcmpTestLowercaseNeon(void)
{
#ifdef PROFILING
#if defined(__ARM_NEON)
    DRIVER(SCMemcmpLowercaseNeon);
#endif
#endif
    PASS;
}

struct MemcmpTest18Tests {
    const char *a;
    const char *b;
    int result;
    int cs_result;
} memcmp_tests18_tests[] = {
    {
            "abcdefgh",
            "!bcdefgh",
            1,
            1,
    },
    {
            "?bcdefgh",
            "!bcdefgh",
            1,
            1,
    },
    {
            "!bcdefgh",
            "abcdefgh",
            1,
            1,
    },
    {
            "!bcdefgh",
            "?bcdefgh",
            1,
            1,
    },
    {
            "zbcdefgh",
            "bbcdefgh",
            1,
            1,
    },
    {
            "abcdefgh       ",
            "!bcdefgh       ",
            1,
            1,
    },
    {
            "?bcdefgh       ",
            "!bcdefgh       ",
            1,
            1,
    },
    {
            "!bcdefgh       ",
            "abcdefgh       ",
            1,
            1,
    },
    {
            "!bcdefgh       ",
            "?bcdefgh       ",
            1,
            1,
    },
    {
            "zbcdefgh       ",
            "bbcdefgh       ",
            1,
            1,
    },

    {
            "abcdefgh12345678",
            "!bcdefgh12345678",
            1,
            1,
    },
    {
            "?bcdefgh12345678",
            "!bcdefgh12345678",
            1,
            1,
    },
    {
            "!bcdefgh12345678",
            "abcdefgh12345678",
            1,
            1,
    },
    {
            "!bcdefgh12345678",
            "?bcdefgh12345678",
            1,
            1,
    },
    {
            "bbcdefgh12345678",
            "zbcdefgh12345678",
            1,
            1,
    },

    {
            "abcdefgh",
            "abcdefgh",
            0,
            0,
    },
    {
            "abcdefgh",
            "Abcdefgh",
            0,
            1,
    },
    {
            "abcdefgh        ",
            "abcdefgh        ",
            0,
            0,
    },
    {
            "abcdefgh        ",
            "Abcdefgh        ",
            0,
            1,
    },
    {
            "abcdefgh12345678",
            "Abcdefgh12345678",
            0,
            1,
    },
    {
            "abcdefghijklmxyz12345678",
            "AbcdefghijKLMXYZ12345678",
            0,
            1,
    },
    {
            "abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijKLMnopqrstuvwXYZ12345678",
            0,
            1,
    },
    {
            "abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijKLMnopqrstXvwXYZ12345678",
            1,
            1,
    },
    {
            "abcdefghijklmnopqrstuvwxyz1234567890",
            "AbcdefghijKLMnopqrstuvwXYZ1234567890",
            0,
            1,
    },
    {
            "abcdefghijklmnopqrstuvwxyz1234567890",
            "AbcdefghijKLMnopqrstXvwXYZ1234567890",
            1,
            1,
    },
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678", 0, 0 },
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678", 0, 1 },
    { "abcdefghijklmnopqrstuvwxyz12345679abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678", 1, 1 },
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678",
            "abcdefghijklmnopqrstUvwxyz12345678abcdefXhijklmnopqrstuvwxyz12345678", 1, 1 },

    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678ABCDEF123", 0, 1 },
    /* 64+13, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678ABCDEF124", 1, 1 },
    /* 64+16, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123456",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678ABCDEF123457", 1,
            1 },
    /* 64+16+1, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef1234567",
            "AbcdefghijklmnopqrstUvwxyZ12345678abcdefghijKLMnopqrstuvwxyZ12345678ABCDEF1234568", 1,
            1 },

    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123", 0, 0 },
    /* 64+13, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef124", 1, 1 },
    /* 64+16, match */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123456",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123456", 0,
            0 },
    /* 64+16, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123456",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef123457", 1,
            1 },
    /* 64+16+1, match */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef1234567",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef1234567", 0,
            0 },
    /* 64+16+1, with mismatch in last byte */
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef1234567",
            "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678abcdef1234568", 1,
            1 },

    { NULL, NULL, 0, 0 },

};

static int MemcmpTest18 (void)
{
    struct MemcmpTest18Tests *t = memcmp_tests18_tests;
    for (; t != NULL; t++) {
        if (t->a == NULL)
            break;
        int result = SCMemcmp((const uint8_t *)t->a, (const uint8_t *)t->b, strlen(t->a));
        FAIL_IF(result != t->cs_result);
    }

    t = memcmp_tests18_tests;
    for (; t != NULL; t++) {
        if (t->a == NULL)
            break;
        int result = SCMemcmpLowercase((const uint8_t *)t->a, (const uint8_t *)t->b, strlen(t->a));
        FAIL_IF(result != t->result);
    }
    PASS;
}

void MemcmpRegisterTests(void)
{
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
    UtRegisterTest("MemcmpTestExactLibcMemcmp", MemcmpTestExactLibcMemcmp);
    UtRegisterTest("MemcmpTestExactSCMemcmpDefault", MemcmpTestExactSCMemcmp);
    UtRegisterTest("MemcmpTestExactSCMemcmpSSE3", MemcmpTestExactSCMemcmpSSE3);
    UtRegisterTest("MemcmpTestExactSCMemcmpSSE42", MemcmpTestExactSCMemcmpSSE42);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX2", MemcmpTestExactSCMemcmpAVX2);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX2_512", MemcmpTestExactSCMemcmpAVX2_512);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX2_1024", MemcmpTestExactSCMemcmpAVX2_1024);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_128", MemcmpTestExactSCMemcmpAVX512_128);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_256", MemcmpTestExactSCMemcmpAVX512_256);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_512", MemcmpTestExactSCMemcmpAVX512_512);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_2048", MemcmpTestExactSCMemcmpAVX512_2048);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_4096", MemcmpTestExactSCMemcmpAVX512_4096);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_6144", MemcmpTestExactSCMemcmpAVX512_6144);
    UtRegisterTest("MemcmpTestExactSCMemcmpSVE", MemcmpTestExactSCMemcmpSVE);
    UtRegisterTest("MemcmpTestLowercaseDefault", MemcmpTestLowercaseDefault);
    UtRegisterTest("MemcmpTestLowercaseNoSIMD", MemcmpTestLowercaseNoSIMD);
    UtRegisterTest("MemcmpTestLowercaseSSE3", MemcmpTestLowercaseSSE3);
    UtRegisterTest("MemcmpTestLowercaseSSE3and", MemcmpTestLowercaseSSE3and);
    UtRegisterTest("MemcmpTestLowercaseSSE3andload", MemcmpTestLowercaseSSE3andload);
    UtRegisterTest("MemcmpTestLowercaseSSE42", MemcmpTestLowercaseSSE42);
    UtRegisterTest("MemcmpTestLowercaseAVX2", MemcmpTestLowercaseAVX2);
    UtRegisterTest("MemcmpTestLowercaseAVX512_256", MemcmpTestLowercaseAVX512_256);
    UtRegisterTest("MemcmpTestLowercaseAVX512_512", MemcmpTestLowercaseAVX512_512);
    UtRegisterTest("MemcmpTestLowercaseNeon", MemcmpTestLowercaseNeon);
    UtRegisterTest("MemcmpTest18", MemcmpTest18);
}
#endif /* UNITTESTS */
