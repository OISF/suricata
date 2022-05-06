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

#define TEST_RUNS 1000000

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

static inline int TestWrapMemcmp(const void *s1, const void *s2, size_t len)
{
    return (memcmp(s1, s2, len) == 0) ? 0 : 1;
}

#define BIGSZ 1024 * 1024
#define DRIVER(f)                                                                                  \
    uint8_t *big = SCCalloc(1, BIGSZ);                                                             \
    memset(big, 'a', BIGSZ);                                                                       \
    int res = 0;                                                                                   \
    uint64_t cnt = 0;                                                                              \
    uint64_t ticks_start = UtilCpuGetTicks();                                                      \
    for (int t = 0; t < TEST_RUNS; t++) {                                                          \
        for (int i = 0; used[i] != NULL; i++) {                                                    \
            size_t alen = strlen(used[i]) - 1;                                                     \
            for (int j = 0; used[j] != NULL; j++) {                                                \
                size_t blen = strlen(used[j]) - 1;                                                 \
                cnt++;                                                                             \
                res += (f)((uint8_t *)used[i], (uint8_t *)used[j], (alen < blen) ? alen : blen);   \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    uint64_t ticks_end = UtilCpuGetTicks();                                                        \
    printf("real: %3" PRIu64 " - ", ((uint64_t)(ticks_end - ticks_start)) / cnt);                  \
    if (res != (504 * TEST_RUNS)) {                                                                \
        SCLogNotice("%d %" PRIu64 "\n", res, ((uint64_t)(ticks_end - ticks_start)) / cnt);         \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    cnt = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < TEST_RUNS; t++) {                                                          \
        for (int i = 0; syn[i] != NULL; i++) {                                                     \
            size_t alen = strlen(syn[i]) - 1;                                                      \
            for (int j = 0; syn[j] != NULL; j++) {                                                 \
                size_t blen = strlen(syn[j]) - 1;                                                  \
                cnt++;                                                                             \
                res += (f)((uint8_t *)syn[i], (uint8_t *)syn[j], (alen < blen) ? alen : blen);     \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("syn: %3" PRIu64 " - ", ((uint64_t)(ticks_end - ticks_start)) / cnt);                   \
    if (res != (128 * TEST_RUNS)) {                                                                \
        SCLogNotice("%d %" PRIu64 "\n", res, ((uint64_t)(ticks_end - ticks_start)) / cnt);         \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    cnt = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < 10; t++) {                                                                 \
        for (int i = 0; used[i] != NULL; i++) {                                                    \
            size_t alen = strlen(used[i]) - 1;                                                     \
            for (size_t j = 0; j < BIGSZ; j++) {                                                   \
                if (BIGSZ - j < alen)                                                              \
                    continue;                                                                      \
                uint8_t *b = big + j;                                                              \
                cnt++;                                                                             \
                res += (f)((uint8_t *)used[i], b, alen);                                           \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("stream1: %3" PRIu64 " - ", ((uint64_t)(ticks_end - ticks_start)) / cnt);               \
    if (res != 241171330) {                                                                        \
        SCLogNotice("%d %" PRIu64 "\n", res, ((uint64_t)(ticks_end - ticks_start)) / cnt);         \
        return 0;                                                                                  \
    }                                                                                              \
    res = 0;                                                                                       \
    cnt = 0;                                                                                       \
    ticks_start = UtilCpuGetTicks();                                                               \
    for (int t = 0; t < 10; t++) {                                                                 \
        for (int i = 0; syn[i] != NULL; i++) {                                                     \
            size_t alen = strlen(syn[i]) - 1;                                                      \
                                                                                                   \
            for (size_t j = 0; j < BIGSZ; j++) {                                                   \
                if (BIGSZ - j < alen)                                                              \
                    continue;                                                                      \
                uint8_t *b = big + j;                                                              \
                cnt++;                                                                             \
                res += (f)((uint8_t *)syn[i], b, alen);                                            \
            }                                                                                      \
        }                                                                                          \
    }                                                                                              \
    ticks_end = UtilCpuGetTicks();                                                                 \
    printf("stream2: %3" PRIu64 " - ", ((uint64_t)(ticks_end - ticks_start)) / cnt);               \
    if (res != 125747460) {                                                                        \
        SCLogNotice("%d %" PRIu64 "\n", res, ((uint64_t)(ticks_end - ticks_start)) / cnt);         \
        return 0;                                                                                  \
    }                                                                                              \
    SCFree(big);
#endif

static int MemcmpTestExactLibcMemcmp(void)
{
#ifdef PROFILING
    DRIVER(TestWrapMemcmp);
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmp(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmp);
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmpSSE3(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpSSE3);
#endif
    PASS;
}

static int MemcmpTestExactSCMemcmpSSE41(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpSSE41);
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpSSE42(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpSSE42);
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX2(void)
{
#ifdef PROFILING
#ifdef __AVX2__
    DRIVER(SCMemcmpAVX2);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_128(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_128);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_256(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_256);
#endif
#endif
    return 1;
}

static int MemcmpTestExactSCMemcmpAVX512_512(void)
{
#ifdef PROFILING
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    DRIVER(SCMemcmpAVX512_512);
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
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3);
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE3and(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3and);
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE3andload(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE3andload);
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE41(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE41);
#endif
    return 1;
}

static int MemcmpTestLowercaseSSE42(void)
{
#ifdef PROFILING
    DRIVER(SCMemcmpLowercaseSSE42);
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

struct MemcmpTest18Tests {
    const char *a;
    const char *b;
    int result;
} memcmp_tests18_tests[] = {
    {
            "abcdefgh",
            "!bcdefgh",
            1,
    },
    {
            "?bcdefgh",
            "!bcdefgh",
            1,
    },
    {
            "!bcdefgh",
            "abcdefgh",
            1,
    },
    {
            "!bcdefgh",
            "?bcdefgh",
            1,
    },
    {
            "zbcdefgh",
            "bbcdefgh",
            1,
    },

    {
            "abcdefgh12345678",
            "!bcdefgh12345678",
            1,
    },
    {
            "?bcdefgh12345678",
            "!bcdefgh12345678",
            1,
    },
    {
            "!bcdefgh12345678",
            "abcdefgh12345678",
            1,
    },
    {
            "!bcdefgh12345678",
            "?bcdefgh12345678",
            1,
    },
    {
            "bbcdefgh12345678",
            "zbcdefgh12345678",
            1,
    },

    {
            "abcdefgh",
            "abcdefgh",
            0,
    },
    {
            "abcdefgh",
            "Abcdefgh",
            0,
    },
    {
            "abcdefgh12345678",
            "Abcdefgh12345678",
            0,
    },
    {
            "abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijKLMnopqrstuvwXYZ12345678",
            0,
    },
    {
            "abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijKLMnopqrstXvwXYZ12345678",
            1,
    },
    {
            "abcdefghijklmnopqrstuvwxyz1234567890",
            "AbcdefghijKLMnopqrstuvwXYZ1234567890",
            0,
    },
    {
            "abcdefghijklmnopqrstuvwxyz1234567890",
            "AbcdefghijKLMnopqrstXvwXYZ1234567890",
            1,
    },
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678",
            "AbcdefghijklmnopqrstUvwxyz12345678abcdefghijklmnopqrstuvwxyZ12345678", 0 },
    { "abcdefghijklmnopqrstuvwxyz12345678abcdefghijklmnopqrstuvwxyz12345678",
            "abcdefghijklmnopqrstUvwxyz12345678abcdefXhijklmnopqrstuvwxyz12345678", 1 },

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
    UtRegisterTest("MemcmpTestExactSCMemcmpSSE41", MemcmpTestExactSCMemcmpSSE41);
    UtRegisterTest("MemcmpTestExactSCMemcmpSSE42", MemcmpTestExactSCMemcmpSSE42);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX2", MemcmpTestExactSCMemcmpAVX2);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_128", MemcmpTestExactSCMemcmpAVX512_128);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_256", MemcmpTestExactSCMemcmpAVX512_256);
    UtRegisterTest("MemcmpTestExactSCMemcmpAVX512_512", MemcmpTestExactSCMemcmpAVX512_512);
    UtRegisterTest("MemcmpTestLowercaseDefault", MemcmpTestLowercaseDefault);
    UtRegisterTest("MemcmpTestLowercaseNoSIMD", MemcmpTestLowercaseNoSIMD);
    UtRegisterTest("MemcmpTestLowercaseSSE3", MemcmpTestLowercaseSSE3);
    UtRegisterTest("MemcmpTestLowercaseSSE3and", MemcmpTestLowercaseSSE3and);
    UtRegisterTest("MemcmpTestLowercaseSSE3andload", MemcmpTestLowercaseSSE3andload);
    UtRegisterTest("MemcmpTestLowercaseSSE41", MemcmpTestLowercaseSSE41);
    UtRegisterTest("MemcmpTestLowercaseSSE42", MemcmpTestLowercaseSSE42);
    UtRegisterTest("MemcmpTestLowercaseAVX2", MemcmpTestLowercaseAVX2);
    UtRegisterTest("MemcmpTestLowercaseAVX512_256", MemcmpTestLowercaseAVX512_256);
    UtRegisterTest("MemcmpTestLowercaseAVX512_512", MemcmpTestLowercaseAVX512_512);
    UtRegisterTest("MemcmpTest18", MemcmpTest18);
}
#endif /* UNITTESTS */
