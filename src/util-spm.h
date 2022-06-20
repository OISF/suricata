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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef __UTIL_SPM_H__
#define __UTIL_SPM_H__

#include "util-spm-bs.h"

enum {
    SPM_BM, /* Boyer-Moore */
    SPM_HS, /* Hyperscan */
    /* Other SPM matchers will go here. */
    SPM_TABLE_SIZE
};

uint16_t SinglePatternMatchDefaultMatcher(void);

/** Structure holding an immutable "built" SPM matcher (such as the Boyer-Moore
 * tables, Hyperscan database etc) that is passed to the Scan call. */
typedef struct SpmCtx_ {
    uint16_t matcher;
    void *ctx;
} SpmCtx;

/** Structure holding a global prototype for per-thread scratch space, passed
 * to each InitCtx call. */
typedef struct SpmGlobalThreadCtx_ {
    uint16_t matcher;
    void *ctx;
} SpmGlobalThreadCtx;

/** Structure holding some mutable per-thread space for use by a matcher at
 * scan time. Constructed from SpmGlobalThreadCtx by the MakeThreadCtx call. */
typedef struct SpmThreadCtx_ {
    uint16_t matcher;
    void *ctx;
} SpmThreadCtx;

typedef struct SpmTableElmt_ {
    const char *name;
    SpmGlobalThreadCtx *(*InitGlobalThreadCtx)(void);
    void (*DestroyGlobalThreadCtx)(SpmGlobalThreadCtx *g_thread_ctx);
    SpmThreadCtx *(*MakeThreadCtx)(const SpmGlobalThreadCtx *g_thread_ctx);
    void (*DestroyThreadCtx)(SpmThreadCtx *thread_ctx);
    SpmCtx *(*InitCtx)(const uint8_t *needle, uint16_t needle_len, int nocase,
                       SpmGlobalThreadCtx *g_thread_ctx);
    void (*DestroyCtx)(SpmCtx *);
    uint8_t *(*Scan)(const SpmCtx *ctx, SpmThreadCtx *thread_ctx,
                     const uint8_t *haystack, uint32_t haystack_len);
} SpmTableElmt;

extern SpmTableElmt spm_table[SPM_TABLE_SIZE];

void SpmTableSetup(void);

SpmGlobalThreadCtx *SpmInitGlobalThreadCtx(uint16_t matcher);

void SpmDestroyGlobalThreadCtx(SpmGlobalThreadCtx *g_thread_ctx);

SpmThreadCtx *SpmMakeThreadCtx(const SpmGlobalThreadCtx *g_thread_ctx);

void SpmDestroyThreadCtx(SpmThreadCtx *thread_ctx);

SpmCtx *SpmInitCtx(const uint8_t *needle, uint16_t needle_len, int nocase,
                   SpmGlobalThreadCtx *g_thread_ctx);

void SpmDestroyCtx(SpmCtx *ctx);

uint8_t *SpmScan(const SpmCtx *ctx, SpmThreadCtx *thread_ctx,
                 const uint8_t *haystack, uint32_t haystack_len);

/** Default algorithm to use: Boyer Moore */
uint8_t *Bs2bmSearch(const uint8_t *text, uint32_t textlen, const uint8_t *needle, uint16_t needlelen);
uint8_t *Bs2bmNocaseSearch(const uint8_t *text, uint32_t textlen, const uint8_t *needle, uint16_t needlelen);
uint8_t *BoyerMooreSearch(const uint8_t *text, uint32_t textlen, const uint8_t *needle, uint16_t needlelen);
uint8_t *BoyerMooreNocaseSearch(const uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen);

/* Macros for automatic algorithm selection (use them only when you can't store the context) */
#define SpmSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearch(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreSearch(text, textlen, needle, needlelen); \
    mfound; \
    })

#define SpmNocaseSearch(text, textlen, needle, needlelen) ({\
    uint8_t *mfound; \
    if (needlelen < 4 && textlen < 512) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else if (needlelen < 4) \
          mfound = BasicSearchNocase(text, textlen, needle, needlelen); \
    else \
          mfound = BoyerMooreNocaseSearch(text, textlen, needle, needlelen); \
    mfound; \
    })

#ifdef UNITTESTS
void UtilSpmSearchRegistertests(void);
#endif
#endif /* __UTIL_SPM_H__ */
