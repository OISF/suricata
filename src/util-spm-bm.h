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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 */

#ifndef __UTIL_SPM_BM__
#define __UTIL_SPM_BM__

#include "suricata-common.h"

#define ALPHABET_SIZE 256

/* Context for booyer moore */
typedef struct BmCtx_ {
    uint16_t bmBc[ALPHABET_SIZE];
    //C99 "flexible array member"
    uint16_t bmGs[]; // = SCMalloc(sizeof(int16_t)*(needlelen + 1));
} BmCtx;

/** Prepare and return a Boyer Moore context */
BmCtx *BoyerMooreCtxInit(const uint8_t *needle, uint16_t needle_len);
BmCtx *BoyerMooreNocaseCtxInit(uint8_t *needle, uint16_t needle_len);

void BoyerMooreCtxToNocase(BmCtx *, uint8_t *, uint16_t);
uint8_t *BoyerMoore(const uint8_t *x, uint16_t m, const uint8_t *y, uint32_t n, BmCtx *bm_ctx);
uint8_t *BoyerMooreNocase(const uint8_t *x, uint16_t m, const uint8_t *y, uint32_t n, BmCtx *bm_ctx);
void BoyerMooreCtxDeInit(BmCtx *);

void SpmBMRegister(void);

#endif /* __UTIL_SPM_BM__ */

