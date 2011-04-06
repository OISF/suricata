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
#include "suricata.h"

#define ALPHABET_SIZE 256

/* Context for booyer moore */
typedef struct BmCtx_ {
    int32_t bmBc[ALPHABET_SIZE];
    int32_t *bmGs; // = SCMalloc(sizeof(int32_t)*(needlelen + 1));
} BmCtx;

/** Prepare and return a Boyer Moore context */
BmCtx *BoyerMooreCtxInit(uint8_t *needle, uint32_t needle_len);

void BoyerMooreCtxToNocase(BmCtx *, uint8_t *, uint32_t);
void PreBmBc(const uint8_t *x, int32_t m, int32_t *bmBc);
void BoyerMooreSuffixes(const uint8_t *x, int32_t m, int32_t *suff);
int PreBmGs(const uint8_t *, int32_t, int32_t *);
uint8_t *BoyerMoore(uint8_t *x, int32_t m, uint8_t *y, int32_t n, int32_t *bmGs, int32_t *bmBc);
void PreBmBcNocase(const uint8_t *x, int32_t m, int32_t *bmBc);
void BoyerMooreSuffixesNocase(const uint8_t *x, int32_t m, int32_t *suff);
void PreBmGsNocase(const uint8_t *x, int32_t m, int32_t *bmGs);
uint8_t *BoyerMooreNocase(uint8_t *x, int32_t m, uint8_t *y, int32_t n, int32_t *bmGs, int32_t *bmBc);
void BoyerMooreCtxDeInit(BmCtx *);
#endif /* __UTIL_SPM_BM__ */

