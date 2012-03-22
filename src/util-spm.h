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
 */

#ifndef __UTIL_SPM_H__
#define __UTIL_SPM_H__

#include "util-spm-bs.h"
#include "util-spm-bs2bm.h"
#include "util-spm-bm.h"

/** Default algorithm to use: Boyer Moore */
uint8_t *Bs2bmSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen);
uint8_t *Bs2bmNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen);
uint8_t *BoyerMooreSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen);
uint8_t *BoyerMooreNocaseSearch(uint8_t *text, uint32_t textlen, uint8_t *needle, uint16_t needlelen);

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

void UtilSpmSearchRegistertests(void);
#endif /* __UTIL_SPM_H__ */
