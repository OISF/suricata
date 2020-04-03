/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 */

#ifndef __DETECT_ENGINE_UINT_H
#define __DETECT_ENGINE_UINT_H

#include "detect-engine-prefilter-common.h"

typedef enum {
    DETECT_UINT_LT,
    DETECT_UINT_EQ,
    DETECT_UINT_GT,
    DETECT_UINT_RA,
} DetectUintMode;

typedef struct DetectU32Data_ {
    uint32_t arg1;   /**< first arg value in the signature*/
    uint32_t arg2;   /**< second arg value in the signature, in case of range
                          operator*/
    DetectUintMode mode;    /**< operator used in the signature */
} DetectU32Data;

int DetectU32Match(const uint32_t parg, const DetectU32Data *du32);
DetectU32Data *DetectU32Parse (const char *u32str);
void PrefilterPacketU32Set(PrefilterPacketHeaderValue *v, void *smctx);
bool PrefilterPacketU32Compare(PrefilterPacketHeaderValue v, void *smctx);

void DetectUintRegister(void);

typedef struct DetectU8Data_ {
    uint8_t arg1;   /**< first arg value in the signature*/
    uint8_t arg2;   /**< second arg value in the signature, in case of range
                          operator*/
    DetectUintMode mode;    /**< operator used in the signature */
} DetectU8Data;

int DetectU8Match(const uint8_t parg, const DetectU8Data *du8);
DetectU8Data *DetectU8Parse (const char *u8str);

#endif /* __DETECT_UTIL_UINT_H */
