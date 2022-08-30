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

/**
 * \file
 *
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 */

#ifndef __DETECT_ENGINE_UINT_H
#define __DETECT_ENGINE_UINT_H

#include "rust.h"
#include "detect-engine-prefilter-common.h"

// These definitions are kept to minimize the diff
// We can run a big sed commit next
#define DETECT_UINT_GT  DetectUintModeGt
#define DETECT_UINT_GTE DetectUintModeGte
#define DETECT_UINT_RA  DetectUintModeRange
#define DETECT_UINT_EQ  DetectUintModeEqual
#define DETECT_UINT_NE  DetectUintModeNe
#define DETECT_UINT_LT  DetectUintModeLt
#define DETECT_UINT_LTE DetectUintModeLte

typedef DetectUintData_u64 DetectU64Data;
typedef DetectUintData_u32 DetectU32Data;
typedef DetectUintData_u16 DetectU16Data;
typedef DetectUintData_u8 DetectU8Data;

int DetectU64Match(const uint64_t parg, const DetectUintData_u64 *du64);
DetectUintData_u64 *DetectU64Parse(const char *u64str);

int DetectU32Match(const uint32_t parg, const DetectUintData_u32 *du32);
DetectUintData_u32 *DetectU32Parse(const char *u32str);
void PrefilterPacketU32Set(PrefilterPacketHeaderValue *v, void *smctx);
bool PrefilterPacketU32Compare(PrefilterPacketHeaderValue v, void *smctx);

int DetectU8Match(const uint8_t parg, const DetectUintData_u8 *du8);
DetectUintData_u8 *DetectU8Parse(const char *u8str);
void PrefilterPacketU8Set(PrefilterPacketHeaderValue *v, void *smctx);
bool PrefilterPacketU8Compare(PrefilterPacketHeaderValue v, void *smctx);

int DetectU16Match(const uint16_t parg, const DetectUintData_u16 *du16);
DetectUintData_u16 *DetectU16Parse(const char *u16str);
void PrefilterPacketU16Set(PrefilterPacketHeaderValue *v, void *smctx);
bool PrefilterPacketU16Compare(PrefilterPacketHeaderValue v, void *smctx);

#endif /* __DETECT_UTIL_UINT_H */
