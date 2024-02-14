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
 *
 */

#include "suricata-common.h"

#include "util-byte.h"
#include "detect-parse.h"
#include "detect-engine-uint.h"

int DetectU32Match(const uint32_t parg, const DetectUintData_u32 *du32)
{
    return rs_detect_u32_match(parg, du32);
}

/**
 * \brief This function is used to parse u32 options passed via some u32 keyword
 *
 * \param u32str Pointer to the user provided u32 options
 *
 * \retval DetectU32Data pointer to DetectU32Data on success
 * \retval NULL on failure
 */

DetectUintData_u32 *DetectU32Parse(const char *u32str)
{
    return rs_detect_u32_parse(u32str);
}

void
PrefilterPacketU32Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectUintData_u32 *a = smctx;
    v->u8[0] = a->mode;
    v->u32[1] = a->arg1;
    v->u32[2] = a->arg2;
}

bool
PrefilterPacketU32Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectUintData_u32 *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u32[1] == a->arg1 &&
        v.u32[2] == a->arg2)
        return true;
    return false;
}

//same as u32 but with u8
int DetectU8Match(const uint8_t parg, const DetectUintData_u8 *du8)
{
    return rs_detect_u8_match(parg, du8);
}

/**
 * \brief This function is used to parse u8 options passed via some u8 keyword
 *
 * \param u8str Pointer to the user provided u8 options
 *
 * \retval DetectU8Data pointer to DetectU8Data on success
 * \retval NULL on failure
 */

DetectUintData_u8 *DetectU8Parse(const char *u8str)
{
    return rs_detect_u8_parse(u8str);
}

void PrefilterPacketU8Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectUintData_u8 *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->arg1;
    v->u8[2] = a->arg2;
}

bool PrefilterPacketU8Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectUintData_u8 *a = smctx;
    if (v.u8[0] == a->mode && v.u8[1] == a->arg1 && v.u8[2] == a->arg2)
        return true;
    return false;
}

// same as u32 but with u16
int DetectU16Match(const uint16_t parg, const DetectUintData_u16 *du16)
{
    return rs_detect_u16_match(parg, du16);
}

/**
 * \brief This function is used to parse u16 options passed via some u16 keyword
 *
 * \param u16str Pointer to the user provided u16 options
 *
 * \retval DetectU16Data pointer to DetectU16Data on success
 * \retval NULL on failure
 */

DetectUintData_u16 *DetectU16Parse(const char *u16str)
{
    return rs_detect_u16_parse(u16str);
}

void PrefilterPacketU16Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectUintData_u16 *a = smctx;
    v->u8[0] = a->mode;
    v->u16[1] = a->arg1;
    v->u16[2] = a->arg2;
}

bool PrefilterPacketU16Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectUintData_u16 *a = smctx;
    if (v.u8[0] == a->mode && v.u16[1] == a->arg1 && v.u16[2] == a->arg2)
        return true;
    return false;
}

int DetectU64Match(const uint64_t parg, const DetectUintData_u64 *du64)
{
    return rs_detect_u64_match(parg, du64);
}

DetectUintData_u64 *DetectU64Parse(const char *u64str)
{
    return rs_detect_u64_parse(u64str);
}
