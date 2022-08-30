/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

#ifndef __DETECT_BYTEMATH_H__
#define __DETECT_BYTEMATH_H__

/* flags */
#define DETECT_BYTEMATH_FLAG_RELATIVE   0x01
#define DETECT_BYTEMATH_FLAG_STRING     0x02
#define DETECT_BYTEMATH_FLAG_BITMASK    0x04
#define DETECT_BYTEMATH_FLAG_ENDIAN     0x08
#define DETECT_BYTEMATH_RVALUE_VAR      0x10

/* endian value to be used.  Would be stored in DetectByteMathData->endian */
#define DETECT_BYTEMATH_ENDIAN_NONE    0
#define DETECT_BYTEMATH_ENDIAN_BIG     1
#define DETECT_BYTEMATH_ENDIAN_LITTLE  2
#define DETECT_BYTEMATH_ENDIAN_DCE     3

#define DETECT_BYTEMATH_OPERATOR_NONE     1
#define DETECT_BYTEMATH_OPERATOR_PLUS     2
#define DETECT_BYTEMATH_OPERATOR_MINUS    3
#define DETECT_BYTEMATH_OPERATOR_DIVIDE   4
#define DETECT_BYTEMATH_OPERATOR_MULTIPLY 5
#define DETECT_BYTEMATH_OPERATOR_LSHIFT   6
#define DETECT_BYTEMATH_OPERATOR_RSHIFT   7

/**
 * \brief Holds data related to byte_math keyword.
 */
typedef struct DetectByteMathData_ {
    /* local id used by other keywords in the sig to reference this */
    uint8_t local_id;
    uint8_t nbytes;
    int32_t offset;

    uint32_t rvalue;

    /* "result" variable, if present */
    const char *result; /* consumed */

    uint8_t flags;
    uint8_t endian;
    uint8_t base;
    uint8_t oper;

    uint32_t bitmask_val;

    uint16_t bitmask_shift_count;
    /* unique id used to reference this byte_math keyword */
    uint16_t id;

} DetectByteMathData;

void DetectBytemathRegister(void);

SigMatch *DetectByteMathRetrieveSMVar(const char *, const Signature *);
int DetectByteMathDoMatch(DetectEngineThreadCtx *, const SigMatchData *, const Signature *,
                             const uint8_t *, uint16_t, uint64_t, uint64_t *, uint8_t);

#endif /* __DETECT_BYTEMATH_H__ */
