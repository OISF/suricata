/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef SURICATA_DETECT_BYTETEST_H
#define SURICATA_DETECT_BYTETEST_H

/** Bytetest Operators */
#define DETECT_BYTETEST_OP_LT     1 /**< "less than" operator */
#define DETECT_BYTETEST_OP_GT     2 /**< "greater than" operator */
#define DETECT_BYTETEST_OP_EQ     3 /**< "equals" operator */
#define DETECT_BYTETEST_OP_AND    4 /**< "bitwise and" operator */
#define DETECT_BYTETEST_OP_OR     5 /**< "bitwise or" operator */
#define DETECT_BYTETEST_OP_GE     6 /**< greater than equal operator */
#define DETECT_BYTETEST_OP_LE     7 /**< less than equal operator */

/** Bytetest Base */
#define DETECT_BYTETEST_BASE_UNSET  0 /**< Unset type value string (automatic)*/
#define DETECT_BYTETEST_BASE_OCT    8 /**< "oct" type value string */
#define DETECT_BYTETEST_BASE_DEC   10 /**< "dec" type value string */
#define DETECT_BYTETEST_BASE_HEX   16 /**< "hex" type value string */

/** Bytetest Flags */
#define DETECT_BYTETEST_LITTLE     BIT_U16(0) /**< "little" endian value */
#define DETECT_BYTETEST_BIG        BIT_U16(1) /**< "bi" endian value */
#define DETECT_BYTETEST_STRING     BIT_U16(2) /**< "string" value */
#define DETECT_BYTETEST_RELATIVE   BIT_U16(3) /**< "relative" offset */
#define DETECT_BYTETEST_DCE        BIT_U16(4) /**< dce enabled */
#define DETECT_BYTETEST_BITMASK    BIT_U16(5) /**< bitmask supplied*/
#define DETECT_BYTETEST_VALUE_VAR  BIT_U16(6) /**< byte extract value enabled */
#define DETECT_BYTETEST_OFFSET_VAR BIT_U16(7) /**< byte extract value enabled */
#define DETECT_BYTETEST_NBYTES_VAR BIT_U16(8) /**< byte extract value enabled */

typedef struct DetectBytetestData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t op;                       /**< Operator used to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint8_t bitmask_shift_count;      /**< bitmask trailing 0 count */
    uint16_t flags;                   /**< Flags (big|little|relative|string|bitmask) */
    bool neg_op;
    int32_t offset;                   /**< Offset in payload */
    uint32_t bitmask;                 /**< bitmask value */
    uint64_t value;                   /**< Value to compare against */
} DetectBytetestData;

/* prototypes */

/**
 * Registration function for byte_test.
 *
 * \todo add support for no_stream and stream_only
 */
void DetectBytetestRegister (void);

int DetectBytetestDoMatch(DetectEngineThreadCtx *, const Signature *, const SigMatchCtx *ctx,
        const uint8_t *, uint32_t, uint16_t, int32_t, int32_t, uint64_t);

#endif /* SURICATA_DETECT_BYTETEST_H */
