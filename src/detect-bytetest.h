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
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DETECT_BYTETEST_H__
#define __DETECT_BYTETEST_H__

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
#define DETECT_BYTETEST_NEGOP    0x01 /**< "!" negated operator */
#define DETECT_BYTETEST_LITTLE   0x02 /**< "little" endian value */
#define DETECT_BYTETEST_BIG      0x04 /**< "bi" endian value */
#define DETECT_BYTETEST_STRING   0x08 /**< "string" value */
#define DETECT_BYTETEST_RELATIVE 0x10 /**< "relative" offset */
#define DETECT_BYTETEST_DCE      0x20 /**< dce enabled */
#define DETECT_BYTETEST_VALUE_BE  0x40 /**< byte extract value enabled */
#define DETECT_BYTETEST_OFFSET_BE 0x80 /**< byte extract value enabled */

typedef struct DetectBytetestData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t op;                       /**< Operator used to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint8_t flags;                    /**< Flags (big|little|relative|string) */
    int32_t offset;                   /**< Offset in payload */
    uint64_t value;                   /**< Value to compare against */
} DetectBytetestData;

/* prototypes */

/**
 * Registration function for byte_test.
 *
 * \todo add support for no_stream and stream_only
 */
void DetectBytetestRegister (void);

int DetectBytetestDoMatch(DetectEngineThreadCtx *, const Signature *,
                          const SigMatchCtx *ctx, uint8_t *, uint32_t,
                          uint8_t, int32_t, uint64_t);

#endif /* __DETECT_BYTETEST_H__ */
