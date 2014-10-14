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

/**
 * This function is used to add the parsed byte_test data
 * into the current signature.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectBytetestSetup(DetectEngineCtx *, Signature *, char *);

/**
 * \brief this function will free memory associated with DetectBytetestData
 *
 * \param data pointer to DetectBytetestData
 */
void DetectBytetestFree(void *ptr);

/**
 * This function is used to parse byte_test options passed via
 *
 * byte_test: bytes, [!]op, value, offset [,flags [, ...]]
 *
 * flags: "big", "little", "relative", "string", "oct", "dec", "hex"
 *
 * \param optstr Pointer to the user provided byte_test options
 * \param value Used to pass the value back, if byte_test uses a byte_extract
 *              var.
 * \param offset Used to pass the offset back, if byte_test uses a byte_extract
 *               var.
 *
 * \retval data pointer to DetectBytetestData on success
 * \retval NULL on failure
 */
DetectBytetestData *DetectBytetestParse(char *optstr, char **value,
                                        char **offset);

/**
 * This function is used to match byte_test
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectBytetestData
 *
 * \retval -1 error
 * \retval  0 no match
 * \retval  1 match
 *
 * \todo The return seems backwards.  We should return a non-zero error code.  One of the error codes is "no match".  As-is if someone accidentally does: if (DetectBytetestMatch(...)) { match }, then they catch an error as a match.
 */
int DetectBytetestMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, const SigMatchCtx *ctx);
int DetectBytetestDoMatch(DetectEngineThreadCtx *, Signature *,
                          const SigMatchCtx *ctx, uint8_t *, uint32_t,
                          uint8_t, int32_t, uint64_t);

#endif /* __DETECT_BYTETEST_H__ */
