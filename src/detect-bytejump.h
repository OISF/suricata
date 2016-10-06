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

#ifndef __DETECT_BYTEJUMP_H__
#define __DETECT_BYTEJUMP_H__

/** Bytejump Base */
#define DETECT_BYTEJUMP_BASE_UNSET  0 /**< Unset type value string (automatic)*/
#define DETECT_BYTEJUMP_BASE_OCT    8 /**< "oct" type value string */
#define DETECT_BYTEJUMP_BASE_DEC   10 /**< "dec" type value string */
#define DETECT_BYTEJUMP_BASE_HEX   16 /**< "hex" type value string */

/** Bytejump Flags */
#define DETECT_BYTEJUMP_BEGIN    0x01 /**< "from_beginning" jump */
#define DETECT_BYTEJUMP_LITTLE   0x02 /**< "little" endian value */
#define DETECT_BYTEJUMP_BIG      0x04 /**< "big" endian value */
#define DETECT_BYTEJUMP_STRING   0x08 /**< "string" value */
#define DETECT_BYTEJUMP_RELATIVE 0x10 /**< "relative" offset */
#define DETECT_BYTEJUMP_ALIGN    0x20 /**< "align" offset */
#define DETECT_BYTEJUMP_DCE      0x40 /**< "dce" enabled */
#define DETECT_BYTEJUMP_OFFSET_BE 0x80 /**< "byte extract" enabled */

typedef struct DetectBytejumpData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint8_t flags;                    /**< Flags (big|little|relative|string) */
    uint32_t multiplier;              /**< Multiplier for nbytes (multiplier n)*/
    int32_t offset;                   /**< Offset in payload to extract value */
    int32_t post_offset;              /**< Offset to adjust post-jump */
} DetectBytejumpData;

/* prototypes */

/**
 * Registration function for byte_jump.
 *
 * \todo add support for no_stream and stream_only
 */
void DetectBytejumpRegister (void);

/**
 * This function is used to match byte_jump
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectBytejumpData
 *
 * \retval -1 error
 * \retval  0 no match
 * \retval  1 match
 *
 * \todo The return seems backwards.  We should return a non-zero error code.
 *       One of the error codes is "no match".  As-is if someone accidentally
 *       does: if (DetectBytejumpMatch(...)) { match }, then they catch an
 *       error as a match.
 */
int DetectBytejumpDoMatch(DetectEngineThreadCtx *, const Signature *, const SigMatchCtx *,
                          uint8_t *, uint32_t, uint8_t, int32_t);

#endif /* __DETECT_BYTEJUMP_H__ */

