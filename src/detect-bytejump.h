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

#ifndef SURICATA_DETECT_BYTEJUMP_H
#define SURICATA_DETECT_BYTEJUMP_H

/** Bytejump Base */
#define DETECT_BYTEJUMP_BASE_UNSET  0 /**< Unset type value string (automatic)*/
#define DETECT_BYTEJUMP_BASE_OCT    8 /**< "oct" type value string */
#define DETECT_BYTEJUMP_BASE_DEC   10 /**< "dec" type value string */
#define DETECT_BYTEJUMP_BASE_HEX   16 /**< "hex" type value string */

/** Bytejump Flags */
#define DETECT_BYTEJUMP_BEGIN     BIT_U16(0) /**< "from_beginning" jump */
#define DETECT_BYTEJUMP_LITTLE    BIT_U16(1) /**< "little" endian value */
#define DETECT_BYTEJUMP_BIG       BIT_U16(2) /**< "big" endian value */
#define DETECT_BYTEJUMP_STRING    BIT_U16(3) /**< "string" value */
#define DETECT_BYTEJUMP_RELATIVE  BIT_U16(4) /**< "relative" offset */
#define DETECT_BYTEJUMP_ALIGN     BIT_U16(5) /**< "align" offset */
#define DETECT_BYTEJUMP_DCE       BIT_U16(6) /**< "dce" enabled */
#define DETECT_BYTEJUMP_OFFSET_BE BIT_U16(7) /**< "byte extract" enabled */
#define DETECT_BYTEJUMP_END       BIT_U16(8) /**< "from_end" jump */
#define DETECT_BYTEJUMP_NBYTES_VAR BIT_U16(9) /**< nbytes string*/
#define DETECT_BYTEJUMP_OFFSET_VAR BIT_U16(10) /**< byte extract value enabled */

typedef struct DetectBytejumpData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint16_t flags;                   /**< Flags (big|little|relative|string) */
    int32_t offset;                   /**< Offset in payload to extract value */
    int32_t post_offset;              /**< Offset to adjust post-jump */
    uint16_t multiplier;              /**< Multiplier for nbytes (multiplier n)*/
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
 * \retval  false no match
 * \retval  true
 */
bool DetectBytejumpDoMatch(DetectEngineThreadCtx *, const Signature *, const SigMatchCtx *,
        const uint8_t *, uint32_t, uint16_t, int32_t, int32_t);

#endif /* SURICATA_DETECT_BYTEJUMP_H */
