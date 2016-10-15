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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_BYTEEXTRACT_H__
#define __DETECT_BYTEEXTRACT_H__

/* flags */
#define DETECT_BYTE_EXTRACT_FLAG_RELATIVE   0x01
#define DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER 0x02
#define DETECT_BYTE_EXTRACT_FLAG_STRING     0x04
#define DETECT_BYTE_EXTRACT_FLAG_ALIGN      0x08
#define DETECT_BYTE_EXTRACT_FLAG_ENDIAN     0x10

/* endian value to be used.  Would be stored in DetectByteParseData->endian */
#define DETECT_BYTE_EXTRACT_ENDIAN_NONE    0
#define DETECT_BYTE_EXTRACT_ENDIAN_BIG     1
#define DETECT_BYTE_EXTRACT_ENDIAN_LITTLE  2
#define DETECT_BYTE_EXTRACT_ENDIAN_DCE     3

/**
 * \brief Holds data related to byte_extract keyword.
 */
typedef struct DetectByteExtractData_ {
    /* local id used by other keywords in the sig to reference this */
    uint8_t local_id;

    uint8_t nbytes;
    int16_t pad;
    int32_t offset;
    const char *name;
    uint8_t flags;
    uint8_t endian;
    uint8_t base;
    uint8_t align_value;

    uint16_t multiplier_value;
    /* unique id used to reference this byte_extract keyword */
    uint16_t id;

} DetectByteExtractData;

void DetectByteExtractRegister(void);

SigMatch *DetectByteExtractRetrieveSMVar(const char *, const Signature *);
int DetectByteExtractDoMatch(DetectEngineThreadCtx *, const SigMatchData *, const Signature *,
                             uint8_t *, uint16_t, uint64_t *, uint8_t);

#endif /* __DETECT_BYTEEXTRACT_H__ */
