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
 * \file detect-asn1.h
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements "asn1" keyword
 */
#ifndef __DETECT_ASN1_H__
#define __DETECT_ASN1_H__


/* Function check flags */
#define         ASN1_BITSTRING_OVF       0x01
#define         ASN1_DOUBLE_OVF          0x02
#define         ASN1_OVERSIZE_LEN        0x04
#define         ASN1_ABSOLUTE_OFFSET     0x10
#define         ASN1_RELATIVE_OFFSET     0x20

typedef struct DetectAsn1Data_ {
    uint8_t flags;     /* flags indicating the checks loaded */
    uint32_t oversize_length;   /* Length argument if needed */
    int32_t absolute_offset;   /* Length argument if needed */
    int32_t relative_offset;   /* Length argument if needed */
} DetectAsn1Data;

/* prototypes */
void DetectAsn1Register (void);

#endif /* __DETECT_ASN1_H__ */

