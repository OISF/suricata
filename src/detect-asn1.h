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
 * \file detect-asn1.h
 *
 * Implements "asn1" keyword
 */
#ifndef SURICATA_DETECT_ASN1_H
#define SURICATA_DETECT_ASN1_H

/* prototypes */
void DetectAsn1Register (void);

bool DetectAsn1Match(const SigMatchData *smd, const uint8_t *buffer, const uint32_t buffer_len,
        const uint32_t offset);

#endif /* SURICATA_DETECT_ASN1_H */
