/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Fupeng Zhao <fupeng.zhao@foxmail.com>
 */

#ifndef SURICATA_DECODE_ETAG_H
#define SURICATA_DECODE_ETAG_H

/** E-Tag header struct */
typedef struct ETagHdr_ {
    uint16_t pcp_dei_ingress_base;
    uint16_t resv_grp_ecid_base;
    uint8_t ingress_ecid_ext;
    uint8_t ecid_ext;
    uint16_t protocol; /**< next protocol */
} __attribute__((__packed__)) ETagHdr;

/** E-Tag header length */
#define ETAG_HEADER_LEN 8

void DecodeETagRegisterTests(void);

#endif /* SURICATA_DECODE_ETAG_H */
