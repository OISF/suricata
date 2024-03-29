/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef SURICATA_DECODE_SCTP_H
#define SURICATA_DECODE_SCTP_H

/** size of the packet header without any chunk headers */
#define SCTP_HEADER_LEN                       12

typedef struct SCTPHdr_
{
    uint16_t sh_sport;     /* source port */
    uint16_t sh_dport;     /* destination port */
    uint32_t sh_vtag;      /* verification tag, defined per flow */
    uint32_t sh_sum;       /* checksum, computed via crc32 */
} __attribute__((__packed__)) SCTPHdr;

void DecodeSCTPRegisterTests(void);

#endif /* SURICATA_DECODE_SCTP_H */
