/* Copyright (C) 2022 Open Information Security Foundation
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

#ifndef __DECODE_SCTP_H__
#define __DECODE_SCTP_H__

/** size of the packet header without any chunk headers */
#define SCTP_HEADER_LEN                       12

/* XXX RAW* needs to be really 'raw', so no SCNtohs there */
#define SCTP_GET_RAW_SRC_PORT(sctph)          SCNtohs((sctph)->sh_sport)
#define SCTP_GET_RAW_DST_PORT(sctph)          SCNtohs((sctph)->sh_dport)

#define SCTP_GET_SRC_PORT(p)                  SCTP_GET_RAW_SRC_PORT(p->sctph)
#define SCTP_GET_DST_PORT(p)                  SCTP_GET_RAW_DST_PORT(p->sctph)

typedef struct SCTPHdr_
{
    uint16_t sh_sport;     /* source port */
    uint16_t sh_dport;     /* destination port */
    uint32_t sh_vtag;      /* verification tag, defined per flow */
    uint32_t sh_sum;       /* checksum, computed via crc32 */
} __attribute__((__packed__)) SCTPHdr;

#define CLEAR_SCTP_PACKET(p) { \
    (p)->sctph = NULL; \
} while (0)

void DecodeSCTPRegisterTests(void);

#endif /* __DECODE_SCTP_H__ */
