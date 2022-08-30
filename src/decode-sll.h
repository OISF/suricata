/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_SLL_H__
#define __DECODE_SLL_H__

#define SLL_HEADER_LEN                16

typedef struct SllHdr_ {
    uint16_t sll_pkttype;      /* packet type */
    uint16_t sll_hatype;       /* link-layer address type */
    uint16_t sll_halen;        /* link-layer address length */
    uint8_t sll_addr[8];       /* link-layer address */
    uint16_t sll_protocol;     /* protocol */
} __attribute__((__packed__)) SllHdr;

#endif /* __DECODE_SLL_H__ */

