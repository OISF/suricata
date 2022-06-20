/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Carl Smith <carl.smith@alliedtelesis.co.nz>
 *
 */

#ifndef __DECODE_NSH_H__
#define __DECODE_NSH_H__


#define NSH_NEXT_PROTO_UNASSIGNED  0x0
#define NSH_NEXT_PROTO_IPV4        0x1
#define NSH_NEXT_PROTO_IPV6        0x2
#define NSH_NEXT_PROTO_ETHERNET    0x3
#define NSH_NEXT_PROTO_NSH         0x4
#define NSH_NEXT_PROTO_MPLS        0x5
#define NSH_NEXT_PROTO_EXPERIMENT1 0xFE
#define NSH_NEXT_PROTO_EXPERIMENT2 0xFF

/*
 * Network Service Header (NSH)
 */
typedef struct NshHdr_ {
    uint16_t ver_flags_len;
    uint8_t md_type;
    uint8_t next_protocol;
    uint32_t spi_si;
} __attribute__((packed)) NshHdr;

void DecodeNSHRegisterTests(void);

#endif /* __DECODE_NSH_H__ */
