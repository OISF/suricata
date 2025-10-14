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
 * \author Damian Poole <poodle@amazon.com>
 *
 * Layer Two Tunneling Protocol (L2TP) Version 3 over IP or UDP decoder.
 */

#ifndef __DECODE_L2TP_H__
#define __DECODE_L2TP_H__

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

#define L2TP_MAX_PORTS      4
#define L2TP_UNSET_PORT     -1
#define L2TP_DEFAULT_PORT   1701
#define L2TP_DEFAULT_PORT_S "1701"

/* Although L2TPv3 can do non-IP (like ATM), assume that there's a trailing ethernet header */
#define L2TP_MIN_HEADER_LEN sizeof(L2TPoverUDPDataHdr) + sizeof(EthernetHdr)

typedef struct L2TPoverUDPDataHdr_ {
    uint8_t type;
    uint8_t version;
    uint16_t reserved;
} L2TPoverUDPDataHdr;

void DecodeL2TPRegisterTests(void);
void DecodeL2TPConfig(void);
bool DecodeL2TPEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif /* !__DECODE_L2TP_H__ */