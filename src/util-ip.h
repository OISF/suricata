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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 */

#ifndef __UTIL_IP_H__
#define __UTIL_IP_H__

bool IPv4AddressStringIsValid(const char *str);
bool IPv6AddressStringIsValid(const char *str);
struct in_addr *ValidateIPV4Address(const char *);
struct in6_addr *ValidateIPV6Address(const char *);
void MaskIPNetblock(uint8_t *, int, int);

#endif /* __UTIL_IP_H__ */
