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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef __DATASETS_IPV6_H__
#define __DATASETS_IPV6_H__

#include "datasets-reputation.h"

#if defined(OS_DARWIN) || defined(OS_FREEBSD) || defined(__OpenBSD__)
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif /* BSD check */

typedef struct IPv6Type {
    uint8_t ipv6[16];
    DataRepType rep;
} IPv6Type;

int IPv6Set(void *dst, void *src);
bool IPv6Compare(void *a, void *b);
uint32_t IPv6Hash(void *s);
void IPv6Free(void *s);

#endif /* __DATASETS_IPV4_H__ */
