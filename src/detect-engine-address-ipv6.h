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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_ADDRESS_IPV6_H__
#define __DETECT_ENGINE_ADDRESS_IPV6_H__

int AddressIPv6Lt(uint32_t *, uint32_t *);
int AddressIPv6Gt(uint32_t *, uint32_t *);
int AddressIPv6Eq(uint32_t *, uint32_t *);
int AddressIPv6Le(uint32_t *, uint32_t *);
int AddressIPv6Ge(uint32_t *, uint32_t *);

int DetectAddressCutNotIPv6(DetectAddress *, DetectAddress **);
int DetectAddressCmpIPv6(DetectAddress *a, DetectAddress *b);

int DetectAddressCutIPv6(DetectEngineCtx *, DetectAddress *, DetectAddress *,
                         DetectAddress **);
int DetectAddressJoinIPv6(DetectEngineCtx *, DetectAddress *, DetectAddress *);

void DetectAddressIPv6Tests(void);

#endif /* __DETECT_ENGINE_ADDRESS_IPV6_H__ */

