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
 */

#ifndef __UTIL_HOST_OS_INFO_H__
#define __UTIL_HOST_OS_INFO_H__

#define SC_HINFO_IS_IPV6 0
#define SC_HINFO_IS_IPV4 1

int SCHInfoAddHostOSInfo(const char *, const char *, int);
int SCHInfoGetHostOSFlavour(const char *);
int SCHInfoGetIPv4HostOSFlavour(uint8_t *);
int SCHInfoGetIPv6HostOSFlavour(uint8_t *);
void SCHInfoCleanResources(void);
void SCHInfoLoadFromConfig(void);
void SCHInfoRegisterTests(void);

#endif /* __UTIL_HOST_OS_INFO_H__ */
