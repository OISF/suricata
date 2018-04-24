/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 * Isolation for WMI/COM functionality
 */

#ifndef __WIN32_SYSCALL_H__
#define __WIN32_SYSCALL_H__
#ifdef OS_WIN32

#include "util-device.h"

struct _IP_ADAPTER_ADDRESSES_LH;

uint32_t
Win32GetAdaptersAddresses(struct _IP_ADAPTER_ADDRESSES_LH **pif_info_list);
uint32_t
Win32FindAdapterAddresses(struct _IP_ADAPTER_ADDRESSES_LH *if_info_list,
                          const char *adapter_name,
                          struct _IP_ADAPTER_ADDRESSES_LH **pif_info);

int GetIfaceMTUWin32(const char *pcap_dev);
int GetGlobalMTUWin32(void);

int GetIfaceOffloadingWin32(const char *ifname, int csum, int other);
int DisableIfaceOffloadingWin32(LiveDevice *ldev, int csum, int other);
int RestoreIfaceOffloadingWin32(LiveDevice *ldev);

void Win32SyscallRegisterTests(void);

#endif /* OS_WIN32 */
#endif /* __WIN32_SYSCALL_H__ */