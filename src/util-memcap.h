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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 */

#ifndef __UTIL_MEMCAP_H__
#define __UTIL_MEMCAP_H__

typedef struct MemcapList_ {
    const char *name;
    const char *option;
    int (*SetFunc)(uint64_t);
    uint64_t (*GetFunc)(void);
    uint64_t (*GetMemuseFunc)(void);
    struct MemcapList_ *next;
} MemcapList;

int MemcapListRegisterMemcap(const char *name, const char *option,
                             int (*SetFunc)(uint64_t),
                             uint64_t (*GetFunc)(void),
                             uint64_t (*GetMemuseFunc)(void));
MemcapList *MemcapListGetElement(int index);
void MemcapListFreeList(void);

#endif
