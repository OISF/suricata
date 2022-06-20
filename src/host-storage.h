/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 *
 * Host wrapper around storage api
 */

#ifndef __HOST_STORAGE_H__
#define __HOST_STORAGE_H__

#include "host.h"

typedef struct HostStorageId_ {
    int id;
} HostStorageId;

unsigned int HostStorageSize(void);

void *HostGetStorageById(Host *h, HostStorageId id);
int HostSetStorageById(Host *h, HostStorageId id, void *ptr);
void *HostAllocStorageById(Host *h, HostStorageId id);

void HostFreeStorageById(Host *h, HostStorageId id);
void HostFreeStorage(Host *h);

void RegisterHostStorageTests(void);

HostStorageId HostStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *));

#endif /* __HOST_STORAGE_H__ */
