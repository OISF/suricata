/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Storage API
 */

#ifndef __UTIL_STORAGE_H__
#define __UTIL_STORAGE_H__

typedef enum StorageEnum_ {
    STORAGE_HOST,
    STORAGE_FLOW,

    STORAGE_MAX,
} StorageEnum;

/** void ptr array for now */
typedef void* Storage;

void StorageInit(void);
void StorageCleanup(void);
int StorageRegister(const StorageEnum type, const char *name, const unsigned int size, int (*Init)(void *), void (*Free)(void *));
int StorageFinalize(void);

void *StorageGetById(Storage *storage, StorageEnum type, int id);
void *StorageAllocById(Storage **storage, StorageEnum type, int id);
void StorageFreeById(Storage *storage, StorageEnum type, int id);
void StorageFree(Storage **storage, StorageEnum type);

void StorageRegisterTests(void);
#endif
