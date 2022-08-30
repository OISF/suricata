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
    STORAGE_IPPAIR,
    STORAGE_DEVICE,

    STORAGE_MAX,
} StorageEnum;

/** void ptr array for now */
typedef void* Storage;

void StorageInit(void);
void StorageCleanup(void);

/** \brief Register new storage
 *
 *  \param type type from StorageEnum
 *  \param name name
 *  \param size size of the per instance storage
 *  \param Alloc alloc function for per instance storage
 *  \param Free free function for per instance storage
 *
 *  \note if size == ptr size (so sizeof(void *)) and Alloc == NULL the API just
 *        gives the caller a ptr to store something it alloc'ed itself.
 */
int StorageRegister(const StorageEnum type, const char *name, const unsigned int size, void *(*Alloc)(unsigned int), void (*Free)(void *));
int StorageFinalize(void);

unsigned int StorageGetCnt(const StorageEnum type);
unsigned int StorageGetSize(const StorageEnum type);

/** \brief get storage for id */
void *StorageGetById(const Storage *storage, const StorageEnum type, const int id);
/** \brief set storage for id */
int StorageSetById(Storage *storage, const StorageEnum type, const int id, void *ptr);

/** \brief AllocById func for prealloc'd base storage (storage ptrs are part
 *         of another memory block) */
void *StorageAllocByIdPrealloc(Storage *storage, StorageEnum type, int id);
/** \brief AllocById func for when we manage the Storage ptr itself */
void *StorageAllocById(Storage **storage, const StorageEnum type, const int id);
void StorageFreeById(Storage *storage, const StorageEnum type, const int id);
void StorageFreeAll(Storage *storage, const StorageEnum type);
void StorageFree(Storage **storage, const StorageEnum type);

void StorageRegisterTests(void);
#endif
