/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Device wrapper around storage api
 */

#include "suricata-common.h"
#include "device-storage.h"
#include "util-unittest.h"

unsigned int LiveDevStorageSize(void)
{
    return StorageGetSize(STORAGE_DEVICE);
}

/** \defgroup devicestorage Device storage API
 *
 * The device storage API is a per-device storage. It is a mean to extend
 * the LiveDevice structure with arbitrary data.
 *
 * You have first to register the storage via LiveDevStorageRegister() during
 * the init of your module. Then you can attach data via LiveDevSetStorageById()
 * and access them via LiveDevGetStorageById().
 * @{
 */

/**
 * \brief Register a LiveDevice storage
 *
 * \param name the name of the storage
 * \param size integer coding the size of the stored value (sizeof(void *) is best choice here)
 * \param Alloc allocation function for the storage (can be null)
 * \param Free free function for the new storage
 *
 * \retval The ID of the newly register storage that will be used to access data
 *
 * It has to be called once during the init of the sub system
 */

LiveDevStorageId LiveDevStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_DEVICE, name, size, Alloc, Free);
    LiveDevStorageId ldsi = { .id = id };
    return ldsi;
}

/**
 * \brief Store a pointer in a given LiveDevice storage
 *
 * \param d a pointer to the LiveDevice
 * \param id the id of the storage (return of HostStorageRegister() call)
 * \param ptr pointer to the data to store
 */

int LiveDevSetStorageById(LiveDevice *d, LiveDevStorageId id, void *ptr)
{
    return StorageSetById((Storage *)((void *)d + sizeof(LiveDevice)), STORAGE_DEVICE, id.id, ptr);
}

/**
 * \brief Get a value from a given LiveDevice storage
 *
 * \param d a pointer to the LiveDevice
 * \param id the id of the storage (return of LiveDevStorageRegister() call)
 *
 */

void *LiveDevGetStorageById(LiveDevice *d, LiveDevStorageId id)
{
    return StorageGetById((Storage *)((void *)d + sizeof(LiveDevice)), STORAGE_DEVICE, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void *LiveDevAllocStorageById(LiveDevice *d, LiveDevStorageId id)
{
    return StorageAllocByIdPrealloc(
            (Storage *)((void *)d + sizeof(LiveDevice)), STORAGE_DEVICE, id.id);
}

void LiveDevFreeStorageById(LiveDevice *d, LiveDevStorageId id)
{
    StorageFreeById((Storage *)((void *)d + sizeof(LiveDevice)), STORAGE_DEVICE, id.id);
}

void LiveDevFreeStorage(LiveDevice *d)
{
    if (LiveDevStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)d + sizeof(LiveDevice)), STORAGE_DEVICE);
}


