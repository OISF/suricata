/* Copyright (C) 2018-2021 Open Information Security Foundation
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
#include "util-device-private.h"
#include "util-storage.h"
#include "util-unittest.h"

unsigned int SCLiveDevStorageSize(void)
{
    return SCStorageGetSize(STORAGE_DEVICE);
}

/** \defgroup devicestorage Device storage API
 *
 * The device storage API is a per-device storage. It is a mean to extend
 * the LiveDevice structure with arbitrary data.
 *
 * You have first to register the storage via SCLiveDevStorageRegister() during
 * the init of your module. Then you can attach data via SCLiveDevSetStorageById()
 * and access them via SCLiveDevGetStorageById().
 * @{
 */

/**
 * \brief Register a LiveDevice storage
 *
 * \param name the name of the storage
 * \param Free free function for the new storage
 *
 * \retval The ID of the newly register storage that will be used to access data
 *
 * It has to be called once during the init of the sub system
 */

SCLiveDevStorageId SCLiveDevStorageRegister(const char *name, void (*Free)(void *))
{
    int id = SCStorageRegister(STORAGE_DEVICE, name, Free);
    SCLiveDevStorageId ldsi = { .id = id };
    return ldsi;
}

/**
 * \brief Store a pointer in a given LiveDevice storage
 *
 * \param d a pointer to the LiveDevice
 * \param id the id of the storage (return of SCHostStorageRegister() call)
 * \param ptr pointer to the data to store
 */

int SCLiveDevSetStorageById(LiveDevice *d, SCLiveDevStorageId id, void *ptr)
{
    return SCStorageSetById(d->storage, STORAGE_DEVICE, id.id, ptr);
}

/**
 * \brief Get a value from a given LiveDevice storage
 *
 * \param d a pointer to the LiveDevice
 * \param id the id of the storage (return of SCLiveDevStorageRegister() call)
 *
 */

void *SCLiveDevGetStorageById(LiveDevice *d, SCLiveDevStorageId id)
{
    return SCStorageGetById(d->storage, STORAGE_DEVICE, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void SCLiveDevFreeStorage(LiveDevice *d)
{
    if (SCLiveDevStorageSize() > 0)
        SCStorageFreeAll(d->storage, STORAGE_DEVICE);
}


