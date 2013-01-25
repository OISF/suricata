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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Host wrapper around storage api
 */

#include "suricata-common.h"
#include "host-storage.h"
#include "util-unittest.h"

unsigned int HostStorageSize(void) {
    return StorageGetSize(STORAGE_HOST);
}

void *HostGetStorageById(Host *h, int id) {
    return StorageGetById((Storage *)(h + HostStorageSize()), STORAGE_HOST, id);
}

void *HostAllocStorageById(Host *h, int id) {
    return StorageAllocById((Storage **)&h + HostStorageSize(), STORAGE_HOST, id);
}

void HostFreeStorageById(Host *h, int id) {
    StorageFreeById((Storage *)(h + HostStorageSize()), STORAGE_HOST, id);
}

void HostFreeStorage(Host *h) {
    StorageFreeAll((Storage *)(h + HostStorageSize()), STORAGE_HOST);
}

#ifdef UNITTESTS
static int HostStorageTest01(void) {
    return 1;
}
#endif

void RegisterHostStorageTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HostStorageTest01", HostStorageTest01, 1);
#endif
}
