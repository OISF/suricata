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

#include "suricata-common.h"
#include "host-storage.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
unsigned int HostStorageSize(void)
{
    return StorageGetSize(STORAGE_HOST);
}

/** \defgroup hoststorage Host storage API
 *
 * The Host storage API is a per-host storage. It is a mean to extend
 * the Host structure with arbitrary data.
 *
 * You have first to register the storage via HostStorageRegister() during
 * the init of your module. Then you can attach data via HostSetStorageById()
 * and access them via HostGetStorageById().
 * @{
 */

/**
 * \brief Register a Host storage
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

HostStorageId HostStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_HOST, name, size, Alloc, Free);
    HostStorageId hsi = { .id = id };
    return hsi;
}

/**
 * \brief Store a pointer in a given Host storage
 *
 * \param h a pointer to the Host
 * \param id the id of the storage (return of HostStorageRegister() call)
 * \param ptr pointer to the data to store
 */

int HostSetStorageById(Host *h, HostStorageId id, void *ptr)
{
    return StorageSetById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id.id, ptr);
}

/**
 * \brief Get a value from a given Host storage
 *
 * \param h a pointer to the Host
 * \param id the id of the storage (return of HostStorageRegister() call)
 *
 */

void *HostGetStorageById(Host *h, HostStorageId id)
{
    return StorageGetById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void *HostAllocStorageById(Host *h, HostStorageId id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id.id);
}

void HostFreeStorageById(Host *h, HostStorageId id)
{
    StorageFreeById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id.id);
}

void HostFreeStorage(Host *h)
{
    if (HostStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST);
}


#ifdef UNITTESTS

static void *StorageTestAlloc(unsigned int size)
{
    void *x = SCMalloc(size);
    return x;
}
static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int HostStorageTest01(void)
{
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1.id < 0)
        goto error;
    HostStorageId id2 = HostStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2.id < 0)
        goto error;
    HostStorageId id3 =
            HostStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    if (h == NULL) {
        printf("failed to get host: ");
        goto error;
    }

    void *ptr = HostGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }
    ptr = HostGetStorageById(h, id2);
    if (ptr != NULL) {
        goto error;
    }
    ptr = HostGetStorageById(h, id3);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = HostAllocStorageById(h, id1);
    if (ptr1a == NULL) {
        goto error;
    }
    void *ptr2a = HostAllocStorageById(h, id2);
    if (ptr2a == NULL) {
        goto error;
    }
    void *ptr3a = HostAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = HostGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = HostGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = HostGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    return 1;
error:
    HostShutdown();
    StorageCleanup();
    return 0;
}

static int HostStorageTest02(void)
{
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    if (h == NULL) {
        printf("failed to get host: ");
        goto error;
    }

    void *ptr = HostGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    HostSetStorageById(h, id1, ptr1a);

    void *ptr1b = HostGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    return 1;
error:
    HostShutdown();
    StorageCleanup();
    return 0;
}

static int HostStorageTest03(void)
{
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;
    HostStorageId id2 = HostStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2.id < 0)
        goto error;
    HostStorageId id3 = HostStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    if (h == NULL) {
        printf("failed to get host: ");
        goto error;
    }

    void *ptr = HostGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    HostSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    if (unlikely(ptr2a == NULL)) {
        goto error;
    }
    HostSetStorageById(h, id2, ptr2a);

    void *ptr3a = HostAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = HostGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = HostGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = HostGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    return 1;
error:
    HostShutdown();
    StorageCleanup();
    return 0;
}
#endif

void RegisterHostStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HostStorageTest01", HostStorageTest01);
    UtRegisterTest("HostStorageTest02", HostStorageTest02);
    UtRegisterTest("HostStorageTest03", HostStorageTest03);
#endif
}
