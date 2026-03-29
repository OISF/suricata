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
#include "util-unittest.h"

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
 * \param Free free function for the new storage
 *
 * \retval The ID of the newly register storage that will be used to access data
 *
 * It has to be called once during the init of the sub system
 */

HostStorageId HostStorageRegister(const char *name, void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_HOST, name, Free);
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
    return StorageSetById(h->storage, STORAGE_HOST, id.id, ptr);
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
    return StorageGetById(h->storage, STORAGE_HOST, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void HostFreeStorage(Host *h)
{
    if (HostStorageSize() > 0)
        StorageFreeAll(h->storage, STORAGE_HOST);
}


#ifdef UNITTESTS

static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int HostStorageTest01(void)
{
    StorageCleanup();
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);
    HostStorageId id2 = HostStorageRegister("variable", StorageTestFree);
    FAIL_IF(id2.id < 0);
    HostStorageId id3 = HostStorageRegister("store", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = HostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);
    ptr = HostGetStorageById(h, id2);
    FAIL_IF_NOT_NULL(ptr);
    ptr = HostGetStorageById(h, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(8);
    FAIL_IF_NULL(ptr1a);
    FAIL_IF(HostSetStorageById(h, id1, ptr1a) != 0);
    void *ptr2a = SCMalloc(24);
    FAIL_IF_NULL(ptr2a);
    FAIL_IF(HostSetStorageById(h, id2, ptr2a) != 0);
    void *ptr3a = SCMalloc(16);
    FAIL_IF_NULL(ptr3a);
    FAIL_IF(HostSetStorageById(h, id3, ptr3a) != 0);

    void *ptr1b = HostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = HostGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = HostGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    PASS;
}

static int HostStorageTest02(void)
{
    StorageCleanup();
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = HostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    HostSetStorageById(h, id1, ptr1a);

    void *ptr1b = HostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    PASS;
}

static int HostStorageTest03(void)
{
    StorageCleanup();
    StorageInit();

    HostStorageId id1 = HostStorageRegister("test1", StorageTestFree);
    FAIL_IF(id1.id < 0);
    HostStorageId id2 = HostStorageRegister("test2", StorageTestFree);
    FAIL_IF(id2.id < 0);
    HostStorageId id3 = HostStorageRegister("test3", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = HostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    HostSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF_NULL(ptr2a);
    HostSetStorageById(h, id2, ptr2a);

    void *ptr3a = SCMalloc(32);
    FAIL_IF_NULL(ptr3a);
    HostSetStorageById(h, id3, ptr3a);

    void *ptr1b = HostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = HostGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = HostGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    HostRelease(h);

    HostShutdown();
    StorageCleanup();
    PASS;
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
