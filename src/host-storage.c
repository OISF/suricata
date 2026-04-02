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

unsigned int SCHostStorageSize(void)
{
    return SCStorageGetSize(STORAGE_HOST);
}

/** \defgroup hoststorage Host storage API
 *
 * The Host storage API is a per-host storage. It is a mean to extend
 * the Host structure with arbitrary data.
 *
 * You have first to register the storage via SCHostStorageRegister() during
 * the init of your module. Then you can attach data via SCHostSetStorageById()
 * and access them via SCHostGetStorageById().
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

SCHostStorageId SCHostStorageRegister(const char *name, void (*Free)(void *))
{
    int id = SCStorageRegister(STORAGE_HOST, name, Free);
    SCHostStorageId hsi = { .id = id };
    return hsi;
}

/**
 * \brief Store a pointer in a given Host storage
 *
 * \param h a pointer to the Host
 * \param id the id of the storage (return of SCHostStorageRegister() call)
 * \param ptr pointer to the data to store
 */

int SCHostSetStorageById(Host *h, SCHostStorageId id, void *ptr)
{
    return SCStorageSetById(h->storage, STORAGE_HOST, id.id, ptr);
}

/**
 * \brief Get a value from a given Host storage
 *
 * \param h a pointer to the Host
 * \param id the id of the storage (return of SCHostStorageRegister() call)
 *
 */

void *SCHostGetStorageById(Host *h, SCHostStorageId id)
{
    return SCStorageGetById(h->storage, STORAGE_HOST, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void SCHostFreeStorage(Host *h)
{
    if (SCHostStorageSize() > 0)
        SCStorageFreeAll(h->storage, STORAGE_HOST);
}


#ifdef UNITTESTS

static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int HostStorageTest01(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCHostStorageId id1 = SCHostStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCHostStorageId id2 = SCHostStorageRegister("variable", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCHostStorageId id3 = SCHostStorageRegister("store", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = SCHostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCHostGetStorageById(h, id2);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCHostGetStorageById(h, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(8);
    FAIL_IF_NULL(ptr1a);
    FAIL_IF(SCHostSetStorageById(h, id1, ptr1a) != 0);
    void *ptr2a = SCMalloc(24);
    FAIL_IF_NULL(ptr2a);
    FAIL_IF(SCHostSetStorageById(h, id2, ptr2a) != 0);
    void *ptr3a = SCMalloc(16);
    FAIL_IF_NULL(ptr3a);
    FAIL_IF(SCHostSetStorageById(h, id3, ptr3a) != 0);

    void *ptr1b = SCHostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCHostGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCHostGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    HostRelease(h);

    HostShutdown();
    SCStorageCleanup();
    PASS;
}

static int HostStorageTest02(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCHostStorageId id1 = SCHostStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = SCHostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    SCHostSetStorageById(h, id1, ptr1a);

    void *ptr1b = SCHostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);

    HostRelease(h);

    HostShutdown();
    SCStorageCleanup();
    PASS;
}

static int HostStorageTest03(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCHostStorageId id1 = SCHostStorageRegister("test1", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCHostStorageId id2 = SCHostStorageRegister("test2", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCHostStorageId id3 = SCHostStorageRegister("test3", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    HostInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Host *h = HostGetHostFromHash(&a);
    FAIL_IF_NULL(h);

    void *ptr = SCHostGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    SCHostSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF_NULL(ptr2a);
    SCHostSetStorageById(h, id2, ptr2a);

    void *ptr3a = SCMalloc(32);
    FAIL_IF_NULL(ptr3a);
    SCHostSetStorageById(h, id3, ptr3a);

    void *ptr1b = SCHostGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCHostGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCHostGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    HostRelease(h);

    HostShutdown();
    SCStorageCleanup();
    PASS;
}
#endif

void SCRegisterHostStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HostStorageTest01", HostStorageTest01);
    UtRegisterTest("HostStorageTest02", HostStorageTest02);
    UtRegisterTest("HostStorageTest03", HostStorageTest03);
#endif
}
