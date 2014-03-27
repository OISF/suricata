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

unsigned int HostStorageSize(void)
{
    return StorageGetSize(STORAGE_HOST);
}

void *HostGetStorageById(Host *h, int id)
{
    return StorageGetById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id);
}

int HostSetStorageById(Host *h, int id, void *ptr)
{
    return StorageSetById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id, ptr);
}

void *HostAllocStorageById(Host *h, int id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id);
}

void HostFreeStorageById(Host *h, int id)
{
    StorageFreeById((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST, id);
}

void HostFreeStorage(Host *h)
{
    if (HostStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)h + sizeof(Host)), STORAGE_HOST);
}

int HostStorageRegister(const char *name, const unsigned int size, void *(*Alloc)(unsigned int), void (*Free)(void *)) {
    return StorageRegister(STORAGE_HOST, name, size, Alloc, Free);
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

    int id1 = HostStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = HostStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = HostStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
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

    int id1 = HostStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
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

    int id1 = HostStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = HostStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = HostStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
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
    UtRegisterTest("HostStorageTest01", HostStorageTest01, 1);
    UtRegisterTest("HostStorageTest02", HostStorageTest02, 1);
    UtRegisterTest("HostStorageTest03", HostStorageTest03, 1);
#endif
}
