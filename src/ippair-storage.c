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
 * IPPair wrapper around storage api
 */

#include "suricata-common.h"
#include "ippair-storage.h"
#include "util-unittest.h"

unsigned int IPPairStorageSize(void)
{
    return StorageGetSize(STORAGE_IPPAIR);
}

void *IPPairGetStorageById(IPPair *h, int id)
{
    return StorageGetById((Storage *)((void *)h + sizeof(IPPair)), STORAGE_IPPAIR, id);
}

int IPPairSetStorageById(IPPair *h, int id, void *ptr)
{
    return StorageSetById((Storage *)((void *)h + sizeof(IPPair)), STORAGE_IPPAIR, id, ptr);
}

void *IPPairAllocStorageById(IPPair *h, int id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)h + sizeof(IPPair)), STORAGE_IPPAIR, id);
}

void IPPairFreeStorageById(IPPair *h, int id)
{
    StorageFreeById((Storage *)((void *)h + sizeof(IPPair)), STORAGE_IPPAIR, id);
}

void IPPairFreeStorage(IPPair *h)
{
    if (IPPairStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)h + sizeof(IPPair)), STORAGE_IPPAIR);
}

int IPPairStorageRegister(const char *name, const unsigned int size, void *(*Alloc)(unsigned int), void (*Free)(void *)) {
    return StorageRegister(STORAGE_IPPAIR, name, size, Alloc, Free);
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

static int IPPairStorageTest01(void)
{
    StorageInit();

    int id1 = IPPairStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = IPPairStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = IPPairStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    if (h == NULL) {
        printf("failed to get ippair: ");
        goto error;
    }

    void *ptr = IPPairGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }
    ptr = IPPairGetStorageById(h, id2);
    if (ptr != NULL) {
        goto error;
    }
    ptr = IPPairGetStorageById(h, id3);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = IPPairAllocStorageById(h, id1);
    if (ptr1a == NULL) {
        goto error;
    }
    void *ptr2a = IPPairAllocStorageById(h, id2);
    if (ptr2a == NULL) {
        goto error;
    }
    void *ptr3a = IPPairAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = IPPairGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = IPPairGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = IPPairGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    IPPairRelease(h);

    IPPairShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairShutdown();
    StorageCleanup();
    return 0;
}

static int IPPairStorageTest02(void)
{
    StorageInit();

    int id1 = IPPairStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    if (h == NULL) {
        printf("failed to get ippair: ");
        goto error;
    }

    void *ptr = IPPairGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    IPPairSetStorageById(h, id1, ptr1a);

    void *ptr1b = IPPairGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }

    IPPairRelease(h);

    IPPairShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairShutdown();
    StorageCleanup();
    return 0;
}

static int IPPairStorageTest03(void)
{
    StorageInit();

    int id1 = IPPairStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = IPPairStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = IPPairStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    if (h == NULL) {
        printf("failed to get ippair: ");
        goto error;
    }

    void *ptr = IPPairGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    IPPairSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    if (unlikely(ptr2a == NULL)) {
        goto error;
    }
    IPPairSetStorageById(h, id2, ptr2a);

    void *ptr3a = IPPairAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = IPPairGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = IPPairGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = IPPairGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    IPPairRelease(h);

    IPPairShutdown();
    StorageCleanup();
    return 1;
error:
    IPPairShutdown();
    StorageCleanup();
    return 0;
}
#endif

void RegisterIPPairStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairStorageTest01", IPPairStorageTest01, 1);
    UtRegisterTest("IPPairStorageTest02", IPPairStorageTest02, 1);
    UtRegisterTest("IPPairStorageTest03", IPPairStorageTest03, 1);
#endif
}
