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
 * IPPair wrapper around storage api
 */

#include "suricata-common.h"
#include "ippair-storage.h"
#include "util-unittest.h"

unsigned int IPPairStorageSize(void)
{
    return StorageGetSize(STORAGE_IPPAIR);
}

void *IPPairGetStorageById(IPPair *h, IPPairStorageId id)
{
    return StorageGetById(h->storage, STORAGE_IPPAIR, id.id);
}

int IPPairSetStorageById(IPPair *h, IPPairStorageId id, void *ptr)
{
    return StorageSetById(h->storage, STORAGE_IPPAIR, id.id, ptr);
}

void *IPPairAllocStorageById(IPPair *h, IPPairStorageId id)
{
    return StorageAllocByIdPrealloc(h->storage, STORAGE_IPPAIR, id.id);
}

void IPPairFreeStorage(IPPair *h)
{
    if (IPPairStorageSize() > 0)
        StorageFreeAll(h->storage, STORAGE_IPPAIR);
}

IPPairStorageId IPPairStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_IPPAIR, name, size, Alloc, Free);
    IPPairStorageId ippsi = { .id = id };
    return ippsi;
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
    StorageCleanup();
    StorageInit();

    IPPairStorageId id1 = IPPairStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id1.id < 0);
    IPPairStorageId id2 = IPPairStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id2.id < 0);
    IPPairStorageId id3 =
            IPPairStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    FAIL_IF_NULL(h);

    void *ptr = IPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);
    ptr = IPPairGetStorageById(h, id2);
    FAIL_IF_NOT_NULL(ptr);
    ptr = IPPairGetStorageById(h, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = IPPairAllocStorageById(h, id1);
    FAIL_IF(ptr1a == NULL);
    void *ptr2a = IPPairAllocStorageById(h, id2);
    FAIL_IF(ptr2a == NULL);
    void *ptr3a = IPPairAllocStorageById(h, id3);
    FAIL_IF(ptr3a == NULL);

    void *ptr1b = IPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = IPPairGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = IPPairGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    IPPairRelease(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairStorageTest02(void)
{
    StorageCleanup();
    StorageInit();

    IPPairStorageId id1 = IPPairStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    FAIL_IF(h == NULL);

    void *ptr = IPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF(ptr1a == NULL);

    IPPairSetStorageById(h, id1, ptr1a);

    void *ptr1b = IPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);

    IPPairRelease(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairStorageTest03(void)
{
    StorageCleanup();
    StorageInit();

    IPPairStorageId id1 = IPPairStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id1.id < 0);
    IPPairStorageId id2 = IPPairStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id2.id < 0);
    IPPairStorageId id3 = IPPairStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    IPPairInitConfig(1);

    Address a, b;
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0x00, sizeof(b));
    a.addr_data32[0] = 0x01020304;
    b.addr_data32[0] = 0x04030201;
    a.family = AF_INET;
    b.family = AF_INET;
    IPPair *h = IPPairGetIPPairFromHash(&a, &b);
    FAIL_IF(h == NULL);

    void *ptr = IPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF(ptr1a == NULL);

    IPPairSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF(ptr2a == NULL);

    IPPairSetStorageById(h, id2, ptr2a);

    void *ptr3a = IPPairAllocStorageById(h, id3);
    FAIL_IF(ptr3a == NULL);

    void *ptr1b = IPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = IPPairGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = IPPairGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    IPPairRelease(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}
#endif

void RegisterIPPairStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairStorageTest01", IPPairStorageTest01);
    UtRegisterTest("IPPairStorageTest02", IPPairStorageTest02);
    UtRegisterTest("IPPairStorageTest03", IPPairStorageTest03);
#endif
}