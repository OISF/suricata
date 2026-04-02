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

unsigned int SCIPPairStorageSize(void)
{
    return SCStorageGetSize(STORAGE_IPPAIR);
}

void *SCIPPairGetStorageById(IPPair *h, SCIPPairStorageId id)
{
    return SCStorageGetById(h->storage, STORAGE_IPPAIR, id.id);
}

int SCIPPairSetStorageById(IPPair *h, SCIPPairStorageId id, void *ptr)
{
    return SCStorageSetById(h->storage, STORAGE_IPPAIR, id.id, ptr);
}

void SCIPPairFreeStorage(IPPair *h)
{
    if (SCIPPairStorageSize() > 0)
        SCStorageFreeAll(h->storage, STORAGE_IPPAIR);
}

SCIPPairStorageId SCIPPairStorageRegister(const char *name, void (*Free)(void *))
{
    int id = SCStorageRegister(STORAGE_IPPAIR, name, Free);
    SCIPPairStorageId ippsi = { .id = id };
    return ippsi;
}

#ifdef UNITTESTS

static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int IPPairStorageTest01(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCIPPairStorageId id1 = SCIPPairStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCIPPairStorageId id2 = SCIPPairStorageRegister("variable", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCIPPairStorageId id3 = SCIPPairStorageRegister("store", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

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

    void *ptr = SCIPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCIPPairGetStorageById(h, id2);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCIPPairGetStorageById(h, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(8);
    FAIL_IF(ptr1a == NULL);
    FAIL_IF(SCIPPairSetStorageById(h, id1, ptr1a) != 0);
    void *ptr2a = SCMalloc(24);
    FAIL_IF(ptr2a == NULL);
    FAIL_IF(SCIPPairSetStorageById(h, id2, ptr2a) != 0);
    void *ptr3a = SCMalloc(16);
    FAIL_IF(ptr3a == NULL);
    FAIL_IF(SCIPPairSetStorageById(h, id3, ptr3a) != 0);

    void *ptr1b = SCIPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCIPPairGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCIPPairGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    IPPairRelease(h);
    IPPairShutdown();
    SCStorageCleanup();
    PASS;
}

static int IPPairStorageTest02(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCIPPairStorageId id1 = SCIPPairStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

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

    void *ptr = SCIPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF(ptr1a == NULL);

    SCIPPairSetStorageById(h, id1, ptr1a);

    void *ptr1b = SCIPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);

    IPPairRelease(h);
    IPPairShutdown();
    SCStorageCleanup();
    PASS;
}

static int IPPairStorageTest03(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCIPPairStorageId id1 = SCIPPairStorageRegister("test1", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCIPPairStorageId id2 = SCIPPairStorageRegister("test2", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCIPPairStorageId id3 = SCIPPairStorageRegister("test3", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

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

    void *ptr = SCIPPairGetStorageById(h, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF(ptr1a == NULL);

    SCIPPairSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF(ptr2a == NULL);

    SCIPPairSetStorageById(h, id2, ptr2a);

    void *ptr3a = SCMalloc(32);
    FAIL_IF(ptr3a == NULL);
    SCIPPairSetStorageById(h, id3, ptr3a);

    void *ptr1b = SCIPPairGetStorageById(h, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCIPPairGetStorageById(h, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCIPPairGetStorageById(h, id3);
    FAIL_IF(ptr3a != ptr3b);

    IPPairRelease(h);
    IPPairShutdown();
    SCStorageCleanup();
    PASS;
}
#endif

void SCRegisterIPPairStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairStorageTest01", IPPairStorageTest01);
    UtRegisterTest("IPPairStorageTest02", IPPairStorageTest02);
    UtRegisterTest("IPPairStorageTest03", IPPairStorageTest03);
#endif
}
