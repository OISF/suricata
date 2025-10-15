/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata-common.h"
#include "thread-storage.h"
#include "util-storage.h"
#include "util-unittest.h"

const StorageEnum storage_type = STORAGE_THREAD;

unsigned int ThreadStorageSize(void)
{
    return StorageGetSize(storage_type);
}

void *ThreadGetStorageById(const ThreadVars *tv, ThreadStorageId id)
{
    return StorageGetById(tv->storage, storage_type, id.id);
}

int ThreadSetStorageById(ThreadVars *tv, ThreadStorageId id, void *ptr)
{
    return StorageSetById(tv->storage, storage_type, id.id, ptr);
}

void *ThreadAllocStorageById(ThreadVars *tv, ThreadStorageId id)
{
    return StorageAllocByIdPrealloc(tv->storage, storage_type, id.id);
}

void ThreadFreeStorageById(ThreadVars *tv, ThreadStorageId id)
{
    StorageFreeById(tv->storage, storage_type, id.id);
}

void ThreadFreeStorage(ThreadVars *tv)
{
    if (ThreadStorageSize() > 0)
        StorageFreeAll(tv->storage, storage_type);
}

ThreadStorageId ThreadStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(storage_type, name, size, Alloc, Free);
    ThreadStorageId tsi = { .id = id };
    return tsi;
}

#ifdef UNITTESTS

static void *StorageTestAlloc(unsigned int size)
{
    return SCCalloc(1, size);
}

static void StorageTestFree(void *x)
{
    SCFree(x);
}

static int ThreadStorageTest01(void)
{
    StorageCleanup();
    StorageInit();

    ThreadStorageId id1 = ThreadStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id1.id < 0);

    ThreadStorageId id2 = ThreadStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id2.id < 0);

    ThreadStorageId id3 =
            ThreadStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + ThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = ThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    ptr = ThreadGetStorageById(tv, id2);
    FAIL_IF_NOT_NULL(ptr);

    ptr = ThreadGetStorageById(tv, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = ThreadAllocStorageById(tv, id1);
    FAIL_IF_NULL(ptr1a);

    void *ptr2a = ThreadAllocStorageById(tv, id2);
    FAIL_IF_NULL(ptr2a);

    void *ptr3a = ThreadAllocStorageById(tv, id3);
    FAIL_IF_NULL(ptr3a);

    void *ptr1b = ThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    void *ptr2b = ThreadGetStorageById(tv, id2);
    FAIL_IF(ptr2a != ptr2b);

    void *ptr3b = ThreadGetStorageById(tv, id3);
    FAIL_IF(ptr3a != ptr3b);

    ThreadFreeStorage(tv);
    StorageCleanup();
    SCFree(tv);
    PASS;
}

static int ThreadStorageTest02(void)
{
    StorageCleanup();
    StorageInit();

    ThreadStorageId id1 = ThreadStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + ThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = ThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);

    ThreadSetStorageById(tv, id1, ptr1a);

    void *ptr1b = ThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    ThreadFreeStorage(tv);
    StorageCleanup();
    SCFree(tv);
    PASS;
}

static int ThreadStorageTest03(void)
{
    StorageCleanup();
    StorageInit();

    ThreadStorageId id1 = ThreadStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id1.id < 0);

    ThreadStorageId id2 = ThreadStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    FAIL_IF(id2.id < 0);

    ThreadStorageId id3 = ThreadStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(StorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + ThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = ThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);

    ThreadSetStorageById(tv, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF_NULL(ptr2a);

    ThreadSetStorageById(tv, id2, ptr2a);

    void *ptr3a = ThreadAllocStorageById(tv, id3);
    FAIL_IF_NULL(ptr3a);

    void *ptr1b = ThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    void *ptr2b = ThreadGetStorageById(tv, id2);
    FAIL_IF(ptr2a != ptr2b);

    void *ptr3b = ThreadGetStorageById(tv, id3);
    FAIL_IF(ptr3a != ptr3b);

    ThreadFreeStorage(tv);
    StorageCleanup();
    SCFree(tv);
    PASS;
}
#endif

void RegisterThreadStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ThreadStorageTest01", ThreadStorageTest01);
    UtRegisterTest("ThreadStorageTest02", ThreadStorageTest02);
    UtRegisterTest("ThreadStorageTest03", ThreadStorageTest03);
#endif
}
