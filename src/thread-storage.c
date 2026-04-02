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

unsigned int SCThreadStorageSize(void)
{
    return SCStorageGetSize(storage_type);
}

void *SCThreadGetStorageById(const ThreadVars *tv, SCThreadStorageId id)
{
    return SCStorageGetById(tv->storage, storage_type, id.id);
}

int SCThreadSetStorageById(ThreadVars *tv, SCThreadStorageId id, void *ptr)
{
    return SCStorageSetById(tv->storage, storage_type, id.id, ptr);
}

void SCThreadFreeStorageById(ThreadVars *tv, SCThreadStorageId id)
{
    SCStorageFreeById(tv->storage, storage_type, id.id);
}

void SCThreadFreeStorage(ThreadVars *tv)
{
    if (SCThreadStorageSize() > 0)
        SCStorageFreeAll(tv->storage, storage_type);
}

SCThreadStorageId SCThreadStorageRegister(const char *name, void (*Free)(void *))
{
    int id = SCStorageRegister(storage_type, name, Free);
    SCThreadStorageId tsi = { .id = id };
    return tsi;
}

#ifdef UNITTESTS

static void StorageTestFree(void *x)
{
    SCFree(x);
}

static int ThreadStorageTest01(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCThreadStorageId id1 = SCThreadStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    SCThreadStorageId id2 = SCThreadStorageRegister("variable", StorageTestFree);
    FAIL_IF(id2.id < 0);

    SCThreadStorageId id3 = SCThreadStorageRegister("store", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + SCThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = SCThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    ptr = SCThreadGetStorageById(tv, id2);
    FAIL_IF_NOT_NULL(ptr);

    ptr = SCThreadGetStorageById(tv, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(8);
    FAIL_IF_NULL(ptr1a);
    FAIL_IF(SCThreadSetStorageById(tv, id1, ptr1a) != 0);

    void *ptr2a = SCMalloc(24);
    FAIL_IF_NULL(ptr2a);
    FAIL_IF(SCThreadSetStorageById(tv, id2, ptr2a) != 0);

    void *ptr3a = SCMalloc(16);
    FAIL_IF_NULL(ptr3a);
    FAIL_IF(SCThreadSetStorageById(tv, id3, ptr3a) != 0);

    void *ptr1b = SCThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    void *ptr2b = SCThreadGetStorageById(tv, id2);
    FAIL_IF(ptr2a != ptr2b);

    void *ptr3b = SCThreadGetStorageById(tv, id3);
    FAIL_IF(ptr3a != ptr3b);

    SCThreadFreeStorage(tv);
    SCStorageCleanup();
    SCFree(tv);
    PASS;
}

static int ThreadStorageTest02(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCThreadStorageId id1 = SCThreadStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + SCThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = SCThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);

    SCThreadSetStorageById(tv, id1, ptr1a);

    void *ptr1b = SCThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    SCThreadFreeStorage(tv);
    SCStorageCleanup();
    SCFree(tv);
    PASS;
}

static int ThreadStorageTest03(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCThreadStorageId id1 = SCThreadStorageRegister("test1", StorageTestFree);
    FAIL_IF(id1.id < 0);

    SCThreadStorageId id2 = SCThreadStorageRegister("test2", StorageTestFree);
    FAIL_IF(id2.id < 0);

    SCThreadStorageId id3 = SCThreadStorageRegister("test3", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + SCThreadStorageSize());
    FAIL_IF_NULL(tv);

    void *ptr = SCThreadGetStorageById(tv, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);

    SCThreadSetStorageById(tv, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF_NULL(ptr2a);

    SCThreadSetStorageById(tv, id2, ptr2a);

    void *ptr3a = SCMalloc(32);
    FAIL_IF_NULL(ptr3a);
    SCThreadSetStorageById(tv, id3, ptr3a);

    void *ptr1b = SCThreadGetStorageById(tv, id1);
    FAIL_IF(ptr1a != ptr1b);

    void *ptr2b = SCThreadGetStorageById(tv, id2);
    FAIL_IF(ptr2a != ptr2b);

    void *ptr3b = SCThreadGetStorageById(tv, id3);
    FAIL_IF(ptr3a != ptr3b);

    SCThreadFreeStorage(tv);
    SCStorageCleanup();
    SCFree(tv);
    PASS;
}
#endif

void SCRegisterThreadStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ThreadStorageTest01", ThreadStorageTest01);
    UtRegisterTest("ThreadStorageTest02", ThreadStorageTest02);
    UtRegisterTest("ThreadStorageTest03", ThreadStorageTest03);
#endif
}
