/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * based on host-storage by Victor Julien <victor@inliniac.net>
 *
 * Flow wrapper around storage api
 */

#include "suricata-common.h"
#include "flow-storage.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "util-unittest.h"

unsigned int FlowStorageSize(void)
{
    return StorageGetSize(STORAGE_FLOW);
}

void *FlowGetStorageById(Flow *f, int id)
{
    return StorageGetById((Storage *)((void *)f + sizeof(Flow)), STORAGE_FLOW, id);
}

int FlowSetStorageById(Flow *f, int id, void *ptr)
{
    return StorageSetById((Storage *)((void *)f + sizeof(Flow)), STORAGE_FLOW, id, ptr);
}

void *FlowAllocStorageById(Flow *f, int id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)f + sizeof(Flow)), STORAGE_FLOW, id);
}

void FlowFreeStorageById(Flow *f, int id)
{
    StorageFreeById((Storage *)((void *)f + sizeof(Flow)), STORAGE_FLOW, id);
}

void FlowFreeStorage(Flow *f)
{
    if (FlowStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)f + sizeof(Flow)), STORAGE_FLOW);
}

int FlowStorageRegister(const char *name, const unsigned int size, void *(*Alloc)(unsigned int), void (*Free)(void *)) {
    return StorageRegister(STORAGE_FLOW, name, size, Alloc, Free);
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

static int FlowStorageTest01(void)
{
    Flow *f = NULL;

    StorageInit();

    int id1 = FlowStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = FlowStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = FlowStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    FlowInitConfig(FLOW_QUIET);

    f = FlowAlloc();
    if (f == NULL) {
        goto error;
    }

    void *ptr = FlowGetStorageById(f, id1);
    if (ptr != NULL) {
        goto error;
    }
    ptr = FlowGetStorageById(f, id2);
    if (ptr != NULL) {
        goto error;
    }
    ptr = FlowGetStorageById(f, id3);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = FlowAllocStorageById(f, id1);
    if (ptr1a == NULL) {
        goto error;
    }
    void *ptr2a = FlowAllocStorageById(f, id2);
    if (ptr2a == NULL) {
        goto error;
    }
    void *ptr3a = FlowAllocStorageById(f, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = FlowGetStorageById(f, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = FlowGetStorageById(f, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = FlowGetStorageById(f, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    StorageCleanup();
    return 1;
error:
    if (f != NULL) {
        FlowClearMemory(f, 0);
        FlowFree(f);
    }
    FlowShutdown();
    StorageCleanup();
    return 0;
}

static int FlowStorageTest02(void)
{
    Flow *f = NULL;

    StorageInit();

    int id1 = FlowStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    FlowInitConfig(FLOW_QUIET);
    f = FlowAlloc();
    if (f == NULL) {
        goto error;
    }

    void *ptr = FlowGetStorageById(f, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    FlowSetStorageById(f, id1, ptr1a);

    void *ptr1b = FlowGetStorageById(f, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }


    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    StorageCleanup();
    return 1;
error:
    if (f != NULL) {
        FlowClearMemory(f, 0);
        FlowFree(f);
    }
    FlowShutdown();
    StorageCleanup();
    return 0;
}

static int FlowStorageTest03(void)
{
    Flow *f = NULL;

    StorageInit();

    int id1 = FlowStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1 < 0)
        goto error;
    int id2 = FlowStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2 < 0)
        goto error;
    int id3 = FlowStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3 < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    FlowInitConfig(FLOW_QUIET);
    f = FlowAlloc();
    if (f == NULL) {
        goto error;
    }

    void *ptr = FlowGetStorageById(f, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    FlowSetStorageById(f, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    if (unlikely(ptr2a == NULL)) {
        goto error;
    }
    FlowSetStorageById(f, id2, ptr2a);

    void *ptr3a = FlowAllocStorageById(f, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = FlowGetStorageById(f, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = FlowGetStorageById(f, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = FlowGetStorageById(f, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    StorageCleanup();
    return 1;
error:
    if (f != NULL) {
        FlowClearMemory(f, 0);
        FlowFree(f);
    }
    FlowShutdown();
    StorageCleanup();
    return 0;
}
#endif

void RegisterFlowStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowStorageTest01", FlowStorageTest01);
    UtRegisterTest("FlowStorageTest02", FlowStorageTest02);
    UtRegisterTest("FlowStorageTest03", FlowStorageTest03);
#endif
}
