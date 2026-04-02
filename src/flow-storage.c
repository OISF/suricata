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
#include "util-storage.h"
#include "util-unittest.h"

unsigned int SCFlowStorageSize(void)
{
    return SCStorageGetSize(STORAGE_FLOW);
}

void *SCFlowGetStorageById(const Flow *f, SCFlowStorageId id)
{
    return SCStorageGetById(f->storage, STORAGE_FLOW, id.id);
}

int SCFlowSetStorageById(Flow *f, SCFlowStorageId id, void *ptr)
{
    return SCStorageSetById(f->storage, STORAGE_FLOW, id.id, ptr);
}

void SCFlowFreeStorageById(Flow *f, SCFlowStorageId id)
{
    SCStorageFreeById(f->storage, STORAGE_FLOW, id.id);
}

void SCFlowFreeStorage(Flow *f)
{
    if (SCFlowStorageSize() > 0)
        SCStorageFreeAll(f->storage, STORAGE_FLOW);
}

SCFlowStorageId SCFlowStorageRegister(const char *name, void (*Free)(void *))
{
    int id = SCStorageRegister(STORAGE_FLOW, name, Free);
    SCFlowStorageId fsi = { .id = id };
    return fsi;
}

#ifdef UNITTESTS

static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int FlowStorageTest01(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCFlowStorageId id1 = SCFlowStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCFlowStorageId id2 = SCFlowStorageRegister("variable", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCFlowStorageId id3 = SCFlowStorageRegister("store", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    FlowInitConfig(FLOW_QUIET);

    Flow *f = FlowAlloc();
    FAIL_IF_NULL(f);

    void *ptr = SCFlowGetStorageById(f, id1);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCFlowGetStorageById(f, id2);
    FAIL_IF_NOT_NULL(ptr);
    ptr = SCFlowGetStorageById(f, id3);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(8);
    FAIL_IF_NULL(ptr1a);
    FAIL_IF(SCFlowSetStorageById(f, id1, ptr1a) != 0);
    void *ptr2a = SCMalloc(24);
    FAIL_IF_NULL(ptr2a);
    FAIL_IF(SCFlowSetStorageById(f, id2, ptr2a) != 0);
    void *ptr3a = SCMalloc(16);
    FAIL_IF_NULL(ptr3a);
    FAIL_IF(SCFlowSetStorageById(f, id3, ptr3a) != 0);

    void *ptr1b = SCFlowGetStorageById(f, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCFlowGetStorageById(f, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCFlowGetStorageById(f, id3);
    FAIL_IF(ptr3a != ptr3b);

    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    SCStorageCleanup();
    PASS;
}

static int FlowStorageTest02(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCFlowStorageId id1 = SCFlowStorageRegister("test", StorageTestFree);
    FAIL_IF(id1.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    FlowInitConfig(FLOW_QUIET);
    Flow *f = FlowAlloc();
    FAIL_IF_NULL(f);

    void *ptr = SCFlowGetStorageById(f, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    SCFlowSetStorageById(f, id1, ptr1a);

    void *ptr1b = SCFlowGetStorageById(f, id1);
    FAIL_IF(ptr1a != ptr1b);

    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    SCStorageCleanup();
    PASS;
}

static int FlowStorageTest03(void)
{
    SCStorageCleanup();
    SCStorageInit();

    SCFlowStorageId id1 = SCFlowStorageRegister("test1", StorageTestFree);
    FAIL_IF(id1.id < 0);
    SCFlowStorageId id2 = SCFlowStorageRegister("test2", StorageTestFree);
    FAIL_IF(id2.id < 0);
    SCFlowStorageId id3 = SCFlowStorageRegister("test3", StorageTestFree);
    FAIL_IF(id3.id < 0);

    FAIL_IF(SCStorageFinalize() < 0);

    FlowInitConfig(FLOW_QUIET);
    Flow *f = FlowAlloc();
    FAIL_IF_NULL(f);

    void *ptr = SCFlowGetStorageById(f, id1);
    FAIL_IF_NOT_NULL(ptr);

    void *ptr1a = SCMalloc(128);
    FAIL_IF_NULL(ptr1a);
    SCFlowSetStorageById(f, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    FAIL_IF_NULL(ptr2a);
    SCFlowSetStorageById(f, id2, ptr2a);

    void *ptr3a = SCMalloc(32);
    FAIL_IF_NULL(ptr3a);
    SCFlowSetStorageById(f, id3, ptr3a);

    void *ptr1b = SCFlowGetStorageById(f, id1);
    FAIL_IF(ptr1a != ptr1b);
    void *ptr2b = SCFlowGetStorageById(f, id2);
    FAIL_IF(ptr2a != ptr2b);
    void *ptr3b = SCFlowGetStorageById(f, id3);
    FAIL_IF(ptr3a != ptr3b);

    FlowClearMemory(f, 0);
    FlowFree(f);
    FlowShutdown();
    SCStorageCleanup();
    PASS;
}
#endif

void SCRegisterFlowStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowStorageTest01", FlowStorageTest01);
    UtRegisterTest("FlowStorageTest02", FlowStorageTest02);
    UtRegisterTest("FlowStorageTest03", FlowStorageTest03);
#endif
}
