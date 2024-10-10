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

/* License note: While this "glue" code to the nDPI library is GPLv2,
 * nDPI is itself LGPLv3 which is known to be incompatible with the
 * GPLv2. */

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "util-debug.h"

#include "thread-callbacks.h"
#include "thread-storage.h"

#include "flow-callbacks.h"
#include "flow-storage.h"

static ThreadStorageId thread_storage_id = { .id = -1 };
static FlowStorageId flow_storage_id = { .id = -1 };

static void ThreadStorageFree(void *ptr)
{
    SCLogNotice("Free'ing nDPI thread storage");
    SCFree(ptr);
}

static void FlowStorageFree(void *ptr)
{
    SCLogNotice("De-allocating nDPI flow storage");
    int *dummy_storage = ptr;
    SCLogNotice("%d", *dummy_storage);
    SCFree(ptr);
}

static void OnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *_data)
{
    SCLogNotice("...");
    static int counter = 0;
    int *dummy_storage = SCCalloc(1, sizeof(int));
    *dummy_storage = counter++;
    FlowSetStorageById(f, flow_storage_id, dummy_storage);
}

static void OnFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *_data)
{
    SCLogNotice("...");
    int *dummy_storage = FlowGetStorageById(f, flow_storage_id);
    int *thread_storage = ThreadGetStorageById(tv, thread_storage_id);
    SCLogNotice("dummy_storage=%d, thread_storage=%d", *dummy_storage, *thread_storage);
}

static void OnFlowFinish(ThreadVars *tv, Flow *f, void *_data)
{
    SCLogNotice("Flow %p is now finished", f);
}

static void OnThreadInit(ThreadVars *tv, void *_data)
{
    static int count = 0;
    SCLogNotice("Thread initialized");
    int *thread_storage = SCCalloc(1, sizeof(int));
    *thread_storage = count++;
    ThreadSetStorageById(tv, thread_storage_id, thread_storage);
}

static void NdpiInit(void)
{
    SCLogNotice("Initializing nDPI plugin");

    /* Register thread storage. */
    thread_storage_id = ThreadStorageRegister("ndpi", sizeof(void *), NULL, ThreadStorageFree);
    if (thread_storage_id.id < 0) {
        FatalError("Failed to register nDPI thread storage");
    }

    /* Register flow storage. */
    flow_storage_id = FlowStorageRegister("ndpi", sizeof(void *), NULL, FlowStorageFree);
    if (flow_storage_id.id < 0) {
        FatalError("Failed to register nDPI flow storage");
    }

    /* Register flow lifecycle callbacks. */
    SCFlowRegisterInitCallback(OnFlowInit, NULL);
    SCFlowRegisterUpdateCallback(OnFlowUpdate, NULL);

    /* Not needed for nDPI, but exists for completeness. */
    SCFlowRegisterFinishCallback(OnFlowFinish, NULL);

    /* Register thread init callback. */
    SCThreadRegisterInitCallback(OnThreadInit, NULL);
}

const SCPlugin PluginRegistration = {
    .name = "ndpi-dummy",
    .author = "FirstName LastName",
    .license = "GPLv2",
    .Init = NdpiInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
