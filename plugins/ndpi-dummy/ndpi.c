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

#include "flow-callbacks.h"
#include "flow-storage.h"

static FlowStorageId flow_storage_id = { .id = -1 };

static void *FlowStorageAlloc(unsigned int size)
{
    SCLogNotice("Allocating nDPI flow storage, size=%d", size);
    return NULL;
}

static void FlowStorageFree(void *ptr)
{
    SCLogNotice("De-allocating nDPI flow storage");
    int *dummy_storage = ptr;
    SCLogNotice("%d", *dummy_storage);
    SCFree(ptr);
}

static void OnFlowInit(Flow *f, const Packet *p)
{
    SCLogNotice("...");
    static int counter = 0;
    int *dummy_storage = SCCalloc(1, sizeof(int));
    *dummy_storage = counter++;
    FlowSetStorageById(f, flow_storage_id, dummy_storage);
}

static void OnFlowUpdate(Flow *f, Packet *p, ThreadVars *tv)
{
    SCLogNotice("...");
    int *dummy_storage = FlowGetStorageById(f, flow_storage_id);
    SCLogNotice("dummy_storage=%d", *dummy_storage);
}

static void NdpiInit(void)
{
    SCLogNotice("Initializing nDPI plugin");

    flow_storage_id = FlowStorageRegister("ndpi", sizeof(void *), NULL, FlowStorageFree);
    if (flow_storage_id.id < 0) {
        FatalError("Failed to register nDPI flow storage");
    }

    SCFlowRegisterInitCallback(OnFlowInit);
    SCFlowRegisterUpdateCallback(OnFlowUpdate);
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
