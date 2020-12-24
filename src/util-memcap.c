/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * \brief Utility functions to handle memcaps over unix socket
 */

#include "suricata-common.h"
#include "suricata.h"

#include "conf.h"
#include "util-mem.h"
#include "util-misc.h"

#include "util-memcap.h"

SC_ATOMIC_DECLARE(uint64_t, global_memcap);

static bool g_use_global_memcap = FALSE;
static uint64_t g_memcaps_sum = 0;

static MemcapList *memcaps = NULL;

/**
 * \brief Register a memcap to the memcaps list
 *
 * \param name          name that will be shown through unix socket
 * \param option        yaml option name
 * \param GetFunc       pointer to a function that return a memcap value
 * \param GetmemuseFunc pointer to a function that return a memuse value
 *
 */
void MemcapListRegisterMemcap(const char *name, const char *option, int (*SetFunc)(uint64_t),
        uint64_t (*GetFunc)(void), uint64_t (*GetMemuseFunc)(void))
{
    MemcapList *new_memcap = SCMalloc(sizeof(MemcapList));
    if (new_memcap == NULL) {
        FatalError(SC_ERR_FATAL, "Failed to register \'%s\'", option);
    }
    new_memcap->name = name;
    new_memcap->option = option;
    new_memcap->SetFunc = SetFunc;
    new_memcap->GetFunc = GetFunc;
    new_memcap->GetMemuseFunc = GetMemuseFunc;
    new_memcap->next = NULL;

    if (memcaps == NULL) {
        memcaps = new_memcap;
    } else {
        new_memcap->next = memcaps;
        memcaps = new_memcap;
    }
}

void MemcapListFreeList(void)
{
    MemcapList *instance = memcaps;

    while (instance) {
        MemcapList *next = instance->next;
        SCFree(instance);
        instance = next;
    }
}

MemcapList *MemcapListGetElement(int index)
{
    MemcapList *node = memcaps;

    for (int i = 0; node != NULL; i++) {
        if (i == index) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

void DisplayMemcaps(void)
{
    int i;
    MemcapList *memcap = NULL;

    for (i = 0; (memcap = MemcapListGetElement(i)); i++) {
        if (memcap->option) {
            const char *memcapval;
            if (ConfGetValue(memcap->option, &memcapval) == 1) {
                printf("%s = %s\n", memcap->option, memcapval);
            }
        }
    }
}

void GlobalMemcapInitConfig(void)
{
    const char *conf_val = NULL;
    SC_ATOMIC_INIT(global_memcap);

    MemcapListRegisterMemcap(
            "global", "global-memcap", GlobalMemcapSetValue, GlobalMemcapGetValue, NULL);

    if ((ConfGet("global-memcap", &conf_val)) == 1) {
        if (conf_val == NULL) {
            FatalError(SC_ERR_FATAL, "Invalid value for global-memcap: NULL");
        }
        uint64_t global_memcap_copy;
        if (ParseSizeStringU64(conf_val, &global_memcap_copy) < 0) {
            FatalError(SC_ERR_FATAL,
                    "Error parsing global-memcap "
                    "from conf file - %s. Killing engine",
                    conf_val);
        } else {
            SC_ATOMIC_SET(global_memcap, global_memcap_copy);
            g_use_global_memcap = TRUE;
            SCLogConfig("global memcap is set: %" PRIu64, SC_ATOMIC_GET(global_memcap));
        }
    }
}

bool GlobalMemcapEnabled(void)
{
    return g_use_global_memcap;
}

uint64_t GlobalMemcapGetValue(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(global_memcap);
    return memcapcopy;
}

int GlobalMemcapSetValue(uint64_t size)
{
    SC_ATOMIC_SET(global_memcap, size);
    return 1;
}

void GlobalMemcapReached(uint64_t memcap_val, const char *name, bool unlimited)
{
    if (g_use_global_memcap == FALSE) {
        return;
    }

    if (g_memcaps_sum + memcap_val > SC_ATOMIC_GET(global_memcap)) {
        FatalError(SC_ERR_FATAL,
                "Global memcap value needs to be "
                "increased to fit \'%s\' value",
                name);
    } else if (memcap_val == 0 && unlimited) {
        /* Some memcaps (http, ftp, ...) can be unlimited and
         * in this case global memcap is ignored
         */
        SCLogWarning(SC_WARN_MEMCAP_UNLIMITED,
                "%s is set to unlimited, global memcap won't be honored", name);
        return;
    }

    g_memcaps_sum += memcap_val;
}
