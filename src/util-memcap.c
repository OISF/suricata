/* Copyright (C) 2018 Open Information Security Foundation
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
 * \param name          name that will be shown through unix socket (eg. "stream")
 * \param option        yaml option name (eg. "stream.memcap")
 * \param GetFunc       pointer to a function that return a memcap value (eg. StreamTcpGetMemcap)
 * \param GetmemuseFunc pointer to a function that return a memuse value (eg. StreamTcpMemuseCounter)
 *
 * \return              1 if success, 0 otherwise
 */
int MemcapListRegisterMemcap(const char *name,
                             const char *option,
                             int (*SetFunc)(uint64_t),
                             uint64_t (*GetFunc)(void),
                             uint64_t (*GetMemuseFunc)(void))
{
    MemcapList *new_memcap = SCMalloc(sizeof(MemcapList));
    if (new_memcap == NULL) {
        return 0;
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

    return 1;
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
    int i;

    for (i = 0; node != NULL; i++) {
        if (i == index) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

void GlobalMemcapInitConfig(void)
{
    const char *conf_val = NULL;
    SC_ATOMIC_INIT(global_memcap);

    MemcapListRegisterMemcap("global", "global-memcap",
                             GlobalMemcapSetValue, GlobalMemcapGetValue,
                             NULL);

    if ((ConfGet("global-memcap", &conf_val)) == 1)
    {
        if (conf_val == NULL) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid value for "
                       "global-memcap: NULL");
            exit(EXIT_FAILURE);
        }
        uint64_t global_memcap_copy;
        if (ParseSizeStringU64(conf_val, &global_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing global-memcap "
                       "from conf file - %s. Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(global_memcap, global_memcap_copy);
            g_use_global_memcap = TRUE;
            SCLogConfig("global memcap is set: %"PRIu64"", SC_ATOMIC_GET(global_memcap));
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

void GlobalMemcapReached(uint64_t value, const char *name, bool allow_unlimited)
{
    if (g_use_global_memcap == FALSE) {
        return;
    }

    if (g_memcaps_sum + value > SC_ATOMIC_GET(global_memcap)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Global memcap value needs to be "
                   "increased to fit \'%s\' value", name);
        exit(EXIT_FAILURE);
    } else if (allow_unlimited && value == 0) {
        SCLogWarning(SC_WARN_MEMCAP_UNLIMITED,
                     "%s is set to unlimited, global memcap won't be honored",
                     name);
        return;
    }

    g_memcaps_sum += value;
}
