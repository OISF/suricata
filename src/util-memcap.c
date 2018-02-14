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
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 * \brief Utility functions to handle memcaps over unix socket
 */

#include "suricata-common.h"
#include "suricata.h"

#include "conf.h"
#include "util-mem.h"
#include "util-misc.h"

#include "util-memcap.h"

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
