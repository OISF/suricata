/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "flow.h"
#include "flow-file.h"
#include "util-hash.h"
#include "util-debug.h"
#include "util-memcmp.h"

/**
 *  \brief allocate a FlowFileContainer
 *
 *  \retval new newly allocated FlowFileContainer
 *  \retval NULL error
 */
FlowFileContainer *FlowFileContainerAlloc(void) {
    FlowFileContainer *new = SCMalloc(sizeof(FlowFileContainer));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(new));
    new->start = new->end = NULL;
    new->cnt = 0;
    return new;
}

/**
 *  \brief Recycle a FlowFileContainer
 *
 *  \param ffc FlowFileContainer
 */
void FlowFileContainerRecycle(FlowFileContainer *ffc) {
    if (ffc == NULL)
        return;

    FlowFile *cur = ffc->start;
    FlowFile *next = NULL;
    for (;cur != NULL && ffc->cnt > 0; cur = next) {
        next = cur->next;
        FlowFileFree(cur);
        ffc->cnt--;
    }
    ffc->start = ffc->end = NULL;
    ffc->cnt = 0;
}

/**
 *  \brief Free a FlowFileContainer
 *
 *  \param ffc FlowFileContainer
 */
void FlowFileContainerFree(FlowFileContainer *ffc) {
    if (ffc == NULL)
        return;

    FlowFile *ptr = ffc->start;
    FlowFile *next = NULL;
    for (;ptr != NULL && ffc->cnt > 0; ptr = next) {
        next = ptr->next;
        FlowFileFree(ptr);
        ffc->cnt--;
    }
    ffc->start = ffc->end = NULL;
    ffc->cnt = 0;
    SCFree(ffc);
}

FlowFileChunk *FlowFileChunkAlloc(void) {
    FlowFileChunk *new = SCMalloc(sizeof(FlowFileChunk));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(new));

    return new;
}

void FlowFileChunkFree(FlowFileChunk *ffc) {
    if (ffc == NULL)
        return;

    //TODO: To implement
    SCFree(ffc);
}

FlowFile *FlowFileAlloc(void) {
    FlowFile *new = SCMalloc(sizeof(FlowFile));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(new));

    new->state = FLOWFILE_STATE_EMPTY;
    new->name = NULL;
    new->ext = NULL;
    new->next = NULL;
    return new;
}

void FlowFileFree(FlowFile *ff) {
    if (ff == NULL)
        return;

    if (ff->name != NULL)
        SCFree(ff->name);
    SCFree(ff);
}

void FlowFileContainerAdd(FlowFileContainer *ffc, FlowFile *ff) {
    if (ffc->start == NULL) {
        ffc->start = ffc->end = ff;
    } else {
        ffc->end->next = ff;
        ffc->end = ff;
    }
    ffc->cnt += 1;
}

FlowFile *FlowFileContainerRetrieve(FlowFileContainer *ffc, uint16_t alproto,
        uint8_t *name, uint16_t name_len) //, uint8_t *type, uint16_t type_len)
{
    FlowFile *ptr = ffc->start;

    if (ffc->cnt > 0) {
        while (ptr != NULL) {
            if (ptr->alproto == alproto &&
                    name_len == ptr->name_len &&
                    SCMemcmp(ptr->name, name, name_len) == 0)
            {
                return ptr;
            }

            ptr = ptr->next;
        }
    }

    return NULL;
}

FlowFile *FlowFileAppendChunk(FlowFile *ff, FlowFileChunk *ffc) {
    //TODO: To implement
    return NULL;
}
