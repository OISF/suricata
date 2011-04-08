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


FlowFileContainer *FlowFileContainerAlloc() {
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

void FlowFileContainerRecycle(FlowFileContainer *ffc) {
    FlowFile *ptr = ffc->start;
    FlowFile *next = NULL;
    for (;ptr != NULL && ffc->cnt > 0; ptr = next) {
        next = ptr->next;
        FlowFileFree(ptr);
        ffc->cnt--;
    }
    ffc->start = ffc->end = NULL;
    ffc->cnt = 0;
}

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

FlowFileChunk *FlowFileChunkAlloc() {
    FlowFileChunk *new = SCMalloc(sizeof(FlowFileChunk));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(new));
    return new;
}

void FlowFileChunkFree(FlowFileChunk *ffc) {
    //TODO: To implement
    SCFree(ffc);
}

FlowFile *FlowFileAlloc() {
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
    if (ff->name != NULL)
        SCFree(ff->name);
    if (ff->ext != NULL)
        SCFree(ff->ext);
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

FlowFile *FlowFileContainerRetrieve(FlowFileContainer *ffc, uint8_t *name, uint16_t alproto, uint8_t *proto_type) {
    FlowFile *ptr = ffc->start;
    if (ffc->cnt > 0) {
        while (ptr != NULL) {
            if ( (strcmp((char *)ptr->name, (char *)name) == 0) && ptr->alproto == alproto && (!proto_type || strcmp((char *)ptr->proto_type, (char *)proto_type) == 0)) {
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
