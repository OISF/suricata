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

#ifndef __FLOW_FILE_H__
#define __FLOW_FILE_H__

#include "flow.h"
#include "util-hash.h"


typedef enum _FlowFileState {
    FLOWFILE_STATE_EMPTY,
    FLOWFILE_STATE_DATA,
    FLOWFILE_STATE_COMPLETED,
    FLOWFILE_STATE_STORING,
    FLOWFILE_STATE_MAX
} FlowFileState;

typedef uint8_t FlowFileHash;

typedef struct _FlowFileChunk {
    uint8_t                 *buf;
    uint32_t                *len;
    struct _FlowFileChunk   *next;
} FlowFileChunk;

typedef struct _FlowFile {
    uint8_t             *name;
    uint16_t            name_len;
    uint8_t             *ext;
    uint16_t            ext_len;
    uint8_t             *real_type;
    uint16_t            real_type_len;
    uint8_t             *proto_type; /* The content type set at Content-Type in the MIME header (of http or smtp..) */
    uint16_t            proto_type_len;
    uint16_t            alproto;
    uint32_t            size;
    uint8_t             flags;

    FlowFileState       state;
    FlowFileChunk       *chunks_start;
    FlowFileChunk       *chunks_end;

    uint32_t            chunk_cnt;
    struct _FlowFile    *next;
} FlowFile;

typedef struct _FlowFileContainer {
    FlowFile    *start;
    FlowFile    *end;
    uint32_t    cnt;
} FlowFileContainer;

FlowFileContainer *FlowFileContainerAlloc();
void FlowFileContainerFree(FlowFileContainer *);

void FlowFileContainerRecycle(FlowFileContainer *);

FlowFileChunk *FlowFileChunkAlloc();
void FlowFileChunkFree(FlowFileChunk *);

FlowFile *FlowFileAlloc();
void FlowFileFree(FlowFile *);

void FlowFileContainerAdd(FlowFileContainer *, FlowFile *);
FlowFile *FlowFileContainerRetrieve(FlowFileContainer *, uint8_t *, uint16_t, uint8_t *);
FlowFile *FlowFileAppendChunk(FlowFile *, FlowFileChunk *);

#endif /* __FLOW_FILE_H__ */
