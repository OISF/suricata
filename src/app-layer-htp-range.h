/* Copyright (C) 2021 Open Information Security Foundation
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

#ifndef __APP_LAYER_HTP_RANGE_H__
#define __APP_LAYER_HTP_RANGE_H__

void HttpRangeContainersInit(void);
void HttpRangeContainersDestroy(void);
uint32_t HttpRangeContainersTimeoutHash(struct timeval *ts);

void *HttpRangeContainerUrlGet(const uint8_t *key, size_t keylen, struct timeval *ts);

// linked list of ranges : buffer with offset
typedef struct HttpRangeContainerBuffer {
    // next item in lined list
    struct HttpRangeContainerBuffer *next;
    // allocated buffer
    uint8_t *buffer;
    // length of buffer
    uint64_t buflen;
    // the start of the range (offset relative to the absolute beginning of the file)
    uint64_t start;
    // offset of bytes written in buffer (relative to the start of the range)
    uint64_t offset;
} HttpRangeContainerBuffer;

// Item in hash table for a file in multiple ranges
typedef struct HttpRangeContainerFile {
    // key for hashtable
    uint8_t *key;
    // key length
    uint32_t len;
    // expire time in epoch
    uint32_t expire;
    // total size of the file in ranges
    uint64_t totalsize;
    // file flags
    uint16_t flags;
    // number of flows referencing this structure
    uint16_t nbref;
    // file container, with only one file
    FileContainer *files;
    // linked list of ranges which came out of order
    HttpRangeContainerBuffer *ranges;
    // mutex
    SCMutex mutex;
    // wether a range file is currently appending
    bool appending;
} HttpRangeContainerFile;

typedef struct HttpRangeContainerBlock {
    // state where we skip content
    uint64_t toskip;
    // current out of order range to write into
    HttpRangeContainerBuffer *current;
    // file container, with only one file
    HttpRangeContainerFile *container;
} HttpRangeContainerBlock;

int ContainerUrlRangeAppendData(HttpRangeContainerBlock *c, const uint8_t *data, size_t len);
File *ContainerUrlRangeClose(HttpRangeContainerBlock *c, uint16_t flags);

HttpRangeContainerBlock *ContainerUrlRangeOpenFile(HttpRangeContainerFile *c, uint64_t start,
        uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg, const uint8_t *name,
        uint16_t name_len, uint16_t flags);

#endif /* __APP_LAYER_HTP_RANGE_H__ */
