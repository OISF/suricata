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

#include "suricata-common.h"

#include "util-thash.h"
#include "rust.h"

void FileRangeContainersInit(void);
void FileRangeContainersDestroy(void);
void HttpRangeContainersTimeoutHash(struct timeval *ts);

// linked list of ranges : buffer with offset
typedef struct HttpRangeContainerBuffer {
    /** red and black tree */
    RB_ENTRY(HttpRangeContainerBuffer) rb;
    /** allocated buffer */
    uint8_t *buffer;
    /** length of buffer */
    uint64_t buflen;
    /** the start of the range (offset relative to the absolute beginning of the file) */
    uint64_t start;
    /** offset of bytes written in buffer (relative to the start of the range) */
    uint64_t offset;
    /** number of gaped bytes */
    uint64_t gap;
    /** pointer to hashtable, for memuse */
    THashTableContext *ht;
} HttpRangeContainerBuffer;

int HttpRangeContainerBufferCompare(HttpRangeContainerBuffer *a, HttpRangeContainerBuffer *b);

RB_HEAD(HTTP_RANGES, HttpRangeContainerBuffer);
RB_PROTOTYPE(HTTP_RANGES, HttpRangeContainerBuffer, rb, HttpRangeContainerBufferCompare);

/** Item in hash table for a file in multiple ranges
 * Thread-safety is ensured with the thread-safe hash table cf THashData
 * The number of use is increased for each flow opening a new FileRangeContainerBlock
 * until it closes this FileRangeContainerBlock
 * The design goal is to have concurrency only on opening and closing a range request
 * and have a lock-free data structure belonging to one Flow
 * (see FileRangeContainerBlock below)
 * for every append in between (we suppose we have many appends per range request)
 */
typedef struct FileRangeContainerFile {
    /** key for hashtable */
    uint8_t *key;
    /** key length */
    uint32_t len;
    /** expire time in epoch */
    uint32_t expire;
    /** pointer to hashtable data, for locking and use count */
    THashData *hdata;
    /** pointer to hashtable, for memuse */
    THashTableContext *ht;
    /** total expected size of the file in ranges */
    uint64_t totalsize;
    /** size of the file after last sync */
    uint64_t lastsize;
    /** file container, with only one file */
    FileContainer *files;
    /** red and black tree list of ranges which came out of order */
    struct HTTP_RANGES fragment_tree;
    /** file flags */
    uint16_t flags;
    /** error condition for this range. Its up to timeout handling to cleanup */
    bool error;
} FileRangeContainerFile;

/** A structure representing a single range request :
 * either skipping, buffering, or appending
 * As this belongs to a flow, appending data to it is ensured to be thread-safe
 * Only one block per file has the pointer to the container
 */
typedef struct FileRangeContainerBlock {
    /** state where we skip content */
    uint64_t toskip;
    /** current out of order range to write into */
    HttpRangeContainerBuffer *current;
    /** pointer to the main file container, where to directly append data */
    FileRangeContainerFile *container;
    /** file container we are owning for now */
    FileContainer *files;
} FileRangeContainerBlock;

int FileRangeAppendData(FileRangeContainerBlock *c, const uint8_t *data, uint32_t len);
File *HttpRangeClose(FileRangeContainerBlock *c, uint16_t flags);

// FileRangeContainerBlock but trouble with headers inclusion order
FileRangeContainerBlock *HttpRangeContainerOpenFile(const unsigned char *key, uint32_t keylen,
        const Flow *f, const FileContentRange *cr, const StreamingBufferConfig *sbcfg,
        const unsigned char *name, uint16_t name_len, uint16_t flags, const unsigned char *data,
        uint32_t data_len);

FileRangeContainerBlock *SmbRangeContainerOpenFile(const unsigned char *key, uint32_t keylen,
        const Flow *f, const FileContentRange *cr, const StreamingBufferConfig *sbcfg,
        const unsigned char *name, uint16_t name_len, uint16_t flags, const unsigned char *data,
        uint32_t data_len);

void FileRangeFreeBlock(FileRangeContainerBlock *b);

FileRangeContainerFile *SmbRangeContainerUrlGet(const uint8_t *key, uint32_t keylen, const Flow *f);

#endif /* __APP_LAYER_HTP_RANGE_H__ */
