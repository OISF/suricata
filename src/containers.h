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

#ifndef __CONTAINERS_H__
#define __CONTAINERS_H__

void ContainersInit(void);
void ContainersDestroy(void);
uint32_t ContainersTimeoutHash(struct timeval *ts);

void *ContainerUrlRangeGet(const uint8_t *key, size_t keylen, struct timeval *ts);

// linked list of ranges : buffer with offset
typedef struct RangeContainer {
    // next item in lined list
    struct RangeContainer *next;
    // allocated buffer
    uint8_t *buffer;
    // length of buffer
    uint64_t buflen;
    // the start of the range (offset relative to the absolute beginning of the file)
    uint64_t start;
    // offset of bytes written in buffer (relative to the start of the range)
    uint64_t offset;
} RangeContainer;

// Item in hash table for a file in multiple ranges
typedef struct ContainerUrlRange {
    // key for hashtable
    uint8_t *key;
    // key length
    uint32_t len;
    // expire time in epoch
    uint32_t expire;
    // total size of the file in ranges
    uint64_t totalsize;
    // state where we skip content
    uint64_t toskip;
    // file flags
    uint16_t flags;
    // number of flows referencing this structure
    uint16_t nbref;
    // file container, with only one file
    FileContainer *files;
    // linked list of ranges which came out of order
    RangeContainer *ranges;
    // current out of order range to write into
    RangeContainer *current;
} ContainerUrlRange;

int ContainerUrlRangeSetRange(ContainerUrlRange *c, uint64_t start, uint64_t end, uint64_t total);
int ContainerUrlRangeAppendData(ContainerUrlRange *c, const uint8_t *data, size_t len);
File *ContainerUrlRangeClose(ContainerUrlRange *c, uint16_t flags);

#endif /* __CONTAINERS_H__ */
