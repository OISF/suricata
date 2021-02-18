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

typedef struct RangeContainer {
    struct RangeContainer *next;
    uint8_t *buffer;
    uint64_t buflen;
    uint64_t start;
    uint64_t offset;
} RangeContainer;

typedef struct ContainerUrlRange {
    uint8_t *key;
    uint32_t len;
    uint32_t expire;
    uint64_t totalsize;
    uint64_t toskip;
    uint16_t flags;
    FileContainer *files;
    RangeContainer *ranges;
    RangeContainer *current;
} ContainerUrlRange;

int ContainerUrlRangeSetRange(ContainerUrlRange *c, uint64_t start, uint64_t end, uint64_t total);
int ContainerUrlRangeAppendData(ContainerUrlRange *c, const uint8_t *data, size_t len);
File *ContainerUrlRangeClose(ContainerUrlRange *c, uint16_t flags);

#endif /* __CONTAINERS_H__ */
