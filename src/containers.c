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

/**
 * \file
 *
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 */

#include "suricata-common.h"
#include "containers.h"
#include "util-misc.h"        //ParseSizeStringU64
#include "util-thash.h"       //HashTable
#include "util-memcmp.h"      //SCBufferCmp
#include "util-hash-string.h" //StringHashDjb2
#include "util-validate.h"    //DEBUG_VALIDATE_BUG_ON

typedef struct ContainerTHashTable {
    THashTableContext *ht;
    uint32_t timeout;
} ContainerTHashTable;

// globals
ContainerTHashTable ContainerUrlRangeList;

#define CONTAINER_URLRANGE_HASH_SIZE 256

static int ContainerUrlRangeSet(void *dst, void *src)
{
    ContainerUrlRange *src_s = src;
    ContainerUrlRange *dst_s = dst;
    dst_s->len = src_s->len;
    dst_s->key = SCMalloc(dst_s->len);
    BUG_ON(dst_s->key == NULL);
    memcpy(dst_s->key, src_s->key, dst_s->len);
    dst_s->files = FileContainerAlloc();
    BUG_ON(dst_s->files == NULL);
    dst_s->ranges = NULL;
    dst_s->current = NULL;
    dst_s->toskip = 0;
    dst_s->flags = 0;
    dst_s->totalsize = 0;

    return 0;
}

static bool ContainerUrlRangeCompare(void *a, void *b)
{
    const ContainerUrlRange *as = a;
    const ContainerUrlRange *bs = b;
    if (SCBufferCmp(as->key, as->len, bs->key, bs->len) == 0) {
        return true;
    }
    return false;
}

static uint32_t ContainerUrlRangeHash(void *s)
{
    ContainerUrlRange *cur = s;
    uint32_t h = StringHashDjb2(cur->key, cur->len);
    return h;
}

static void RangeContainerFree(ContainerUrlRange *c)
{
    RangeContainer *range = c->ranges;
    while (range) {
        RangeContainer *next = range->next;
        SCFree(range->buffer);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range);
        range = next;
    }
}

// base data stays in hash
static void ContainerUrlRangeFree(void *s)
{
    ContainerUrlRange *cu = s;
    SCFree(cu->key);
    FileContainerFree(cu->files);
    RangeContainerFree(cu);
}

static bool ContainerValueRangeTimeout(ContainerUrlRange *cu, struct timeval *ts)
{
    // we only timeout if we have no flow referencing us
    return ((uint32_t)ts->tv_sec > cu->expire && cu->nbref == 0);
}

static void ContainerUrlRangeUpdate(ContainerUrlRange *cu, uint32_t expire)
{
    cu->expire = expire;
}

void ContainersInit(void)
{
    SCLogDebug("containers start");
    const char *str = NULL;
    uint64_t memcap = 0;
    uint32_t timeout = 0;
    if (ConfGetValue("containers.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, &memcap) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "memcap value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            memcap = 0;
        }
    }
    if (ConfGetValue("containers.timeout", &str) == 1) {
        if (ParseSizeStringU32(str, &timeout) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "timeout value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            timeout = 0;
        }
    }

    ContainerUrlRangeList.ht = THashInit("containers.urlrange", sizeof(ContainerUrlRange),
            ContainerUrlRangeSet, ContainerUrlRangeFree, ContainerUrlRangeHash,
            ContainerUrlRangeCompare, false, memcap, CONTAINER_URLRANGE_HASH_SIZE);
    ContainerUrlRangeList.timeout = timeout;

    SCLogDebug("containers started");
}

void ContainersDestroy(void)
{
    THashShutdown(ContainerUrlRangeList.ht);
}

uint32_t ContainersTimeoutHash(struct timeval *ts)
{
    uint32_t cnt = 0;

    for (size_t i = 0; i < ContainerUrlRangeList.ht->config.hash_size; i++) {
        THashHashRow *hb = &ContainerUrlRangeList.ht->array[i];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;
        /* hash bucket is now locked */
        THashData *h = hb->head;
        while (h) {
            THashData *n = h->next;
            if (ContainerValueRangeTimeout(h->data, ts)) {
                /* remove from the hash */
                if (h->prev != NULL)
                    h->prev->next = h->next;
                if (h->next != NULL)
                    h->next->prev = h->prev;
                if (hb->head == h)
                    hb->head = h->next;
                if (hb->tail == h)
                    hb->tail = h->prev;
                h->next = NULL;
                h->prev = NULL;
                ContainerUrlRange *c = h->data;
                FileCloseFile(c->files, NULL, 0, FILE_TRUNCATED);
                // we should log it somehow...
                RangeContainerFree(c);
                THashDataMoveToSpare(ContainerUrlRangeList.ht, h->data);
            }
            h = n;
        }
        HRLOCK_UNLOCK(hb);
    }

    return cnt;
}

void *ContainerUrlRangeGet(const uint8_t *key, size_t keylen, struct timeval *ts)
{
    ContainerUrlRange lookup;
    // cast so as not to have const in the structure
    lookup.key = (uint8_t *)key;
    lookup.len = keylen;
    struct THashDataGetResult res = THashGetFromHash(ContainerUrlRangeList.ht, &lookup);
    if (res.data) {
        // nothing more to do if (res.is_new)
        ContainerUrlRangeUpdate(res.data->data, ts->tv_sec + ContainerUrlRangeList.timeout);
        THashDecrUsecnt(res.data);
        ContainerUrlRange *c = res.data->data;
        if (c->nbref == UINT16_MAX) {
            THashDataUnlock(res.data);
            return NULL;
        }
        c->nbref++;
        THashDataUnlock(res.data);
        return res.data->data;
    }
    return NULL;
}

int ContainerUrlRangeSetRange(ContainerUrlRange *c, uint64_t start, uint64_t end, uint64_t total)
{
    if (total > c->totalsize) {
        // TODOask add checks about totalsize remaining the same
        c->totalsize = total;
    }
    if (start == c->files->tail->size) {
        // easy case : append to current file
        return 0;
    } else if (start < c->files->tail->size) {
        // skip first overlap
        c->toskip = c->files->tail->size - start;
        return 0;
    }
    // else {
    // insert range in ordered linked list, if we have enough memcap
    uint64_t buflen = end - start + 1;
    if (!(THASH_CHECK_MEMCAP(ContainerUrlRangeList.ht, buflen))) {
        // TODOask release memory for others RangeContainerFree(c);
        // skips this range
        c->toskip = buflen;
        return -1;
    }
    (void)SC_ATOMIC_ADD(ContainerUrlRangeList.ht->memuse, buflen);
    RangeContainer *range = SCCalloc(1, sizeof(RangeContainer));
    BUG_ON(range == NULL);
    range->buffer = SCMalloc(buflen);
    BUG_ON(range->buffer == NULL);
    range->buflen = buflen;
    range->start = start;

    if (c->ranges == NULL || range->start < c->ranges->start) {
        range->next = c->ranges;
        c->ranges = range;
    } else {
        RangeContainer *next = c->ranges;
        while (next->next != NULL && range->start >= next->next->start) {
            next = next->next;
        }
        range->next = next->next;
        next->next = range;
    }
    c->current = range;
    return 0;
}

int ContainerUrlRangeAppendData(ContainerUrlRange *c, const uint8_t *data, size_t len)
{
    // first check if we have a current allocated buffer to copy to
    // in the case of an unordered range being handled
    if (c->current) {
        if (c->current->offset + len <= c->current->buflen) {
            memcpy(c->current->buffer + c->current->offset, data, len);
            c->current->offset += len;
        } else {
            memcpy(c->current->buffer + c->current->offset, data,
                    c->current->buflen - c->current->offset);
            c->current->offset = c->current->buflen;
        }
        return 0;
        // then check if we are skipping
    } else if (c->toskip > 0) {
        if (c->toskip >= len) {
            c->toskip -= len;
            return 0;
        } // else
        int r = FileAppendData(c->files, data + c->toskip, len - c->toskip);
        c->toskip = 0;
        return r;
    } // else {
    // last we are ordered, simply append
    return FileAppendData(c->files, data, len);
}

static void ContainerUrlRangeFileClose(ContainerUrlRange *c, uint16_t flags)
{
    FileCloseFile(c->files, NULL, 0, c->flags | flags);
    c->files->head = NULL;
    c->files->tail = NULL;
    DEBUG_VALIDATE_BUG_ON(c->nbref == 0);
    c->nbref--;
    THashRemoveFromHash(ContainerUrlRangeList.ht, c);
}

File *ContainerUrlRangeClose(ContainerUrlRange *c, uint16_t flags)
{
    if (c->toskip > 0) {
        // was only an overlapping range
        c->toskip = 0;
        return NULL;
    } else if (c->current) {
        // a stored range
        c->current = NULL;
        return NULL;
    } // else {
    File *f = c->files->tail;

    // just finished appending to a file, have we reached a saved range ?
    RangeContainer *range = c->ranges;
    while (range && f->size >= range->start) {
        if (f->size == range->start) {
            if (FileAppendData(c->files, range->buffer, range->offset) != 0) {
                ContainerUrlRangeFileClose(c, flags);
                return f;
            }
        } else {
            // in case of overlap, only add the extra data (if any)
            uint64_t overlap = f->size + 1 - range->start;
            if (overlap > range->offset) {
                if (FileAppendData(c->files, range->buffer + overlap, range->offset - overlap) !=
                        0) {
                    ContainerUrlRangeFileClose(c, flags);
                    return f;
                }
            }
        }
        RangeContainer *next = range->next;
        SCFree(range->buffer);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range);
        range = next;
        c->ranges = range;
    }

    if (f->size + 1 >= c->totalsize) {
        ContainerUrlRangeFileClose(c, flags);
        // move ownership to caller
        return f;
    }
    return NULL;
}
