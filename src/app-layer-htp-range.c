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
#include "app-layer-htp-range.h"
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
    HttpRangeContainerFile *src_s = src;
    HttpRangeContainerFile *dst_s = dst;
    dst_s->len = src_s->len;
    dst_s->key = SCMalloc(dst_s->len);
    BUG_ON(dst_s->key == NULL);
    memcpy(dst_s->key, src_s->key, dst_s->len);
    dst_s->files = FileContainerAlloc();
    BUG_ON(dst_s->files == NULL);
    dst_s->ranges = NULL;
    dst_s->flags = 0;
    dst_s->totalsize = 0;
    SCMutexInit(&dst_s->mutex, NULL);

    return 0;
}

static bool ContainerUrlRangeCompare(void *a, void *b)
{
    const HttpRangeContainerFile *as = a;
    const HttpRangeContainerFile *bs = b;
    if (SCBufferCmp(as->key, as->len, bs->key, bs->len) == 0) {
        return true;
    }
    return false;
}

static uint32_t ContainerUrlRangeHash(void *s)
{
    HttpRangeContainerFile *cur = s;
    uint32_t h = StringHashDjb2(cur->key, cur->len);
    return h;
}

static void RangeContainerFree(HttpRangeContainerFile *c)
{
    HttpRangeContainerBuffer *range = c->ranges;
    while (range) {
        HttpRangeContainerBuffer *next = range->next;
        SCFree(range->buffer);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range);
        range = next;
    }
    c->ranges = NULL;
}

// base data stays in hash
static void ContainerUrlRangeFree(void *s)
{
    HttpRangeContainerFile *cu = s;
    SCFree(cu->key);
    FileContainerFree(cu->files);
    SCMutexDestroy(&cu->mutex);
    RangeContainerFree(cu);
}

static bool ContainerValueRangeTimeout(HttpRangeContainerFile *cu, struct timeval *ts)
{
    // we only timeout if we have no flow referencing us
    return ((uint32_t)ts->tv_sec > cu->expire && cu->nbref == 0);
}

static void ContainerUrlRangeUpdate(HttpRangeContainerFile *cu, uint32_t expire)
{
    cu->expire = expire;
}

void HttpRangeContainersInit(void)
{
    SCLogDebug("containers start");
    const char *str = NULL;
    uint64_t memcap = 0;
    uint32_t timeout = 0;
    if (ConfGetValue("app-layer.protocols.http.urlrange.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, &memcap) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "memcap value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            memcap = 0;
        }
    }
    if (ConfGetValue("app-layer.protocols.http.urlrange.timeout", &str) == 1) {
        if (ParseSizeStringU32(str, &timeout) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "timeout value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            timeout = 0;
        }
    }

    ContainerUrlRangeList.ht =
            THashInit("app-layer.protocols.http.urlrange", sizeof(HttpRangeContainerFile),
                    ContainerUrlRangeSet, ContainerUrlRangeFree, ContainerUrlRangeHash,
                    ContainerUrlRangeCompare, false, memcap, CONTAINER_URLRANGE_HASH_SIZE);
    ContainerUrlRangeList.timeout = timeout;

    SCLogDebug("containers started");
}

void HttpRangeContainersDestroy(void)
{
    THashShutdown(ContainerUrlRangeList.ht);
}

uint32_t HttpRangeContainersTimeoutHash(struct timeval *ts)
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
                HttpRangeContainerFile *c = h->data;
                SCMutexLock(&c->mutex);
                FileCloseFile(c->files, NULL, 0, FILE_TRUNCATED);
                // we should log the timed out file somehow...
                RangeContainerFree(c);
                SCMutexUnlock(&c->mutex);
                THashDataMoveToSpare(ContainerUrlRangeList.ht, h->data);
            }
            h = n;
        }
        HRLOCK_UNLOCK(hb);
    }

    return cnt;
}

void *HttpRangeContainerUrlGet(const uint8_t *key, size_t keylen, struct timeval *ts)
{
    HttpRangeContainerFile lookup;
    // cast so as not to have const in the structure
    lookup.key = (uint8_t *)key;
    lookup.len = keylen;
    struct THashDataGetResult res = THashGetFromHash(ContainerUrlRangeList.ht, &lookup);
    if (res.data) {
        // nothing more to do if (res.is_new)
        ContainerUrlRangeUpdate(res.data->data, ts->tv_sec + ContainerUrlRangeList.timeout);
        THashDecrUsecnt(res.data);
        HttpRangeContainerFile *c = res.data->data;
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

HttpRangeContainerBlock *ContainerUrlRangeOpenFile(HttpRangeContainerFile *c, uint64_t start,
        uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg, const uint8_t *name,
        uint16_t name_len, uint16_t flags)
{
    SCMutexLock(&c->mutex);
    if (c->files->tail == NULL) {
        if (FileOpenFileWithId(c->files, sbcfg, 0, name, name_len, NULL, 0, flags) != 0) {
            SCLogDebug("open file for range failed");
            c->nbref--;
            SCMutexUnlock(&c->mutex);
            return NULL;
        }
    }
    HttpRangeContainerBlock *curf = SCCalloc(1, sizeof(HttpRangeContainerBlock));
    if (curf == NULL) {
        c->nbref--;
        SCMutexUnlock(&c->mutex);
        return NULL;
    }
    if (total > c->totalsize) {
        // TODOask add checks about totalsize remaining the same
        c->totalsize = total;
    }
    uint64_t buflen = end - start + 1;
    if (start == c->files->tail->size && !c->appending) {
        // easy case : append to current file
        curf->container = c;
        c->appending = true;
        SCMutexUnlock(&c->mutex);
        return curf;
    } else if (start < c->files->tail->size && c->files->tail->size - start >= buflen) {
        // only overlap
        curf->toskip = buflen;
        SCMutexUnlock(&c->mutex);
        return curf;
    } else if (start < c->files->tail->size && c->files->tail->size - start < buflen &&
               !c->appending) {
        // skip first overlap, then append
        curf->toskip = c->files->tail->size - start;
        c->appending = true;
        curf->container = c;
        SCMutexUnlock(&c->mutex);
        return curf;
    }
    // else {
    // insert range in ordered linked list, if we have enough memcap
    if (!(THASH_CHECK_MEMCAP(ContainerUrlRangeList.ht, buflen))) {
        // TODOask release memory for others RangeContainerFree(c);
        // skips this range
        curf->toskip = buflen;
        SCMutexUnlock(&c->mutex);
        return curf;
    }
    curf->container = c;
    (void)SC_ATOMIC_ADD(ContainerUrlRangeList.ht->memuse, buflen);
    HttpRangeContainerBuffer *range = SCCalloc(1, sizeof(HttpRangeContainerBuffer));
    BUG_ON(range == NULL);
    range->buffer = SCMalloc(buflen);
    BUG_ON(range->buffer == NULL);
    range->buflen = buflen;
    range->start = start;

    curf->current = range;
    SCMutexUnlock(&c->mutex);
    return curf;
}

int ContainerUrlRangeAppendData(HttpRangeContainerBlock *c, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    // first check if we have a current allocated buffer to copy to
    // in the case of an unordered range being handled
    if (c->current) {
        if (data == NULL) {
            // just feed the gap in the current position, instead of its right one
            return FileAppendData(c->container->files, data, len);
        } else if (c->current->offset + len <= c->current->buflen) {
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
        DEBUG_VALIDATE_BUG_ON(c->container->files == NULL);
        int r;
        if (data == NULL) {
            // gap overlaping already known data
            r = FileAppendData(c->container->files, data, len - c->toskip);
        } else {
            r = FileAppendData(c->container->files, data + c->toskip, len - c->toskip);
        }
        c->toskip = 0;
        return r;
    } // else {
    // last we are ordered, simply append
    DEBUG_VALIDATE_BUG_ON(c->container->files == NULL);
    return FileAppendData(c->container->files, data, len);
}

static void ContainerUrlRangeFileClose(HttpRangeContainerFile *c, uint16_t flags)
{
    DEBUG_VALIDATE_BUG_ON(c->nbref == 0);
    c->nbref--;
    if (c->nbref == 0) {
        FileCloseFile(c->files, NULL, 0, c->flags | flags);
        c->files->head = NULL;
        c->files->tail = NULL;

        RangeContainerFree(c);
        THashRemoveFromHash(ContainerUrlRangeList.ht, c);
    }
}

File *ContainerUrlRangeClose(HttpRangeContainerBlock *c, uint16_t flags)
{
    SCMutexLock(&c->container->mutex);
    if (c->toskip > 0) {
        // was only an overlapping range
        c->toskip = 0;
        c->container->nbref--;
        SCMutexUnlock(&c->container->mutex);
        return NULL;
    } else if (c->current) {
        // if the range has become obsolete because we received the data already
        if (c->container->files && c->container->files->tail &&
                c->container->files->tail->size >= c->current->start + c->current->offset) {
            SCFree(c->current->buffer);
            SCFree(c->current);
            // otherwise insert in linked list
        } else if (c->container->ranges == NULL ||
                   c->current->start < c->container->ranges->start) {
            c->current->next = c->container->ranges;
            c->container->ranges = c->current;
        } else {
            HttpRangeContainerBuffer *next = c->container->ranges;
            while (next->next != NULL && c->current->start >= next->next->start) {
                next = next->next;
            }
            c->current->next = next->next;
            next->next = c->current;
        }
        c->container->nbref--;
        SCMutexUnlock(&c->container->mutex);
        c->current = NULL;
        return NULL;
    } // else {
    if (c->container == NULL) {
        // everything was skipped
        c->container->nbref--;
        SCMutexUnlock(&c->container->mutex);
        return NULL;
    }
    c->container->appending = false;
    DEBUG_VALIDATE_BUG_ON(c->container->files->tail == NULL);
    File *f = c->container->files->tail;

    // just finished appending to a file, have we reached a saved range ?
    HttpRangeContainerBuffer *range = c->container->ranges;
    while (range && f->size >= range->start) {
        if (f->size == range->start) {
            if (FileAppendData(c->container->files, range->buffer, range->offset) != 0) {
                ContainerUrlRangeFileClose(c->container, flags);
                SCMutexUnlock(&c->container->mutex);
                return f;
            }
        } else {
            // in case of overlap, only add the extra data (if any)
            uint64_t overlap = f->size - range->start;
            if (overlap < range->offset) {
                if (FileAppendData(c->container->files, range->buffer + overlap,
                            range->offset - overlap) != 0) {
                    ContainerUrlRangeFileClose(c->container, flags);
                    SCMutexUnlock(&c->container->mutex);
                    return f;
                }
            }
        }
        HttpRangeContainerBuffer *next = range->next;
        SCFree(range->buffer);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range);
        range = next;
        c->container->ranges = range;
    }

    if (f->size + 1 >= c->container->totalsize) {
        ContainerUrlRangeFileClose(c->container, flags);
        // move ownership to caller
    } else {
        f = NULL;
    }
    SCMutexUnlock(&c->container->mutex);
    return f;
}
