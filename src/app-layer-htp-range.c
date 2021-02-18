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
#include "util-byte.h"        //StringParseUint32

typedef struct ContainerTHashTable {
    THashTableContext *ht;
    uint32_t timeout;
} ContainerTHashTable;

// globals
ContainerTHashTable ContainerUrlRangeList;

#define CONTAINER_URLRANGE_HASH_SIZE 256

int HttpRangeContainerBufferCompare(HttpRangeContainerBuffer *a, HttpRangeContainerBuffer *b)
{
    // lexical order : start, buflen, offset
    if (a->start > b->start)
        return 1;
    if (a->start < b->start)
        return -1;
    if (a->buflen > b->buflen)
        return 1;
    if (a->buflen < b->buflen)
        return -1;
    if (a->offset > b->offset)
        return 1;
    if (a->offset < b->offset)
        return -1;
    return 0;
}

RB_GENERATE(HTTP_RANGES, HttpRangeContainerBuffer, rb, HttpRangeContainerBufferCompare);

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
    RB_INIT(&dst_s->fragment_tree);
    dst_s->flags = 0;
    dst_s->totalsize = 0;
    SCMutexInit(&dst_s->mutex, NULL);
    dst_s->hdata = NULL;

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

// base data stays in hash
static void ContainerUrlRangeFree(void *s)
{
    HttpRangeContainerBuffer *range, *tmp;

    HttpRangeContainerFile *cu = s;
    SCFree(cu->key);
    cu->key = NULL;
    FileContainerFree(cu->files);
    cu->files = NULL;
    RB_FOREACH_SAFE (range, HTTP_RANGES, &cu->fragment_tree, tmp) {
        RB_REMOVE(HTTP_RANGES, &cu->fragment_tree, range);
        SCFree(range->buffer);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range);
    }
    SCMutexDestroy(&cu->mutex);
}

static bool ContainerValueRangeTimeout(HttpRangeContainerFile *cu, struct timeval *ts)
{
    // we only timeout if we have no flow referencing us
    SCMutexLock(&cu->mutex);
    bool r = ((uint32_t)ts->tv_sec > cu->expire && SC_ATOMIC_GET(cu->hdata->use_cnt) == 0);
    SCMutexUnlock(&cu->mutex);
    return r;
}

static void ContainerUrlRangeUpdate(HttpRangeContainerFile *cu, uint32_t expire)
{
    cu->expire = expire;
}

#define HTTP_RANGE_DEFAULT_TIMEOUT 60
#define HTTP_RANGE_DEFAULT_MEMCAP  100 * 1024 * 1024

void HttpRangeContainersInit(void)
{
    SCLogDebug("containers start");
    const char *str = NULL;
    uint64_t memcap = HTTP_RANGE_DEFAULT_MEMCAP;
    uint32_t timeout = HTTP_RANGE_DEFAULT_TIMEOUT;
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
        if (StringParseUint32(&timeout, 10, strlen(str), str) <= 0) {
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
                // we should log the timed out file somehow...
                // but it does not belong to any flow...
                ContainerUrlRangeFree(h->data);
                THashDataMoveToSpare(ContainerUrlRangeList.ht, h);
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
        HttpRangeContainerFile *c = res.data->data;
        c->hdata = res.data;
        THashDataUnlock(res.data);
        return res.data->data;
    }
    return NULL;
}

static HttpRangeContainerBlock *ContainerUrlRangeOpenFileAux(HttpRangeContainerFile *c,
        uint64_t start, uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg,
        const uint8_t *name, uint16_t name_len, uint16_t flags)
{
    SCMutexLock(&c->mutex);
    if (c->files->tail == NULL) {
        if (FileOpenFileWithId(c->files, sbcfg, 0, name, name_len, NULL, 0, flags) != 0) {
            SCLogDebug("open file for range failed");
            THashDecrUsecnt(c->hdata);
            SCMutexUnlock(&c->mutex);
            return NULL;
        }
    }
    HttpRangeContainerBlock *curf = SCCalloc(1, sizeof(HttpRangeContainerBlock));
    if (curf == NULL) {
        THashDecrUsecnt(c->hdata);
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
        THashDecrUsecnt(c->hdata);
        // redundant to be explicit that this block is independent
        curf->container = NULL;
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
    // block/range to be inserted in ordered linked list
    if (!(THASH_CHECK_MEMCAP(ContainerUrlRangeList.ht, buflen))) {
        // TODOask release memory for other ranges cf RangeContainerFree(c);
        // skips this range
        curf->toskip = buflen;
        curf->container = NULL;
        THashDecrUsecnt(c->hdata);
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

HttpRangeContainerBlock *ContainerUrlRangeOpenFile(HttpRangeContainerFile *c, uint64_t start,
        uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg, const uint8_t *name,
        uint16_t name_len, uint16_t flags, const uint8_t *data, size_t len)
{
    HttpRangeContainerBlock *r =
            ContainerUrlRangeOpenFileAux(c, start, end, total, sbcfg, name, name_len, flags);
    if (ContainerUrlRangeAppendData(r, data, len) < 0) {
        SCLogDebug("Failed to append data while openeing");
    }
    return r;
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
            r = FileAppendData(c->container->files, NULL, len - c->toskip);
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
    DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(c->hdata->use_cnt) == 0);
    THashDecrUsecnt(c->hdata);
    // move ownership of file c->files->head to caller
    FileCloseFile(c->files, NULL, 0, c->flags | flags);
    c->files->head = NULL;
    c->files->tail = NULL;
    if (SC_ATOMIC_GET(c->hdata->use_cnt) == 0) {
        THashRemoveFromHash(ContainerUrlRangeList.ht, c);
    }
    // otherwise, the hash entry will be used for another read of the file
}

File *ContainerUrlRangeClose(HttpRangeContainerBlock *c, uint16_t flags)
{
    if (c->container == NULL) {
        // everything was just skipped : nothing to do
        return NULL;
    }

    SCMutexLock(&c->container->mutex);

    if (c->current) {
        // some out-or-order range is finished
        if (c->container->files->tail &&
                c->container->files->tail->size >= c->current->start + c->current->offset) {
            // if the range has become obsolete because we received the data already
            // we just free it
            (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, c->current->buflen);
            SCFree(c->current->buffer);
            SCFree(c->current);
        } else {
            // otherwise insert in red and black tree
            HTTP_RANGES_RB_INSERT(&c->container->fragment_tree, c->current);
        }
        THashDecrUsecnt(c->container->hdata);
        SCMutexUnlock(&c->container->mutex);
        return NULL;
    }

    // else {
    if (c->toskip > 0) {
        // was only an overlapping range, truncated before new bytes
        THashDecrUsecnt(c->container->hdata);
        SCMutexUnlock(&c->container->mutex);
        return NULL;
    }

    // else {
    // we just finished an in-order block
    c->container->appending = false;
    DEBUG_VALIDATE_BUG_ON(c->container->files->tail == NULL);
    File *f = c->container->files->tail;

    // have we reached a saved range ?
    HttpRangeContainerBuffer *range;
    RB_FOREACH(range, HTTP_RANGES, &c->container->fragment_tree)
    {
        if (f->size < range->start) {
            break;
        }
        if (f->size == range->start) {
            // a new range just begins where we ended, append it
            if (FileAppendData(c->container->files, range->buffer, range->offset) != 0) {
                ContainerUrlRangeFileClose(c->container, flags);
                SCMutexUnlock(&c->container->mutex);
                return f;
            }
        } else {
            // the range starts before where we ended
            uint64_t overlap = f->size - range->start;
            if (overlap < range->offset) {
                // And the range ends beyond where we ended
                // in this case of overlap, only add the extra data
                if (FileAppendData(c->container->files, range->buffer + overlap,
                            range->offset - overlap) != 0) {
                    ContainerUrlRangeFileClose(c->container, flags);
                    SCMutexUnlock(&c->container->mutex);
                    return f;
                }
            }
        }
        // anyways, remove this range from the linked list, as we are now beyond it
        RB_REMOVE(HTTP_RANGES, &c->container->fragment_tree, range);
    }

    if (f->size >= c->container->totalsize) {
        // we finished the whole file
        ContainerUrlRangeFileClose(c->container, flags);
    } else {
        // we are expecting more ranges
        THashDecrUsecnt(c->container->hdata);
        f = NULL;
    }
    SCMutexUnlock(&c->container->mutex);
    return f;
}
