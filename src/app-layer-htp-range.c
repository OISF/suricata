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

static void HttpRangeBlockDerefContainer(HttpRangeContainerBlock *b);

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
    if (dst_s->key == NULL)
        return -1;
    memcpy(dst_s->key, src_s->key, dst_s->len);
    dst_s->files = FileContainerAlloc();
    if (dst_s->files == NULL) {
        SCFree(dst_s->key);
        return -1;
    }
    RB_INIT(&dst_s->fragment_tree);
    dst_s->flags = 0;
    dst_s->lastsize = 0;
    dst_s->totalsize = 0;
    dst_s->hdata = NULL;
    dst_s->error = false;
    return 0;
}

static bool ContainerUrlRangeCompare(void *a, void *b)
{
    const HttpRangeContainerFile *as = a;
    const HttpRangeContainerFile *bs = b;

    /* ranges in the error state should not be found so they can
     * be evicted */
    if (as->error || bs->error) {
        return false;
    }

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
    HttpRangeContainerBuffer *range = NULL, *tmp = NULL;

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
}

static inline bool ContainerValueRangeTimeout(HttpRangeContainerFile *cu, struct timeval *ts)
{
    // we only timeout if we have no flow referencing us
    if ((uint32_t)ts->tv_sec > cu->expire || cu->error) {
        if (SC_ATOMIC_GET(cu->hdata->use_cnt) == 0) {
            DEBUG_VALIDATE_BUG_ON(cu->files == NULL);
            return true;
        }
    }
    return false;
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
    if (ConfGet("app-layer.protocols.http.byterange.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, &memcap) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "memcap value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            memcap = 0;
        }
    }
    if (ConfGet("app-layer.protocols.http.byterange.timeout", &str) == 1) {
        size_t slen = strlen(str);
        if (slen > UINT16_MAX || StringParseUint32(&timeout, 10, (uint16_t)slen, str) <= 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "timeout value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            timeout = 0;
        }
    }

    ContainerUrlRangeList.ht =
            THashInit("app-layer.protocols.http.byterange", sizeof(HttpRangeContainerFile),
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
    SCLogDebug("timeout: starting");
    uint32_t cnt = 0;

    for (uint32_t i = 0; i < ContainerUrlRangeList.ht->config.hash_size; i++) {
        THashHashRow *hb = &ContainerUrlRangeList.ht->array[i];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;
        /* hash bucket is now locked */
        THashData *h = hb->head;
        while (h) {
            DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(h->use_cnt) > (uint32_t)INT_MAX);
            THashData *n = h->next;
            THashDataLock(h);
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
                SCLogDebug("timeout: removing range %p", h);
                ContainerUrlRangeFree(h->data); // TODO do we need a "RECYCLE" func?
                DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(h->use_cnt) > (uint32_t)INT_MAX);
                THashDataUnlock(h);
                THashDataMoveToSpare(ContainerUrlRangeList.ht, h);
            } else {
                THashDataUnlock(h);
            }
            h = n;
        }
        HRLOCK_UNLOCK(hb);
    }

    SCLogDebug("timeout: ending");
    return cnt;
}

/**
 * \returns locked data
 */
static void *HttpRangeContainerUrlGet(const uint8_t *key, uint32_t keylen, const Flow *f)
{
    const struct timeval *ts = &f->lastts;
    HttpRangeContainerFile lookup;
    memset(&lookup, 0, sizeof(lookup));
    // cast so as not to have const in the structure
    lookup.key = (uint8_t *)key;
    lookup.len = keylen;
    struct THashDataGetResult res = THashGetFromHash(ContainerUrlRangeList.ht, &lookup);
    if (res.data) {
        // nothing more to do if (res.is_new)
        ContainerUrlRangeUpdate(res.data->data, ts->tv_sec + ContainerUrlRangeList.timeout);
        HttpRangeContainerFile *c = res.data->data;
        c->hdata = res.data;
        SCLogDebug("c %p", c);
        return res.data->data;
    }
    return NULL;
}

static HttpRangeContainerBlock *HttpRangeOpenFileAux(HttpRangeContainerFile *c, uint64_t start,
        uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg, const uint8_t *name,
        uint16_t name_len, uint16_t flags)
{
    if (c->files != NULL && c->files->tail == NULL) {
        /* this is the first request, we open a single file in the file container
         * this could be part of ContainerUrlRangeSet if we could have
         * all the arguments there
         */
        if (FileOpenFileWithId(c->files, sbcfg, 0, name, name_len, NULL, 0, flags) != 0) {
            SCLogDebug("open file for range failed");
            return NULL;
        }
    }
    HttpRangeContainerBlock *curf = SCCalloc(1, sizeof(HttpRangeContainerBlock));
    if (curf == NULL) {
        c->error = true;
        return NULL;
    }
    curf->files = NULL;
    if (total > c->totalsize) {
        // we grow to the maximum size indicated by different range requests
        // we could add some warning/app-layer event in this case where
        // different range requests indicate different total sizes
        c->totalsize = total;
    }
    const uint64_t buflen = end - start + 1;

    /* The big part of this function is now to decide which kind of HttpRangeContainerBlock
     * we will return :
     * - skipping already processed data
     * - storing out of order data for later use
     * - directly appending to the file if we are at the right offset
     */
    if (start == c->lastsize && c->files != NULL) {
        // easy case : append to current file
        curf->container = c;
        // If we see 2 duplicate range requests with the same range,
        // the first one takes the ownership of the files container
        // protected by the lock from caller HTPFileOpenWithRange
        curf->files = c->files;
        c->files = NULL;
        return curf;
    } else if (start < c->lastsize && c->lastsize - start >= buflen) {
        // only overlap
        // redundant to be explicit that this block is independent
        curf->toskip = buflen;
        return curf;
    } else if (start < c->lastsize && c->lastsize - start < buflen && c->files != NULL) {
        // some overlap, then some data to append to the file
        curf->toskip = c->lastsize - start;
        curf->files = c->files;
        c->files = NULL;
        curf->container = c;
        return curf;
    }
    // Because we are not in the previous cases, we will store the data for later use

    // block/range to be inserted in ordered linked list
    if (!(THASH_CHECK_MEMCAP(ContainerUrlRangeList.ht, buflen))) {
        // skips this range
        curf->toskip = buflen;
        return curf;
    }
    curf->container = c;

    HttpRangeContainerBuffer *range = SCCalloc(1, sizeof(HttpRangeContainerBuffer));
    if (range == NULL) {
        c->error = true;
        SCFree(curf);
        return NULL;
    }

    (void)SC_ATOMIC_ADD(ContainerUrlRangeList.ht->memuse, buflen);
    range->buffer = SCMalloc(buflen);
    if (range->buffer == NULL) {
        c->error = true;
        SCFree(curf);
        SCFree(range);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, buflen);
        return NULL;
    }
    range->buflen = buflen;
    range->start = start;
    range->offset = 0;
    range->gap = 0;
    curf->current = range;
    return curf;
}

static HttpRangeContainerBlock *HttpRangeOpenFile(HttpRangeContainerFile *c, uint64_t start,
        uint64_t end, uint64_t total, const StreamingBufferConfig *sbcfg, const uint8_t *name,
        uint16_t name_len, uint16_t flags, const uint8_t *data, uint32_t len)
{
    HttpRangeContainerBlock *r =
            HttpRangeOpenFileAux(c, start, end, total, sbcfg, name, name_len, flags);
    if (HttpRangeAppendData(r, data, len) < 0) {
        SCLogDebug("Failed to append data while openeing");
    }
    return r;
}

HttpRangeContainerBlock *HttpRangeContainerOpenFile(const uint8_t *key, uint32_t keylen,
        const Flow *f, const HTTPContentRange *crparsed, const StreamingBufferConfig *sbcfg,
        const uint8_t *name, uint16_t name_len, uint16_t flags, const uint8_t *data,
        uint32_t data_len)
{
    HttpRangeContainerFile *file_range_container = HttpRangeContainerUrlGet(key, keylen, f);
    if (file_range_container == NULL) {
        // probably reached memcap
        return NULL;
    }
    HttpRangeContainerBlock *r = HttpRangeOpenFile(file_range_container, crparsed->start,
            crparsed->end, crparsed->size, sbcfg, name, name_len, flags, data, data_len);
    SCLogDebug("s->file_range == %p", r);
    if (r == NULL) {
        THashDecrUsecnt(file_range_container->hdata);
        DEBUG_VALIDATE_BUG_ON(
                SC_ATOMIC_GET(file_range_container->hdata->use_cnt) > (uint32_t)INT_MAX);
        THashDataUnlock(file_range_container->hdata);

        // probably reached memcap
        return NULL;
        /* in some cases we don't take a reference, so decr use cnt */
    } else if (r->container == NULL) {
        THashDecrUsecnt(file_range_container->hdata);
    } else {
        SCLogDebug("container %p use_cnt %u", r, SC_ATOMIC_GET(r->container->hdata->use_cnt));
        DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(r->container->hdata->use_cnt) > (uint32_t)INT_MAX);
    }

    /* we're done, so unlock. But since we have a reference in s->file_range keep use_cnt. */
    THashDataUnlock(file_range_container->hdata);
    return r;
}

int HttpRangeAppendData(HttpRangeContainerBlock *c, const uint8_t *data, uint32_t len)
{
    if (len == 0) {
        return 0;
    }
    // first check if we need to skip all bytes
    if (c->toskip >= len) {
        c->toskip -= len;
        return 0;
    }
    // then if we need to skip only some bytes
    if (c->toskip > 0) {
        int r = 0;
        if (c->files) {
            if (data == NULL) {
                // gap overlaping already known data
                r = FileAppendData(c->files, NULL, len - c->toskip);
            } else {
                r = FileAppendData(c->files, data + c->toskip, len - c->toskip);
            }
        }
        c->toskip = 0;
        return r;
    }
    // If we are owning the file to append to it, let's do it
    if (c->files) {
        SCLogDebug("update files (FileAppendData)");
        return FileAppendData(c->files, data, len);
    }
    // Maybe we were in the skipping case,
    // but we get more data than expected and had set c->toskip = 0
    // so we need to check for last case with something to do
    if (c->current) {
        // So we have a current allocated buffer to copy to
        // in the case of an unordered range being handled
        SCLogDebug("update current: adding %u bytes to block %p", len, c);
        // GAP "data"
        if (data == NULL) {
            // just save the length of the gap
            c->current->gap += len;
            // data, but we're not yet complete
        } else if (c->current->offset + len < c->current->buflen) {
            memcpy(c->current->buffer + c->current->offset, data, len);
            c->current->offset += len;
            // data, we're complete
        } else if (c->current->offset + len == c->current->buflen) {
            memcpy(c->current->buffer + c->current->offset, data, len);
            c->current->offset += len;
            // data, more than expected
        } else {
            memcpy(c->current->buffer + c->current->offset, data,
                    c->current->buflen - c->current->offset);
            c->current->offset = c->current->buflen;
        }
    }
    return 0;
}

static void HttpRangeFileClose(HttpRangeContainerFile *c, uint16_t flags)
{
    SCLogDebug("closing range %p flags %04x", c, flags);
    DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(c->hdata->use_cnt) == 0);
    // move ownership of file c->files->head to caller
    FileCloseFile(c->files, NULL, 0, c->flags | flags);
    c->files->head = NULL;
    c->files->tail = NULL;
}

/**
 *  \note if `f` is non-NULL, the ownership of the file is transfered to the caller.
 */
File *HttpRangeClose(HttpRangeContainerBlock *c, uint16_t flags)
{
    SCLogDebug("c %p c->container %p c->current %p", c, c->container, c->current);

    DEBUG_VALIDATE_BUG_ON(c->container == NULL);

    /* we're processing an OOO chunk, won't be able to get us a full file just yet */
    if (c->current) {
        SCLogDebug("processing ooo chunk as c->current is set %p", c->current);
        // some out-or-order range is finished
        if (c->container->lastsize >= c->current->start + c->current->offset) {
            // if the range has become obsolete because we received the data already
            // we just free it
            (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, c->current->buflen);
            SCFree(c->current->buffer);
            SCFree(c->current);
            c->current = NULL;
            SCLogDebug("c->current was obsolete");
            return NULL;
        } else {
            /* otherwise insert in red and black tree. If res != NULL, the insert
               failed because its a dup. */
            HttpRangeContainerBuffer *res =
                    HTTP_RANGES_RB_INSERT(&c->container->fragment_tree, c->current);
            if (res) {
                SCLogDebug("duplicate range fragment");
                (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, c->current->buflen);
                SCFree(c->current->buffer);
                SCFree(c->current);
                c->current = NULL;
                return NULL;
            }
            SCLogDebug("inserted range fragment");
            c->current = NULL;
            if (c->container->files == NULL) {
                // we have to wait for the flow owning the file
                return NULL;
            }
            if (c->container->files->tail == NULL) {
                // file has already been closed meanwhile
                return NULL;
            }
            // keep on going, maybe this out of order chunk
            // became the missing part between open and close
        }
        SCLogDebug("c->current was set, file incomplete so return NULL");
    } else if (c->toskip > 0) {
        // was only an overlapping range, truncated before new bytes
        SCLogDebug("c->toskip %" PRIu64, c->toskip);
        if (c->files) {
            // if we expected new bytes after overlap
            c->container->files = c->files;
            c->files = NULL;
        }
        return NULL;
    } else {
        // we just finished an in-order block
        DEBUG_VALIDATE_BUG_ON(c->files == NULL);
        // move back the ownership of the file container to HttpRangeContainerFile
        c->container->files = c->files;
        c->files = NULL;
        DEBUG_VALIDATE_BUG_ON(c->container->files->tail == NULL);
    }

    File *f = c->container->files->tail;

    /* See if we can use our stored fragments to (partly) reconstruct the file */
    HttpRangeContainerBuffer *range, *safe = NULL;
    RB_FOREACH_SAFE (range, HTTP_RANGES, &c->container->fragment_tree, safe) {
        if (f->size < range->start) {
            // this next range is not reached yet
            break;
        }
        if (f->size == range->start) {
            // a new range just begins where we ended, append it
            if (range->gap > 0) {
                // if the range had a gap, begin by it
                if (FileAppendData(c->container->files, NULL, range->gap) != 0) {
                    c->container->lastsize = f->size;
                    HttpRangeFileClose(c->container, flags | FILE_TRUNCATED);
                    c->container->error = true;
                    return f;
                }
            }
            if (FileAppendData(c->container->files, range->buffer, range->offset) != 0) {
                c->container->lastsize = f->size;
                HttpRangeFileClose(c->container, flags | FILE_TRUNCATED);
                c->container->error = true;
                return f;
            }
        } else {
            // the range starts before where we ended
            uint64_t overlap = f->size - range->start;
            if (overlap < range->offset) {
                if (range->gap > 0) {
                    // if the range had a gap, begin by it
                    if (FileAppendData(c->container->files, NULL, range->gap) != 0) {
                        c->container->lastsize = f->size;
                        HttpRangeFileClose(c->container, flags | FILE_TRUNCATED);
                        c->container->error = true;
                        return f;
                    }
                }
                // And the range ends beyond where we ended
                // in this case of overlap, only add the extra data
                if (FileAppendData(c->container->files, range->buffer + overlap,
                            range->offset - overlap) != 0) {
                    c->container->lastsize = f->size;
                    HttpRangeFileClose(c->container, flags | FILE_TRUNCATED);
                    c->container->error = true;
                    return f;
                }
            }
        }
        /* Remove this range from the tree */
        HTTP_RANGES_RB_REMOVE(&c->container->fragment_tree, range);
        (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, range->buflen);
        SCFree(range->buffer);
        SCFree(range);
    }
    // wait until we merged all the buffers to update known size
    c->container->lastsize = f->size;

    if (f->size >= c->container->totalsize) {
        // we finished the whole file
        HttpRangeFileClose(c->container, flags);
    } else {
        // we are expecting more ranges
        f = NULL;
        SCLogDebug("expecting more use_cnt %u", SC_ATOMIC_GET(c->container->hdata->use_cnt));
    }
    SCLogDebug("returning f %p (c:%p container:%p)", f, c, c->container);
    return f;
}

static void HttpRangeBlockDerefContainer(HttpRangeContainerBlock *b)
{
    if (b && b->container) {
        DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(b->container->hdata->use_cnt) == 0);
        THashDecrUsecnt(b->container->hdata);
        b->container = NULL;
    }
}

void HttpRangeFreeBlock(HttpRangeContainerBlock *b)
{
    if (b) {
        HttpRangeBlockDerefContainer(b);

        if (b->current) {
            (void)SC_ATOMIC_SUB(ContainerUrlRangeList.ht->memuse, b->current->buflen);
            SCFree(b->current->buffer);
            SCFree(b->current);
        }
        // we did not move ownership of the file container back to HttpRangeContainerFile
        DEBUG_VALIDATE_BUG_ON(b->files != NULL);
        if (b->files != NULL) {
            FileContainerFree(b->files);
            b->files = NULL;
        }
        SCFree(b);
    }
}
