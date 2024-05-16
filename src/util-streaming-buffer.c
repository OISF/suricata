/* Copyright (C) 2015-2023 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-streaming-buffer.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-validate.h"
#include "util-debug.h"
#include "util-error.h"

#include "app-layer-htp-mem.h"
#include "conf-yaml-loader.h"
#include "app-layer-htp.h"

static void ListRegions(StreamingBuffer *sb);

#define DUMP_REGIONS 0 // set to 1 to dump a visual representation of the regions list and sbb tree.

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 *  \brief Streaming Buffer API
 */

static void *ReallocFunc(void *ptr, const size_t size)
{
    void *ptrmem = SCRealloc(ptr, size);
    if (unlikely(ptrmem == NULL)) {
        sc_errno = SC_ENOMEM;
    }
    return ptrmem;
}

static void *CallocFunc(const size_t nm, const size_t sz)
{
    void *ptrmem = SCCalloc(nm, sz);
    if (unlikely(ptrmem == NULL)) {
        sc_errno = SC_ENOMEM;
    }
    return ptrmem;
}

/* memory handling wrappers. If config doesn't define it's own set of
 * functions, use the defaults */
// TODO the default allocators don't set `sc_errno` yet.
#define CALLOC(cfg, n, s) (cfg)->Calloc ? (cfg)->Calloc((n), (s)) : CallocFunc((n), (s))
#define REALLOC(cfg, ptr, orig_s, s)                                                               \
    (cfg)->Realloc ? (cfg)->Realloc((ptr), (orig_s), (s)) : ReallocFunc((ptr), (s))
#define FREE(cfg, ptr, s) \
    (cfg)->Free ? (cfg)->Free((ptr), (s)) : SCFree((ptr))

static void SBBFree(StreamingBuffer *sb, const StreamingBufferConfig *cfg);

RB_GENERATE(SBB, StreamingBufferBlock, rb, SBBCompare);

int SBBCompare(struct StreamingBufferBlock *a, struct StreamingBufferBlock *b)
{
    SCLogDebug("a %" PRIu64 " len %u, b %" PRIu64 " len %u", a->offset, a->len, b->offset, b->len);

    if (a->offset > b->offset)
        SCReturnInt(1);
    else if (a->offset < b->offset)
        SCReturnInt(-1);
    else {
        if (a->len == 0 || b->len == 0 || a->len ==  b->len)
            SCReturnInt(0);
        else if (a->len > b->len)
            SCReturnInt(1);
        else
            SCReturnInt(-1);
    }
}

/* inclusive compare function that also considers the right edge,
 * not just the offset. */
static inline int InclusiveCompare(StreamingBufferBlock *lookup, StreamingBufferBlock *intree) {
    const uint64_t lre = lookup->offset + lookup->len;
    const uint64_t tre = intree->offset + intree->len;
    if (lre <= intree->offset)   // entirely before
        return -1;
    else if (lookup->offset < tre && lre <= tre) // (some) overlap
        return 0;
    else
        return 1;   // entirely after
}

StreamingBufferBlock *SBB_RB_FIND_INCLUSIVE(struct SBB *head, StreamingBufferBlock *elm)
{
    SCLogDebug("looking up %" PRIu64, elm->offset);

    struct StreamingBufferBlock *tmp = RB_ROOT(head);
    struct StreamingBufferBlock *res = NULL;
    while (tmp) {
        SCLogDebug("compare with %" PRIu64 "/%u", tmp->offset, tmp->len);
        const int comp = InclusiveCompare(elm, tmp);
        SCLogDebug("compare result: %d", comp);
        if (comp < 0) {
            res = tmp;
            tmp = RB_LEFT(tmp, rb);
        } else if (comp > 0) {
            tmp = RB_RIGHT(tmp, rb);
        } else {
            return tmp;
        }
    }
    return res;
}

/** \interal
 *  \brief does data region intersect with list region 'r'
 *  Takes the max gap into account.
 */
static inline bool RegionsIntersect(const StreamingBufferConfig *cfg,
        const StreamingBufferRegion *r, const uint64_t offset, const uint64_t re)
{
    /* create the data range for the region, adding the max gap */
    const uint64_t reg_o =
            r->stream_offset > cfg->region_gap ? (r->stream_offset - cfg->region_gap) : 0;
    const uint64_t reg_re = r->stream_offset + r->buf_size + cfg->region_gap;
    SCLogDebug("r %p: %" PRIu64 "/%" PRIu64 " - adjusted %" PRIu64 "/%" PRIu64, r, r->stream_offset,
            r->stream_offset + r->buf_size, reg_o, reg_re);
    /* check if data range intersects with region range */
    if (offset >= reg_o && offset <= reg_re) {
        SCLogDebug("r %p is in-scope", r);
        return true;
    }
    if (re >= reg_o && re <= reg_re) {
        SCLogDebug("r %p is in-scope: %" PRIu64 " >= %" PRIu64 " && %" PRIu64 " <= %" PRIu64, r, re,
                reg_o, re, reg_re);
        return true;
    }
    SCLogDebug("r %p is out of scope: %" PRIu64 "/%" PRIu64, r, offset, re);
    return false;
}

/** \internal
 *  \brief find the first region for merging.
 */
static StreamingBufferRegion *FindFirstRegionForOffset(const StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, StreamingBufferRegion *r, const uint64_t offset,
        const uint32_t len, StreamingBufferRegion **prev)
{
    const uint64_t data_re = offset + len;
    SCLogDebug("looking for first region matching %" PRIu64 "/%" PRIu64, offset, data_re);

    StreamingBufferRegion *p = NULL;
    for (; r != NULL; r = r->next) {
        if (RegionsIntersect(cfg, r, offset, data_re) == true) {
            *prev = p;
            return r;
        }
        p = r;
    }
    *prev = NULL;
    return NULL;
}

static StreamingBufferRegion *FindLargestRegionForOffset(const StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, StreamingBufferRegion *r, const uint64_t offset,
        const uint32_t len)
{
    const uint64_t data_re = offset + len;
    SCLogDebug("starting at %p/%" PRIu64 ", offset %" PRIu64 ", data_re %" PRIu64, r,
            r->stream_offset, offset, data_re);
    StreamingBufferRegion *candidate = r;
    for (; r != NULL; r = r->next) {
#ifdef DEBUG
        const uint64_t reg_re = r->stream_offset + r->buf_size;
        SCLogDebug("checking: %p/%" PRIu64 "/%" PRIu64 ", offset %" PRIu64 "/%" PRIu64, r,
                r->stream_offset, reg_re, offset, data_re);
#endif
        if (!RegionsIntersect(cfg, r, offset, data_re))
            return candidate;

        if (r->buf_size > candidate->buf_size) {
            SCLogDebug("candidate %p as size %u > %u", candidate, r->buf_size, candidate->buf_size);
            candidate = r;
        }
    }
    return candidate;
}

static StreamingBufferRegion *FindRightEdge(const StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, StreamingBufferRegion *r, const uint64_t offset,
        const uint32_t len)
{
    const uint64_t data_re = offset + len;
    StreamingBufferRegion *candidate = r;
    for (; r != NULL; r = r->next) {
        if (!RegionsIntersect(cfg, r, offset, data_re)) {
            SCLogDebug(
                    "r %p is out of scope: %" PRIu64 "/%u/%" PRIu64, r, offset, len, offset + len);
            return candidate;
        }
        candidate = r;
    }
    return candidate;
}

/** \note uses sc_errno to give error details */
static inline StreamingBufferRegion *InitBufferRegion(
        StreamingBuffer *sb, const StreamingBufferConfig *cfg, const uint32_t min_size)
{
    if (sb->regions == USHRT_MAX || (cfg->max_regions != 0 && sb->regions >= cfg->max_regions)) {
        SCLogDebug("max regions reached");
        sc_errno = SC_ELIMIT;
        return NULL;
    }

    StreamingBufferRegion *aux_r = CALLOC(cfg, 1, sizeof(*aux_r));
    if (aux_r == NULL) {
        return NULL;
    }

    aux_r->buf = CALLOC(cfg, 1, MAX(cfg->buf_size, min_size));
    if (aux_r->buf == NULL) {
        FREE(cfg, aux_r, sizeof(*aux_r));
        return NULL;
    }
    aux_r->buf_size = MAX(cfg->buf_size, min_size);
    sb->regions++;
    sb->max_regions = MAX(sb->regions, sb->max_regions);
    return aux_r;
}

static inline int InitBuffer(StreamingBuffer *sb, const StreamingBufferConfig *cfg)
{
    sb->region.buf = CALLOC(cfg, 1, cfg->buf_size);
    if (sb->region.buf == NULL) {
        return sc_errno;
    }
    sb->region.buf_size = cfg->buf_size;
    return SC_OK;
}

StreamingBuffer *StreamingBufferInit(const StreamingBufferConfig *cfg)
{
    StreamingBuffer *sb = CALLOC(cfg, 1, sizeof(StreamingBuffer));
    if (sb == NULL) {
        return NULL;
    }

    sb->region.buf_size = cfg->buf_size;
    sb->regions = sb->max_regions = 1;

    if (cfg->buf_size == 0) {
        return sb;
    }

    int r = InitBuffer(sb, cfg);
    if (r != SC_OK) {
        FREE(cfg, sb, sizeof(StreamingBuffer));
        sc_errno = r;
        return NULL;
    }
    return sb;
}

void StreamingBufferClear(StreamingBuffer *sb, const StreamingBufferConfig *cfg)
{
    if (sb != NULL) {
        SCLogDebug("sb->region.buf_size %u max %u", sb->region.buf_size, sb->buf_size_max);

        SBBFree(sb, cfg);
        ListRegions(sb);
        if (sb->region.buf != NULL) {
            FREE(cfg, sb->region.buf, sb->region.buf_size);
            sb->region.buf = NULL;
        }

        for (StreamingBufferRegion *r = sb->region.next; r != NULL;) {
            StreamingBufferRegion *next = r->next;
            FREE(cfg, r->buf, r->buf_size);
            FREE(cfg, r, sizeof(*r));
            r = next;
        }
        sb->region.next = NULL;
        sb->regions = sb->max_regions = 1;
    }
}

void StreamingBufferFree(StreamingBuffer *sb, const StreamingBufferConfig *cfg)
{
    if (sb != NULL) {
        StreamingBufferClear(sb, cfg);
        FREE(cfg, sb, sizeof(StreamingBuffer));
    }
}

#ifdef DEBUG
static void SBBPrintList(StreamingBuffer *sb)
{
    StreamingBufferBlock *sbb = NULL;
    RB_FOREACH(sbb, SBB, &sb->sbb_tree) {
        SCLogDebug("sbb: offset %" PRIu64 ", len %u", sbb->offset, sbb->len);
        StreamingBufferBlock *next = SBB_RB_NEXT(sbb);
        if (next) {
            if ((sbb->offset + sbb->len) != next->offset) {
                SCLogDebug("gap: offset %" PRIu64 ", len %" PRIu64, (sbb->offset + sbb->len),
                        next->offset - (sbb->offset + sbb->len));
            }
        }
    }
}
#endif

/* setup with gap between 2 blocks
 *
 * [block][gap][block]
 **/
static int WARN_UNUSED SBBInit(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferRegion *region, uint32_t rel_offset, uint32_t data_len)
{
    DEBUG_VALIDATE_BUG_ON(!RB_EMPTY(&sb->sbb_tree));
    DEBUG_VALIDATE_BUG_ON(region->buf_offset > region->stream_offset + rel_offset);

    /* need to set up 2: existing data block and new data block */
    StreamingBufferBlock *sbb = CALLOC(cfg, 1, sizeof(*sbb));
    if (sbb == NULL) {
        return sc_errno;
    }
    sbb->offset = sb->region.stream_offset;
    sbb->len = sb->region.buf_offset;
    (void)SBB_RB_INSERT(&sb->sbb_tree, sbb);
    sb->head = sbb;
    sb->sbb_size = sbb->len;

    StreamingBufferBlock *sbb2 = CALLOC(cfg, 1, sizeof(*sbb2));
    if (sbb2 == NULL) {
        return sc_errno;
    }
    sbb2->offset = region->stream_offset + rel_offset;
    sbb2->len = data_len;
    DEBUG_VALIDATE_BUG_ON(sbb2->offset < sbb->len);
    SCLogDebug("sbb1 %" PRIu64 ", len %u, sbb2 %" PRIu64 ", len %u", sbb->offset, sbb->len,
            sbb2->offset, sbb2->len);

    sb->sbb_size += sbb2->len;
    if (SBB_RB_INSERT(&sb->sbb_tree, sbb2) != NULL) {
        FREE(cfg, sbb2, sizeof(*sbb2));
        return SC_EINVAL;
    }

#ifdef DEBUG
    SBBPrintList(sb);
#endif
    return SC_OK;
}

/* setup with leading gap
 *
 * [gap][block]
 **/
static int WARN_UNUSED SBBInitLeadingGap(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferRegion *region, uint64_t offset, uint32_t data_len)
{
    DEBUG_VALIDATE_BUG_ON(!RB_EMPTY(&sb->sbb_tree));

    StreamingBufferBlock *sbb = CALLOC(cfg, 1, sizeof(*sbb));
    if (sbb == NULL) {
        return sc_errno;
    }
    sbb->offset = offset;
    sbb->len = data_len;

    sb->head = sbb;
    sb->sbb_size = sbb->len;
    (void)SBB_RB_INSERT(&sb->sbb_tree, sbb);

    SCLogDebug("sbb %" PRIu64 ", len %u", sbb->offset, sbb->len);
#ifdef DEBUG
    SBBPrintList(sb);
#endif
    return SC_OK;
}

static inline void ConsolidateFwd(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferRegion *region, struct SBB *tree, StreamingBufferBlock *sa)
{
    uint64_t sa_re = sa->offset + sa->len;
    StreamingBufferBlock *tr, *s = sa;
    RB_FOREACH_FROM(tr, SBB, s) {
        if (sa == tr)
            continue;

        const uint64_t tr_re = tr->offset + tr->len;
        SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u re %" PRIu64, tr, tr->offset, tr->len, tr_re);

        if (sa_re < tr->offset) {
            SCLogDebug("entirely before: %" PRIu64 " < %" PRIu64, sa_re, tr->offset);
            break; // entirely before
        }

        /* new block (sa) entirely eclipsed by in tree block (tr)
            sa:     [   ]
            tr: [           ]
            sa:     [   ]
            tr:     [       ]
            sa:     [   ]
            tr: [       ]
        */
        if (sa->offset >= tr->offset && sa_re <= tr_re) {
            sb->sbb_size -= sa->len;
            sa->len = tr->len;
            sa->offset = tr->offset;
            sa_re = sa->offset + sa->len;
            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u REMOVED ECLIPSED (sa overlapped by tr)", tr,
                    tr->offset, tr->len);
            SBB_RB_REMOVE(tree, tr);
            FREE(cfg, tr, sizeof(StreamingBufferBlock));
            /* new block (sa) entire eclipses in tree block (tr)
                sa: [         ]
                tr: [         ]
                sa: [         ]
                tr:    [      ]
                sa: [         ]
                tr:    [   ]
            */
        } else if (sa->offset <= tr->offset && sa_re >= tr_re) {
            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u REMOVED ECLIPSED (tr overlapped by sa)", tr,
                    tr->offset, tr->len);
            SBB_RB_REMOVE(tree, tr);
            sb->sbb_size -= tr->len;
            FREE(cfg, tr, sizeof(StreamingBufferBlock));

            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64 " bo %u sz %u", sa,
                    sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                    region->buf_size);
            if (sa->offset == region->stream_offset &&
                    sa_re > (region->stream_offset + region->buf_offset)) {
                DEBUG_VALIDATE_BUG_ON(sa_re < region->stream_offset);
                region->buf_offset = sa_re - region->stream_offset;
                SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64
                           " bo %u sz %u BUF_OFFSET UPDATED",
                        sa, sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                        region->buf_size);
            }
            /* new block (sa) extended by in tree block (tr)
                sa: [         ]
                tr:      [         ]
                sa: [       ]
                tr:         [       ]
            */
        } else if (sa->offset < tr->offset && // starts before
                   sa_re >= tr->offset && sa_re < tr_re) // ends inside
        {
            // merge. sb->sbb_size includes both so we need to adjust that too.
            uint32_t combined_len = sa->len + tr->len;
            sa->len = tr_re - sa->offset;
            sa_re = sa->offset + sa->len;
            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u REMOVED MERGED", tr, tr->offset, tr->len);
            SBB_RB_REMOVE(tree, tr);
            sb->sbb_size -= (combined_len - sa->len); // remove what we added twice
            FREE(cfg, tr, sizeof(StreamingBufferBlock));
            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u RESULT", sa, sa->offset, sa->len);
            SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64 " bo %u sz %u", sa,
                    sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                    region->buf_size);
            if (sa->offset == region->stream_offset &&
                    sa_re > (region->stream_offset + region->buf_offset)) {
                DEBUG_VALIDATE_BUG_ON(sa_re < region->stream_offset);
                region->buf_offset = sa_re - region->stream_offset;
                SCLogDebug("-> (fwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64
                           " bo %u sz %u BUF_OFFSET UPDATED",
                        sa, sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                        region->buf_size);
            }
        }
    }
}

static inline void ConsolidateBackward(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferRegion *region, struct SBB *tree, StreamingBufferBlock *sa)
{
    uint64_t sa_re = sa->offset + sa->len;
    StreamingBufferBlock *tr, *s = sa;
    RB_FOREACH_REVERSE_FROM(tr, SBB, s) {
        if (sa == tr)
            continue;
        const uint64_t tr_re = tr->offset + tr->len;
        SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u", tr, tr->offset, tr->len);

        if (sa->offset > tr_re)
            break; // entirely after

        /* new block (sa) entirely eclipsed by in tree block (tr)
            sa: [         ]
            tr: [         ]
            sa:    [      ]
            tr: [         ]
            sa:    [   ]
            tr: [         ]
        */
        if (sa->offset >= tr->offset && sa_re <= tr_re) {
            sb->sbb_size -= sa->len; // sa entirely eclipsed so remove double accounting
            sa->len = tr->len;
            sa->offset = tr->offset;
            sa_re = sa->offset + sa->len;
            SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u REMOVED ECLIPSED (sa overlapped by tr)", tr,
                    tr->offset, tr->len);
            if (sb->head == tr)
                sb->head = sa;
            SBB_RB_REMOVE(tree, tr);
            FREE(cfg, tr, sizeof(StreamingBufferBlock));
            /* new block (sa) entire eclipses in tree block (tr)
                sa: [         ]
                tr:    [      ]
                sa: [         ]
                tr: [      ]
                sa: [         ]
                tr:    [    ]
            */
        } else if (sa->offset <= tr->offset && sa_re >= tr_re) {
            SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u REMOVED ECLIPSED (tr overlapped by sa)", tr,
                    tr->offset, tr->len);
            if (sb->head == tr)
                sb->head = sa;
            SBB_RB_REMOVE(tree, tr);
            sb->sbb_size -= tr->len; // tr entirely eclipsed so remove double accounting
            FREE(cfg, tr, sizeof(StreamingBufferBlock));

            SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64 " bo %u sz %u", sa,
                    sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                    region->buf_size);

            if (sa->offset == region->stream_offset &&
                    sa_re > (region->stream_offset + region->buf_offset)) {
                DEBUG_VALIDATE_BUG_ON(sa_re < region->stream_offset);
                region->buf_offset = sa_re - region->stream_offset;
                SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64
                           " bo %u sz %u BUF_OFFSET UPDATED",
                        sa, sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                        region->buf_size);
            }

            /* new block (sa) extends in tree block (tr)
                sa:     [   ]
                tr: [   ]
                sa:    [    ]
                tr: [   ]
            */
        } else if (sa->offset > tr->offset && sa_re > tr_re && sa->offset <= tr_re) {
            // merge. sb->sbb_size includes both so we need to adjust that too.
            uint32_t combined_len = sa->len + tr->len;
            sa->len = sa_re - tr->offset;
            sa->offset = tr->offset;
            sa_re = sa->offset + sa->len;
            SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u REMOVED MERGED", tr, tr->offset, tr->len);
            if (sb->head == tr)
                sb->head = sa;
            SBB_RB_REMOVE(tree, tr);
            sb->sbb_size -= (combined_len - sa->len); // remove what we added twice
            FREE(cfg, tr, sizeof(StreamingBufferBlock));

            SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64 " bo %u sz %u", sa,
                    sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                    region->buf_size);
            if (sa->offset == region->stream_offset &&
                    sa_re > (region->stream_offset + region->buf_offset)) {
                DEBUG_VALIDATE_BUG_ON(sa_re < region->stream_offset);
                region->buf_offset = sa_re - region->stream_offset;
                SCLogDebug("-> (bwd) tr %p %" PRIu64 "/%u region %p so %" PRIu64
                           " bo %u sz %u BUF_OFFSET UPDATED",
                        sa, sa->offset, sa->len, region, region->stream_offset, region->buf_offset,
                        region->buf_size);
            }
        }
    }
}

/** \internal
 *  \param region the region that holds the new data
 */
static int SBBUpdate(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferRegion *region, uint32_t rel_offset, uint32_t len)
{
    struct SBB *tree = &sb->sbb_tree;
    SCLogDebug("* inserting: %u/%u", rel_offset, len);

    StreamingBufferBlock *sbb = CALLOC(cfg, 1, sizeof(*sbb));
    if (sbb == NULL) {
        return sc_errno;
    }
    sbb->offset = region->stream_offset + rel_offset;
    sbb->len = len;

    StreamingBufferBlock *res = SBB_RB_INSERT(tree, sbb);
    if (res) {
        // exact overlap
        SCLogDebug("* insert failed: exact match in tree with %p %" PRIu64 "/%u", res, res->offset,
                res->len);
        FREE(cfg, sbb, sizeof(StreamingBufferBlock));
        return SC_OK;
    }
    sb->sbb_size += len; // may adjust based on consolidation below

    /* handle backwards and forwards overlaps */
    if (SBB_RB_PREV(sbb) == NULL) {
        sb->head = sbb;
    } else {
        ConsolidateBackward(sb, cfg, region, tree, sbb);
    }
    ConsolidateFwd(sb, cfg, region, tree, sbb);
#ifdef DEBUG
    SBBPrintList(sb);
#endif
    if (sbb->offset == region->stream_offset) {
        SCLogDebug("insert at region head");
        region->buf_offset = sbb->len;
    }
    return SC_OK;
}

static void SBBFree(StreamingBuffer *sb, const StreamingBufferConfig *cfg)
{
    StreamingBufferBlock *sbb = NULL, *safe = NULL;
    RB_FOREACH_SAFE(sbb, SBB, &sb->sbb_tree, safe) {
        SBB_RB_REMOVE(&sb->sbb_tree, sbb);
        sb->sbb_size -= sbb->len;
        FREE(cfg, sbb, sizeof(StreamingBufferBlock));
    }
    sb->head = NULL;
}

static void SBBPrune(StreamingBuffer *sb, const StreamingBufferConfig *cfg)
{
    SCLogDebug("pruning %p to %" PRIu64, sb, sb->region.stream_offset);
    StreamingBufferBlock *sbb = NULL, *safe = NULL;
    RB_FOREACH_SAFE(sbb, SBB, &sb->sbb_tree, safe) {
        /* completely beyond window, we're done */
        if (sbb->offset >= sb->region.stream_offset) {
            sb->head = sbb;
            if (sbb->offset == sb->region.stream_offset) {
                SCLogDebug("set buf_offset?");
                if (sbb->offset == sb->region.stream_offset) {
                    SCLogDebug("set buf_offset to first sbb len %u", sbb->len);
                    DEBUG_VALIDATE_BUG_ON(sbb->len > sb->region.buf_size);
                    sb->region.buf_offset = sbb->len;
                }
            }
            break;
        }

        /* partly before, partly beyond. Adjust */
        if (sbb->offset < sb->region.stream_offset &&
                sbb->offset + sbb->len > sb->region.stream_offset) {
            uint32_t shrink_by = sb->region.stream_offset - sbb->offset;
            DEBUG_VALIDATE_BUG_ON(shrink_by > sbb->len);
            if (sbb->len >= shrink_by) {
                sbb->len -=  shrink_by;
                sbb->offset += shrink_by;
                sb->sbb_size -= shrink_by;
                SCLogDebug("shrunk by %u", shrink_by);
                DEBUG_VALIDATE_BUG_ON(sbb->offset != sb->region.stream_offset);
            }
            sb->head = sbb;
            if (sbb->offset == sb->region.stream_offset) {
                SCLogDebug("set buf_offset to first sbb len %u", sbb->len);
                DEBUG_VALIDATE_BUG_ON(sbb->len > sb->region.buf_size);
                sb->region.buf_offset = sbb->len;
            }
            break;
        }

        SBB_RB_REMOVE(&sb->sbb_tree, sbb);
        /* either we set it again for the next sbb, or there isn't any */
        sb->head = NULL;
        sb->sbb_size -= sbb->len;
        SCLogDebug("sb %p removed %p %" PRIu64 ", %u", sb, sbb, sbb->offset, sbb->len);
        FREE(cfg, sbb, sizeof(StreamingBufferBlock));
    }
#ifdef DEBUG
    SBBPrintList(sb);
#endif
}

static inline uint32_t ToNextMultipleOf(const uint32_t in, const uint32_t m)
{
    uint32_t r = in;
    if (m > 0) {
        const uint32_t x = in % m;
        if (x != 0) {
            r = (in - x) + m;
        }
    }
    return r;
}

static thread_local bool g2s_warn_once = false;

static inline int WARN_UNUSED GrowRegionToSize(StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, StreamingBufferRegion *region, const uint32_t size)
{
    DEBUG_VALIDATE_BUG_ON(region->buf_size > BIT_U32(30));
    if (size > BIT_U32(30)) { // 1GiB
        if (!g2s_warn_once) {
            SCLogWarning("StreamingBuffer::GrowRegionToSize() tried to alloc %u bytes, exceeds "
                         "limit of %lu",
                    size, BIT_U32(30));
            g2s_warn_once = true;
        }
        return SC_ELIMIT;
    }

    /* try to grow in multiples of cfg->buf_size */
    const uint32_t grow = ToNextMultipleOf(size, cfg->buf_size);
    SCLogDebug("grow %u", grow);

    void *ptr = REALLOC(cfg, region->buf, region->buf_size, grow);
    if (ptr == NULL) {
        if (sc_errno == SC_OK)
            sc_errno = SC_ENOMEM;
        return sc_errno;
    }
    /* for safe printing and general caution, lets memset the
     * new data to 0 */
    size_t diff = grow - region->buf_size;
    void *new_mem = ((char *)ptr) + region->buf_size;
    memset(new_mem, 0, diff);

    region->buf = ptr;
    region->buf_size = grow;
    SCLogDebug("grown buffer to %u", grow);
#ifdef DEBUG
    if (region->buf_size > sb->buf_size_max) {
        sb->buf_size_max = region->buf_size;
    }
#endif
    return SC_OK;
}

static int WARN_UNUSED GrowToSize(
        StreamingBuffer *sb, const StreamingBufferConfig *cfg, uint32_t size)
{
    return GrowRegionToSize(sb, cfg, &sb->region, size);
}

static inline bool RegionBeforeOffset(const StreamingBufferRegion *r, const uint64_t o)
{
    return (r->stream_offset + r->buf_size <= o);
}

static inline bool RegionContainsOffset(const StreamingBufferRegion *r, const uint64_t o)
{
    return (o >= r->stream_offset && (r->stream_offset + r->buf_size) >= o);
}

/** \internal
 *  \brief slide to offset for regions
 *
 *
 *     [ main ] [ gap ] [ aux ] [ gap ] [ aux ]
 *                 ^
 *     - main reset to 0
 *
 *
 *     [ main ] [ gap ] [ aux ] [ gap ] [ aux ]
 *         ^
 *     - main shift
 *
 *     [ main ] [ gap ] [ aux ] [ gap ] [ aux ]
 *                          ^
 *     - main reset
 *     - move aux into main
 *     - free aux
 *     - shift
 *
 *     [ main ] [ gap ] [ aux ] [ gap ] [ aux ]
 *                      ^
 *     - main reset
 *     - move aux into main
 *     - free aux
 *     - no shift
 */
static inline void StreamingBufferSlideToOffsetWithRegions(
        StreamingBuffer *sb, const StreamingBufferConfig *cfg, const uint64_t slide_offset)
{
    ListRegions(sb);
    DEBUG_VALIDATE_BUG_ON(slide_offset == sb->region.stream_offset);

    SCLogDebug("slide_offset %" PRIu64, slide_offset);
    SCLogDebug("main: offset %" PRIu64 " buf %p size %u offset %u", sb->region.stream_offset,
            sb->region.buf, sb->region.buf_size, sb->region.buf_offset);

    StreamingBufferRegion *to_shift = NULL;
    const bool main_is_oow = RegionBeforeOffset(&sb->region, slide_offset);
    if (main_is_oow) {
        SCLogDebug("main_is_oow");
        if (sb->region.buf != NULL) {
            SCLogDebug("clearing main");
            FREE(cfg, sb->region.buf, sb->region.buf_size);
            sb->region.buf = NULL;
            sb->region.buf_size = 0;
            sb->region.buf_offset = 0;
            sb->region.stream_offset = slide_offset;
        } else {
            sb->region.stream_offset = slide_offset;
        }

        /* remove regions that are out of window & select the region to
         * become the new main */
        StreamingBufferRegion *prev = &sb->region;
        for (StreamingBufferRegion *r = sb->region.next; r != NULL;) {
            SCLogDebug("r %p so %" PRIu64 ", re %" PRIu64, r, r->stream_offset,
                    r->stream_offset + r->buf_offset);
            StreamingBufferRegion *next = r->next;
            if (RegionBeforeOffset(r, slide_offset)) {
                SCLogDebug("r %p so %" PRIu64 ", re %" PRIu64 " -> before", r, r->stream_offset,
                        r->stream_offset + r->buf_offset);
                DEBUG_VALIDATE_BUG_ON(r == &sb->region);
                prev->next = next;

                FREE(cfg, r->buf, r->buf_size);
                FREE(cfg, r, sizeof(*r));
                sb->regions--;
                DEBUG_VALIDATE_BUG_ON(sb->regions == 0);
            } else if (RegionContainsOffset(r, slide_offset)) {
                SCLogDebug("r %p so %" PRIu64 ", re %" PRIu64 " -> within", r, r->stream_offset,
                        r->stream_offset + r->buf_offset);
                /* remove from list, we will xfer contents to main below */
                prev->next = next;
                to_shift = r;
                break;
            } else {
                SCLogDebug("r %p so %" PRIu64 ", re %" PRIu64 " -> post", r, r->stream_offset,
                        r->stream_offset + r->buf_offset);
                /* implied beyond slide offset */
                DEBUG_VALIDATE_BUG_ON(r->stream_offset < slide_offset);
                break;
            }
            r = next;
        }
        SCLogDebug("to_shift %p", to_shift);

        // this region is main, or will xfer its buffer to main
        if (to_shift && to_shift != &sb->region) {
            SCLogDebug("main: offset %" PRIu64 " buf %p size %u offset %u", to_shift->stream_offset,
                    to_shift->buf, to_shift->buf_size, to_shift->buf_offset);
            DEBUG_VALIDATE_BUG_ON(sb->region.buf != NULL);

            sb->region.buf = to_shift->buf;
            sb->region.stream_offset = to_shift->stream_offset;
            sb->region.buf_offset = to_shift->buf_offset;
            sb->region.buf_size = to_shift->buf_size;
            sb->region.next = to_shift->next;

            BUG_ON(to_shift == &sb->region);
            FREE(cfg, to_shift, sizeof(*to_shift));
            to_shift = &sb->region;
            sb->regions--;
            DEBUG_VALIDATE_BUG_ON(sb->regions == 0);
        }

    } else {
        to_shift = &sb->region;
        SCLogDebug("shift start region %p", to_shift);
    }

    // this region is main, or will xfer its buffer to main
    if (to_shift) {
        // Do the shift. If new region is exactly at the slide offset we can skip this.
        DEBUG_VALIDATE_BUG_ON(to_shift->stream_offset > slide_offset);
        const uint32_t s = slide_offset - to_shift->stream_offset;
        if (s > 0) {
            const uint32_t new_data_size = to_shift->buf_size - s;
            uint32_t new_mem_size = ToNextMultipleOf(new_data_size, cfg->buf_size);

            /* see if after the slide we'd overlap with the next region. If so, we need
             * to consolidate them into one. Error handling is a bit peculiar. We need
             * to grow a region, move data from another region into it, then free the
             * other region. This could fail if we're close to the memcap. In this case
             * we relax our rounding up logic so we only shrink and don't merge the 2
             * regions after all. */
            if (to_shift->next && slide_offset + new_mem_size >= to_shift->next->stream_offset) {
                StreamingBufferRegion *start = to_shift;
                StreamingBufferRegion *next = start->next;
                const uint64_t next_re = next->stream_offset + next->buf_size;
                const uint32_t mem_size = ToNextMultipleOf(next_re - slide_offset, cfg->buf_size);

                /* using next as the new main */
                if (start->buf_size < next->buf_size) {
                    SCLogDebug("replace main with the next bigger region");

                    const uint32_t next_data_offset = next->stream_offset - slide_offset;
                    const uint32_t prev_buf_size = next->buf_size;
                    const uint32_t start_data_offset = slide_offset - start->stream_offset;
                    DEBUG_VALIDATE_BUG_ON(start_data_offset > start->buf_size);
                    if (start_data_offset > start->buf_size) {
                        new_mem_size = new_data_size;
                        goto just_main;
                    }
                    /* expand "next" to include relevant part of "start" */
                    if (GrowRegionToSize(sb, cfg, next, mem_size) != 0) {
                        new_mem_size = new_data_size;
                        goto just_main;
                    }
                    SCLogDebug("region now sized %u", mem_size);

                    // slide "next":
                    // pre-grow: [nextnextnext]
                    // post-grow [nextnextnextXXX]
                    // post-move [XXXnextnextnext]
                    memmove(next->buf + next_data_offset, next->buf, prev_buf_size);

                    // move portion of "start" into "next"
                    //
                    // start: [ooooookkkkk] (o: old, k: keep)
                    // pre-next     [xxxxxnextnextnext]
                    // post-next    [kkkkknextnextnext]
                    const uint32_t start_data_size = start->buf_size - start_data_offset;
                    memcpy(next->buf, start->buf + start_data_offset, start_data_size);

                    // free "start"s buffer, we will use the one from "next"
                    FREE(cfg, start->buf, start->buf_size);

                    // update "main" to use "next"
                    start->stream_offset = slide_offset;
                    start->buf = next->buf;
                    start->buf_size = next->buf_size;
                    start->next = next->next;

                    // free "next"
                    FREE(cfg, next, sizeof(*next));
                    sb->regions--;
                    DEBUG_VALIDATE_BUG_ON(sb->regions == 0);
                    goto done;
                } else {
                    /* using "main", expand to include "next" */
                    if (GrowRegionToSize(sb, cfg, start, mem_size) != 0) {
                        new_mem_size = new_data_size;
                        goto just_main;
                    }
                    SCLogDebug("start->buf now size %u", mem_size);

                    // slide "start"
                    // pre:     [xxxxxxxAAA]
                    // post:    [AAAxxxxxxx]
                    SCLogDebug("s %u new_data_size %u", s, new_data_size);
                    memmove(start->buf, start->buf + s, new_data_size);

                    // copy in "next"
                    // pre:     [AAAxxxxxxx]
                    //             [BBBBBBB]
                    // post:    [AAABBBBBBB]
                    SCLogDebug("copy next->buf %p/%u to start->buf offset %u", next->buf,
                            next->buf_size, new_data_size);
                    memcpy(start->buf + new_data_size, next->buf, next->buf_size);

                    start->stream_offset = slide_offset;
                    start->next = next->next;

                    // free "next"
                    FREE(cfg, next->buf, next->buf_size);
                    FREE(cfg, next, sizeof(*next));
                    sb->regions--;
                    DEBUG_VALIDATE_BUG_ON(sb->regions == 0);
                    goto done;
                }
            }

        just_main:
            SCLogDebug("s %u new_data_size %u", s, new_data_size);
            memmove(to_shift->buf, to_shift->buf + s, new_data_size);
            /* shrink memory region. If this fails we keep the old */
            void *ptr = REALLOC(cfg, to_shift->buf, to_shift->buf_size, new_mem_size);
            if (ptr != NULL) {
                to_shift->buf = ptr;
                to_shift->buf_size = new_mem_size;
                SCLogDebug("new buf_size %u", to_shift->buf_size);
            }
            if (s < to_shift->buf_offset)
                to_shift->buf_offset -= s;
            else
                to_shift->buf_offset = 0;
            to_shift->stream_offset = slide_offset;
        }
    }

done:
    SCLogDebug("main: offset %" PRIu64 " buf %p size %u offset %u", sb->region.stream_offset,
            sb->region.buf, sb->region.buf_size, sb->region.buf_offset);
    SCLogDebug("end of slide");
}

/**
 *  \brief slide to absolute offset
 *  \todo if sliding beyond window, we could perhaps reset?
 */
void StreamingBufferSlideToOffset(
        StreamingBuffer *sb, const StreamingBufferConfig *cfg, uint64_t offset)
{
    SCLogDebug("sliding to offset %" PRIu64, offset);
    ListRegions(sb);
#ifdef DEBUG
    SBBPrintList(sb);
#endif

    if (sb->region.next) {
        StreamingBufferSlideToOffsetWithRegions(sb, cfg, offset);
        SBBPrune(sb, cfg);
        SCLogDebug("post SBBPrune");
        ListRegions(sb);
#ifdef DEBUG
        SBBPrintList(sb);
#endif
        DEBUG_VALIDATE_BUG_ON(sb->region.buf != NULL && sb->region.buf_size == 0);
        DEBUG_VALIDATE_BUG_ON(sb->region.buf_offset > sb->region.buf_size);
        DEBUG_VALIDATE_BUG_ON(offset > sb->region.stream_offset);
        DEBUG_VALIDATE_BUG_ON(sb->head && sb->head->offset == sb->region.stream_offset &&
                              sb->head->len > sb->region.buf_offset);
        DEBUG_VALIDATE_BUG_ON(sb->region.stream_offset < offset);
        return;
    }

    if (offset > sb->region.stream_offset) {
        const uint32_t slide = offset - sb->region.stream_offset;
        if (sb->head != NULL) {
            /* have sbb's, so can't rely on buf_offset for the slide */
            if (slide < sb->region.buf_size) {
                const uint32_t size = sb->region.buf_size - slide;
                SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide,
                        size);
                memmove(sb->region.buf, sb->region.buf + slide, size);
                if (sb->region.buf_offset > slide) {
                    sb->region.buf_offset -= slide;
                } else {
                    sb->region.buf_offset = 0;
                }
            } else {
                sb->region.buf_offset = 0;
            }
            sb->region.stream_offset = offset;
        } else {
            /* no sbb's, so we can use buf_offset */
            if (offset <= sb->region.stream_offset + sb->region.buf_offset) {
                const uint32_t size = sb->region.buf_offset - slide;
                SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide,
                        size);
                memmove(sb->region.buf, sb->region.buf + slide, size);
                sb->region.stream_offset = offset;
                sb->region.buf_offset = size;
            } else {
                /* moved past all data */
                sb->region.stream_offset = offset;
                sb->region.buf_offset = 0;
            }
        }
        SBBPrune(sb, cfg);
    }
#ifdef DEBUG
    SBBPrintList(sb);
#endif
    DEBUG_VALIDATE_BUG_ON(sb->region.stream_offset < offset);
}

static int DataFits(const StreamingBuffer *sb, const uint32_t len)
{
    uint64_t buf_offset64 = sb->region.buf_offset;
    uint64_t len64 = len;
    if (len64 + buf_offset64 > UINT32_MAX) {
        return -1;
    }
    return sb->region.buf_offset + len <= sb->region.buf_size;
}

int StreamingBufferAppend(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferSegment *seg, const uint8_t *data, uint32_t data_len)
{
    DEBUG_VALIDATE_BUG_ON(seg == NULL);
    DEBUG_VALIDATE_BUG_ON(data_len > BIT_U32(27)); // 128MiB is excessive already

    if (sb->region.buf == NULL) {
        if (InitBuffer(sb, cfg) == -1)
            return -1;
    }

    int r = DataFits(sb, data_len);
    if (r < 0) {
        DEBUG_VALIDATE_BUG_ON(1);
        return -1;
    } else if (r == 0) {
        if (sb->region.buf_size == 0) {
            if (GrowToSize(sb, cfg, data_len) != SC_OK)
                return -1;
        } else {
            if (GrowToSize(sb, cfg, sb->region.buf_offset + data_len) != SC_OK)
                return -1;
        }
    }
    DEBUG_VALIDATE_BUG_ON(DataFits(sb, data_len) != 1);

    memcpy(sb->region.buf + sb->region.buf_offset, data, data_len);
    seg->stream_offset = sb->region.stream_offset + sb->region.buf_offset;
    seg->segment_len = data_len;
    uint32_t rel_offset = sb->region.buf_offset;
    sb->region.buf_offset += data_len;

    if (!RB_EMPTY(&sb->sbb_tree)) {
        return SBBUpdate(sb, cfg, &sb->region, rel_offset, data_len);
    } else {
        return 0;
    }
}

/**
 *  \brief add data w/o tracking a segment
 */
int StreamingBufferAppendNoTrack(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        const uint8_t *data, uint32_t data_len)
{
    DEBUG_VALIDATE_BUG_ON(data_len > BIT_U32(27)); // 128MiB is excessive already

    if (sb->region.buf == NULL) {
        if (InitBuffer(sb, cfg) == -1)
            return -1;
    }

    int r = DataFits(sb, data_len);
    if (r < 0) {
        DEBUG_VALIDATE_BUG_ON(1);
        return -1;
    } else if (r == 0) {
        if (sb->region.buf_size == 0) {
            if (GrowToSize(sb, cfg, data_len) != SC_OK)
                return -1;
        } else {
            if (GrowToSize(sb, cfg, sb->region.buf_offset + data_len) != SC_OK)
                return -1;
        }
    }
    DEBUG_VALIDATE_BUG_ON(DataFits(sb, data_len) != 1);

    memcpy(sb->region.buf + sb->region.buf_offset, data, data_len);
    uint32_t rel_offset = sb->region.buf_offset;
    sb->region.buf_offset += data_len;

    if (!RB_EMPTY(&sb->sbb_tree)) {
        return SBBUpdate(sb, cfg, &sb->region, rel_offset, data_len);
    } else {
        return 0;
    }
}

static int DataFitsAtOffset(
        const StreamingBufferRegion *region, const uint32_t len, const uint32_t offset)
{
    const uint64_t offset64 = offset;
    const uint64_t len64 = len;
    if (offset64 + len64 > UINT32_MAX)
        return -1;
    return (offset + len <= region->buf_size);
}

#if defined(DEBUG) || defined(DEBUG_VALIDATION)
static void Validate(const StreamingBuffer *sb)
{
    bool bail = false;
    uint32_t cnt = 0;
    for (const StreamingBufferRegion *r = &sb->region; r != NULL; r = r->next) {
        cnt++;
        if (r->next) {
            bail |= ((r->stream_offset + r->buf_size) > r->next->stream_offset);
        }

        bail |= (r->buf != NULL && r->buf_size == 0);
        bail |= (r->buf_offset > r->buf_size);
    }
    // leading gap, so buf_offset should be 0?
    if (sb->head && sb->head->offset > sb->region.stream_offset) {
        SCLogDebug("leading gap of size %" PRIu64, sb->head->offset - sb->region.stream_offset);
        BUG_ON(sb->region.buf_offset != 0);
    }

    if (sb->head && sb->head->offset == sb->region.stream_offset) {
        BUG_ON(sb->head->len > sb->region.buf_offset);
        BUG_ON(sb->head->len < sb->region.buf_offset);
    }
    BUG_ON(sb->regions != cnt);
    BUG_ON(bail);
}
#endif

static void ListRegions(StreamingBuffer *sb)
{
    if (sb->region.buf == NULL && sb->region.buf_offset == 0 && sb->region.next == NULL)
        return;
#if defined(DEBUG) && DUMP_REGIONS == 1
    uint32_t cnt = 0;
    for (StreamingBufferRegion *r = &sb->region; r != NULL; r = r->next) {
        cnt++;
        char gap[64] = "";
        if (r->next) {
            snprintf(gap, sizeof(gap), "[ gap:%" PRIu64 " ]",
                    r->next->stream_offset - (r->stream_offset + r->buf_size));
        }

        printf("[ %s offset:%" PRIu64 " size:%u offset:%u ]%s", r == &sb->region ? "main" : "aux",
                r->stream_offset, r->buf_size, r->buf_offset, gap);
    }
    printf("(max %u, cnt %u, sb->regions %u)\n", sb->max_regions, cnt, sb->regions);
    bool at_least_one = false;
    uint64_t last_re = sb->region.stream_offset;
    StreamingBufferBlock *sbb = NULL;
    RB_FOREACH(sbb, SBB, &sb->sbb_tree)
    {
        if (last_re != sbb->offset) {
            printf("[ gap:%" PRIu64 " ]", sbb->offset - last_re);
        }
        printf("[ sbb offset:%" PRIu64 " len:%u ]", sbb->offset, sbb->len);
        at_least_one = true;
        last_re = sbb->offset + sbb->len;
    }
    if (at_least_one)
        printf("\n");
#endif
#if defined(DEBUG) || defined(DEBUG_VALIDATION)
    StreamingBufferBlock *sbb2 = NULL;
    RB_FOREACH(sbb2, SBB, &sb->sbb_tree)
    {
        const uint8_t *_data = NULL;
        uint32_t _data_len = 0;
        (void)StreamingBufferSBBGetData(sb, sbb2, &_data, &_data_len);
    }
    Validate(sb);
#endif
}

/** \internal
 *  \brief process insert by consolidating the affected regions into one
 *  \note sets sc_errno
 */
static StreamingBufferRegion *BufferInsertAtRegionConsolidate(StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, StreamingBufferRegion *dst,
        StreamingBufferRegion *src_start, StreamingBufferRegion *src_end,
        const uint64_t data_offset, const uint32_t data_len, StreamingBufferRegion *prev,
        uint32_t dst_buf_size)
{
    int retval;
#ifdef DEBUG
    const uint64_t data_re = data_offset + data_len;
    SCLogDebug("sb %p dst %p src_start %p src_end %p data_offset %" PRIu64
               "/data_len %u/data_re %" PRIu64,
            sb, dst, src_start, src_end, data_offset, data_len, data_re);
#endif

    // 1. determine size and offset for dst.
    const uint64_t dst_offset = MIN(src_start->stream_offset, data_offset);
    DEBUG_VALIDATE_BUG_ON(dst_offset < sb->region.stream_offset);
    const uint32_t dst_size = dst_buf_size;
    SCLogDebug("dst_size %u", dst_size);

    // 2. resize dst
    const uint32_t old_size = dst->buf_size;
    const uint32_t dst_copy_offset = dst->stream_offset - dst_offset;
#ifdef DEBUG
    const uint32_t old_offset = dst->buf_offset;
    SCLogDebug("old_size %u, old_offset %u, dst_copy_offset %u", old_size, old_offset,
            dst_copy_offset);
#endif
    if ((retval = GrowRegionToSize(sb, cfg, dst, dst_size)) != SC_OK) {
        sc_errno = retval;
        return NULL;
    }
    SCLogDebug("resized to %u -> %u", dst_size, dst->buf_size);
    /* validate that the size is exactly what we asked for */
    DEBUG_VALIDATE_BUG_ON(dst_size != dst->buf_size);
    if (dst_copy_offset != 0)
        memmove(dst->buf + dst_copy_offset, dst->buf, old_size);
    if (dst_offset != dst->stream_offset) {
        dst->stream_offset = dst_offset;
        // buf_offset no longer valid, reset.
        dst->buf_offset = 0;
    }

    uint32_t new_offset = src_start->buf_offset;
    if (data_offset == src_start->stream_offset + src_start->buf_offset) {
        new_offset += data_len;
    }

    bool start_is_main = false;
    if (src_start == &sb->region) {
        DEBUG_VALIDATE_BUG_ON(src_start->stream_offset != dst_offset);

        start_is_main = true;
        SCLogDebug("src_start is main region");
        if (src_start != dst)
            memcpy(dst->buf, src_start->buf, src_start->buf_offset);
        if (src_start == src_end) {
            SCLogDebug("src_start == src_end == main, we're done");
            DEBUG_VALIDATE_BUG_ON(src_start != dst);
            return src_start;
        }
        prev = src_start;
        src_start = src_start->next; // skip in the loop below
    }

    // 3. copy all regions from src_start to dst_start into the new region
    for (StreamingBufferRegion *r = src_start; r != NULL;) {
        SCLogDebug("r %p %" PRIu64 ", offset %u, len %u, %s, last %s", r, r->stream_offset,
                r->buf_offset, r->buf_size, r == &sb->region ? "main" : "aux",
                BOOL2STR(r == src_end));
        // skip dst
        if (r == dst) {
            SCLogDebug("skipping r %p as it is 'dst'", r);
            if (r == src_end)
                break;
            prev = r;
            r = r->next;
            continue;
        }
        const uint32_t target_offset = r->stream_offset - dst_offset;
        SCLogDebug("r %p: target_offset %u", r, target_offset);
        DEBUG_VALIDATE_BUG_ON(target_offset > dst->buf_size);
        DEBUG_VALIDATE_BUG_ON(target_offset + r->buf_size > dst->buf_size);
        memcpy(dst->buf + target_offset, r->buf, r->buf_size);

        StreamingBufferRegion *next = r->next;
        FREE(cfg, r->buf, r->buf_size);
        FREE(cfg, r, sizeof(*r));
        sb->regions--;
        DEBUG_VALIDATE_BUG_ON(sb->regions == 0);

        DEBUG_VALIDATE_BUG_ON(prev == NULL && src_start != &sb->region);
        if (prev != NULL) {
            SCLogDebug("setting prev %p next to %p (was %p)", prev, next, prev->next);
            prev->next = next;
        } else {
            SCLogDebug("no prev yet");
        }

        if (r == src_end)
            break;
        r = next;
    }

    /* special handling of main region being the start, but not the
     * region we expand. In this case we'll have main and dst. We will
     * move the buffer from dst into main and free dst. */
    if (start_is_main && dst != &sb->region) {
        DEBUG_VALIDATE_BUG_ON(sb->region.next != dst);
        SCLogDebug("start_is_main && dst != main region");
        FREE(cfg, sb->region.buf, sb->region.buf_size);
        sb->region.buf = dst->buf;
        sb->region.buf_size = dst->buf_size;
        sb->region.buf_offset = new_offset;
        SCLogDebug("sb->region.buf_offset set to %u", sb->region.buf_offset);
        sb->region.next = dst->next;
        FREE(cfg, dst, sizeof(*dst));
        dst = &sb->region;
        sb->regions--;
        DEBUG_VALIDATE_BUG_ON(sb->regions == 0);
    } else {
        SCLogDebug("dst: %p next %p", dst, dst->next);
    }

    SCLogDebug("returning dst %p stream_offset %" PRIu64 " buf_offset %u buf_size %u", dst,
            dst->stream_offset, dst->buf_offset, dst->buf_size);
    return dst;
}

/** \note sets sc_errno */
static StreamingBufferRegion *BufferInsertAtRegionDo(StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, const uint64_t offset, const uint32_t len)
{
    SCLogDebug("offset %" PRIu64 ", len %u", offset, len);
    StreamingBufferRegion *start_prev = NULL;
    StreamingBufferRegion *start =
            FindFirstRegionForOffset(sb, cfg, &sb->region, offset, len, &start_prev);
    if (start) {
        const uint64_t insert_re = offset + len;
        const uint64_t insert_start_offset = MIN(start->stream_offset, offset);
        uint64_t insert_adjusted_re = insert_re;

        SCLogDebug("start region %p/%" PRIu64 "/%u", start, start->stream_offset, start->buf_size);
        StreamingBufferRegion *big = FindLargestRegionForOffset(sb, cfg, start, offset, len);
        DEBUG_VALIDATE_BUG_ON(big == NULL);
        if (big == NULL) {
            sc_errno = SC_EINVAL;
            return NULL;
        }
        SCLogDebug("big region %p/%" PRIu64 "/%u", big, big->stream_offset, big->buf_size);
        StreamingBufferRegion *end = FindRightEdge(sb, cfg, big, offset, len);
        DEBUG_VALIDATE_BUG_ON(end == NULL);
        if (end == NULL) {
            sc_errno = SC_EINVAL;
            return NULL;
        }
        insert_adjusted_re = MAX(insert_adjusted_re, (end->stream_offset + end->buf_size));

        uint32_t new_buf_size =
                ToNextMultipleOf(insert_adjusted_re - insert_start_offset, cfg->buf_size);
        SCLogDebug("new_buf_size %u", new_buf_size);

        /* see if our new buf size + cfg->buf_size margin leads to an overlap with the next region.
         * If so, include that in the consolidation. */
        if (end->next != NULL && new_buf_size + insert_start_offset > end->next->stream_offset) {
            SCLogDebug("adjusted end from %p to %p", end, end->next);
            end = end->next;
            insert_adjusted_re = MAX(insert_adjusted_re, (end->stream_offset + end->buf_size));
            new_buf_size =
                    ToNextMultipleOf(insert_adjusted_re - insert_start_offset, cfg->buf_size);
            SCLogDebug("new_buf_size %u", new_buf_size);
        }

        SCLogDebug("end region %p/%" PRIu64 "/%u", end, end->stream_offset, end->buf_size);
        /* sets sc_errno */
        StreamingBufferRegion *ret = BufferInsertAtRegionConsolidate(
                sb, cfg, big, start, end, offset, len, start_prev, new_buf_size);
        return ret;
    } else {
        /* if there was no region we can use we add a new region and insert it */
        StreamingBufferRegion *append = &sb->region;
        for (StreamingBufferRegion *r = append; r != NULL; r = r->next) {
            if (r->stream_offset > offset) {
                break;
            } else {
                append = r;
            }
        }

        SCLogDebug("no matching region found, append to %p (%s)", append,
                append == &sb->region ? "main" : "aux");
        /* sets sc_errno */
        StreamingBufferRegion *add = InitBufferRegion(sb, cfg, len);
        if (add == NULL)
            return NULL;
        add->stream_offset = offset;
        add->next = append->next;
        append->next = add;
        SCLogDebug("new region %p offset %" PRIu64, add, add->stream_offset);
        return add;
    }
}

/** \internal
 *  \brief return the region to put the new data in
 *
 *  Will find an existing region, expand it if needed. If no existing region exists or is
 *  a good fit, it will try to set up a new region. If the region then overlaps or gets
 *  too close to the next, merge them.
 *
 *  \note sets sc_errno
 */
static StreamingBufferRegion *BufferInsertAtRegion(StreamingBuffer *sb,
        const StreamingBufferConfig *cfg, const uint8_t *data, const uint32_t data_len,
        const uint64_t data_offset)
{
    SCLogDebug("data_offset %" PRIu64 ", data_len %u, re %" PRIu64, data_offset, data_len,
            data_offset + data_len);
    ListRegions(sb);

    if (RegionsIntersect(cfg, &sb->region, data_offset, data_offset + data_len)) {
        SCLogDebug("data_offset %" PRIu64 ", data_len %u intersects with main region (next %p)",
                data_offset, data_len, sb->region.next);
        if (sb->region.next == NULL ||
                !RegionsIntersect(cfg, sb->region.next, data_offset, data_offset + data_len)) {
            SCLogDebug(
                    "data_offset %" PRIu64
                    ", data_len %u intersects with main region, no next or way before next region",
                    data_offset, data_len);
            if (sb->region.buf == NULL) {
                int r;
                if ((r = InitBuffer(sb, cfg)) != SC_OK) { // TODO init with size
                    sc_errno = r;
                    return NULL;
                }
            }
            return &sb->region;
        }
    } else if (sb->region.next == NULL) {
        /* InitBufferRegion sets sc_errno */
        StreamingBufferRegion *aux_r = sb->region.next = InitBufferRegion(sb, cfg, data_len);
        if (aux_r == NULL)
            return NULL;
        aux_r->stream_offset = data_offset;
        DEBUG_VALIDATE_BUG_ON(data_len > aux_r->buf_size);
        SCLogDebug("created new region %p with offset %" PRIu64 ", size %u", aux_r,
                aux_r->stream_offset, aux_r->buf_size);
        return aux_r;
    }
    /* BufferInsertAtRegionDo sets sc_errno */
    StreamingBufferRegion *blob = BufferInsertAtRegionDo(sb, cfg, data_offset, data_len);
    SCLogDebug("blob %p (%s)", blob, blob == &sb->region ? "main" : "aux");
    return blob;
}

/**
 *  \param offset offset relative to StreamingBuffer::stream_offset
 *
 *  \return SC_OK in case of success
 *  \return SC_E* errors otherwise
 */
int StreamingBufferInsertAt(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferSegment *seg, const uint8_t *data, uint32_t data_len, uint64_t offset)
{
    DEBUG_VALIDATE_BUG_ON(seg == NULL);
    DEBUG_VALIDATE_BUG_ON(data_len > BIT_U32(27)); // 128MiB is excessive already
    DEBUG_VALIDATE_BUG_ON(offset < sb->region.stream_offset);
    if (offset < sb->region.stream_offset) {
        return SC_EINVAL;
    }

    StreamingBufferRegion *region = BufferInsertAtRegion(sb, cfg, data, data_len, offset);
    if (region == NULL) {
        return sc_errno;
    }

    const bool region_is_main = region == &sb->region;

    SCLogDebug("inserting %" PRIu64 "/%u using %s region %p", offset, data_len,
            region == &sb->region ? "main" : "aux", region);

    uint32_t rel_offset = offset - region->stream_offset;
    int r = DataFitsAtOffset(region, data_len, rel_offset);
    if (r < 0) {
        DEBUG_VALIDATE_BUG_ON(1);
        return SC_ELIMIT;
    } else if (r == 0) {
        if ((r = GrowToSize(sb, cfg, (rel_offset + data_len))) != SC_OK)
            return r;
    }
    DEBUG_VALIDATE_BUG_ON(DataFitsAtOffset(region, data_len, rel_offset) != 1);

    SCLogDebug("offset %" PRIu64 " data_len %u, rel_offset %u into region offset %" PRIu64
               ", buf_offset %u, buf_size %u",
            offset, data_len, rel_offset, region->stream_offset, region->buf_offset,
            region->buf_size);
    memcpy(region->buf + rel_offset, data, data_len);
    seg->stream_offset = offset;
    seg->segment_len = data_len;

    SCLogDebug("rel_offset %u region->stream_offset %" PRIu64 ", buf_offset %u", rel_offset,
            region->stream_offset, region->buf_offset);

    if (RB_EMPTY(&sb->sbb_tree)) {
        SCLogDebug("empty sbb list");

        if (region_is_main) {
            if (sb->region.stream_offset == offset) {
                SCLogDebug("empty sbb list: block exactly what was expected, fall through");
                /* empty list, data is exactly what is expected (append),
                 * so do nothing.
                 * Update buf_offset if needed, but in case of overlaps it might be beyond us. */
                sb->region.buf_offset = MAX(sb->region.buf_offset, rel_offset + data_len);
            } else if ((rel_offset + data_len) <= sb->region.buf_offset) {
                SCLogDebug("empty sbb list: block is within existing main data region");
            } else {
                if (sb->region.buf_offset && rel_offset == sb->region.buf_offset) {
                    SCLogDebug("exactly at expected offset");
                    // nothing to do
                    sb->region.buf_offset = rel_offset + data_len;

                } else if (rel_offset < sb->region.buf_offset) {
                    // nothing to do

                    SCLogDebug("before expected offset: %u < sb->region.buf_offset %u", rel_offset,
                            sb->region.buf_offset);
                    if (rel_offset + data_len > sb->region.buf_offset) {
                        SCLogDebug("before expected offset, ends after: %u < sb->region.buf_offset "
                                   "%u, %u > %u",
                                rel_offset, sb->region.buf_offset, rel_offset + data_len,
                                sb->region.buf_offset);
                        sb->region.buf_offset = rel_offset + data_len;
                    }

                } else if (sb->region.buf_offset) {
                    SCLogDebug("beyond expected offset: SBBInit");
                    /* existing data, but there is a gap between us */
                    if ((r = SBBInit(sb, cfg, region, rel_offset, data_len)) != SC_OK)
                        return r;
                } else {
                    /* gap before data in empty list */
                    SCLogDebug("empty sbb list: invoking SBBInitLeadingGap");
                    if ((r = SBBInitLeadingGap(sb, cfg, region, offset, data_len)) != SC_OK)
                        return r;
                }
            }
        } else {
            if (sb->region.buf_offset) {
                /* existing data, but there is a gap between us */
                SCLogDebug("empty sbb list, no data in main: use SBBInit");
                if ((r = SBBInit(sb, cfg, region, rel_offset, data_len)) != SC_OK)
                    return r;
            } else {
                /* gap before data in empty list */
                SCLogDebug("empty sbb list: invoking SBBInitLeadingGap");
                if ((r = SBBInitLeadingGap(sb, cfg, region, offset, data_len)) != SC_OK)
                    return r;
            }
            if (rel_offset == region->buf_offset) {
                SCLogDebug("pre region->buf_offset %u", region->buf_offset);
                region->buf_offset = rel_offset + data_len;
                SCLogDebug("post region->buf_offset %u", region->buf_offset);
            }
        }
    } else {
        SCLogDebug("updating sbb tree");
        /* already have blocks, so append new block based on new data */
        if ((r = SBBUpdate(sb, cfg, region, rel_offset, data_len)) != SC_OK)
            return r;
    }
    DEBUG_VALIDATE_BUG_ON(!region_is_main && sb->head == NULL);

    ListRegions(sb);
    if (RB_EMPTY(&sb->sbb_tree)) {
        DEBUG_VALIDATE_BUG_ON(offset + data_len > sb->region.stream_offset + sb->region.buf_offset);
    }

    return SC_OK;
}

int StreamingBufferSegmentIsBeforeWindow(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg)
{
    if (seg->stream_offset < sb->region.stream_offset) {
        if (seg->stream_offset + seg->segment_len <= sb->region.stream_offset) {
            return 1;
        }
    }
    return 0;
}

static inline const StreamingBufferRegion *GetRegionForOffset(
        const StreamingBuffer *sb, const uint64_t offset)
{
    if (sb == NULL)
        return NULL;
    if (sb->region.next == NULL) {
        return &sb->region;
    }
    if (offset >= sb->region.stream_offset &&
            offset < (sb->region.stream_offset + sb->region.buf_size)) {
        return &sb->region;
    }
    for (const StreamingBufferRegion *r = sb->region.next; r != NULL; r = r->next) {
        if (offset >= r->stream_offset && offset < (r->stream_offset + r->buf_size)) {
            return r;
        }
    }
    return NULL;
}

/** \brief get the data for one SBB */
void StreamingBufferSBBGetData(const StreamingBuffer *sb,
                               const StreamingBufferBlock *sbb,
                               const uint8_t **data, uint32_t *data_len)
{
    const StreamingBufferRegion *region = GetRegionForOffset(sb, sbb->offset);
    SCLogDebug("first find our region (offset %" PRIu64 ") -> %p", sbb->offset, region);
    if (region) {
        SCLogDebug("region %p found %" PRIu64 "/%u/%u", region, region->stream_offset,
                region->buf_size, region->buf_offset);
        DEBUG_VALIDATE_BUG_ON(
                region->stream_offset == sbb->offset && region->buf_offset > sbb->len);
        // buf_offset should match first sbb len if it has the same offset

        if (sbb->offset >= region->stream_offset) {
            SCLogDebug("1");
            uint64_t offset = sbb->offset - region->stream_offset;
            *data = region->buf + offset;
            DEBUG_VALIDATE_BUG_ON(offset + sbb->len > region->buf_size);
            *data_len = sbb->len;
            return;
        } else {
            SCLogDebug("2");
            uint64_t offset = region->stream_offset - sbb->offset;
            if (offset < sbb->len) {
                *data = region->buf;
                *data_len = sbb->len - offset;
                return;
            }
            SCLogDebug("3");
        }
    }
    *data = NULL;
    *data_len = 0;
    return;
}

/** \brief get the data for one SBB */
void StreamingBufferSBBGetDataAtOffset(const StreamingBuffer *sb,
                                       const StreamingBufferBlock *sbb,
                                       const uint8_t **data, uint32_t *data_len,
                                       uint64_t offset)
{
    /* validate that we are looking for a offset within the sbb */
    DEBUG_VALIDATE_BUG_ON(!(offset >= sbb->offset && offset < (sbb->offset + sbb->len)));
    if (!(offset >= sbb->offset && offset < (sbb->offset + sbb->len))) {
        *data = NULL;
        *data_len = 0;
        return;
    }

    const StreamingBufferRegion *region = GetRegionForOffset(sb, offset);
    if (region) {
        uint32_t sbblen = sbb->len - (offset - sbb->offset);

        if (offset >= region->stream_offset) {
            uint64_t data_offset = offset - region->stream_offset;
            *data = region->buf + data_offset;
            if (data_offset + sbblen > region->buf_size)
                *data_len = region->buf_size - data_offset;
            else
                *data_len = sbblen;
            DEBUG_VALIDATE_BUG_ON(*data_len > sbblen);
            return;
        } else {
            uint64_t data_offset = region->stream_offset - sbb->offset;
            if (data_offset < sbblen) {
                *data = region->buf;
                *data_len = sbblen - data_offset;
                DEBUG_VALIDATE_BUG_ON(*data_len > sbblen);
                return;
            }
        }
    }

    *data = NULL;
    *data_len = 0;
    return;
}

void StreamingBufferSegmentGetData(const StreamingBuffer *sb,
                                   const StreamingBufferSegment *seg,
                                   const uint8_t **data, uint32_t *data_len)
{
    const StreamingBufferRegion *region = GetRegionForOffset(sb, seg->stream_offset);
    if (region) {
        if (seg->stream_offset >= region->stream_offset) {
            uint64_t offset = seg->stream_offset - region->stream_offset;
            *data = region->buf + offset;
            if (offset + seg->segment_len > region->buf_size)
                *data_len = region->buf_size - offset;
            else
                *data_len = seg->segment_len;
            SCLogDebug("*data_len %u", *data_len);
            return;
        } else {
            uint64_t offset = region->stream_offset - seg->stream_offset;
            if (offset < seg->segment_len) {
                *data = region->buf;
                *data_len = seg->segment_len - offset;
                SCLogDebug("*data_len %u", *data_len);
                return;
            }
        }
    }
    *data = NULL;
    *data_len = 0;
    return;
}

/**
 *  \retval 1 data is the same
 *  \retval 0 data is different
 */
int StreamingBufferSegmentCompareRawData(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg,
                                         const uint8_t *rawdata, uint32_t rawdata_len)
{
    const uint8_t *segdata = NULL;
    uint32_t segdata_len = 0;
    StreamingBufferSegmentGetData(sb, seg, &segdata, &segdata_len);
    if (segdata && segdata_len &&
        segdata_len == rawdata_len &&
        memcmp(segdata, rawdata, segdata_len) == 0)
    {
        return 1;
    }
    return 0;
}

int StreamingBufferGetData(const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t *stream_offset)
{
    if (sb != NULL && sb->region.buf != NULL) {
        *data = sb->region.buf;
        *data_len = sb->region.buf_offset;
        *stream_offset = sb->region.stream_offset;
        return 1;
    } else {
        *data = NULL;
        *data_len = 0;
        *stream_offset = 0;
        return 0;
    }
}

int StreamingBufferGetDataAtOffset (const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t offset)
{
    const StreamingBufferRegion *region = GetRegionForOffset(sb, offset);
    if (region != NULL && region->buf != NULL && offset >= region->stream_offset &&
            offset < (region->stream_offset + region->buf_offset)) {
        uint32_t skip = offset - region->stream_offset;
        *data = region->buf + skip;
        *data_len = region->buf_offset - skip;
        return 1;
    } else {
        *data = NULL;
        *data_len = 0;
        return 0;
    }
}

/**
 *  \retval 1 data is the same
 *  \retval 0 data is different
 */
int StreamingBufferCompareRawData(const StreamingBuffer *sb,
                                  const uint8_t *rawdata, uint32_t rawdata_len)
{
    const uint8_t *sbdata = NULL;
    uint32_t sbdata_len = 0;
    uint64_t offset = 0;
    StreamingBufferGetData(sb, &sbdata, &sbdata_len, &offset);
    if (offset == 0 &&
        sbdata && sbdata_len &&
        sbdata_len == rawdata_len &&
        memcmp(sbdata, rawdata, sbdata_len) == 0)
    {
        return 1;
    }
    SCLogDebug("sbdata_len %u, offset %" PRIu64, sbdata_len, offset);
    printf("got:\n");
    PrintRawDataFp(stdout, sbdata,sbdata_len);
    printf("wanted:\n");
    PrintRawDataFp(stdout, rawdata,rawdata_len);
    return 0;
}

#ifdef UNITTESTS
static void Dump(StreamingBuffer *sb)
{
    PrintRawDataFp(stdout, sb->region.buf, sb->region.buf_offset);
}

static void DumpSegment(StreamingBuffer *sb, StreamingBufferSegment *seg)
{
    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    StreamingBufferSegmentGetData(sb, seg, &data, &data_len);
    if (data && data_len) {
        PrintRawDataFp(stdout, data, data_len);
    }
}

static int StreamingBufferTest02(void)
{
    StreamingBufferConfig cfg = { 24, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg2, (const uint8_t *)"01234567", 8) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 16);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    FAIL_IF_NOT_NULL(sb->head);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSlideToOffset(sb, &cfg, 6);
    FAIL_IF_NOT_NULL(sb->head);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg3, (const uint8_t *)"QWERTY", 6) != 0);
    FAIL_IF(sb->region.stream_offset != 6);
    FAIL_IF(sb->region.buf_offset != 16);
    FAIL_IF(seg3.stream_offset != 16);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    FAIL_IF_NOT_NULL(sb->head);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSlideToOffset(sb, &cfg, 12);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    FAIL_IF_NOT_NULL(sb->head);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

static int StreamingBufferTest03(void)
{
    StreamingBufferConfig cfg = { 24, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"01234567", 8, 14) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 8);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 14);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 16);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"QWERTY", 6, 8) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 22);
    FAIL_IF(seg3.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 22);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSlideToOffset(sb, &cfg, 10);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 12);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

static int StreamingBufferTest04(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    FAIL_IF(!RB_EMPTY(&sb->sbb_tree));
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"01234567", 8, 14) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 8);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 14);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(RB_EMPTY(&sb->sbb_tree));
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF(sbb1 != sb->head);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 8);
    StreamingBufferBlock *sbb2 = SBB_RB_NEXT(sbb1);
    FAIL_IF_NULL(sbb2);
    FAIL_IF(sbb2 == sb->head);
    FAIL_IF(sbb2->offset != 14);
    FAIL_IF(sbb2->len != 8);
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"QWERTY", 6, 8) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 22);
    FAIL_IF(seg3.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1 != sb->head);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 22);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 22);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    /* far ahead of curve: */
    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"XYZ", 3, 124) != 0);
    FAIL_IF(sb->region.stream_offset != 0);
    FAIL_IF(sb->region.buf_offset != 22);
    FAIL_IF(sb->region.buf_size != 128);
    FAIL_IF(seg4.stream_offset != 124);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg4));
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1 != sb->head);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 22);
    FAIL_IF(!SBB_RB_NEXT(sbb1));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    DumpSegment(sb, &seg4);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 25);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg1,(const uint8_t *)"ABCDEFGH", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg2,(const uint8_t *)"01234567", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg3,(const uint8_t *)"QWERTY", 6));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg4,(const uint8_t *)"XYZ", 3));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest06(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"A", 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"C", 1, 2) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 2);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 3);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 4);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest07(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 2);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 3);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 4);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest08(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 2);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 3);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 4);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg6, (const uint8_t *)"abcdefghij", 10) != 0);
    Dump(sb);
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 20);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 20);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest09(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 2);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 3);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 4);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));

    StreamingBufferFree(sb, &cfg);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest10(void)
{
    StreamingBufferConfig cfg = { 16, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg1, (const uint8_t *)"A", 1, 0) != 0);
    Dump(sb);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);
    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg3, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 3);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg4, (const uint8_t *)"B", 1, 1) != 0);
    Dump(sb);
    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg5, (const uint8_t *)"C", 1, 2) != 0);
    Dump(sb);
    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg6, (const uint8_t *)"G", 1, 6) != 0);
    Dump(sb);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 6);

    StreamingBufferSegment seg7;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg7, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    StreamingBufferBlock *sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);

    StreamingBufferSegment seg8;
    FAIL_IF(StreamingBufferInsertAt(sb, &cfg, &seg8, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    sbb1 = RB_MIN(SBB, &sb->sbb_tree);
    FAIL_IF_NOT(sb->head == RB_MIN(SBB, &sb->sbb_tree));
    FAIL_IF_NULL(sbb1);
    FAIL_IF(sbb1->offset != 0);
    FAIL_IF(sbb1->len != 10);
    FAIL_IF(SBB_RB_NEXT(sbb1));
    FAIL_IF_NULL(sb->head);
    FAIL_IF_NOT(sb->sbb_size == 10);

    StreamingBufferFree(sb, &cfg);
    PASS;
}

static int StreamingBufferTest11(void)
{
    StreamingBufferConfig cfg = { 24, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    unsigned int data_len = 0xffffffff;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg2, (const uint8_t *)"unused", data_len) != -1);
    FAIL_IF(StreamingBufferInsertAt(
                    sb, &cfg, &seg2, (const uint8_t *)"abcdefghij", data_len, 100000) != SC_ELIMIT);
    StreamingBufferFree(sb, &cfg);
    PASS;
}

static const char *dummy_conf_string = "%YAML 1.1\n"
                                       "---\n"
                                       "\n"
                                       "app-layer:\n"
                                       "  protocols:\n"
                                       "    http:\n"
                                       "      enabled: yes\n"
                                       "      memcap: 72\n"
                                       "\n";

static int StreamingBufferTest12(void)
{
    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString((const char *)dummy_conf_string, strlen(dummy_conf_string));
    HTPConfigure();

    StreamingBufferConfig cfg = { 8, 1, STREAMING_BUFFER_REGION_GAP_DEFAULT, HTPCalloc, HTPRealloc,
        HTPFree };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg1, (const uint8_t *)"ABCDEFGHIJKLMNOP", 16) != 0);

    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferAppend(sb, &cfg, &seg2, (const uint8_t *)"ABCDEFGH", 8) != -1);
    FAIL_IF(sc_errno != SC_ENOMEM);

    StreamingBufferFree(sb, &cfg);
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    PASS;
}
#endif

void StreamingBufferRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamingBufferTest02", StreamingBufferTest02);
    UtRegisterTest("StreamingBufferTest03", StreamingBufferTest03);
    UtRegisterTest("StreamingBufferTest04", StreamingBufferTest04);
    UtRegisterTest("StreamingBufferTest06", StreamingBufferTest06);
    UtRegisterTest("StreamingBufferTest07", StreamingBufferTest07);
    UtRegisterTest("StreamingBufferTest08", StreamingBufferTest08);
    UtRegisterTest("StreamingBufferTest09", StreamingBufferTest09);
    UtRegisterTest("StreamingBufferTest10", StreamingBufferTest10);
    UtRegisterTest("StreamingBufferTest11 Bug 6903", StreamingBufferTest11);
    UtRegisterTest("StreamingBufferTest12 Bug 6782", StreamingBufferTest12);
#endif
}
