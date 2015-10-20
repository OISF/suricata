/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Reference:
 * Judy Novak, Steve Sturges: Target-Based TCP Stream Reassembly August, 2007
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "threads.h"
#include "conf.h"

#include "flow-util.h"

#include "threadvars.h"
#include "tm-threads.h"

#include "util-pool.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-host-os-info.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-util.h"

#include "stream.h"

#include "util-debug.h"
#include "app-layer-protos.h"
#include "app-layer.h"
#include "app-layer-events.h"

#include "detect-engine-state.h"

#include "util-profiling.h"

#define PSEUDO_PACKET_PAYLOAD_SIZE  65416 /* 64 Kb minus max IP and TCP header */

#ifdef DEBUG
static SCMutex segment_pool_memuse_mutex;
static uint64_t segment_pool_memuse = 0;
static uint64_t segment_pool_memcnt = 0;
#endif

/* We define several pools with prealloced segments with fixed size
 * payloads. We do this to prevent having to do an SCMalloc call for every
 * data segment we receive, which would be a large performance penalty.
 * The cost is in memory of course. The number of pools and the properties
 * of the pools are determined by the yaml. */
static int segment_pool_num = 0;
static Pool **segment_pool = NULL;
static SCMutex *segment_pool_mutex = NULL;
static uint16_t *segment_pool_pktsizes = NULL;
#ifdef DEBUG
static SCMutex segment_pool_cnt_mutex;
static uint64_t segment_pool_cnt = 0;
#endif
/* index to the right pool for all packet sizes. */
static uint16_t segment_pool_idx[65536]; /* O(1) lookups of the pool */
static int check_overlap_different_data = 0;

/* Memory use counter */
SC_ATOMIC_DECLARE(uint64_t, ra_memuse);

/* prototypes */
static int HandleSegmentStartsBeforeListSegment(ThreadVars *, TcpReassemblyThreadCtx *,
                                    TcpStream *, TcpSegment *, TcpSegment *, Packet *);
static int HandleSegmentStartsAtSameListSegment(ThreadVars *, TcpReassemblyThreadCtx *,
                                    TcpStream *, TcpSegment *, TcpSegment *, Packet *);
static int HandleSegmentStartsAfterListSegment(ThreadVars *, TcpReassemblyThreadCtx *,
                                    TcpStream *, TcpSegment *, TcpSegment *, Packet *);
void StreamTcpSegmentDataReplace(TcpSegment *, TcpSegment *, uint32_t, uint16_t);
void StreamTcpSegmentDataCopy(TcpSegment *, TcpSegment *);
TcpSegment* StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *, uint16_t);
void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);
void StreamTcpReassemblePseudoPacketCreate(TcpStream *, Packet *, PacketQueue *);
static int StreamTcpSegmentDataCompare(TcpSegment *dst_seg, TcpSegment *src_seg,
                                 uint32_t start_point, uint16_t len);

void StreamTcpReassembleConfigEnableOverlapCheck(void)
{
    check_overlap_different_data = 1;
}

/**
 *  \brief  Function to Increment the memory usage counter for the TCP reassembly
 *          segments
 *
 *  \param  size Size of the TCP segment and its payload length memory allocated
 */
void StreamTcpReassembleIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(ra_memuse, size);
    return;
}

/**
 *  \brief  Function to Decrease the memory usage counter for the TCP reassembly
 *          segments
 *
 *  \param  size Size of the TCP segment and its payload length memory allocated
 */
void StreamTcpReassembleDecrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_SUB(ra_memuse, size);
    return;
}

uint64_t StreamTcpReassembleMemuseGlobalCounter(void)
{
    uint64_t smemuse = SC_ATOMIC_GET(ra_memuse);
    return smemuse;
}

/**
 * \brief  Function to Check the reassembly memory usage counter against the
 *         allowed max memory usgae for TCP segments.
 *
 * \param  size Size of the TCP segment and its payload length memory allocated
 * \retval 1 if in bounds
 * \retval 0 if not in bounds
 */
int StreamTcpReassembleCheckMemcap(uint32_t size)
{
    if (stream_config.reassembly_memcap == 0 ||
            (uint64_t)((uint64_t)size + SC_ATOMIC_GET(ra_memuse)) <= stream_config.reassembly_memcap)
        return 1;
    return 0;
}

/** \brief alloc a tcp segment pool entry */
void *TcpSegmentPoolAlloc()
{
    if (StreamTcpReassembleCheckMemcap((uint32_t)sizeof(TcpSegment)) == 0) {
        return NULL;
    }

    TcpSegment *seg = NULL;

    seg = SCMalloc(sizeof (TcpSegment));
    if (unlikely(seg == NULL))
        return NULL;
    return seg;
}

int TcpSegmentPoolInit(void *data, void *payload_len)
{
    TcpSegment *seg = (TcpSegment *) data;
    uint16_t size = *((uint16_t *) payload_len);

    /* do this before the can bail, so TcpSegmentPoolCleanup
     * won't have uninitialized memory to consider. */
    memset(seg, 0, sizeof (TcpSegment));

    if (StreamTcpReassembleCheckMemcap((uint32_t)size + (uint32_t)sizeof(TcpSegment)) == 0) {
        return 0;
    }

    seg->pool_size = size;
    seg->payload_len = seg->pool_size;

    seg->payload = SCMalloc(seg->payload_len);
    if (seg->payload == NULL) {
        return 0;
    }

#ifdef DEBUG
    SCMutexLock(&segment_pool_memuse_mutex);
    segment_pool_memuse += seg->payload_len;
    segment_pool_memcnt++;
    SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexUnlock(&segment_pool_memuse_mutex);
#endif

    StreamTcpReassembleIncrMemuse((uint32_t)seg->pool_size + sizeof(TcpSegment));
    return 1;
}

/** \brief clean up a tcp segment pool entry */
void TcpSegmentPoolCleanup(void *ptr)
{
    if (ptr == NULL)
        return;

    TcpSegment *seg = (TcpSegment *) ptr;

    StreamTcpReassembleDecrMemuse((uint32_t)seg->pool_size + sizeof(TcpSegment));

#ifdef DEBUG
    SCMutexLock(&segment_pool_memuse_mutex);
    segment_pool_memuse -= seg->pool_size;
    segment_pool_memcnt--;
    SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexUnlock(&segment_pool_memuse_mutex);
#endif

    SCFree(seg->payload);
    return;
}

/**
 *  \brief Function to return the segment back to the pool.
 *
 *  \param seg Segment which will be returned back to the pool.
 */
void StreamTcpSegmentReturntoPool(TcpSegment *seg)
{
    if (seg == NULL)
        return;

    seg->next = NULL;
    seg->prev = NULL;

    uint16_t idx = segment_pool_idx[seg->pool_size];
    SCMutexLock(&segment_pool_mutex[idx]);
    PoolReturn(segment_pool[idx], (void *) seg);
    SCLogDebug("segment_pool[%"PRIu16"]->empty_stack_size %"PRIu32"",
               idx,segment_pool[idx]->empty_stack_size);
    SCMutexUnlock(&segment_pool_mutex[idx]);

#ifdef DEBUG
    SCMutexLock(&segment_pool_cnt_mutex);
    segment_pool_cnt--;
    SCMutexUnlock(&segment_pool_cnt_mutex);
#endif
}

/**
 *  \brief return all segments in this stream into the pool(s)
 *
 *  \param stream the stream to cleanup
 */
void StreamTcpReturnStreamSegments (TcpStream *stream)
{
    TcpSegment *seg = stream->seg_list;
    TcpSegment *next_seg;

    if (seg == NULL)
        return;

    while (seg != NULL) {
        next_seg = seg->next;
        StreamTcpSegmentReturntoPool(seg);
        seg = next_seg;
    }

    stream->seg_list = NULL;
    stream->seg_list_tail = NULL;
}

/** \param f locked flow */
void StreamTcpDisableAppLayer(Flow *f)
{
    if (f->protoctx == NULL)
        return;

    TcpSession *ssn = (TcpSession *)f->protoctx;
    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
    StreamTcpDisableAppLayerReassembly(ssn);
}

/** \param f locked flow */
int StreamTcpAppLayerIsDisabled(Flow *f)
{
    if (f->protoctx == NULL || f->proto != IPPROTO_TCP)
        return 0;

    TcpSession *ssn = (TcpSession *)f->protoctx;
    return (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
}

typedef struct SegmentSizes_
{
    uint16_t pktsize;
    uint32_t prealloc;
} SegmentSizes;

/* sort small to big */
static int SortByPktsize(const void *a, const void *b)
{
    const SegmentSizes *s0 = a;
    const SegmentSizes *s1 = b;
    return s0->pktsize - s1->pktsize;
}

int StreamTcpReassemblyConfig(char quiet)
{
    Pool **my_segment_pool = NULL;
    SCMutex *my_segment_lock = NULL;
    uint16_t *my_segment_pktsizes = NULL;
    SegmentSizes sizes[256];
    memset(&sizes, 0x00, sizeof(sizes));

    int npools = 0;
    ConfNode *segs = ConfGetNode("stream.reassembly.segments");
    if (segs != NULL) {
        ConfNode *seg;
        TAILQ_FOREACH(seg, &segs->head, next) {
            ConfNode *segsize = ConfNodeLookupChild(seg,"size");
            if (segsize == NULL)
                continue;
            ConfNode *segpre = ConfNodeLookupChild(seg,"prealloc");
            if (segpre == NULL)
                continue;

            if (npools >= 256) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "too many segment packet "
                                                    "pools defined, max is 256");
                return -1;
            }

            SCLogDebug("segsize->val %s", segsize->val);
            SCLogDebug("segpre->val %s", segpre->val);

            uint16_t pktsize = 0;
            if (ByteExtractStringUint16(&pktsize, 10, strlen(segsize->val),
                                        segsize->val) == -1)
            {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "segment packet size "
                                                    "of %s is invalid", segsize->val);
                return -1;
            }
            uint32_t prealloc = 0;
            if (ByteExtractStringUint32(&prealloc, 10, strlen(segpre->val),
                                        segpre->val) == -1)
            {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "segment prealloc of "
                                                    "%s is invalid", segpre->val);
                return -1;
            }

            sizes[npools].pktsize = pktsize;
            sizes[npools].prealloc = prealloc;
            SCLogDebug("pktsize %u, prealloc %u", sizes[npools].pktsize,
                                                  sizes[npools].prealloc);
            npools++;
        }
    }

    SCLogDebug("npools %d", npools);
    if (npools > 0) {
        /* sort the array as the index code below relies on it */
        qsort(&sizes, npools, sizeof(sizes[0]), SortByPktsize);
        if (sizes[npools - 1].pktsize != 0xffff) {
            sizes[npools].pktsize = 0xffff;
            sizes[npools].prealloc = 8;
            npools++;
            SCLogInfo("appended a segment pool for pktsize 65536");
        }
    } else if (npools == 0) {
        /* defaults */
        sizes[0].pktsize = 4;
        sizes[0].prealloc = 256;
        sizes[1].pktsize = 16;
        sizes[1].prealloc = 512;
        sizes[2].pktsize = 112;
        sizes[2].prealloc = 512;
        sizes[3].pktsize = 248;
        sizes[3].prealloc = 512;
        sizes[4].pktsize = 512;
        sizes[4].prealloc = 512;
        sizes[5].pktsize = 768;
        sizes[5].prealloc = 1024;
        sizes[6].pktsize = 1448;
        sizes[6].prealloc = 1024;
        sizes[7].pktsize = 0xffff;
        sizes[7].prealloc = 128;
        npools = 8;
    }

    int i = 0;
    for (i = 0; i < npools; i++) {
        SCLogDebug("pktsize %u, prealloc %u", sizes[i].pktsize, sizes[i].prealloc);
    }

    my_segment_pool = SCMalloc(npools * sizeof(Pool *));
    if (my_segment_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        return -1;
    }
    my_segment_lock = SCMalloc(npools * sizeof(SCMutex));
    if (my_segment_lock == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");

        SCFree(my_segment_pool);
        return -1;
    }
    my_segment_pktsizes = SCMalloc(npools * sizeof(uint16_t));
    if (my_segment_pktsizes == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");

        SCFree(my_segment_lock);
        SCFree(my_segment_pool);
        return -1;
    }
    uint32_t my_segment_poolsizes[npools];

    for (i = 0; i < npools; i++) {
        my_segment_pktsizes[i] = sizes[i].pktsize;
        my_segment_poolsizes[i] = sizes[i].prealloc;
        SCMutexInit(&my_segment_lock[i], NULL);

        /* setup the pool */
        SCMutexLock(&my_segment_lock[i]);
        my_segment_pool[i] = PoolInit(0, my_segment_poolsizes[i], 0,
                TcpSegmentPoolAlloc, TcpSegmentPoolInit,
                (void *) &my_segment_pktsizes[i],
                TcpSegmentPoolCleanup, NULL);
        SCMutexUnlock(&my_segment_lock[i]);

        if (my_segment_pool[i] == NULL) {
            SCLogError(SC_ERR_INITIALIZATION, "couldn't set up segment pool "
                    "for packet size %u. Memcap too low?", my_segment_pktsizes[i]);
            exit(EXIT_FAILURE);
        }

        SCLogDebug("my_segment_pktsizes[i] %u, my_segment_poolsizes[i] %u",
                my_segment_pktsizes[i], my_segment_poolsizes[i]);
        if (!quiet)
            SCLogInfo("segment pool: pktsize %u, prealloc %u",
                    my_segment_pktsizes[i], my_segment_poolsizes[i]);
    }

    uint16_t idx = 0;
    uint16_t u16 = 0;
    while (1) {
        if (idx <= my_segment_pktsizes[u16]) {
            segment_pool_idx[idx] = u16;
            if (my_segment_pktsizes[u16] == idx)
                u16++;
        }

        if (idx == 0xffff)
            break;

        idx++;
    }
    /* set the globals */
    segment_pool = my_segment_pool;
    segment_pool_mutex = my_segment_lock;
    segment_pool_pktsizes = my_segment_pktsizes;
    segment_pool_num = npools;

    uint32_t stream_chunk_prealloc = 250;
    ConfNode *chunk = ConfGetNode("stream.reassembly.chunk-prealloc");
    if (chunk) {
        uint32_t prealloc = 0;
        if (ByteExtractStringUint32(&prealloc, 10, strlen(chunk->val), chunk->val) == -1)
        {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "chunk-prealloc of "
                    "%s is invalid", chunk->val);
            return -1;
        }
        stream_chunk_prealloc = prealloc;
    }
    if (!quiet)
        SCLogInfo("stream.reassembly \"chunk-prealloc\": %u", stream_chunk_prealloc);
    StreamMsgQueuesInit(stream_chunk_prealloc);

    intmax_t zero_copy_size = 128;
    if (ConfGetInt("stream.reassembly.zero-copy-size", &zero_copy_size) == 1) {
        if (zero_copy_size < 0 || zero_copy_size > 0xffff) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "stream.reassembly.zero-copy-size of "
                    "%"PRIiMAX" is invalid: valid values are 0 to 65535", zero_copy_size);
            return -1;
        }
    }
    stream_config.zero_copy_size = (uint16_t)zero_copy_size;
    if (!quiet)
        SCLogInfo("stream.reassembly \"zero-copy-size\": %u", stream_config.zero_copy_size);

    return 0;
}

int StreamTcpReassembleInit(char quiet)
{
    /* init the memcap/use tracker */
    SC_ATOMIC_INIT(ra_memuse);

    if (StreamTcpReassemblyConfig(quiet) < 0)
        return -1;
#ifdef DEBUG
    SCMutexInit(&segment_pool_memuse_mutex, NULL);
    SCMutexInit(&segment_pool_cnt_mutex, NULL);
#endif

    StatsRegisterGlobalCounter("tcp.reassembly_memuse",
            StreamTcpReassembleMemuseGlobalCounter);
    return 0;
}

#ifdef DEBUG
static uint32_t dbg_app_layer_gap;
static uint32_t dbg_app_layer_gap_candidate;
#endif

void StreamTcpReassembleFree(char quiet)
{
    uint16_t u16 = 0;
    for (u16 = 0; u16 < segment_pool_num; u16++) {
        SCMutexLock(&segment_pool_mutex[u16]);

        if (quiet == FALSE) {
            PoolPrintSaturation(segment_pool[u16]);
            SCLogDebug("segment_pool[u16]->empty_stack_size %"PRIu32", "
                       "segment_pool[u16]->alloc_stack_size %"PRIu32", alloced "
                       "%"PRIu32"", segment_pool[u16]->empty_stack_size,
                       segment_pool[u16]->alloc_stack_size,
                       segment_pool[u16]->allocated);

            if (segment_pool[u16]->max_outstanding > segment_pool[u16]->allocated) {
                SCLogInfo("TCP segment pool of size %u had a peak use of %u segments, "
                        "more than the prealloc setting of %u", segment_pool_pktsizes[u16],
                        segment_pool[u16]->max_outstanding, segment_pool[u16]->allocated);
            }
        }
        PoolFree(segment_pool[u16]);

        SCMutexUnlock(&segment_pool_mutex[u16]);
        SCMutexDestroy(&segment_pool_mutex[u16]);
    }
    SCFree(segment_pool);
    SCFree(segment_pool_mutex);
    SCFree(segment_pool_pktsizes);
    segment_pool = NULL;
    segment_pool_mutex = NULL;
    segment_pool_pktsizes = NULL;

    StreamMsgQueuesDeinit(quiet);

#ifdef DEBUG
    SCLogDebug("segment_pool_cnt %"PRIu64"", segment_pool_cnt);
    SCLogDebug("segment_pool_memuse %"PRIu64"", segment_pool_memuse);
    SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexDestroy(&segment_pool_memuse_mutex);
    SCMutexDestroy(&segment_pool_cnt_mutex);
    SCLogInfo("dbg_app_layer_gap %u", dbg_app_layer_gap);
    SCLogInfo("dbg_app_layer_gap_candidate %u", dbg_app_layer_gap_candidate);
#endif
}

TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(ThreadVars *tv)
{
    SCEnter();
    TcpReassemblyThreadCtx *ra_ctx = SCMalloc(sizeof(TcpReassemblyThreadCtx));
    if (unlikely(ra_ctx == NULL))
        return NULL;

    memset(ra_ctx, 0x00, sizeof(TcpReassemblyThreadCtx));

    ra_ctx->app_tctx = AppLayerGetCtxThread(tv);

    SCReturnPtr(ra_ctx, "TcpReassemblyThreadCtx");
}

void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *ra_ctx)
{
    SCEnter();
    AppLayerDestroyCtxThread(ra_ctx->app_tctx);
#ifdef DEBUG
    SCLogDebug("reassembly fast path stats: fp1 %"PRIu64" fp2 %"PRIu64" sp %"PRIu64,
            ra_ctx->fp1, ra_ctx->fp2, ra_ctx->sp);
#endif
    SCFree(ra_ctx);
    SCReturn;
}

void PrintList2(TcpSegment *seg)
{
    TcpSegment *prev_seg = NULL;

    if (seg == NULL)
        return;

    uint32_t next_seq = seg->seq;

    while (seg != NULL) {
        if (SEQ_LT(next_seq,seg->seq)) {
            SCLogDebug("missing segment(s) for %" PRIu32 " bytes of data",
                        (seg->seq - next_seq));
        }

        SCLogDebug("seg %10"PRIu32" len %" PRIu16 ", seg %p, prev %p, next %p",
                    seg->seq, seg->payload_len, seg, seg->prev, seg->next);

        if (seg->prev != NULL && SEQ_LT(seg->seq,seg->prev->seq)) {
            /* check for SEQ_LT cornercase where a - b is exactly 2147483648,
             * which makes the marco return TRUE in both directions. This is
             * a hack though, we're going to check next how we end up with
             * a segment list with seq differences that big */
            if (!(SEQ_LT(seg->prev->seq,seg->seq))) {
                SCLogDebug("inconsistent list: SEQ_LT(seg->seq,seg->prev->seq)) =="
                        " TRUE, seg->seq %" PRIu32 ", seg->prev->seq %" PRIu32 ""
                        "", seg->seq, seg->prev->seq);
            }
        }

        if (SEQ_LT(seg->seq,next_seq)) {
            SCLogDebug("inconsistent list: SEQ_LT(seg->seq,next_seq)) == TRUE, "
                       "seg->seq %" PRIu32 ", next_seq %" PRIu32 "", seg->seq,
                       next_seq);
        }

        if (prev_seg != seg->prev) {
            SCLogDebug("inconsistent list: prev_seg %p != seg->prev %p",
                        prev_seg, seg->prev);
        }

        next_seq = seg->seq + seg->payload_len;
        SCLogDebug("next_seq is now %"PRIu32"", next_seq);
        prev_seg = seg;
        seg = seg->next;
    }
}

void PrintList(TcpSegment *seg)
{
    TcpSegment *prev_seg = NULL;
    TcpSegment *head_seg = seg;

    if (seg == NULL)
        return;

    uint32_t next_seq = seg->seq;

    while (seg != NULL) {
        if (SEQ_LT(next_seq,seg->seq)) {
            SCLogDebug("missing segment(s) for %" PRIu32 " bytes of data",
                        (seg->seq - next_seq));
        }

        SCLogDebug("seg %10"PRIu32" len %" PRIu16 ", seg %p, prev %p, next %p, flags 0x%02x",
                    seg->seq, seg->payload_len, seg, seg->prev, seg->next, seg->flags);

        if (seg->prev != NULL && SEQ_LT(seg->seq,seg->prev->seq)) {
            /* check for SEQ_LT cornercase where a - b is exactly 2147483648,
             * which makes the marco return TRUE in both directions. This is
             * a hack though, we're going to check next how we end up with
             * a segment list with seq differences that big */
            if (!(SEQ_LT(seg->prev->seq,seg->seq))) {
                SCLogDebug("inconsistent list: SEQ_LT(seg->seq,seg->prev->seq)) == "
                        "TRUE, seg->seq %" PRIu32 ", seg->prev->seq %" PRIu32 "",
                        seg->seq, seg->prev->seq);
                PrintList2(head_seg);
                abort();
            }
        }

        if (SEQ_LT(seg->seq,next_seq)) {
            SCLogDebug("inconsistent list: SEQ_LT(seg->seq,next_seq)) == TRUE, "
                       "seg->seq %" PRIu32 ", next_seq %" PRIu32 "", seg->seq,
                       next_seq);
            PrintList2(head_seg);
            abort();
        }

        if (prev_seg != seg->prev) {
            SCLogDebug("inconsistent list: prev_seg %p != seg->prev %p",
                       prev_seg, seg->prev);
            PrintList2(head_seg);
            abort();
        }

        next_seq = seg->seq + seg->payload_len;
        SCLogDebug("next_seq is now %"PRIu32"", next_seq);
        prev_seg = seg;
        seg = seg->next;
    }
}

/**
 *  \internal
 *  \brief Get the active ra_base_seq, considering stream gaps
 *
 *  \retval seq the active ra_base_seq
 */
static inline uint32_t StreamTcpReassembleGetRaBaseSeq(TcpStream *stream)
{
    if (!(stream->flags & STREAMTCP_STREAM_FLAG_GAP)) {
        SCReturnUInt(stream->ra_app_base_seq);
    } else {
        SCReturnUInt(stream->ra_raw_base_seq);
    }
}

/**
 *  \internal
 *  \brief  Function to handle the insertion newly arrived segment,
 *          The packet is handled based on its target OS.
 *
 *  \param  stream  The given TCP stream to which this new segment belongs
 *  \param  seg     Newly arrived segment
 *  \param  p       received packet
 *
 *  \retval 0  success
 *  \retval -1 error -- either we hit a memory issue (OOM/memcap) or we received
 *             a segment before ra_base_seq.
 */
int StreamTcpReassembleInsertSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpStream *stream, TcpSegment *seg, Packet *p)
{
    SCEnter();

    TcpSegment *list_seg = stream->seg_list;
    TcpSegment *next_list_seg = NULL;

#if DEBUG
    PrintList(stream->seg_list);
#endif

    int ret_value = 0;
    char return_seg = FALSE;

    /* before our ra_app_base_seq we don't insert it in our list,
     * or ra_raw_base_seq if in stream gap state */
    if (SEQ_LT((TCP_GET_SEQ(p)+p->payload_len),(StreamTcpReassembleGetRaBaseSeq(stream)+1)))
    {
        SCLogDebug("not inserting: SEQ+payload %"PRIu32", last_ack %"PRIu32", "
                "ra_(app|raw)_base_seq %"PRIu32, (TCP_GET_SEQ(p)+p->payload_len),
                stream->last_ack, StreamTcpReassembleGetRaBaseSeq(stream)+1);
        return_seg = TRUE;
        ret_value = -1;

        StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ);
        goto end;
    }

    SCLogDebug("SEQ %"PRIu32", SEQ+payload %"PRIu32", last_ack %"PRIu32", "
            "ra_app_base_seq %"PRIu32, TCP_GET_SEQ(p), (TCP_GET_SEQ(p)+p->payload_len),
            stream->last_ack, stream->ra_app_base_seq);

    if (seg == NULL) {
        goto end;
    }

    /* fast track */
    if (list_seg == NULL) {
        SCLogDebug("empty list, inserting seg %p seq %" PRIu32 ", "
                   "len %" PRIu32 "", seg, seg->seq, seg->payload_len);
        stream->seg_list = seg;
        seg->prev = NULL;
        stream->seg_list_tail = seg;
        goto end;
    }

    /* insert the segment in the stream list using this fast track, if seg->seq
       is equal or higher than stream->seg_list_tail.*/
    if (SEQ_GEQ(seg->seq, (stream->seg_list_tail->seq +
            stream->seg_list_tail->payload_len)))
    {
        stream->seg_list_tail->next = seg;
        seg->prev = stream->seg_list_tail;
        stream->seg_list_tail = seg;

        goto end;
    }

    /* If the OS policy is not set then set the OS policy for this stream */
    if (stream->os_policy == 0) {
        StreamTcpSetOSPolicy(stream, p);
    }

    for (; list_seg != NULL; list_seg = next_list_seg) {
        next_list_seg = list_seg->next;

        SCLogDebug("seg %p, list_seg %p, list_prev %p list_seg->next %p, "
                   "segment length %" PRIu32 "", seg, list_seg, list_seg->prev,
                   list_seg->next, seg->payload_len);
        SCLogDebug("seg->seq %"PRIu32", list_seg->seq %"PRIu32"",
                   seg->seq, list_seg->seq);

        /* segment starts before list */
        if (SEQ_LT(seg->seq, list_seg->seq)) {
            /* seg is entirely before list_seg */
            if (SEQ_LEQ((seg->seq + seg->payload_len), list_seg->seq)) {
                SCLogDebug("before list seg: seg->seq %" PRIu32 ", list_seg->seq"
                           " %" PRIu32 ", list_seg->payload_len %" PRIu32 ", "
                           "list_seg->prev %p", seg->seq, list_seg->seq,
                           list_seg->payload_len, list_seg->prev);
                seg->next = list_seg;
                if (list_seg->prev == NULL) {
                    stream->seg_list = seg;
                }
                if (list_seg->prev != NULL) {
                    list_seg->prev->next = seg;
                    seg->prev = list_seg->prev;
                }
                list_seg->prev = seg;

                goto end;

            /* seg overlap with next seg(s) */
            } else {
                ret_value = HandleSegmentStartsBeforeListSegment(tv, ra_ctx, stream, list_seg, seg, p);
                if (ret_value == 1) {
                    ret_value = 0;
                    return_seg = TRUE;
                    goto end;
                } else if (ret_value == -1) {
                    SCLogDebug("HandleSegmentStartsBeforeListSegment failed");
                    ret_value = -1;
                    return_seg = TRUE;
                    goto end;
                }
            }

        /* seg starts at same sequence number as list_seg */
        } else if (SEQ_EQ(seg->seq, list_seg->seq)) {
            ret_value = HandleSegmentStartsAtSameListSegment(tv, ra_ctx, stream, list_seg, seg, p);
            if (ret_value == 1) {
                ret_value = 0;
                return_seg = TRUE;
                goto end;
            } else if (ret_value == -1) {
                SCLogDebug("HandleSegmentStartsAtSameListSegment failed");
                ret_value = -1;
                return_seg = TRUE;
                goto end;
            }

        /* seg starts at sequence number higher than list_seg */
        } else if (SEQ_GT(seg->seq, list_seg->seq)) {
            if (((SEQ_GEQ(seg->seq, (list_seg->seq + list_seg->payload_len))))
                    && SEQ_GT((seg->seq + seg->payload_len),
                    (list_seg->seq + list_seg->payload_len)))
            {
                SCLogDebug("starts beyond list end, ends after list end: "
                           "seg->seq %" PRIu32 ", list_seg->seq %" PRIu32 ", "
                           "list_seg->payload_len %" PRIu32 " (%" PRIu32 ")",
                           seg->seq, list_seg->seq, list_seg->payload_len,
                           list_seg->seq + list_seg->payload_len);

                if (list_seg->next == NULL) {
                    list_seg->next = seg;
                    seg->prev = list_seg;
                    stream->seg_list_tail = seg;
                    goto end;
                }
            } else {
                ret_value = HandleSegmentStartsAfterListSegment(tv, ra_ctx, stream, list_seg, seg, p);
                if (ret_value == 1) {
                    ret_value = 0;
                    return_seg = TRUE;
                    goto end;
                } else if (ret_value == -1) {
                    SCLogDebug("HandleSegmentStartsAfterListSegment failed");
                    ret_value = -1;
                    return_seg = TRUE;
                    goto end;
                }
            }
        }
    }

end:
    if (return_seg == TRUE && seg != NULL) {
        StreamTcpSegmentReturntoPool(seg);
    }

#ifdef DEBUG
    PrintList(stream->seg_list);
#endif
    SCReturnInt(ret_value);
}

/**
 *  \brief Function to handle the newly arrived segment, when newly arrived
 *         starts with the sequence number lower than the original segment and
 *         ends at different position relative to original segment.
 *         The packet is handled based on its target OS.
 *
 *  \param list_seg Original Segment in the stream
 *  \param seg      Newly arrived segment
 *  \param prev_seg Previous segment in the stream segment list
 *  \param p        Packet
 *
 *  \retval 1 success and done
 *  \retval 0 success, but not done yet
 *  \retval -1 error, will *only* happen on memory errors
 */

static int HandleSegmentStartsBeforeListSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, Packet *p)
{
    SCEnter();

    uint16_t overlap = 0;
    uint16_t packet_length = 0;
    uint32_t overlap_point = 0;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;
    char return_after = FALSE;
    uint8_t os_policy = stream->os_policy;
#ifdef DEBUG
    SCLogDebug("seg->seq %" PRIu32 ", seg->payload_len %" PRIu32 "", seg->seq,
                seg->payload_len);
    PrintList(stream->seg_list);
#endif

    if (SEQ_GT((seg->seq + seg->payload_len), list_seg->seq) &&
        SEQ_LT((seg->seq + seg->payload_len),(list_seg->seq +
                                                        list_seg->payload_len)))
    {
        /* seg starts before list seg, ends beyond it but before list end */
        end_before = TRUE;

        /* [aaaa[abab]bbbb] a = seg, b = list_seg, overlap is the part [abab]
         * We know seg->seq + seg->payload_len is bigger than list_seg->seq */
        overlap = (seg->seq + seg->payload_len) - list_seg->seq;
        overlap_point = list_seg->seq;
        SCLogDebug("starts before list seg, ends before list end: seg->seq "
                   "%" PRIu32 ", list_seg->seq %" PRIu32 ", "
                   "list_seg->payload_len %" PRIu16 " overlap is %" PRIu32 ", "
                   "overlap point %"PRIu32"", seg->seq, list_seg->seq,
                   list_seg->payload_len, overlap, overlap_point);
    } else if (SEQ_EQ((seg->seq + seg->payload_len), (list_seg->seq +
                                                        list_seg->payload_len)))
    {
        /* seg fully overlaps list_seg, starts before, at end point
         * [aaa[ababab]] where a = seg, b = list_seg
         * overlap is [ababab], which is list_seg->payload_len */
        overlap = list_seg->payload_len;
        end_same = TRUE;
        overlap_point = list_seg->seq;
        SCLogDebug("starts before list seg, ends at list end: list prev %p"
                   "seg->seq %" PRIu32 ", list_seg->seq %" PRIu32 ","
                   "list_seg->payload_len %" PRIu32 " overlap is %" PRIu32 "",
                   list_seg->prev, seg->seq, list_seg->seq,
                   list_seg->payload_len, overlap);
        /* seg fully overlaps list_seg, starts before, ends after list endpoint */
    } else if (SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq +
                                                        list_seg->payload_len)))
    {
        /* seg fully overlaps list_seg, starts before, ends after list endpoint
         * [aaa[ababab]aaa] where a = seg, b = list_seg
         * overlap is [ababab] which is list_seg->payload_len */
        overlap = list_seg->payload_len;
        end_after = TRUE;
        overlap_point = list_seg->seq;
        SCLogDebug("starts before list seg, ends after list end: seg->seq "
                   "%" PRIu32 ", seg->payload_len %"PRIu32" list_seg->seq "
                   "%" PRIu32 ", list_seg->payload_len %" PRIu32 " overlap is"
                   " %" PRIu32 "", seg->seq, seg->payload_len,
                   list_seg->seq, list_seg->payload_len, overlap);
    }

    if (overlap > 0) {
        /* handle the case where we need to fill a gap before list_seg first */
        if (list_seg->prev != NULL && SEQ_LT((list_seg->prev->seq + list_seg->prev->payload_len), list_seg->seq)) {
            SCLogDebug("GAP to fill before list segment, size %u", list_seg->seq - (list_seg->prev->seq + list_seg->prev->payload_len));

            uint32_t new_seq = (list_seg->prev->seq + list_seg->prev->payload_len);
            if (SEQ_GT(seg->seq, new_seq)) {
                new_seq = seg->seq;
            }

            packet_length = list_seg->seq - new_seq;
            if (packet_length > seg->payload_len) {
                packet_length = seg->payload_len;
            }

            TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
            if (new_seg == NULL) {
                SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                SCReturnInt(-1);
            }
            new_seg->payload_len = packet_length;

            new_seg->seq = new_seq;

            SCLogDebug("new_seg->seq %"PRIu32" and new->payload_len "
                    "%" PRIu16"", new_seg->seq, new_seg->payload_len);

            new_seg->next = list_seg;
            new_seg->prev = list_seg->prev;
            list_seg->prev->next = new_seg;
            list_seg->prev = new_seg;

            /* create a new seg, copy the list_seg data over */
            StreamTcpSegmentDataCopy(new_seg, seg);

#ifdef DEBUG
            PrintList(stream->seg_list);
#endif
        }

        /* Handling case when the segment starts before the first segment in
         * the list */
        if (list_seg->prev == NULL) {
            if (end_after == TRUE && list_seg->next != NULL &&
                    SEQ_LT(list_seg->next->seq, (seg->seq + seg->payload_len)))
            {
                packet_length = (list_seg->seq - seg->seq) + list_seg->payload_len;
            } else {
                packet_length = seg->payload_len + (list_seg->payload_len - overlap);
                return_after = TRUE;
            }

            SCLogDebug("entered here packet_length %" PRIu32 ", seg->payload_len"
                       " %" PRIu32 ", list->payload_len %" PRIu32 "",
                       packet_length, seg->payload_len, list_seg->payload_len);

            TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
            if (new_seg == NULL) {
                SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                SCReturnInt(-1);
            }
            new_seg->payload_len = packet_length;
            new_seg->seq = seg->seq;
            new_seg->next = list_seg->next;
            new_seg->prev = list_seg->prev;

            StreamTcpSegmentDataCopy(new_seg, list_seg);

            /* first the data before the list_seg->seq */
            uint16_t replace = (uint16_t) (list_seg->seq - seg->seq);
            SCLogDebug("copying %"PRIu16" bytes to new_seg", replace);
            StreamTcpSegmentDataReplace(new_seg, seg, seg->seq, replace);

            /* if any, data after list_seg->seq + list_seg->payload_len */
            if (SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq +
                    list_seg->payload_len)) && return_after == TRUE)
            {
                replace = (uint16_t)(((seg->seq + seg->payload_len) -
                                             (list_seg->seq +
                                              list_seg->payload_len)));
                SCLogDebug("replacing %"PRIu16"", replace);
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq +
                                             list_seg->payload_len), replace);
            }

            /* update the stream last_seg in case of removal of list_seg */
            if (stream->seg_list_tail == list_seg)
                stream->seg_list_tail = new_seg;

            StreamTcpSegmentReturntoPool(list_seg);
            list_seg = new_seg;
            if (new_seg->prev != NULL) {
                new_seg->prev->next = new_seg;
            }
            if (new_seg->next != NULL) {
                new_seg->next->prev = new_seg;
            }

            stream->seg_list = new_seg;
            SCLogDebug("list_seg now %p, stream->seg_list now %p", list_seg,
                        stream->seg_list);

        } else if (end_before == TRUE || end_same == TRUE) {
            /* Handling overlapping with more than one segment and filling gap */
            if (SEQ_GT(list_seg->seq, (list_seg->prev->seq +
                                   list_seg->prev->payload_len)))
            {
                SCLogDebug("list_seg->prev %p list_seg->prev->seq %"PRIu32" "
                           "list_seg->prev->payload_len %"PRIu16"",
                            list_seg->prev, list_seg->prev->seq,
                            list_seg->prev->payload_len);
                if (SEQ_LT(list_seg->prev->seq, seg->seq)) {
                    packet_length = list_seg->payload_len + (list_seg->seq -
                                                                    seg->seq);
                } else {
                    packet_length = list_seg->payload_len + (list_seg->seq -
                           (list_seg->prev->seq + list_seg->prev->payload_len));
                }

                TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
                if (new_seg == NULL) {
                    SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                    StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                    SCReturnInt(-1);
                }

                new_seg->payload_len = packet_length;
                if (SEQ_GT((list_seg->prev->seq + list_seg->prev->payload_len),
                        seg->seq))
                {
                    new_seg->seq = (list_seg->prev->seq +
                                    list_seg->prev->payload_len);
                } else {
                    new_seg->seq = seg->seq;
                }
                SCLogDebug("new_seg->seq %"PRIu32" and new->payload_len "
                           "%" PRIu16"", new_seg->seq, new_seg->payload_len);
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;

                StreamTcpSegmentDataCopy(new_seg, list_seg);

                uint16_t copy_len = (uint16_t) (list_seg->seq - seg->seq);
                SCLogDebug("copy_len %" PRIu32 " (%" PRIu32 " - %" PRIu32 ")",
                            copy_len, list_seg->seq, seg->seq);
                StreamTcpSegmentDataReplace(new_seg, seg, seg->seq, copy_len);

                /*update the stream last_seg in case of removal of list_seg*/
                if (stream->seg_list_tail == list_seg)
                    stream->seg_list_tail = new_seg;

                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                if (new_seg->prev != NULL) {
                    new_seg->prev->next = new_seg;
                }
                if (new_seg->next != NULL) {
                    new_seg->next->prev = new_seg;
                }
            }
        } else if (end_after == TRUE) {
            if (list_seg->next != NULL) {
                if (SEQ_LEQ((seg->seq + seg->payload_len), list_seg->next->seq))
                {
                    if (SEQ_GT(seg->seq, (list_seg->prev->seq +
                                list_seg->prev->payload_len)))
                    {
                        packet_length = list_seg->payload_len + (list_seg->seq -
                                                                 seg->seq);
                    } else {
                        packet_length = list_seg->payload_len + (list_seg->seq -
                                                (list_seg->prev->seq +
                                                 list_seg->prev->payload_len));
                    }

                    packet_length += (seg->seq + seg->payload_len) -
                                        (list_seg->seq + list_seg->payload_len);

                    TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
                    if (new_seg == NULL) {
                        SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                        StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                        SCReturnInt(-1);
                    }
                    new_seg->payload_len = packet_length;
                    if (SEQ_GT((list_seg->prev->seq +
                                    list_seg->prev->payload_len), seg->seq))
                    {
                        new_seg->seq = (list_seg->prev->seq +
                                            list_seg->prev->payload_len);
                    } else {
                        new_seg->seq = seg->seq;
                    }
                    SCLogDebug("new_seg->seq %"PRIu32" and new->payload_len "
                           "%" PRIu16"", new_seg->seq, new_seg->payload_len);
                    new_seg->next = list_seg->next;
                    new_seg->prev = list_seg->prev;

                    /* create a new seg, copy the list_seg data over */
                    StreamTcpSegmentDataCopy(new_seg, list_seg);

                    /* copy the part before list_seg */
                    uint16_t copy_len = list_seg->seq - new_seg->seq;
                    StreamTcpSegmentDataReplace(new_seg, seg, new_seg->seq,
                                                copy_len);

                    /* copy the part after list_seg */
                    copy_len = (seg->seq + seg->payload_len) -
                                    (list_seg->seq + list_seg->payload_len);
                    StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq +
                                              list_seg->payload_len), copy_len);

                    if (new_seg->prev != NULL) {
                        new_seg->prev->next = new_seg;
                    }
                    if (new_seg->next != NULL) {
                        new_seg->next->prev = new_seg;
                    }
                    /*update the stream last_seg in case of removal of list_seg*/
                    if (stream->seg_list_tail == list_seg)
                        stream->seg_list_tail = new_seg;

                    StreamTcpSegmentReturntoPool(list_seg);
                    list_seg = new_seg;
                    return_after = TRUE;
                }
            /* Handle the case, when list_seg is the end of segment list, but
               seg is ending after the list_seg. So we need to copy the data
               from newly received segment. After copying return the newly
               received seg to pool */
            } else {
                if (SEQ_GT(seg->seq, (list_seg->prev->seq +
                                list_seg->prev->payload_len)))
                {
                    packet_length = list_seg->payload_len + (list_seg->seq -
                            seg->seq);
                } else {
                    packet_length = list_seg->payload_len + (list_seg->seq -
                            (list_seg->prev->seq +
                             list_seg->prev->payload_len));
                }

                packet_length += (seg->seq + seg->payload_len) -
                    (list_seg->seq + list_seg->payload_len);

                TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
                if (new_seg == NULL) {
                    SCLogDebug("segment_pool[%"PRIu16"] is empty",
                            segment_pool_idx[packet_length]);

                    StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                    SCReturnInt(-1);
                }
                new_seg->payload_len = packet_length;

                if (SEQ_GT((list_seg->prev->seq +
                                list_seg->prev->payload_len), seg->seq))
                {
                    new_seg->seq = (list_seg->prev->seq +
                            list_seg->prev->payload_len);
                } else {
                    new_seg->seq = seg->seq;
                }
                SCLogDebug("new_seg->seq %"PRIu32" and new->payload_len "
                        "%" PRIu16"", new_seg->seq, new_seg->payload_len);
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;

                /* create a new seg, copy the list_seg data over */
                StreamTcpSegmentDataCopy(new_seg, list_seg);

                /* copy the part before list_seg */
                uint16_t copy_len = list_seg->seq - new_seg->seq;
                StreamTcpSegmentDataReplace(new_seg, seg, new_seg->seq,
                        copy_len);

                /* copy the part after list_seg */
                copy_len = (seg->seq + seg->payload_len) -
                    (list_seg->seq + list_seg->payload_len);
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq +
                            list_seg->payload_len), copy_len);

                if (new_seg->prev != NULL) {
                    new_seg->prev->next = new_seg;
                }

                /*update the stream last_seg in case of removal of list_seg*/
                if (stream->seg_list_tail == list_seg)
                    stream->seg_list_tail = new_seg;

                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                return_after = TRUE;
            }
        }

        if (check_overlap_different_data &&
                !StreamTcpSegmentDataCompare(seg, list_seg, list_seg->seq, overlap)) {
            /* interesting, overlap with different data */
            StreamTcpSetEvent(p, STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA);
        }

        if (StreamTcpInlineMode()) {
            if (StreamTcpInlineSegmentCompare(seg, list_seg) != 0) {
                StreamTcpInlineSegmentReplacePacket(p, list_seg);
            }
        } else {
            switch (os_policy) {
                case OS_POLICY_SOLARIS:
                case OS_POLICY_HPUX11:
                    if (end_after == TRUE || end_same == TRUE) {
                        StreamTcpSegmentDataReplace(list_seg, seg, overlap_point,
                                overlap);
                    } else {
                        SCLogDebug("using old data in starts before list case, "
                                "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                                "overlap %" PRIu32 "", list_seg->seq, os_policy,
                                overlap);
                    }
                    break;
                case OS_POLICY_VISTA:
                case OS_POLICY_FIRST:
                    SCLogDebug("using old data in starts before list case, "
                            "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                            "overlap %" PRIu32 "", list_seg->seq, os_policy,
                            overlap);
                    break;
                case OS_POLICY_BSD:
                case OS_POLICY_HPUX10:
                case OS_POLICY_IRIX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_LINUX:
                case OS_POLICY_MACOS:
                case OS_POLICY_LAST:
                default:
                    SCLogDebug("replacing old data in starts before list seg "
                            "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                            "overlap %" PRIu32 "", list_seg->seq, os_policy,
                            overlap);
                    StreamTcpSegmentDataReplace(list_seg, seg, overlap_point,
                            overlap);
                    break;
            }
        }
        /* To return from for loop as seg is finished with current list_seg
           no need to check further (improve performance) */
        if (end_before == TRUE || end_same == TRUE || return_after == TRUE) {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief  Function to handle the newly arrived segment, when newly arrived
 *          starts with the same sequence number as the original segment and
 *          ends at different position relative to original segment.
 *          The packet is handled based on its target OS.
 *
 *  \param  list_seg    Original Segment in the stream
 *  \param  seg         Newly arrived segment
 *  \param  prev_seg    Previous segment in the stream segment list
 *
 *  \retval 1 success and done
 *  \retval 0 success, but not done yet
 *  \retval -1 error, will *only* happen on memory errors
 */

static int HandleSegmentStartsAtSameListSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, Packet *p)
{
    uint16_t overlap = 0;
    uint16_t packet_length;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;
    char handle_beyond = FALSE;
    uint8_t os_policy = stream->os_policy;

    if (SEQ_LT((seg->seq + seg->payload_len), (list_seg->seq +
                                               list_seg->payload_len)))
    {
        /* seg->seg == list_seg->seq and list_seg->payload_len > seg->payload_len
         * [[ababab]bbbb] where a = seg, b = list_seg
         * overlap is the [ababab] part, which equals seg->payload_len. */
        overlap = seg->payload_len;
        end_before = TRUE;
        SCLogDebug("starts at list seq, ends before list end: seg->seq "
                   "%" PRIu32 ", list_seg->seq %" PRIu32 ", "
                   "list_seg->payload_len %" PRIu32 " overlap is %" PRIu32,
                   seg->seq, list_seg->seq, list_seg->payload_len, overlap);

    } else if (SEQ_EQ((seg->seq + seg->payload_len), (list_seg->seq +
                                                        list_seg->payload_len)))
    {
        /* seg starts at seq, ends at seq, retransmission.
         * both segments are the same, so overlap is either
         * seg->payload_len or list_seg->payload_len */

        /* check csum, ack, other differences? */
        overlap = seg->payload_len;
        end_same = TRUE;
        SCLogDebug("(retransmission) starts at list seq, ends at list end: "
                   "seg->seq %" PRIu32 ", list_seg->seq %" PRIu32 ", "
                   "list_seg->payload_len %" PRIu32 " overlap is %"PRIu32"",
                   seg->seq, list_seg->seq, list_seg->payload_len, overlap);

    } else if (SEQ_GT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        /* seg starts at seq, ends beyond seq. */
        /* seg->seg == list_seg->seq and seg->payload_len > list_seg->payload_len
         * [[ababab]aaaa] where a = seg, b = list_seg
         * overlap is the [ababab] part, which equals list_seg->payload_len. */
        overlap = list_seg->payload_len;
        end_after = TRUE;
        SCLogDebug("starts at list seq, ends beyond list end: seg->seq "
                   "%" PRIu32 ", list_seg->seq %" PRIu32 ", "
                   "list_seg->payload_len %" PRIu32 " overlap is %" PRIu32 "",
                   seg->seq, list_seg->seq, list_seg->payload_len, overlap);
    }
    if (overlap > 0) {
        /*Handle the case when newly arrived segment ends after original
          segment and original segment is the last segment in the list
          or the next segment in the list starts after the end of new segment*/
        if (end_after == TRUE) {
            char fill_gap = FALSE;

            if (list_seg->next != NULL) {
                /* first see if we have space left to fill up */
                if (SEQ_LT((list_seg->seq + list_seg->payload_len),
                            list_seg->next->seq))
                {
                    fill_gap = TRUE;
                }

                /* then see if we overlap (partly) with the next seg */
                if (SEQ_GT((seg->seq + seg->payload_len), list_seg->next->seq))
                {
                    handle_beyond = TRUE;
                }
            /* Handle the case, when list_seg is the end of segment list, but
               seg is ending after the list_seg. So we need to copy the data
               from newly received segment. After copying return the newly
               received seg to pool */
            } else {
                fill_gap = TRUE;
            }

            SCLogDebug("fill_gap %s, handle_beyond %s", fill_gap?"TRUE":"FALSE",
                        handle_beyond?"TRUE":"FALSE");

            if (fill_gap == TRUE) {
                /* if there is a gap after this list_seg we fill it now with a
                 * new seg */
                SCLogDebug("filling gap: list_seg->next->seq %"PRIu32"",
                            list_seg->next?list_seg->next->seq:0);
                if (handle_beyond == TRUE) {
                    packet_length = list_seg->next->seq -
                                        (list_seg->seq + list_seg->payload_len);
                } else {
                    packet_length = seg->payload_len - list_seg->payload_len;
                }

                SCLogDebug("packet_length %"PRIu16"", packet_length);

                TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
                if (new_seg == NULL) {
                    SCLogDebug("egment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                    StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                    return -1;
                }
                new_seg->payload_len = packet_length;
                new_seg->seq = list_seg->seq + list_seg->payload_len;
                new_seg->next = list_seg->next;
                if (new_seg->next != NULL)
                    new_seg->next->prev = new_seg;
                new_seg->prev = list_seg;
                list_seg->next = new_seg;
                SCLogDebug("new_seg %p, new_seg->next %p, new_seg->prev %p, "
                           "list_seg->next %p", new_seg, new_seg->next,
                           new_seg->prev, list_seg->next);
                StreamTcpSegmentDataReplace(new_seg, seg, new_seg->seq,
                                            new_seg->payload_len);

                /*update the stream last_seg in case of removal of list_seg*/
                if (stream->seg_list_tail == list_seg)
                    stream->seg_list_tail = new_seg;
            }
        }

        if (check_overlap_different_data &&
                !StreamTcpSegmentDataCompare(list_seg, seg, seg->seq, overlap)) {
            /* interesting, overlap with different data */
            StreamTcpSetEvent(p, STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA);
        }

        if (StreamTcpInlineMode()) {
            if (StreamTcpInlineSegmentCompare(list_seg, seg) != 0) {
                StreamTcpInlineSegmentReplacePacket(p, list_seg);
            }
        } else {
            switch (os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_SOLARIS:
                case OS_POLICY_HPUX11:
                    if (end_after == TRUE || end_same == TRUE) {
                        StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    } else {
                        SCLogDebug("using old data in starts at list case, "
                                "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                                "overlap %" PRIu32 "", list_seg->seq, os_policy,
                                overlap);
                    }
                    break;
                case OS_POLICY_LAST:
                    StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    break;
                case OS_POLICY_LINUX:
                    if (end_after == TRUE) {
                        StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    } else {
                        SCLogDebug("using old data in starts at list case, "
                                "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                                "overlap %" PRIu32 "", list_seg->seq, os_policy,
                                overlap);
                    }
                    break;
                case OS_POLICY_BSD:
                case OS_POLICY_HPUX10:
                case OS_POLICY_IRIX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_MACOS:
                case OS_POLICY_FIRST:
                default:
                    SCLogDebug("using old data in starts at list case, list_seg->seq"
                            " %" PRIu32 " policy %" PRIu32 " overlap %" PRIu32 "",
                            list_seg->seq, os_policy, overlap);
                    break;
            }
        }

        /* return 1 if we're done */
        if (end_before == TRUE || end_same == TRUE || handle_beyond == FALSE) {
            return 1;
        }
    }
    return 0;
}

/**
 *  \internal
 *  \brief  Function to handle the newly arrived segment, when newly arrived
 *          starts with the sequence number higher than the original segment and
 *          ends at different position relative to original segment.
 *          The packet is handled based on its target OS.
 *
 *  \param  list_seg    Original Segment in the stream
 *  \param  seg         Newly arrived segment
 *  \param  prev_seg    Previous segment in the stream segment list

 *  \retval 1 success and done
 *  \retval 0 success, but not done yet
 *  \retval -1 error, will *only* happen on memory errors
 */

static int HandleSegmentStartsAfterListSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, Packet *p)
{
    SCEnter();
    uint16_t overlap = 0;
    uint16_t packet_length;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;
    char handle_beyond = FALSE;
    uint8_t os_policy = stream->os_policy;

    if (SEQ_LT((seg->seq + seg->payload_len), (list_seg->seq +
                list_seg->payload_len)))
    {
        /* seg starts after list, ends before list end
         * [bbbb[ababab]bbbb] where a = seg, b = list_seg
         * overlap is the part [ababab] which is seg->payload_len */
        overlap = seg->payload_len;
        end_before = TRUE;

        SCLogDebug("starts beyond list seq, ends before list end: seg->seq"
            " %" PRIu32 ", list_seg->seq %" PRIu32 ", list_seg->payload_len "
            "%" PRIu32 " overlap is %" PRIu32 "", seg->seq, list_seg->seq,
            list_seg->payload_len, overlap);

    } else if (SEQ_EQ((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        /* seg starts after seq, before end, ends at seq
         * [bbbb[ababab]] where a = seg, b = list_seg
         * overlapping part is [ababab], thus seg->payload_len */
        overlap = seg->payload_len;
        end_same = TRUE;

        SCLogDebug("starts beyond list seq, ends at list end: seg->seq"
            " %" PRIu32 ", list_seg->seq %" PRIu32 ", list_seg->payload_len "
            "%" PRIu32 " overlap is %" PRIu32 "", seg->seq, list_seg->seq,
            list_seg->payload_len, overlap);

    } else if (SEQ_LT(seg->seq, list_seg->seq + list_seg->payload_len) &&
               SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq +
                       list_seg->payload_len)))
    {
        /* seg starts after seq, before end, ends beyond seq.
         *
         * [bbb[ababab]aaa] where a = seg, b = list_seg.
         * overlap is the [ababab] part, which can be get using:
         * (list_seg->seq + list_seg->payload_len) - seg->seg */
        overlap = (list_seg->seq + list_seg->payload_len) - seg->seq;
        end_after = TRUE;

        SCLogDebug("starts beyond list seq, ends after list seq end: "
            "seg->seq %" PRIu32 ", seg->payload_len %"PRIu16" (%"PRIu32") "
            "list_seg->seq %" PRIu32 ", list_seg->payload_len %" PRIu32 " "
            "(%"PRIu32") overlap is %" PRIu32 "", seg->seq, seg->payload_len,
            seg->seq + seg->payload_len, list_seg->seq, list_seg->payload_len,
            list_seg->seq + list_seg->payload_len, overlap);
    }
    if (overlap > 0) {
        /*Handle the case when newly arrived segment ends after original
          segment and original segment is the last segment in the list*/
        if (end_after == TRUE) {
            char fill_gap = FALSE;

            if (list_seg->next != NULL) {
                /* first see if we have space left to fill up */
                if (SEQ_LT((list_seg->seq + list_seg->payload_len),
                            list_seg->next->seq))
                {
                    fill_gap = TRUE;
                }

                /* then see if we overlap (partly) with the next seg */
                if (SEQ_GT((seg->seq + seg->payload_len), list_seg->next->seq))
                {
                    handle_beyond = TRUE;
                }
            } else {
                fill_gap = TRUE;
            }

            SCLogDebug("fill_gap %s, handle_beyond %s", fill_gap?"TRUE":"FALSE",
                        handle_beyond?"TRUE":"FALSE");

            if (fill_gap == TRUE) {
                /* if there is a gap after this list_seg we fill it now with a
                 * new seg */
                if (list_seg->next != NULL) {
                    SCLogDebug("filling gap: list_seg->next->seq %"PRIu32"",
                            list_seg->next?list_seg->next->seq:0);

                    packet_length = list_seg->next->seq - (list_seg->seq +
                            list_seg->payload_len);
                } else {
                    packet_length = seg->payload_len - overlap;
                }
                if (packet_length > (seg->payload_len - overlap)) {
                    packet_length = seg->payload_len - overlap;
                }
                SCLogDebug("packet_length %"PRIu16"", packet_length);

                TcpSegment *new_seg = StreamTcpGetSegment(tv, ra_ctx, packet_length);
                if (new_seg == NULL) {
                    SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[packet_length]);

                    StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
                    SCReturnInt(-1);
                }
                new_seg->payload_len = packet_length;
                new_seg->seq = list_seg->seq + list_seg->payload_len;
                new_seg->next = list_seg->next;
                if (new_seg->next != NULL)
                    new_seg->next->prev = new_seg;
                new_seg->prev = list_seg;
                list_seg->next = new_seg;

                SCLogDebug("new_seg %p, new_seg->next %p, new_seg->prev %p, "
                           "list_seg->next %p new_seg->seq %"PRIu32"", new_seg,
                            new_seg->next, new_seg->prev, list_seg->next,
                            new_seg->seq);

                StreamTcpSegmentDataReplace(new_seg, seg, new_seg->seq,
                                            new_seg->payload_len);

                /* update the stream last_seg in case of removal of list_seg */
                if (stream->seg_list_tail == list_seg)
                    stream->seg_list_tail = new_seg;
            }
        }

        if (check_overlap_different_data &&
                !StreamTcpSegmentDataCompare(list_seg, seg, seg->seq, overlap)) {
            /* interesting, overlap with different data */
            StreamTcpSetEvent(p, STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA);
        }

        if (StreamTcpInlineMode()) {
            if (StreamTcpInlineSegmentCompare(list_seg, seg) != 0) {
                StreamTcpInlineSegmentReplacePacket(p, list_seg);
            }
        } else {
            switch (os_policy) {
                case OS_POLICY_SOLARIS:
                case OS_POLICY_HPUX11:
                    if (end_after == TRUE) {
                        StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    } else {
                        SCLogDebug("using old data in starts beyond list case, "
                                "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                                "overlap %" PRIu32 "", list_seg->seq, os_policy,
                                overlap);
                    }
                    break;
                case OS_POLICY_LAST:
                    StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    break;
                case OS_POLICY_BSD:
                case OS_POLICY_HPUX10:
                case OS_POLICY_IRIX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_LINUX:
                case OS_POLICY_MACOS:
                case OS_POLICY_FIRST:
                default: /* DEFAULT POLICY */
                    SCLogDebug("using old data in starts beyond list case, "
                            "list_seg->seq %" PRIu32 " policy %" PRIu32 " "
                            "overlap %" PRIu32 "", list_seg->seq, os_policy,
                            overlap);
                    break;
            }
        }
        if (end_before == TRUE || end_same == TRUE || handle_beyond == FALSE) {
            SCReturnInt(1);
        }
    }
    SCReturnInt(0);
}

/**
 *  \brief check if stream in pkt direction has depth reached
 *
 *  \param p packet with *LOCKED* flow
 *
 *  \retval 1 stream has depth reached
 *  \retval 0 stream does not have depth reached
 */
int StreamTcpReassembleDepthReached(Packet *p)
{
    if (p->flow != NULL && p->flow->protoctx != NULL) {
        TcpSession *ssn = p->flow->protoctx;
        TcpStream *stream;
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            stream = &ssn->client;
        } else {
            stream = &ssn->server;
        }

        return (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) ? 1 : 0;
    }

    return 0;
}

/**
 *  \internal
 *  \brief Function to Check the reassembly depth valuer against the
 *        allowed max depth of the stream reassmbly for TCP streams.
 *
 *  \param stream stream direction
 *  \param seq sequence number where "size" starts
 *  \param size size of the segment that is added
 *
 *  \retval size Part of the size that fits in the depth, 0 if none
 */
static uint32_t StreamTcpReassembleCheckDepth(TcpStream *stream,
        uint32_t seq, uint32_t size)
{
    SCEnter();

    /* if the configured depth value is 0, it means there is no limit on
       reassembly depth. Otherwise carry on my boy ;) */
    if (stream_config.reassembly_depth == 0) {
        SCReturnUInt(size);
    }

    /* if the final flag is set, we're not accepting anymore */
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        SCReturnUInt(0);
    }

    /* if the ra_base_seq has moved passed the depth window we stop
     * checking and just reject the rest of the packets including
     * retransmissions. Saves us the hassle of dealing with sequence
     * wraps as well */
    if (SEQ_GEQ((StreamTcpReassembleGetRaBaseSeq(stream)+1),(stream->isn + stream_config.reassembly_depth))) {
        stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
        SCReturnUInt(0);
    }

    SCLogDebug("full Depth not yet reached: %"PRIu32" <= %"PRIu32,
            (StreamTcpReassembleGetRaBaseSeq(stream)+1),
            (stream->isn + stream_config.reassembly_depth));

    if (SEQ_GEQ(seq, stream->isn) && SEQ_LT(seq, (stream->isn + stream_config.reassembly_depth))) {
        /* packet (partly?) fits the depth window */

        if (SEQ_LEQ((seq + size),(stream->isn + stream_config.reassembly_depth))) {
            /* complete fit */
            SCReturnUInt(size);
        } else {
            /* partial fit, return only what fits */
            uint32_t part = (stream->isn + stream_config.reassembly_depth) - seq;
#if DEBUG
            BUG_ON(part > size);
#else
            if (part > size)
                part = size;
#endif
            SCReturnUInt(part);
        }
    }

    SCReturnUInt(0);
}

static void StreamTcpStoreStreamChunk(TcpSession *ssn, StreamMsg *smsg, const Packet *p, int streaminline)
{
    uint8_t direction = 0;

    if ((!streaminline && (p->flowflags & FLOW_PKT_TOSERVER)) ||
        ( streaminline && (p->flowflags & FLOW_PKT_TOCLIENT)))
    {
        direction = STREAM_TOCLIENT;
        SCLogDebug("stream chunk is to_client");
    } else {
        direction = STREAM_TOSERVER;
        SCLogDebug("stream chunk is to_server");
    }

    /* store the smsg in the tcp stream */
    if (direction == STREAM_TOSERVER) {
        SCLogDebug("storing smsg in the to_server");

        /* put the smsg in the stream list */
        if (ssn->toserver_smsg_head == NULL) {
            ssn->toserver_smsg_head = smsg;
            ssn->toserver_smsg_tail = smsg;
            smsg->next = NULL;
            smsg->prev = NULL;
        } else {
            StreamMsg *cur = ssn->toserver_smsg_tail;
            cur->next = smsg;
            smsg->prev = cur;
            smsg->next = NULL;
            ssn->toserver_smsg_tail = smsg;
        }
    } else {
        SCLogDebug("storing smsg in the to_client");

        /* put the smsg in the stream list */
        if (ssn->toclient_smsg_head == NULL) {
            ssn->toclient_smsg_head = smsg;
            ssn->toclient_smsg_tail = smsg;
            smsg->next = NULL;
            smsg->prev = NULL;
        } else {
            StreamMsg *cur = ssn->toclient_smsg_tail;
            cur->next = smsg;
            smsg->prev = cur;
            smsg->next = NULL;
            ssn->toclient_smsg_tail = smsg;
        }
    }
}

/**
 *  \brief Insert a packets TCP data into the stream reassembly engine.
 *
 *  \retval 0 good segment, as far as we checked.
 *  \retval -1 badness, reason to drop in inline mode
 *
 *  If the retval is 0 the segment is inserted correctly, or overlap is handled,
 *  or it wasn't added because of reassembly depth.
 *
 */
int StreamTcpReassembleHandleSegmentHandleData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    if (ssn->data_first_seen_dir == 0) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            ssn->data_first_seen_dir = STREAM_TOSERVER;
        } else {
            ssn->data_first_seen_dir = STREAM_TOCLIENT;
        }
    }

    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) &&
        (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)) {
        SCLogDebug("ssn %p: both app and raw reassembly disabled, not reassembling", ssn);
        SCReturnInt(0);
    }

    /* If we have reached the defined depth for either of the stream, then stop
       reassembling the TCP session */
    uint32_t size = StreamTcpReassembleCheckDepth(stream, TCP_GET_SEQ(p), p->payload_len);
    SCLogDebug("ssn %p: check depth returned %"PRIu32, ssn, size);

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        /* increment stream depth counter */
        StatsIncr(tv, ra_ctx->counter_tcp_stream_depth);

        stream->flags |= STREAMTCP_STREAM_FLAG_NOREASSEMBLY;
        SCLogDebug("ssn %p: reassembly depth reached, "
                "STREAMTCP_STREAM_FLAG_NOREASSEMBLY set", ssn);
    }
    if (size == 0) {
        SCLogDebug("ssn %p: depth reached, not reassembling", ssn);
        SCReturnInt(0);
    }

#if DEBUG
    BUG_ON(size > p->payload_len);
#else
    if (size > p->payload_len)
        size = p->payload_len;
#endif

    TcpSegment *seg = StreamTcpGetSegment(tv, ra_ctx, size);
    if (seg == NULL) {
        SCLogDebug("segment_pool[%"PRIu16"] is empty", segment_pool_idx[size]);

        StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
        SCReturnInt(-1);
    }

    memcpy(seg->payload, p->payload, size);
    seg->payload_len = size;
    seg->seq = TCP_GET_SEQ(p);

    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED)
        seg->flags |= SEGMENTTCP_FLAG_APPLAYER_PROCESSED;

    /* if raw reassembly is disabled for new segments, flag each
     * segment as complete for raw before insert */
    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
        seg->flags |= SEGMENTTCP_FLAG_RAW_PROCESSED;
        SCLogDebug("segment %p flagged with SEGMENTTCP_FLAG_RAW_PROCESSED, "
                   "flags %02x", seg, seg->flags);
    }

    /* proto detection skipped, but now we do get data. Set event. */
    if (stream->seg_list == NULL &&
        stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED) {

        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
    }

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, seg, p) != 0) {
        SCLogDebug("StreamTcpReassembleInsertSegment failed");
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

static uint8_t StreamGetAppLayerFlags(TcpSession *ssn, TcpStream *stream,
                                      Packet *p)
{
    uint8_t flag = 0;

    if (!(stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)) {
        flag |= STREAM_START;
    }

    if (ssn->state == TCP_CLOSED) {
        flag |= STREAM_EOF;
    }
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        flag |= STREAM_EOF;
    }

    if (StreamTcpInlineMode() == 0) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            flag |= STREAM_TOCLIENT;
        } else {
            flag |= STREAM_TOSERVER;
        }
    } else {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            flag |= STREAM_TOSERVER;
        } else {
            flag |= STREAM_TOCLIENT;
        }
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        flag |= STREAM_DEPTH;
    }
    return flag;
}

static void StreamTcpSetupMsg(TcpSession *ssn, TcpStream *stream, Packet *p,
                              StreamMsg *smsg)
{
    SCEnter();
    smsg->data_len = 0;
    SCLogDebug("smsg %p", smsg);
    SCReturn;
}

/**
 *  \brief Check the minimum size limits for reassembly.
 *
 *  \retval 0 don't reassemble yet
 *  \retval 1 do reassemble
 */
static int StreamTcpReassembleRawCheckLimit(TcpSession *ssn, TcpStream *stream,
                                         Packet *p)
{
    SCEnter();

    if (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_NOREASSEMBLY is set, so not expecting any new packets");
        SCReturnInt(1);
    }

    if (ssn->flags & STREAMTCP_FLAG_TRIGGER_RAW_REASSEMBLY) {
        SCLogDebug("reassembling now as STREAMTCP_FLAG_TRIGGER_RAW_REASSEMBLY is set");
        ssn->flags &= ~STREAMTCP_FLAG_TRIGGER_RAW_REASSEMBLY;
        SCReturnInt(1);
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
        SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED is set, "
                "so no new segments will be considered");
        SCReturnInt(1);
    }

    /* some states mean we reassemble no matter how much data we have */
    if (ssn->state >= TCP_TIME_WAIT)
        SCReturnInt(1);

    if (p->flags & PKT_PSEUDO_STREAM_END)
        SCReturnInt(1);

    /* check if we have enough data to send to L7 */
    if (p->flowflags & FLOW_PKT_TOCLIENT) {
        SCLogDebug("StreamMsgQueueGetMinChunkLen(STREAM_TOSERVER) %"PRIu32,
                StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER));

        if (StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER) >
                (stream->last_ack - stream->ra_raw_base_seq)) {
            SCLogDebug("toserver min chunk len not yet reached: "
                    "last_ack %"PRIu32", ra_raw_base_seq %"PRIu32", %"PRIu32" < "
                    "%"PRIu32"", stream->last_ack, stream->ra_raw_base_seq,
                    (stream->last_ack - stream->ra_raw_base_seq),
                    StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER));
            SCReturnInt(0);
        }
    } else {
        SCLogDebug("StreamMsgQueueGetMinChunkLen(STREAM_TOCLIENT) %"PRIu32,
                StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT));

        if (StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT) >
                (stream->last_ack - stream->ra_raw_base_seq)) {
            SCLogDebug("toclient min chunk len not yet reached: "
                    "last_ack %"PRIu32", ra_base_seq %"PRIu32",  %"PRIu32" < "
                    "%"PRIu32"", stream->last_ack, stream->ra_raw_base_seq,
                    (stream->last_ack - stream->ra_raw_base_seq),
                    StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT));
            SCReturnInt(0);
        }
    }

    SCReturnInt(1);
}

/**
 *  \brief see if app layer is done with a segment
 *
 *  \retval 1 app layer is done with this segment
 *  \retval 0 not done yet
 */
#define StreamTcpAppLayerSegmentProcessed(ssn, stream, segment) \
    (( ( (ssn)->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) || \
       ( (stream)->flags & STREAMTCP_STREAM_FLAG_GAP ) || \
       ( (segment)->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED ) ? 1 :0 ))

/** \internal
 *  \brief check if we can remove a segment from our segment list
 *
 *  If a segment is entirely before the oldest smsg, we can discard it. Otherwise
 *  we keep it around to be able to log it.
 *
 *  \retval 1 yes
 *  \retval 0 no
 */
static inline int StreamTcpReturnSegmentCheck(const Flow *f, TcpSession *ssn, TcpStream *stream, TcpSegment *seg)
{
    if (stream == &ssn->client && ssn->toserver_smsg_head != NULL) {
        /* not (seg is entirely before first smsg, skip) */
        if (!(SEQ_LEQ(seg->seq + seg->payload_len, ssn->toserver_smsg_head->seq))) {
            SCReturnInt(0);
        }
    } else if (stream == &ssn->server && ssn->toclient_smsg_head != NULL) {
        /* not (seg is entirely before first smsg, skip) */
        if (!(SEQ_LEQ(seg->seq + seg->payload_len, ssn->toclient_smsg_head->seq))) {
            SCReturnInt(0);
        }
    }

    /* if proto detect isn't done, we're not returning */
    if (!(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream))) {
        SCReturnInt(0);
    }

    /* check app layer conditions */
    if (!(StreamTcpAppLayerSegmentProcessed(ssn, stream, seg))) {
        SCReturnInt(0);
    }

    /* check raw reassembly conditions */
    if (!(seg->flags & SEGMENTTCP_FLAG_RAW_PROCESSED)) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

static void StreamTcpRemoveSegmentFromStream(TcpStream *stream, TcpSegment *seg)
{
    if (seg->prev == NULL) {
        stream->seg_list = seg->next;
        if (stream->seg_list != NULL)
            stream->seg_list->prev = NULL;
    } else {
        seg->prev->next = seg->next;
        if (seg->next != NULL)
            seg->next->prev = seg->prev;
    }

    if (stream->seg_list_tail == seg)
        stream->seg_list_tail = seg->prev;
}

/**
 *  \brief Update the stream reassembly upon receiving a data segment
 *
 *  | left edge        | right edge based on sliding window size
 *  [aaa]
 *  [aaabbb]
 *  ...
 *  [aaabbbcccdddeeefff]
 *  [bbbcccdddeeefffggg] <- cut off aaa to adhere to the window size
 *
 *  GAP situation: each chunk that is uninterrupted has it's own smsg
 *  [aaabbb].[dddeeefff]
 *  [aaa].[ccc].[eeefff]
 *
 *  A flag will be set to indicate where the *NEW* payload starts. This
 *  is to aid the detection code for alert only sigs.
 *
 *  \todo this function is too long, we need to break it up. It needs it BAD
 */
static int StreamTcpReassembleInlineRaw (TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();
    SCLogDebug("start p %p, seq %"PRIu32, p, TCP_GET_SEQ(p));

    if (ssn->flags & STREAMTCP_FLAG_DISABLE_RAW)
        SCReturnInt(0);
    if (stream->seg_list == NULL) {
        SCReturnInt(0);
    }

    uint32_t ra_base_seq = stream->ra_raw_base_seq;
    StreamMsg *smsg = NULL;
    uint32_t smsg_offset = 0;
    uint16_t payload_offset = 0;
    uint16_t payload_len = 0;
    TcpSegment *seg = stream->seg_list;
    uint32_t next_seq = ra_base_seq + 1;
    int gap = 0;

    uint32_t chunk_size = PKT_IS_TOSERVER(p) ?
        stream_config.reassembly_toserver_chunk_size :
        stream_config.reassembly_toclient_chunk_size;

    /* determine the left edge and right edge */
    uint32_t right_edge = TCP_GET_SEQ(p) + p->payload_len;
    uint32_t left_edge = right_edge - chunk_size;

    /* shift the window to the right if the left edge doesn't cover segments */
    if (SEQ_GT(seg->seq,left_edge)) {
        right_edge += (seg->seq - left_edge);
        left_edge = seg->seq;
    }

    SCLogDebug("left_edge %"PRIu32", right_edge %"PRIu32, left_edge, right_edge);

    /* loop through the segments and fill one or more msgs */
    for (; seg != NULL && SEQ_LT(seg->seq, right_edge); ) {
        SCLogDebug("seg %p", seg);

        /* If packets are fully before ra_base_seq, skip them. We do this
         * because we've reassembled up to the ra_base_seq point already,
         * so we won't do anything with segments before it anyway. */
        SCLogDebug("checking for pre ra_base_seq %"PRIu32" seg %p seq %"PRIu32""
                   " len %"PRIu16", combined %"PRIu32" and right_edge "
                   "%"PRIu32"", ra_base_seq, seg, seg->seq,
                    seg->payload_len, seg->seq+seg->payload_len, right_edge);

        /* Remove the segments which are completely before the ra_base_seq */
        if (SEQ_LT((seg->seq + seg->payload_len), (ra_base_seq - chunk_size)))
        {
            SCLogDebug("removing pre ra_base_seq %"PRIu32" seg %p seq %"PRIu32""
                        " len %"PRIu16"", ra_base_seq, seg, seg->seq,
                        seg->payload_len);

            /* only remove if app layer reassembly is ready too */
            if (StreamTcpAppLayerSegmentProcessed(ssn, stream, seg)) {
                TcpSegment *next_seg = seg->next;
                StreamTcpRemoveSegmentFromStream(stream, seg);
                StreamTcpSegmentReturntoPool(seg);
                seg = next_seg;
            /* otherwise, just flag it for removal */
            } else {
                seg->flags |= SEGMENTTCP_FLAG_RAW_PROCESSED;
                seg = seg->next;
            }
            continue;
        }

        /* if app layer protocol has been detected, then remove all the segments
         * which has been previously processed and reassembled
         *
         * If the stream is in GAP state the app layer flag won't be set */
        if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream) &&
                (seg->flags & SEGMENTTCP_FLAG_RAW_PROCESSED) &&
                StreamTcpAppLayerSegmentProcessed(ssn, stream, seg))
        {
            SCLogDebug("segment(%p) of length %"PRIu16" has been processed,"
                    " so return it to pool", seg, seg->payload_len);
            TcpSegment *next_seg = seg->next;
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            seg = next_seg;
            continue;
        }

        /* we've run into a sequence gap, wrap up any existing smsg and
         * queue it so the next chunk (if any) is in a new smsg */
        if (SEQ_GT(seg->seq, next_seq)) {
            /* pass on pre existing smsg (if any) */
            if (smsg != NULL && smsg->data_len > 0) {
                StreamTcpStoreStreamChunk(ssn, smsg, p, 1);
                stream->ra_raw_base_seq = ra_base_seq;
                smsg = NULL;
            }

            gap = 1;
        }

        /* if the segment ends beyond left_edge we need to consider it */
        if (SEQ_GT((seg->seq + seg->payload_len), left_edge)) {
            SCLogDebug("seg->seq %" PRIu32 ", seg->payload_len %" PRIu32 ", "
                       "left_edge %" PRIu32 "", seg->seq,
                       seg->payload_len, left_edge);

            /* handle segments partly before ra_base_seq */
            if (SEQ_GT(left_edge, seg->seq)) {
                payload_offset = left_edge - seg->seq;

                if (SEQ_LT(right_edge, (seg->seq + seg->payload_len))) {
                    payload_len = (right_edge - seg->seq) - payload_offset;
                } else {
                    payload_len = seg->payload_len - payload_offset;
                }

                if (SCLogDebugEnabled()) {
                    BUG_ON(payload_offset > seg->payload_len);
                    BUG_ON((payload_len + payload_offset) > seg->payload_len);
                }
            } else {
                payload_offset = 0;

                if (SEQ_LT(right_edge, (seg->seq + seg->payload_len))) {
                    payload_len = right_edge - seg->seq;
                } else {
                    payload_len = seg->payload_len;
                }
            }
            SCLogDebug("payload_offset is %"PRIu16", payload_len is %"PRIu16""
                       " and stream->last_ack is %"PRIu32"", payload_offset,
                        payload_len, stream->last_ack);

            if (payload_len == 0) {
                SCLogDebug("no payload_len, so bail out");
                break;
            }

            if (smsg == NULL) {
                smsg = StreamMsgGetFromPool();
                if (smsg == NULL) {
                    SCLogDebug("stream_msg_pool is empty");
                    return -1;
                }

                smsg_offset = 0;

                StreamTcpSetupMsg(ssn, stream, p, smsg);
                smsg->seq = ra_base_seq + 1;
            }

            /* copy the data into the smsg */
            uint32_t copy_size = smsg->data_size - smsg_offset;
            if (copy_size > payload_len) {
                copy_size = payload_len;
            }
            if (SCLogDebugEnabled()) {
                BUG_ON(copy_size > smsg->data_size);
            }
            SCLogDebug("copy_size is %"PRIu16"", copy_size);
            memcpy(smsg->data + smsg_offset, seg->payload + payload_offset,
                    copy_size);
            smsg_offset += copy_size;

            SCLogDebug("seg total %u, seq %u off %u copy %u, ra_base_seq %u",
                    (seg->seq + payload_offset + copy_size), seg->seq,
                    payload_offset, copy_size, ra_base_seq);
            if (gap == 0 && SEQ_GT((seg->seq + payload_offset + copy_size),ra_base_seq+1)) {
                ra_base_seq += copy_size;
            }
            SCLogDebug("ra_base_seq %"PRIu32, ra_base_seq);

            smsg->data_len += copy_size;

            /* queue the smsg if it's full */
            if (smsg->data_len == smsg->data_size) {
                StreamTcpStoreStreamChunk(ssn, smsg, p, 1);
                stream->ra_raw_base_seq = ra_base_seq;
                smsg = NULL;
            }

            /* if the payload len is bigger than what we copied, we handle the
             * rest of the payload next... */
            if (copy_size < payload_len) {
                SCLogDebug("copy_size %" PRIu32 " < %" PRIu32 "", copy_size,
                            payload_len);
                payload_offset += copy_size;
                payload_len -= copy_size;
                SCLogDebug("payload_offset is %"PRIu16", seg->payload_len is "
                           "%"PRIu16" and stream->last_ack is %"PRIu32"",
                            payload_offset, seg->payload_len, stream->last_ack);
                if (SCLogDebugEnabled()) {
                    BUG_ON(payload_offset > seg->payload_len);
                }

                /* we need a while loop here as the packets theoretically can be
                 * 64k */
                char segment_done = FALSE;
                while (segment_done == FALSE) {
                    SCLogDebug("new msg at offset %" PRIu32 ", payload_len "
                               "%" PRIu32 "", payload_offset, payload_len);

                    /* get a new message
                       XXX we need a setup function */
                    smsg = StreamMsgGetFromPool();
                    if (smsg == NULL) {
                        SCLogDebug("stream_msg_pool is empty");
                        SCReturnInt(-1);
                    }
                    smsg_offset = 0;

                    StreamTcpSetupMsg(ssn, stream,p,smsg);
                    smsg->seq = ra_base_seq + 1;

                    copy_size = smsg->data_size - smsg_offset;
                    if ((int32_t)copy_size > (seg->payload_len - payload_offset)) {
                        copy_size = (seg->payload_len - payload_offset);
                    }
                    if (SCLogDebugEnabled()) {
                        BUG_ON(copy_size > smsg->data_size);
                    }

                    SCLogDebug("copy payload_offset %" PRIu32 ", smsg_offset "
                                "%" PRIu32 ", copy_size %" PRIu32 "",
                                payload_offset, smsg_offset, copy_size);
                    memcpy(smsg->data + smsg_offset, seg->payload +
                            payload_offset, copy_size);
                    smsg_offset += copy_size;
                    if (gap == 0 && SEQ_GT((seg->seq + payload_offset + copy_size),ra_base_seq+1)) {
                        ra_base_seq += copy_size;
                    }
                    SCLogDebug("ra_base_seq %"PRIu32, ra_base_seq);
                    smsg->data_len += copy_size;
                    SCLogDebug("copied payload_offset %" PRIu32 ", "
                               "smsg_offset %" PRIu32 ", copy_size %" PRIu32 "",
                               payload_offset, smsg_offset, copy_size);
                    if (smsg->data_len == smsg->data_size) {
                        StreamTcpStoreStreamChunk(ssn, smsg, p, 1);
                        stream->ra_raw_base_seq = ra_base_seq;
                        smsg = NULL;
                    }

                    /* see if we have segment payload left to process */
                    if ((copy_size + payload_offset) < seg->payload_len) {
                        payload_offset += copy_size;
                        payload_len -= copy_size;

                        if (SCLogDebugEnabled()) {
                            BUG_ON(payload_offset > seg->payload_len);
                        }
                    } else {
                        payload_offset = 0;
                        segment_done = TRUE;
                    }
                }
            }
        }

        /* done with this segment, return it to the pool */
        TcpSegment *next_seg = seg->next;
        next_seq = seg->seq + seg->payload_len;

        if (SEQ_LT((seg->seq + seg->payload_len), (ra_base_seq - chunk_size))) {
            if (seg->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED) {
                StreamTcpRemoveSegmentFromStream(stream, seg);
                SCLogDebug("removing seg %p, seg->next %p", seg, seg->next);
                StreamTcpSegmentReturntoPool(seg);
            } else {
                seg->flags |= SEGMENTTCP_FLAG_RAW_PROCESSED;
            }
        }
        seg = next_seg;
    }

    /* put the partly filled smsg in the queue */
    if (smsg != NULL) {
        StreamTcpStoreStreamChunk(ssn, smsg, p, 1);
        smsg = NULL;
        stream->ra_raw_base_seq = ra_base_seq;
    }

    /* see if we can clean up some segments */
    left_edge = (ra_base_seq + 1) - chunk_size;
    SCLogDebug("left_edge %"PRIu32", ra_base_seq %"PRIu32, left_edge, ra_base_seq);

    /* loop through the segments to remove unneeded segments */
    for (seg = stream->seg_list; seg != NULL && SEQ_LEQ((seg->seq + p->payload_len), left_edge); ) {
        SCLogDebug("seg %p seq %"PRIu32", len %"PRIu16", sum %"PRIu32, seg, seg->seq, seg->payload_len, seg->seq+seg->payload_len);

        /* only remove if app layer reassembly is ready too */
        if (StreamTcpAppLayerSegmentProcessed(ssn, stream, seg)) {
            TcpSegment *next_seg = seg->next;
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            seg = next_seg;
        } else {
            break;
        }
    }
    SCLogDebug("stream->ra_raw_base_seq %u", stream->ra_raw_base_seq);
    SCReturnInt(0);
}

/** \brief Remove idle TcpSegments from TcpSession
 *
 *  \param f flow
 *  \param flags direction flags
 */
void StreamTcpPruneSession(Flow *f, uint8_t flags)
{
    if (f == NULL || f->protoctx == NULL)
        return;

    TcpSession *ssn = f->protoctx;
    TcpStream *stream = NULL;

    if (flags & STREAM_TOSERVER) {
        stream = &ssn->client;
    } else if (flags & STREAM_TOCLIENT) {
        stream = &ssn->server;
    } else {
        return;
    }

    /* loop through the segments and fill one or more msgs */
    TcpSegment *seg = stream->seg_list;

    for (; seg != NULL && SEQ_LT(seg->seq, stream->last_ack);)
    {
        SCLogDebug("seg %p, SEQ %"PRIu32", LEN %"PRIu16", SUM %"PRIu32", FLAGS %02x",
                seg, seg->seq, seg->payload_len,
                (uint32_t)(seg->seq + seg->payload_len), seg->flags);

        if (StreamTcpReturnSegmentCheck(f, ssn, stream, seg) == 0) {
            break;
        }

        TcpSegment *next_seg = seg->next;
        StreamTcpRemoveSegmentFromStream(stream, seg);
        StreamTcpSegmentReturntoPool(seg);
        seg = next_seg;
        continue;
    }
}

#ifdef DEBUG
static uint64_t GetStreamSize(TcpStream *stream)
{
    if (stream) {
        uint64_t size = 0;
        uint32_t cnt = 0;

        TcpSegment *seg = stream->seg_list;
        while (seg) {
            cnt++;
            size += (uint64_t)seg->payload_len;

            seg = seg->next;
        }

        SCLogDebug("size %"PRIu64", cnt %"PRIu32, size, cnt);
        return size;
    }
    return (uint64_t)0;
}

static void GetSessionSize(TcpSession *ssn, Packet *p)
{
    uint64_t size = 0;
    if (ssn) {
        size = GetStreamSize(&ssn->client);
        size += GetStreamSize(&ssn->server);

        //if (size > 900000)
        //    SCLogInfo("size %"PRIu64", packet %"PRIu64, size, p->pcap_cnt);
        SCLogDebug("size %"PRIu64", packet %"PRIu64, size, p->pcap_cnt);
    }
}
#endif

typedef struct ReassembleData_ {
    uint32_t ra_base_seq;
    uint32_t data_len;
    uint8_t data[4096];
    int partial;        /* last segment was processed only partially */
    uint32_t data_sent; /* data passed on this run */
} ReassembleData;

/** \internal
 *  \brief test if segment follows a gap. If so, handle the gap
 *
 *  If in inline mode, segment may be un-ack'd. In this case we
 *  consider it a gap, but it's not 'final' yet.
 *
 *  \retval bool 1 gap 0 no gap
 */
int DoHandleGap(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                 TcpSession *ssn, TcpStream *stream, TcpSegment *seg, ReassembleData *rd,
                 Packet *p, uint32_t next_seq)
{
    if (unlikely(SEQ_GT(seg->seq, next_seq))) {
        /* we've run into a sequence gap */

        if (StreamTcpInlineMode()) {
            /* don't conclude it's a gap until we see that the data
             * that is missing was acked. */
            if (SEQ_GT(seg->seq,stream->last_ack) && ssn->state != TCP_CLOSED)
                return 1;
        }

        /* first, pass on data before the gap */
        if (rd->data_len > 0) {
            SCLogDebug("pre GAP data");

            /* process what we have so far */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    rd->data, rd->data_len,
                    StreamGetAppLayerFlags(ssn, stream, p));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);
            rd->data_sent += rd->data_len;
            rd->data_len = 0;
        }

#ifdef DEBUG
        uint32_t gap_len = seg->seq - next_seq;
        SCLogDebug("expected next_seq %" PRIu32 ", got %" PRIu32 " , "
                "stream->last_ack %" PRIu32 ". Seq gap %" PRIu32"",
                next_seq, seg->seq, stream->last_ack, gap_len);
#endif
        /* We have missed the packet and end host has ack'd it, so
         * IDS should advance it's ra_base_seq and should not consider this
         * packet any longer, even if it is retransmitted, as end host will
         * drop it anyway */
        rd->ra_base_seq = seg->seq - 1;

        /* send gap "signal" */
        AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                NULL, 0, StreamGetAppLayerFlags(ssn, stream, p)|STREAM_GAP);
        AppLayerProfilingStore(ra_ctx->app_tctx, p);

        /* set a GAP flag and make sure not bothering this stream anymore */
        SCLogDebug("STREAMTCP_STREAM_FLAG_GAP set");
        stream->flags |= STREAMTCP_STREAM_FLAG_GAP;

        StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEQ_GAP);
        StatsIncr(tv, ra_ctx->counter_tcp_reass_gap);
#ifdef DEBUG
        dbg_app_layer_gap++;
#endif
        return 1;
    }
    return 0;
}

static inline int DoReassemble(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                 TcpSession *ssn, TcpStream *stream, TcpSegment *seg, ReassembleData *rd,
                 Packet *p)
{
    /* fast paths: send data directly into the app layer, w/o first doing
     * a copy step. However, don't use the fast path until protocol detection
     * has been completed
     * TODO if initial data is big enough for proto detect, we could do the
     *      fast path anyway. */
    if (stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED) {
        /* fast path 1: segment is exactly what we need */
        if (likely(rd->data_len == 0 &&
                    SEQ_EQ(seg->seq, rd->ra_base_seq+1) &&
                    SEQ_EQ(stream->last_ack, (seg->seq + seg->payload_len))))
        {
            /* process single segment directly */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    seg->payload, seg->payload_len,
                    StreamGetAppLayerFlags(ssn, stream, p));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);
            rd->data_sent += seg->payload_len;
            rd->ra_base_seq += seg->payload_len;
#ifdef DEBUG
            ra_ctx->fp1++;
#endif
            /* if after the first data chunk we have no alproto yet,
             * there is no point in continueing here. */
            if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
                SCLogDebug("no alproto after first data chunk");
                return 0;
            }
            return 1;
            /* fast path 2: segment acked completely, meets minimal size req for 0copy processing */
        } else if (rd->data_len == 0 &&
                SEQ_EQ(seg->seq, rd->ra_base_seq+1) &&
                SEQ_GT(stream->last_ack, (seg->seq + seg->payload_len)) &&
                seg->payload_len >= stream_config.zero_copy_size)
        {
            /* process single segment directly */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    seg->payload, seg->payload_len,
                    StreamGetAppLayerFlags(ssn, stream, p));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);
            rd->data_sent += seg->payload_len;
            rd->ra_base_seq += seg->payload_len;
#ifdef DEBUG
            ra_ctx->fp2++;
#endif
            /* if after the first data chunk we have no alproto yet,
             * there is no point in continueing here. */
            if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
                SCLogDebug("no alproto after first data chunk");
                return 0;
            }
            return 1;
        }
    }
#ifdef DEBUG
    ra_ctx->sp++;
#endif
    uint16_t payload_offset = 0;
    uint16_t payload_len = 0;

    /* start clean */
    rd->partial = FALSE;

    /* if the segment ends beyond ra_base_seq we need to consider it */
    if (SEQ_GT((seg->seq + seg->payload_len), rd->ra_base_seq+1)) {
        SCLogDebug("seg->seq %" PRIu32 ", seg->payload_len %" PRIu32 ", "
                "ra_base_seq %" PRIu32 ", last_ack %"PRIu32, seg->seq,
                seg->payload_len, rd->ra_base_seq, stream->last_ack);

        if (StreamTcpInlineMode() == 0) {
            /* handle segments partly before ra_base_seq */
            if (SEQ_GT(rd->ra_base_seq, seg->seq)) {
                payload_offset = (rd->ra_base_seq + 1) - seg->seq;
                SCLogDebug("payload_offset %u", payload_offset);

                if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {
                    if (SEQ_LT(stream->last_ack, (rd->ra_base_seq + 1))) {
                        payload_len = (stream->last_ack - seg->seq);
                        SCLogDebug("payload_len %u", payload_len);
                    } else {
                        payload_len = (stream->last_ack - seg->seq) - payload_offset;
                        SCLogDebug("payload_len %u", payload_len);
                    }
                    rd->partial = TRUE;
                } else {
                    payload_len = seg->payload_len - payload_offset;
                    SCLogDebug("payload_len %u", payload_len);
                }

                if (SCLogDebugEnabled()) {
                    BUG_ON(payload_offset > seg->payload_len);
                    BUG_ON((payload_len + payload_offset) > seg->payload_len);
                }
            } else {
                payload_offset = 0;

                if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {
                    payload_len = stream->last_ack - seg->seq;
                    SCLogDebug("payload_len %u", payload_len);

                    rd->partial = TRUE;
                } else {
                    payload_len = seg->payload_len;
                    SCLogDebug("payload_len %u", payload_len);
                }
            }
        /* inline mode, don't consider last_ack as we process un-ACK'd segments */
        } else {
            /* handle segments partly before ra_base_seq */
            if (SEQ_GT(rd->ra_base_seq, seg->seq)) {
                payload_offset = rd->ra_base_seq - seg->seq - 1;
                payload_len = seg->payload_len - payload_offset;

                if (SCLogDebugEnabled()) {
                    BUG_ON(payload_offset > seg->payload_len);
                    BUG_ON((payload_len + payload_offset) > seg->payload_len);
                }
            } else {
                payload_offset = 0;
                payload_len = seg->payload_len;
            }
        }
        SCLogDebug("payload_offset is %"PRIu16", payload_len is %"PRIu16""
                " and stream->last_ack is %"PRIu32"", payload_offset,
                payload_len, stream->last_ack);

        if (payload_len == 0) {
            SCLogDebug("no payload_len, so bail out");
            return 0;
        }

        /* copy the data into the buffer */
        uint16_t copy_size = sizeof(rd->data) - rd->data_len;
        if (copy_size > payload_len) {
            copy_size = payload_len;
        }
        if (SCLogDebugEnabled()) {
            BUG_ON(copy_size > sizeof(rd->data));
        }
        SCLogDebug("copy_size is %"PRIu16"", copy_size);
        memcpy(rd->data + rd->data_len, seg->payload + payload_offset, copy_size);
        rd->data_len += copy_size;
        rd->ra_base_seq += copy_size;
        SCLogDebug("ra_base_seq %"PRIu32", data_len %"PRIu32, rd->ra_base_seq, rd->data_len);

        /* queue the smsg if it's full */
        if (rd->data_len == sizeof(rd->data)) {
            /* process what we have so far */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    rd->data, rd->data_len,
                    StreamGetAppLayerFlags(ssn, stream, p));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);
            rd->data_sent += rd->data_len;
            rd->data_len = 0;

            /* if after the first data chunk we have no alproto yet,
             * there is no point in continueing here. */
            if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
                SCLogDebug("no alproto after first data chunk");
                return 0;
            }
        }

        /* if the payload len is bigger than what we copied, we handle the
         * rest of the payload next... */
        if (copy_size < payload_len) {
            SCLogDebug("copy_size %" PRIu32 " < %" PRIu32 "", copy_size,
                    payload_len);

            payload_offset += copy_size;
            payload_len -= copy_size;
            SCLogDebug("payload_offset is %"PRIu16", seg->payload_len is "
                    "%"PRIu16" and stream->last_ack is %"PRIu32"",
                    payload_offset, seg->payload_len, stream->last_ack);
            if (SCLogDebugEnabled()) {
                BUG_ON(payload_offset > seg->payload_len);
            }

            /* we need a while loop here as the packets theoretically can be
             * 64k */
            char segment_done = FALSE;
            while (segment_done == FALSE) {
                SCLogDebug("new msg at offset %" PRIu32 ", payload_len "
                        "%" PRIu32 "", payload_offset, payload_len);
                rd->data_len = 0;

                copy_size = sizeof(rd->data) - rd->data_len;
                if (copy_size > (seg->payload_len - payload_offset)) {
                    copy_size = (seg->payload_len - payload_offset);
                }
                if (SCLogDebugEnabled()) {
                    BUG_ON(copy_size > sizeof(rd->data));
                }

                SCLogDebug("copy payload_offset %" PRIu32 ", data_len "
                        "%" PRIu32 ", copy_size %" PRIu32 "",
                        payload_offset, rd->data_len, copy_size);
                memcpy(rd->data + rd->data_len, seg->payload +
                        payload_offset, copy_size);
                rd->data_len += copy_size;
                rd->ra_base_seq += copy_size;
                SCLogDebug("ra_base_seq %"PRIu32, rd->ra_base_seq);
                SCLogDebug("copied payload_offset %" PRIu32 ", "
                        "data_len %" PRIu32 ", copy_size %" PRIu32 "",
                        payload_offset, rd->data_len, copy_size);

                if (rd->data_len == sizeof(rd->data)) {
                    /* process what we have so far */
                    AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                            rd->data, rd->data_len,
                            StreamGetAppLayerFlags(ssn, stream, p));
                    AppLayerProfilingStore(ra_ctx->app_tctx, p);
                    rd->data_sent += rd->data_len;
                    rd->data_len = 0;

                    /* if after the first data chunk we have no alproto yet,
                     * there is no point in continueing here. */
                    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
                        SCLogDebug("no alproto after first data chunk");
                        return 0;
                    }
                }

                /* see if we have segment payload left to process */
                if ((copy_size + payload_offset) < seg->payload_len) {
                    payload_offset += copy_size;
                    payload_len -= copy_size;

                    if (SCLogDebugEnabled()) {
                        BUG_ON(payload_offset > seg->payload_len);
                    }
                } else {
                    payload_offset = 0;
                    segment_done = TRUE;
                }
            }
        }
    }

    return 1;
}

/**
 *  \brief Update the stream reassembly upon receiving an ACK packet.
 *
 *  Stream is in the opposite direction of the packet, as the ACK-packet
 *  is ACK'ing the stream.
 *
 *  One of the utilities call by this function AppLayerHandleTCPData(),
 *  has a feature where it will call this very same function for the
 *  stream opposing the stream it is called with.  This shouldn't cause
 *  any issues, since processing of each stream is independent of the
 *  other stream.
 *
 *  \todo this function is too long, we need to break it up. It needs it BAD
 */
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                 TcpSession *ssn, TcpStream *stream,
                                 Packet *p)
{
    SCEnter();

    /* this function can be directly called by app layer protocol
     * detection. */
    if (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        SCLogDebug("stream no reassembly flag set.  Mostly called via "
                   "app proto detection.");
        SCReturnInt(0);
    }

    SCLogDebug("stream->seg_list %p", stream->seg_list);
#ifdef DEBUG
    PrintList(stream->seg_list);
    GetSessionSize(ssn, p);
#endif

    /* Check if we have a gap at the start of the stream. 2 conditions:
     * 1. no segments, but last_ack moved fwd
     * 2. segments, but clearly some missing: if last_ack is
     *    bigger than the list start and the list start is bigger than
     *    next_seq, we know we are missing data that has been ack'd. That
     *    won't get retransmitted, so it's a data gap.
     */
    if (!(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED)) {
        int ackadd = (ssn->state >= TCP_FIN_WAIT2) ? 2 : 1;
        if ((stream->seg_list == NULL && /*1*/
                    stream->ra_app_base_seq == stream->isn &&
                    SEQ_GT(stream->last_ack, stream->isn + ackadd))
                ||
            (stream->seg_list != NULL && /*2*/
                    SEQ_GT(stream->seg_list->seq, stream->ra_app_base_seq+1) &&
                    SEQ_LT(stream->seg_list->seq, stream->last_ack)))
        {
            if (stream->seg_list == NULL) {
                SCLogDebug("no segs, last_ack moved fwd so GAP "
                        "(base %u, isn %u, last_ack %u => diff %u) p %"PRIu64,
                        stream->ra_app_base_seq, stream->isn, stream->last_ack,
                        stream->last_ack - (stream->isn + ackadd), p->pcap_cnt);
            }

            /* send gap signal */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    NULL, 0,
                    StreamGetAppLayerFlags(ssn, stream, p)|STREAM_GAP);
            AppLayerProfilingStore(ra_ctx->app_tctx, p);

            /* set a GAP flag and make sure not bothering this stream anymore */
            SCLogDebug("STREAMTCP_STREAM_FLAG_GAP set");
            stream->flags |= STREAMTCP_STREAM_FLAG_GAP;

            StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEQ_GAP);
            StatsIncr(tv, ra_ctx->counter_tcp_reass_gap);
#ifdef DEBUG
            dbg_app_layer_gap++;
#endif
            SCReturnInt(0);
        }
    }

    /* if no segments are in the list or all are already processed,
     * and state is beyond established, we send an empty msg */
    TcpSegment *seg_tail = stream->seg_list_tail;
    if (seg_tail == NULL ||
            (seg_tail->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED))
    {
        /* send an empty EOF msg if we have no segments but TCP state
         * is beyond ESTABLISHED */
        if (ssn->state >= TCP_CLOSING || (p->flags & PKT_PSEUDO_STREAM_END)) {
            SCLogDebug("sending empty eof message");
            /* send EOF to app layer */
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                                  NULL, 0,
                                  StreamGetAppLayerFlags(ssn, stream, p));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);

            SCReturnInt(0);
        }
    }

    /* no segments, nothing to do */
    if (stream->seg_list == NULL) {
        SCLogDebug("no segments in the list to reassemble");
        SCReturnInt(0);
    }


    if (stream->flags & STREAMTCP_STREAM_FLAG_GAP) {
        SCReturnInt(0);
    }

    /* stream->ra_app_base_seq remains at stream->isn until protocol is
     * detected. */
    ReassembleData rd;
    rd.ra_base_seq = stream->ra_app_base_seq;
    rd.data_len = 0;
    rd.data_sent = 0;
    rd.partial = FALSE;
    uint32_t next_seq = rd.ra_base_seq + 1;

    SCLogDebug("ra_base_seq %"PRIu32", last_ack %"PRIu32", next_seq %"PRIu32,
            rd.ra_base_seq, stream->last_ack, next_seq);

    /* loop through the segments and fill one or more msgs */
    TcpSegment *seg = stream->seg_list;
    SCLogDebug("pre-loop seg %p", seg);
#ifdef DEBUG_VALIDATION
    uint64_t bytes = 0;
#endif
    for (; seg != NULL; )
    {
#ifdef DEBUG_VALIDATION
        bytes += seg->payload_len;
#endif
        /* if in inline mode, we process all segments regardless of whether
         * they are ack'd or not. In non-inline, we process only those that
         * are at least partly ack'd. */
        if (StreamTcpInlineMode() == 0 && SEQ_GEQ(seg->seq, stream->last_ack))
            break;

        SCLogDebug("seg %p, SEQ %"PRIu32", LEN %"PRIu16", SUM %"PRIu32,
                seg, seg->seq, seg->payload_len,
                (uint32_t)(seg->seq + seg->payload_len));

        if (StreamTcpReturnSegmentCheck(p->flow, ssn, stream, seg) == 1) {
            SCLogDebug("removing segment");
            TcpSegment *next_seg = seg->next;
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            seg = next_seg;
            continue;
        } else if (StreamTcpAppLayerSegmentProcessed(ssn, stream, seg)) {
            TcpSegment *next_seg = seg->next;
            seg = next_seg;
            continue;
        }

        /* check if we have a sequence gap and if so, handle it */
        if (DoHandleGap(tv, ra_ctx, ssn, stream, seg, &rd, p, next_seq) == 1)
            break;

        /* process this segment */
        if (DoReassemble(tv, ra_ctx, ssn, stream, seg, &rd, p) == 0)
            break;

        /* done with this segment, return it to the pool */
        TcpSegment *next_seg = seg->next;
        next_seq = seg->seq + seg->payload_len;
        if (rd.partial == FALSE) {
            SCLogDebug("fully done with segment in app layer reassembly (seg %p seq %"PRIu32")",
                    seg, seg->seq);
            seg->flags |= SEGMENTTCP_FLAG_APPLAYER_PROCESSED;
            SCLogDebug("flags now %02x", seg->flags);
        } else {
            SCLogDebug("not yet fully done with segment in app layer reassembly");
        }
        seg = next_seg;
    }
#ifdef DEBUG_VALIDATION /* we should never have this much data queued */
    BUG_ON(bytes > 1000000ULL && bytes > (stream->window * 1.5));
#endif

    /* put the partly filled smsg in the queue to the l7 handler */
    if (rd.data_len > 0) {
        SCLogDebug("data_len > 0, %u", rd.data_len);
        /* process what we have so far */
        BUG_ON(rd.data_len > sizeof(rd.data));
        AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                              rd.data, rd.data_len,
                              StreamGetAppLayerFlags(ssn, stream, p));
        AppLayerProfilingStore(ra_ctx->app_tctx, p);
    }

    /* if no data was sent to the applayer, we send it a empty 'nudge'
     * when in inline mode */
    if (StreamTcpInlineMode() && rd.data_sent == 0 && ssn->state > TCP_ESTABLISHED) {
        SCLogDebug("sending empty eof message");
        /* send EOF to app layer */
        AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                NULL, 0, StreamGetAppLayerFlags(ssn, stream, p));
        AppLayerProfilingStore(ra_ctx->app_tctx, p);
    }

    /* store ra_base_seq in the stream */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
        stream->ra_app_base_seq = rd.ra_base_seq;
    } else {
        TcpSegment *tmp_seg = stream->seg_list;
        while (tmp_seg != NULL) {
            if (!(tmp_seg->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED))
                break;
            tmp_seg->flags &= ~SEGMENTTCP_FLAG_APPLAYER_PROCESSED;
            tmp_seg = tmp_seg->next;
        }
    }
    SCLogDebug("stream->ra_app_base_seq %u", stream->ra_app_base_seq);
    SCReturnInt(0);
}

typedef struct ReassembleRawData_ {
    uint32_t ra_base_seq;
    int partial;        /* last segment was processed only partially */
    StreamMsg *smsg;
    uint32_t smsg_offset; // TODO diff with smsg->data_len?
} ReassembleRawData;

static void DoHandleRawGap(TcpSession *ssn, TcpStream *stream, TcpSegment *seg, Packet *p,
        ReassembleRawData *rd, uint32_t next_seq)
{
    /* we've run into a sequence gap */
    if (SEQ_GT(seg->seq, next_seq)) {
        /* pass on pre existing smsg (if any) */
        if (rd->smsg != NULL && rd->smsg->data_len > 0) {
            /* if app layer protocol has not been detected till yet,
               then check did we have sent message to app layer already
               or not. If not then sent the message and set flag that first
               message has been sent. No more data till proto has not
               been detected */
            StreamTcpStoreStreamChunk(ssn, rd->smsg, p, 0);
            stream->ra_raw_base_seq = rd->ra_base_seq;
            rd->smsg = NULL;
        }

        /* see what the length of the gap is, gap length is seg->seq -
         * (ra_base_seq +1) */
#ifdef DEBUG
        uint32_t gap_len = seg->seq - next_seq;
        SCLogDebug("expected next_seq %" PRIu32 ", got %" PRIu32 " , "
                "stream->last_ack %" PRIu32 ". Seq gap %" PRIu32"",
                next_seq, seg->seq, stream->last_ack, gap_len);
#endif
        stream->ra_raw_base_seq = rd->ra_base_seq;

        /* We have missed the packet and end host has ack'd it, so
         * IDS should advance it's ra_base_seq and should not consider this
         * packet any longer, even if it is retransmitted, as end host will
         * drop it anyway */
        rd->ra_base_seq = seg->seq - 1;
    }
}

static int DoRawReassemble(TcpSession *ssn, TcpStream *stream, TcpSegment *seg, Packet *p,
    ReassembleRawData *rd)
{
    uint16_t payload_offset = 0;
    uint16_t payload_len = 0;

    /* start clean */
    rd->partial = FALSE;

    /* if the segment ends beyond ra_base_seq we need to consider it */
    if (SEQ_GT((seg->seq + seg->payload_len), rd->ra_base_seq+1)) {
        SCLogDebug("seg->seq %" PRIu32 ", seg->payload_len %" PRIu32 ", "
                "ra_base_seq %" PRIu32 "", seg->seq,
                seg->payload_len, rd->ra_base_seq);

        /* handle segments partly before ra_base_seq */
        if (SEQ_GT(rd->ra_base_seq, seg->seq)) {
            payload_offset = rd->ra_base_seq - seg->seq;

            if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {

                if (SEQ_LT(stream->last_ack, rd->ra_base_seq)) {
                    payload_len = (stream->last_ack - seg->seq);
                } else {
                    payload_len = (stream->last_ack - seg->seq) - payload_offset;
                }
                rd->partial = TRUE;
            } else {
                payload_len = seg->payload_len - payload_offset;
            }

            if (SCLogDebugEnabled()) {
                BUG_ON(payload_offset > seg->payload_len);
                BUG_ON((payload_len + payload_offset) > seg->payload_len);
            }
        } else {
            payload_offset = 0;

            if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {
                payload_len = stream->last_ack - seg->seq;
                rd->partial = TRUE;
            } else {
                payload_len = seg->payload_len;
            }
        }
        SCLogDebug("payload_offset is %"PRIu16", payload_len is %"PRIu16""
                " and stream->last_ack is %"PRIu32"", payload_offset,
                payload_len, stream->last_ack);

        if (payload_len == 0) {
            SCLogDebug("no payload_len, so bail out");
            return 1; // TODO
        }

        if (rd->smsg == NULL) {
            rd->smsg = StreamMsgGetFromPool();
            if (rd->smsg == NULL) {
                SCLogDebug("stream_msg_pool is empty");
                return -1;
            }

            rd->smsg_offset = 0;

            StreamTcpSetupMsg(ssn, stream, p, rd->smsg);
            rd->smsg->seq = rd->ra_base_seq + 1;
            SCLogDebug("smsg->seq %u", rd->smsg->seq);
        }

        /* copy the data into the smsg */
        uint32_t copy_size = rd->smsg->data_size - rd->smsg_offset;
        if (copy_size > payload_len) {
            copy_size = payload_len;
        }
        if (SCLogDebugEnabled()) {
            BUG_ON(copy_size > rd->smsg->data_size);
        }
        SCLogDebug("copy_size is %"PRIu16"", copy_size);
        memcpy(rd->smsg->data + rd->smsg_offset, seg->payload + payload_offset,
                copy_size);
        rd->smsg_offset += copy_size;
        rd->ra_base_seq += copy_size;
        SCLogDebug("ra_base_seq %"PRIu32, rd->ra_base_seq);

        rd->smsg->data_len += copy_size;

        /* queue the smsg if it's full */
        if (rd->smsg->data_len == rd->smsg->data_size) {
            StreamTcpStoreStreamChunk(ssn, rd->smsg, p, 0);
            stream->ra_raw_base_seq = rd->ra_base_seq;
            rd->smsg = NULL;
        }

        /* if the payload len is bigger than what we copied, we handle the
         * rest of the payload next... */
        if (copy_size < payload_len) {
            SCLogDebug("copy_size %" PRIu32 " < %" PRIu32 "", copy_size,
                    payload_len);

            payload_offset += copy_size;
            payload_len -= copy_size;
            SCLogDebug("payload_offset is %"PRIu16", seg->payload_len is "
                    "%"PRIu16" and stream->last_ack is %"PRIu32"",
                    payload_offset, seg->payload_len, stream->last_ack);
            if (SCLogDebugEnabled()) {
                BUG_ON(payload_offset > seg->payload_len);
            }

            /* we need a while loop here as the packets theoretically can be
             * 64k */
            char segment_done = FALSE;
            while (segment_done == FALSE) {
                SCLogDebug("new msg at offset %" PRIu32 ", payload_len "
                        "%" PRIu32 "", payload_offset, payload_len);

                /* get a new message
                   XXX we need a setup function */
                rd->smsg = StreamMsgGetFromPool();
                if (rd->smsg == NULL) {
                    SCLogDebug("stream_msg_pool is empty");
                    SCReturnInt(-1);
                }
                rd->smsg_offset = 0;

                StreamTcpSetupMsg(ssn, stream, p, rd->smsg);
                rd->smsg->seq = rd->ra_base_seq + 1;

                copy_size = rd->smsg->data_size - rd->smsg_offset;
                if (copy_size > payload_len) {
                    copy_size = payload_len;
                }
                if (SCLogDebugEnabled()) {
                    BUG_ON(copy_size > rd->smsg->data_size);
                }

                SCLogDebug("copy payload_offset %" PRIu32 ", smsg_offset "
                        "%" PRIu32 ", copy_size %" PRIu32 "",
                        payload_offset, rd->smsg_offset, copy_size);
                memcpy(rd->smsg->data + rd->smsg_offset, seg->payload +
                        payload_offset, copy_size);
                rd->smsg_offset += copy_size;
                rd->ra_base_seq += copy_size;
                SCLogDebug("ra_base_seq %"PRIu32, rd->ra_base_seq);
                rd->smsg->data_len += copy_size;
                SCLogDebug("copied payload_offset %" PRIu32 ", "
                        "smsg_offset %" PRIu32 ", copy_size %" PRIu32 "",
                        payload_offset, rd->smsg_offset, copy_size);
                if (rd->smsg->data_len == rd->smsg->data_size) {
                    StreamTcpStoreStreamChunk(ssn, rd->smsg, p, 0);
                    stream->ra_raw_base_seq = rd->ra_base_seq;
                    rd->smsg = NULL;
                }

                /* see if we have segment payload left to process */
                if (copy_size < payload_len) {
                    payload_offset += copy_size;
                    payload_len -= copy_size;

                    if (SCLogDebugEnabled()) {
                        BUG_ON(payload_offset > seg->payload_len);
                    }
                } else {
                    payload_offset = 0;
                    segment_done = TRUE;
                }
            }
        }
    }
    return 1;
}

/**
 *  \brief Update the stream reassembly upon receiving an ACK packet.
 *  \todo this function is too long, we need to break it up. It needs it BAD
 */
static int StreamTcpReassembleRaw (TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();
    SCLogDebug("start p %p", p);

    if (ssn->flags & STREAMTCP_FLAG_DISABLE_RAW)
        SCReturnInt(0);

    if (stream->seg_list == NULL) {
        SCLogDebug("no segments in the list to reassemble");
        SCReturnInt(0);
    }

#if 0
    if (ssn->state <= TCP_ESTABLISHED &&
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
        SCLogDebug("only starting raw reassembly after app layer protocol "
                "detection has completed.");
        SCReturnInt(0);
    }
#endif
    /* check if we have enough data */
    if (StreamTcpReassembleRawCheckLimit(ssn,stream,p) == 0) {
        SCLogDebug("not yet reassembling");
        SCReturnInt(0);
    }

    TcpSegment *seg = stream->seg_list;
    ReassembleRawData rd;
    rd.smsg = NULL;
    rd.ra_base_seq = stream->ra_raw_base_seq;
    rd.smsg_offset = 0;
    uint32_t next_seq = rd.ra_base_seq + 1;

    SCLogDebug("ra_base_seq %"PRIu32", last_ack %"PRIu32", next_seq %"PRIu32,
            rd.ra_base_seq, stream->last_ack, next_seq);

    /* loop through the segments and fill one or more msgs */
    for (; seg != NULL && SEQ_LT(seg->seq, stream->last_ack);)
    {
        SCLogDebug("seg %p, SEQ %"PRIu32", LEN %"PRIu16", SUM %"PRIu32", flags %02x",
                seg, seg->seq, seg->payload_len,
                (uint32_t)(seg->seq + seg->payload_len), seg->flags);

        if (StreamTcpReturnSegmentCheck(p->flow, ssn, stream, seg) == 1) {
            SCLogDebug("removing segment");
            TcpSegment *next_seg = seg->next;
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            seg = next_seg;
            continue;
        } else if(seg->flags & SEGMENTTCP_FLAG_RAW_PROCESSED) {
            TcpSegment *next_seg = seg->next;
            seg = next_seg;
            continue;
        }

        DoHandleRawGap(ssn, stream, seg, p, &rd, next_seq);

        if (DoRawReassemble(ssn, stream, seg, p, &rd) == 0)
            break;

        /* done with this segment, return it to the pool */
        TcpSegment *next_seg = seg->next;
        next_seq = seg->seq + seg->payload_len;
        if (rd.partial == FALSE) {
            SCLogDebug("fully done with segment in raw reassembly (seg %p seq %"PRIu32")",
                    seg, seg->seq);
            seg->flags |= SEGMENTTCP_FLAG_RAW_PROCESSED;
            SCLogDebug("flags now %02x", seg->flags);
        } else {
            SCLogDebug("not yet fully done with segment in raw reassembly");
        }
        seg = next_seg;
    }

    /* put the partly filled smsg in the queue to the l7 handler */
    if (rd.smsg != NULL) {
        StreamTcpStoreStreamChunk(ssn, rd.smsg, p, 0);
        rd.smsg = NULL;
        stream->ra_raw_base_seq = rd.ra_base_seq;
    }

    SCReturnInt(0);
}

/** \brief update app layer and raw reassembly
 *
 *  \retval r 0 on success, -1 on error
 */
int StreamTcpReassembleHandleSegmentUpdateACK (ThreadVars *tv,
        TcpReassemblyThreadCtx *ra_ctx, TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    SCLogDebug("stream->seg_list %p", stream->seg_list);

    int r = 0;
    if (!(StreamTcpInlineMode())) {
        if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p) < 0)
            r = -1;
        if (StreamTcpReassembleRaw(ra_ctx, ssn, stream, p) < 0)
            r = -1;
    }

    SCLogDebug("stream->seg_list %p", stream->seg_list);
    SCReturnInt(r);
}

int StreamTcpReassembleHandleSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                     TcpSession *ssn, TcpStream *stream,
                                     Packet *p, PacketQueue *pq)
{
    SCEnter();
    SCLogDebug("ssn %p, stream %p, p %p, p->payload_len %"PRIu16"",
                ssn, stream, p, p->payload_len);

    /* we need to update the opposing stream in
     * StreamTcpReassembleHandleSegmentUpdateACK */
    TcpStream *opposing_stream = NULL;
    if (stream == &ssn->client) {
        opposing_stream = &ssn->server;
    } else {
        opposing_stream = &ssn->client;
    }

    /* handle ack received */
    if (StreamTcpReassembleHandleSegmentUpdateACK(tv, ra_ctx, ssn, opposing_stream, p) != 0)
    {
        SCLogDebug("StreamTcpReassembleHandleSegmentUpdateACK error");
        SCReturnInt(-1);
    }

    /* If no stream reassembly/application layer protocol inspection, then
       simple return */
    if (p->payload_len > 0 && !(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        SCLogDebug("calling StreamTcpReassembleHandleSegmentHandleData");

        if (StreamTcpReassembleHandleSegmentHandleData(tv, ra_ctx, ssn, stream, p) != 0) {
            SCLogDebug("StreamTcpReassembleHandleSegmentHandleData error");
            SCReturnInt(-1);
        }

        p->flags |= PKT_STREAM_ADD;
    }

    /* in stream inline mode even if we have no data we call the reassembly
     * functions to handle EOF */
    if (StreamTcpInlineMode()) {
        int r = 0;
        if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p) < 0)
            r = -1;
        if (StreamTcpReassembleInlineRaw(ra_ctx, ssn, stream, p) < 0)
            r = -1;

        if (r < 0) {
            SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief  Function to replace the data from a specific point up to given length.
 *
 *  \param  dst_seg     Destination segment to replace the data
 *  \param  src_seg     Source segment of which data is to be written to destination
 *  \param  start_point Starting point to replace the data onwards
 *  \param  len         Length up to which data is need to be replaced
 *
 *  \todo VJ We can remove the abort()s later.
 *  \todo VJ Why not memcpy?
 */
void StreamTcpSegmentDataReplace(TcpSegment *dst_seg, TcpSegment *src_seg,
                                 uint32_t start_point, uint16_t len)
{
    uint32_t seq;
    uint16_t src_pos = 0;
    uint16_t dst_pos = 0;

    SCLogDebug("start_point %u", start_point);

    if (SEQ_GT(start_point, dst_seg->seq)) {
        dst_pos = start_point - dst_seg->seq;
    } else if (SEQ_LT(start_point, dst_seg->seq)) {
        dst_pos = dst_seg->seq - start_point;
    }

    if (SCLogDebugEnabled()) {
        BUG_ON(((len + dst_pos) - 1) > dst_seg->payload_len);
    } else {
        if (((len + dst_pos) - 1) > dst_seg->payload_len)
            return;
    }

    src_pos = (uint16_t)(start_point - src_seg->seq);

    SCLogDebug("Replacing data from dst_pos %"PRIu16"", dst_pos);

    for (seq = start_point; SEQ_LT(seq, (start_point + len)) &&
            src_pos < src_seg->payload_len && dst_pos < dst_seg->payload_len;
            seq++, dst_pos++, src_pos++)
    {
        dst_seg->payload[dst_pos] = src_seg->payload[src_pos];
    }

    SCLogDebug("Replaced data of size %"PRIu16" up to src_pos %"PRIu16
            " dst_pos %"PRIu16, len, src_pos, dst_pos);
}

/**
 *  \brief  Function to compare the data from a specific point up to given length.
 *
 *  \param  dst_seg     Destination segment to compare the data
 *  \param  src_seg     Source segment of which data is to be compared to destination
 *  \param  start_point Starting point to compare the data onwards
 *  \param  len         Length up to which data is need to be compared
 *
 *  \retval 1 same
 *  \retval 0 different
 */
static int StreamTcpSegmentDataCompare(TcpSegment *dst_seg, TcpSegment *src_seg,
                                 uint32_t start_point, uint16_t len)
{
    uint32_t seq;
    uint16_t src_pos = 0;
    uint16_t dst_pos = 0;

    SCLogDebug("start_point %u dst_seg %u src_seg %u", start_point, dst_seg->seq, src_seg->seq);

    if (SEQ_GT(start_point, dst_seg->seq)) {
        SCLogDebug("start_point %u > dst %u", start_point, dst_seg->seq);
        dst_pos = start_point - dst_seg->seq;
    } else if (SEQ_LT(start_point, dst_seg->seq)) {
        SCLogDebug("start_point %u < dst %u", start_point, dst_seg->seq);
        dst_pos = dst_seg->seq - start_point;
    }

    if (SCLogDebugEnabled()) {
        BUG_ON(((len + dst_pos) - 1) > dst_seg->payload_len);
    } else {
        if (((len + dst_pos) - 1) > dst_seg->payload_len)
            return 1;
    }

    src_pos = (uint16_t)(start_point - src_seg->seq);

    SCLogDebug("Comparing data from dst_pos %"PRIu16", src_pos %u", dst_pos, src_pos);

    for (seq = start_point; SEQ_LT(seq, (start_point + len)) &&
            src_pos < src_seg->payload_len && dst_pos < dst_seg->payload_len;
            seq++, dst_pos++, src_pos++)
    {
        if (dst_seg->payload[dst_pos] != src_seg->payload[src_pos]) {
            SCLogDebug("data is different %02x != %02x, dst_pos %u, src_pos %u", dst_seg->payload[dst_pos], src_seg->payload[src_pos], dst_pos, src_pos);
            return 0;
        }
    }

    SCLogDebug("Compared data of size %"PRIu16" up to src_pos %"PRIu16
            " dst_pos %"PRIu16, len, src_pos, dst_pos);
    return 1;
}

/**
 *  \brief  Function to copy the data from src_seg to dst_seg.
 *
 *  \param  dst_seg     Destination segment for copying the contents
 *  \param  src_seg     Source segment to copy its contents
 *
 *  \todo VJ wouldn't a memcpy be more appropriate here?
 *
 *  \warning Both segments need to be properly initialized.
 */

void StreamTcpSegmentDataCopy(TcpSegment *dst_seg, TcpSegment *src_seg)
{
    uint32_t u;
    uint16_t dst_pos = 0;
    uint16_t src_pos = 0;
    uint32_t seq;

    if (SEQ_GT(dst_seg->seq, src_seg->seq)) {
        src_pos = dst_seg->seq - src_seg->seq;
        seq = dst_seg->seq;
    } else {
        dst_pos = src_seg->seq - dst_seg->seq;
        seq = src_seg->seq;
    }

    SCLogDebug("Copying data from seq %"PRIu32"", seq);
    for (u = seq;
            (SEQ_LT(u, (src_seg->seq + src_seg->payload_len)) &&
             SEQ_LT(u, (dst_seg->seq + dst_seg->payload_len))); u++)
    {
        //SCLogDebug("u %"PRIu32, u);

        dst_seg->payload[dst_pos] = src_seg->payload[src_pos];

        dst_pos++;
        src_pos++;
    }
    SCLogDebug("Copyied data of size %"PRIu16" up to dst_pos %"PRIu16"",
                src_pos, dst_pos);
}

/**
 *  \brief   Function to get the segment of required length from the pool.
 *
 *  \param   len    Length which tells the required size of needed segment.
 *
 *  \retval seg Segment from the pool or NULL
 */
TcpSegment* StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, uint16_t len)
{
    uint16_t idx = segment_pool_idx[len];
    SCLogDebug("segment_pool_idx %" PRIu32 " for payload_len %" PRIu32 "",
                idx, len);

    SCMutexLock(&segment_pool_mutex[idx]);
    TcpSegment *seg = (TcpSegment *) PoolGet(segment_pool[idx]);

    SCLogDebug("segment_pool[%u]->empty_stack_size %u, segment_pool[%u]->alloc_"
               "list_size %u, alloc %u", idx, segment_pool[idx]->empty_stack_size,
               idx, segment_pool[idx]->alloc_stack_size,
               segment_pool[idx]->allocated);
    SCMutexUnlock(&segment_pool_mutex[idx]);

    SCLogDebug("seg we return is %p", seg);
    if (seg == NULL) {
        SCLogDebug("segment_pool[%u]->empty_stack_size %u, "
                   "alloc %u", idx, segment_pool[idx]->empty_stack_size,
                   segment_pool[idx]->allocated);
        /* Increment the counter to show that we are not able to serve the
           segment request due to memcap limit */
        StatsIncr(tv, ra_ctx->counter_tcp_segment_memcap);
    } else {
        seg->flags = stream_config.segment_init_flags;
        seg->next = NULL;
        seg->prev = NULL;
    }

#ifdef DEBUG
    SCMutexLock(&segment_pool_cnt_mutex);
    segment_pool_cnt++;
    SCMutexUnlock(&segment_pool_cnt_mutex);
#endif

    return seg;
}

/**
 *  \brief Trigger RAW stream reassembly
 *
 *  Used by AppLayerTriggerRawStreamReassembly to trigger RAW stream
 *  reassembly from the applayer, for example upon completion of a
 *  HTTP request.
 *
 *  Works by setting a flag in the TcpSession that is unset as soon
 *  as it's checked. Since everything happens when operating under
 *  a single lock period, no side effects are expected.
 *
 *  \param ssn TcpSession
 */
void StreamTcpReassembleTriggerRawReassembly(TcpSession *ssn)
{
#ifdef DEBUG
    BUG_ON(ssn == NULL);
#endif

    if (ssn != NULL) {
        SCLogDebug("flagged ssn %p for immediate raw reassembly", ssn);
        ssn->flags |= STREAMTCP_FLAG_TRIGGER_RAW_REASSEMBLY;
    }
}

#ifdef UNITTESTS
/** unit tests and it's support functions below */

static int UtTestSmsg(StreamMsg *smsg, const uint8_t *buf, uint32_t buf_len)
{
    if (smsg == NULL)
        return 0;

    if (smsg->data_len != buf_len) {
        return 0;
    }

    if (!(memcmp(buf, smsg->data, buf_len) == 0)) {
        printf("data is not what we expected:\nExpected:\n");
        PrintRawDataFp(stdout, (uint8_t *)buf, buf_len);
        printf("Got:\n");
        PrintRawDataFp(stdout, smsg->data, smsg->data_len);
        return 0;
    }
    return 1;
}

static uint32_t UtSsnSmsgCnt(TcpSession *ssn, uint8_t direction)
{
    uint32_t cnt = 0;
    StreamMsg *smsg = (direction == STREAM_TOSERVER) ?
                            ssn->toserver_smsg_head :
                            ssn->toclient_smsg_head;
    while (smsg) {
        cnt++;
        smsg = smsg->next;
    }
    return cnt;
}

/** \brief  The Function tests the reassembly engine working for different
 *          OSes supported. It includes all the OS cases and send
 *          crafted packets to test the reassembly.
 *
 *  \param  stream  The stream which will contain the reassembled segments
 */

static int StreamTcpReassembleStreamTest(TcpStream *stream)
{

    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->tcph->th_seq = htonl(12);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x42, 2, 4); /*BB*/
    p->tcph->th_seq = htonl(16);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->tcph->th_seq = htonl(18);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x44, 1, 4); /*D*/
    p->tcph->th_seq = htonl(22);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x45, 2, 4); /*EE*/
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x46, 3, 4); /*FFF*/
    p->tcph->th_seq = htonl(27);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x47, 2, 4); /*GG*/
    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x48, 2, 4); /*HH*/
    p->tcph->th_seq = htonl(32);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x49, 1, 4); /*I*/
    p->tcph->th_seq = htonl(34);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4a, 4, 4); /*JJJJ*/
    p->tcph->th_seq = htonl(13);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4b, 3, 4); /*KKK*/
    p->tcph->th_seq = htonl(18);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4c, 3, 4); /*LLL*/
    p->tcph->th_seq = htonl(21);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4d, 3, 4); /*MMM*/
    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4e, 1, 4); /*N*/
    p->tcph->th_seq = htonl(28);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4f, 1, 4); /*O*/
    p->tcph->th_seq = htonl(31);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x50, 1, 4); /*P*/
    p->tcph->th_seq = htonl(32);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x51, 2, 4); /*QQ*/
    p->tcph->th_seq = htonl(34);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x30, 1, 4); /*0*/
    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpReassembleFreeThreadCtx(ra_ctx);

    SCFree(p);
    return 1;
}

/** \brief  The Function to create the packet with given payload, which is used
 *          to test the reassembly of the engine.
 *
 *  \param  payload     The variable used to store the payload contents of the
 *                      current packet.
 *  \param  value       The value which current payload will have for this packet
 *  \param  payload_len The length of the filed payload for current packet.
 *  \param  len         Length of the payload array
 */

void StreamTcpCreateTestPacket(uint8_t *payload, uint8_t value,
                               uint8_t payload_len, uint8_t len)
{
    uint8_t i;
    for (i = 0; i < payload_len; i++)
        payload[i] = value;
    for (; i < len; i++)
        payload = NULL;
}

/** \brief  The Function Checks the reassembled stream contents against predefined
 *          stream contents according to OS policy used.
 *
 *  \param  stream_policy   Predefined value of stream for different OS policies
 *  \param  stream          Reassembled stream returned from the reassembly functions
 */

int StreamTcpCheckStreamContents(uint8_t *stream_policy, uint16_t sp_size, TcpStream *stream)
{
    TcpSegment *temp;
    uint16_t i = 0;
    uint8_t j;

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        TcpSegment *temp1;
        for (temp1 = stream->seg_list; temp1 != NULL; temp1 = temp1->next)
            PrintRawDataFp(stdout, temp1->payload, temp1->payload_len);

        PrintRawDataFp(stdout, stream_policy, sp_size);
    }
#endif

    for (temp = stream->seg_list; temp != NULL; temp = temp->next) {
        j = 0;
        for (; j < temp->payload_len; j++) {
            SCLogDebug("i %"PRIu16", len %"PRIu32", stream %"PRIx32" and temp is %"PRIx8"",
                i, temp->payload_len, stream_policy[i], temp->payload[j]);

            if (stream_policy[i] == temp->payload[j]) {
                i++;
                continue;
            } else
                return 0;
        }
    }
    return 1;
}

/** \brief  The Function Checks the Stream Queue contents against predefined
 *          stream contents.
 *
 *  \param  stream_contents     Predefined value of stream contents
 *  \param  stream              Queue which has the stream contents
 *
 *  \retval On success the function returns 1, on failure 0.
 */
static int StreamTcpCheckChunks (TcpSession *ssn, uint8_t *stream_contents)
{
    SCEnter();

    StreamMsg *msg;
    uint16_t i = 0;
    uint8_t j;
    uint8_t cnt = 0;

    if (ssn == NULL) {
        printf("ssn == NULL, ");
        SCReturnInt(0);
    }

    if (ssn->toserver_smsg_head == NULL) {
        printf("ssn->toserver_smsg_head == NULL, ");
        SCReturnInt(0);
    }

    msg = ssn->toserver_smsg_head;
    while(msg != NULL) {
        cnt++;
        j = 0;
        for (; j < msg->data_len; j++) {
            SCLogDebug("i is %" PRIu32 " and len is %" PRIu32 "  and temp is %" PRIx32 "", i, msg->data_len, msg->data[j]);

            if (stream_contents[i] == msg->data[j]) {
                i++;
                continue;
            } else {
                SCReturnInt(0);
            }
        }
        msg = msg->next;
    }
    SCReturnInt(1);
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats before the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */

static int StreamTcpTestStartsBeforeListSegment(TcpStream *stream) {
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));

    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 1, 4); /*B*/
    p->tcph->th_seq = htonl(16);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x44, 1, 4); /*D*/
    p->tcph->th_seq = htonl(22);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x45, 2, 4); /*EE*/
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4a, 4, 4); /*JJJJ*/
    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    SCLogDebug("sending segment with SEQ 21, len 3");
    StreamTcpCreateTestPacket(payload, 0x4c, 3, 4); /*LLL*/
    p->tcph->th_seq = htonl(21);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4d, 3, 4); /*MMM*/
    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    SCFree(p);
    return 1;
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats at the same seq no. as the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */

static int StreamTcpTestStartsAtSameListSegment(TcpStream *stream)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->tcph->th_seq = htonl(18);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x48, 2, 4); /*HH*/
    p->tcph->th_seq = htonl(32);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x49, 1, 4); /*I*/
    p->tcph->th_seq = htonl(34);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4b, 3, 4); /*KKK*/
    p->tcph->th_seq = htonl(18);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4c, 4, 4); /*LLLL*/
    p->tcph->th_seq = htonl(18);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x50, 1, 4); /*P*/
    p->tcph->th_seq = htonl(32);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x51, 2, 4); /*QQ*/
    p->tcph->th_seq = htonl(34);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    SCFree(p);
    return 1;
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats after the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */


static int StreamTcpTestStartsAfterListSegment(TcpStream *stream)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    p->tcph->th_seq = htonl(12);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x46, 3, 4); /*FFF*/
    p->tcph->th_seq = htonl(27);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x47, 2, 4); /*GG*/
    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4a, 2, 4); /*JJ*/
    p->tcph->th_seq = htonl(13);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4f, 1, 4); /*O*/
    p->tcph->th_seq = htonl(31);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpCreateTestPacket(payload, 0x4e, 1, 4); /*N*/
    p->tcph->th_seq = htonl(28);
    p->tcph->th_ack = htonl(31);
    p->payload = payload;
    p->payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    SCFree(p);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest01(void)
{
    TcpStream stream;
    uint8_t stream_before_bsd[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                      0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_bsd,sizeof(stream_before_bsd), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and BSD policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest02(void)
{
    TcpStream stream;
    uint8_t stream_same_bsd[8] = {0x43, 0x43, 0x43, 0x4c, 0x48, 0x48,
                                    0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_bsd, sizeof(stream_same_bsd), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest03(void)
{
    TcpStream stream;
    uint8_t stream_after_bsd[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                     0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_bsd, sizeof(stream_after_bsd), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and BSD policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest04(void)
{
    TcpStream stream;
    uint8_t stream_bsd[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x43,
                               0x43, 0x43, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                               0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly: ");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_bsd, sizeof(stream_bsd), &stream) == 0) {
        printf("failed in stream matching: ");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and VISTA policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest05(void)
{
    TcpStream stream;
    uint8_t stream_before_vista[10] = {0x4a, 0x41, 0x42, 0x4a, 0x4c, 0x44,
                                        0x4c, 0x4d, 0x45, 0x45};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_vista, sizeof(stream_before_vista), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and VISTA policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest06(void)
{
    TcpStream stream;
    uint8_t stream_same_vista[8] = {0x43, 0x43, 0x43, 0x4c, 0x48, 0x48,
                                     0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_vista, sizeof(stream_same_vista), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest07(void)
{
    TcpStream stream;
    uint8_t stream_after_vista[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                      0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_vista, sizeof(stream_after_vista), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and VISTA policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest08(void)
{
    TcpStream stream;
    uint8_t stream_vista[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x42, 0x42, 0x43,
                                 0x43, 0x43, 0x4c, 0x44, 0x4c, 0x4d, 0x45, 0x45,
                                 0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_vista, sizeof(stream_vista), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest09(void)
{
    TcpStream stream;
    uint8_t stream_before_linux[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                        0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_linux, sizeof(stream_before_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and LINUX policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest10(void)
{
    TcpStream stream;
    uint8_t stream_same_linux[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                     0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_linux, sizeof(stream_same_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest11(void)
{
    TcpStream stream;
    uint8_t stream_after_linux[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                      0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_linux, sizeof(stream_after_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and LINUX policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest12(void)
{
    TcpStream stream;
    uint8_t stream_linux[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x43,
                                 0x43, 0x43, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                 0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_linux, sizeof(stream_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and OLD_LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest13(void)
{
    TcpStream stream;
    uint8_t stream_before_old_linux[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                            0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_old_linux, sizeof(stream_before_old_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and OLD_LINUX policy is
 *              used to reassemble segments.
 */

static int StreamTcpReassembleTest14(void)
{
    TcpStream stream;
    uint8_t stream_same_old_linux[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                         0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_old_linux, sizeof(stream_same_old_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and OLD_LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest15(void)
{
    TcpStream stream;
    uint8_t stream_after_old_linux[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                          0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_old_linux, sizeof(stream_after_old_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and OLD_LINUX policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest16(void)
{
    TcpStream stream;
    uint8_t stream_old_linux[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x4b,
                                     0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                     0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_old_linux, sizeof(stream_old_linux), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and SOLARIS policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest17(void)
{
    TcpStream stream;
    uint8_t stream_before_solaris[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                          0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_solaris, sizeof(stream_before_solaris), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and SOLARIS policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest18(void)
{
    TcpStream stream;
    uint8_t stream_same_solaris[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                       0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_solaris, sizeof(stream_same_solaris), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and SOLARIS policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest19(void)
{
    TcpStream stream;
    uint8_t stream_after_solaris[8] = {0x41, 0x4a, 0x4a, 0x46, 0x46, 0x46,
                                        0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        StreamTcpFreeConfig(TRUE);
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_solaris, sizeof(stream_after_solaris), &stream) == 0) {
        printf("failed in stream matching!!\n");
        StreamTcpFreeConfig(TRUE);
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and SOLARIS policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest20(void)
{
    TcpStream stream;
    uint8_t stream_solaris[25] = {0x30, 0x41, 0x4a, 0x4a, 0x4a, 0x42, 0x42, 0x4b,
                                   0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                   0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        StreamTcpFreeConfig(TRUE);
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_solaris, sizeof(stream_solaris), &stream) == 0) {
        printf("failed in stream matching!!\n");
        StreamTcpFreeConfig(TRUE);
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and LAST policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest21(void)
{
    TcpStream stream;
    uint8_t stream_before_last[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                       0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_last, sizeof(stream_before_last), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and LAST policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest22(void)
{
    TcpStream stream;
    uint8_t stream_same_last[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x50, 0x48,
                                    0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    StreamTcpInitConfig(TRUE);
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_last, sizeof(stream_same_last), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and LAST policy is used to reassemble
 *              segments.
 */
static int StreamTcpReassembleTest23(void)
{
    TcpStream stream;
    uint8_t stream_after_last[8] = {0x41, 0x4a, 0x4a, 0x46, 0x4e, 0x46, 0x47, 0x4f};
    memset(&stream, 0, sizeof (TcpStream));

    stream.os_policy = OS_POLICY_LAST;
    StreamTcpInitConfig(TRUE);

    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_last, sizeof(stream_after_last), &stream) == 0) {
        printf("failed in stream matching!!\n");
        return 0;
    }
    StreamTcpFreeConfig(TRUE);
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and LAST policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest24(void)
{
    int ret = 0;
    TcpStream stream;
    uint8_t stream_last[25] = {0x30, 0x41, 0x4a, 0x4a, 0x4a, 0x4a, 0x42, 0x4b,
                               0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                               0x46, 0x4e, 0x46, 0x47, 0x4f, 0x50, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));

    stream.os_policy = OS_POLICY_LAST;
    StreamTcpInitConfig(TRUE);

    if (StreamTcpReassembleStreamTest(&stream) == 0)  {
        printf("failed in segments reassembly: ");
        goto end;
    }
    if (StreamTcpCheckStreamContents(stream_last, sizeof(stream_last), &stream) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/** \brief  The Function to test the missed packets handling with given payload,
 *          which is used to test the reassembly of the engine.
 *
 *  \param  stream      Stream which contain the packets
 *  \param  seq         Sequence number of the packet
 *  \param  ack         Acknowledgment number of the packet
 *  \param  payload     The variable used to store the payload contents of the
 *                      current packet.
 *  \param  len         The length of the payload for current packet.
 *  \param  th_flag     The TCP flags
 *  \param  flowflags   The packet flow direction
 *  \param  state       The TCP session state
 *
 *  \retval On success it returns 0 and on failure it return -1.
 */

static int StreamTcpTestMissedPacket (TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, uint32_t seq, uint32_t ack, uint8_t *payload,
        uint16_t len, uint8_t th_flags, uint8_t flowflags, uint8_t state)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return -1;
    Flow f;
    TCPHdr tcph;
    Port sp;
    Port dp;
    struct in_addr in;
    ThreadVars tv;
    PacketQueue pq;

    memset(&pq,0,sizeof(PacketQueue));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&tv, 0, sizeof (ThreadVars));

    sp = 200;
    dp = 220;

    FLOW_INITIALIZE(&f);
    if (inet_pton(AF_INET, "1.2.3.4", &in) != 1) {
        SCFree(p);
        return -1;
    }
    f.src.addr_data32[0] = in.s_addr;
    if (inet_pton(AF_INET, "1.2.3.5", &in) != 1) {
        SCFree(p);
        return -1;
    }
    f.dst.addr_data32[0] = in.s_addr;
    f.flags |= FLOW_IPV4;
    f.sp = sp;
    f.dp = dp;
    f.protoctx = ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(seq);
    tcph.th_ack = htonl(ack);
    tcph.th_flags = th_flags;
    p->tcph = &tcph;
    p->flowflags = flowflags;

    p->payload = payload;
    p->payload_len = len;
    ssn->state = state;

    TcpStream *s = NULL;
    if (flowflags & FLOW_PKT_TOSERVER) {
        s = &ssn->server;
    } else {
        s = &ssn->client;
    }

    SCMutexLock(&f.m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, ssn, s, p, &pq) == -1) {
        SCMutexUnlock(&f.m);
        SCFree(p);
        return -1;
    }

    SCMutexUnlock(&f.m);
    SCFree(p);
    return 0;
}

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the starting of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest25 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    TcpSession ssn;
    uint8_t th_flag;
    uint8_t flowflags;
    uint8_t check_contents[7] = {0x41, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43};

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    memset(&ssn, 0, sizeof (TcpSession));

    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    ack = 20;
    StreamTcpInitConfig(TRUE);

    StreamTcpCreateTestPacket(payload, 0x42, 2, 4); /*BB*/
    seq = 10;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    StreamTcpCreateTestPacket(payload, 0x43, 2, 4); /*CC*/
    seq = 12;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }
    ssn.server.next_seq = 14;
    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    seq = 7;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckStreamContents(check_contents, sizeof(check_contents), &ssn.server) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the middle of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest26 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    TcpSession ssn;
    uint8_t th_flag;
    uint8_t flowflags;
    uint8_t check_contents[7] = {0x41, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43};
    memset(&ssn, 0, sizeof (TcpSession));
    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    ack = 20;
    StreamTcpInitConfig(TRUE);

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    seq = 10;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    StreamTcpCreateTestPacket(payload, 0x43, 2, 4); /*CC*/
    seq = 15;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    StreamTcpCreateTestPacket(payload, 0x42, 2, 4); /*BB*/
    seq = 13;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckStreamContents(check_contents, sizeof(check_contents), &ssn.server) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the end of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest27 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    TcpSession ssn;
    uint8_t th_flag;
    uint8_t flowflags;
    uint8_t check_contents[7] = {0x41, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43};
    memset(&ssn, 0, sizeof (TcpSession));
    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    ack = 20;
    StreamTcpInitConfig(TRUE);

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    seq = 10;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    StreamTcpCreateTestPacket(payload, 0x42, 2, 4); /*BB*/
    seq = 13;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    StreamTcpCreateTestPacket(payload, 0x43, 2, 4); /*CC*/
    seq = 15;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckStreamContents(check_contents, sizeof(check_contents), &ssn.server) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the handling of packets missed by IDS, but the end host has
 *          received it and send the acknowledgment of it. The packet is missed
 *          in the starting of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest28 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    uint8_t th_flag;
    uint8_t th_flags;
    uint8_t flowflags;
    uint8_t check_contents[5] = {0x41, 0x41, 0x42, 0x42, 0x42};
    TcpSession ssn;
    memset(&ssn, 0, sizeof (TcpSession));
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    StreamTcpInitConfig(TRUE);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    th_flags = TH_ACK;

    ssn.server.last_ack = 22;
    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 6;
    ssn.server.isn = 6;

    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    seq = 10;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly (1): ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 12;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly (2): ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    seq = 12;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly (4): ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 15;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_TIME_WAIT) == -1) {
        printf("failed in segments reassembly (5): ");
        goto end;
    }

    if (StreamTcpCheckChunks(&ssn, check_contents) == 0) {
        printf("failed in stream matching (6): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the handling of packets missed by IDS, but the end host has
 *          received it and send the acknowledgment of it. The packet is missed
 *          in the middle of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest29 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    uint8_t th_flag;
    uint8_t th_flags;
    uint8_t flowflags;
    uint8_t check_contents[5] = {0x41, 0x41, 0x42, 0x42, 0x42};
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpSession ssn;
    memset(&ssn, 0, sizeof (TcpSession));

    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    th_flags = TH_ACK;

    ssn.server.last_ack = 22;
    ssn.server.ra_raw_base_seq = 9;
    ssn.server.isn = 9;
    StreamTcpInitConfig(TRUE);

    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    seq = 10;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 15;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    seq = 15;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 18;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_TIME_WAIT) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckChunks(&ssn, check_contents) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the handling of packets missed by IDS, but the end host has
 *          received it and send the acknowledgment of it. The packet is missed
 *          at the end of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest30 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    uint8_t th_flag;
    uint8_t th_flags;
    uint8_t flowflags;
    uint8_t check_contents[6] = {0x41, 0x41, 0x42, 0x42, 0x42, 0x00};
    TcpSession ssn;
    memset(&ssn, 0, sizeof (TcpSession));

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;
    th_flags = TH_ACK;

    ssn.client.last_ack = 2;
    ssn.client.isn = 1;

    ssn.server.last_ack = 22;
    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 9;
    ssn.server.isn = 9;

    StreamTcpInitConfig(TRUE);
    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    seq = 10;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 12;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    seq = 12;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 3, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 18;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flags, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    th_flag = TH_FIN|TH_ACK;
    seq = 18;
    ack = 20;
    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x00, 1, 4);
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 1, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOCLIENT;
    StreamTcpCreateTestPacket(payload, 0x00, 0, 4);
    seq = 20;
    ack = 18;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 0, th_flag, flowflags, TCP_TIME_WAIT) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckChunks(&ssn, check_contents) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test to reassemble the packets using the fast track method, as most
 *          packets arrives in order.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest31 (void)
{
    int ret = 0;
    uint8_t payload[4];
    uint32_t seq;
    uint32_t ack;
    uint8_t th_flag;
    uint8_t flowflags;
    uint8_t check_contents[5] = {0x41, 0x41, 0x42, 0x42, 0x42};
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpSession ssn;
    memset(&ssn, 0, sizeof (TcpSession));

    flowflags = FLOW_PKT_TOSERVER;
    th_flag = TH_ACK|TH_PUSH;

    ssn.server.ra_raw_base_seq = 9;
    ssn.server.isn = 9;
    StreamTcpInitConfig(TRUE);

    StreamTcpCreateTestPacket(payload, 0x41, 2, 4); /*AA*/
    seq = 10;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 2, th_flag, flowflags, TCP_ESTABLISHED) == -1){
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 1, 4); /*B*/
    seq = 15;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 1, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 1, 4); /*B*/
    seq = 12;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 1, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x42, 1, 4); /*B*/
    seq = 16;
    ack = 20;
    if (StreamTcpTestMissedPacket (ra_ctx, &ssn, seq, ack, payload, 1, th_flag, flowflags, TCP_ESTABLISHED) == -1) {
        printf("failed in segments reassembly: ");
        goto end;
    }

    if (StreamTcpCheckStreamContents(check_contents, 5, &ssn.server) == 0) {
        printf("failed in stream matching: ");
        goto end;
    }

    if (ssn.server.seg_list_tail->seq != 16) {
        printf("failed in fast track handling: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

static int StreamTcpReassembleTest32(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    uint8_t ret = 0;
    uint8_t check_contents[35] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                                 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                                 0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42,
                                 0x42, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
                                 0x43, 0x43, 0x43};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    uint8_t payload[20] = "";

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;
    StreamTcpCreateTestPacket(payload, 0x41, 10, 20); /*AA*/
    p->payload = payload;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;
    StreamTcpCreateTestPacket(payload, 0x42, 10, 20); /*BB*/
    p->payload = payload;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(40);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;
    StreamTcpCreateTestPacket(payload, 0x43, 10, 20); /*CC*/
    p->payload = payload;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(5);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 20;
    StreamTcpCreateTestPacket(payload, 0x41, 20, 20); /*AA*/
    p->payload = payload;
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1)
        goto end;

    if (StreamTcpCheckStreamContents(check_contents, 35, &stream) != 0) {
        ret = 1;
    } else {
        printf("failed in stream matching: ");
    }


end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

static int StreamTcpReassembleTest33(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(40);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(5);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 30;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return 1;
}

static int StreamTcpReassembleTest34(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;

    p->tcph->th_seq = htonl(857961230);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 304;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(857961534);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(857963582);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(857960946);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return 1;
}

/** \test Test the bug 56 condition */
static int StreamTcpReassembleTest35(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 10);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 10);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;

    p->tcph->th_seq = htonl(2257022155UL);
    p->tcph->th_ack = htonl(1374943142);
    p->payload_len = 142;
    stream.last_ack = 2257022285UL;
    stream.ra_raw_base_seq = 2257022172UL;
    stream.ra_app_base_seq = 2257022172UL;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(2257022285UL);
    p->tcph->th_ack = htonl(1374943142);
    p->payload_len = 34;
    stream.last_ack = 2257022285UL;
    stream.ra_raw_base_seq = 2257022172UL;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return 1;
}

/** \test Test the bug 57 condition */
static int StreamTcpReassembleTest36(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 10);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 10);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;

    p->tcph->th_seq = htonl(1549588966);
    p->tcph->th_ack = htonl(4162241372UL);
    p->payload_len = 204;
    stream.last_ack = 1549589007;
    stream.ra_raw_base_seq = 1549589101;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(1549589007);
    p->tcph->th_ack = htonl(4162241372UL);
    p->payload_len = 23;
    stream.last_ack = 1549589007;
    stream.ra_raw_base_seq = 1549589101;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return 1;
}

/** \test Test the bug 76 condition */
static int StreamTcpReassembleTest37(void)
{
    TcpSession ssn;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    TcpStream stream;
    uint8_t packet[1460] = "";
    PacketQueue pq;
    ThreadVars tv;

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 10);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 10);

    memset(&stream, 0, sizeof (TcpStream));
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&tv, 0, sizeof (ThreadVars));

    FLOW_INITIALIZE(&f);
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    stream.os_policy = OS_POLICY_BSD;

    p->tcph->th_seq = htonl(3061088537UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    stream.last_ack = 3061091137UL;
    stream.ra_raw_base_seq = 3061091309UL;
    stream.ra_app_base_seq = 3061091309UL;

    /* pre base_seq, so should be rejected */
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) != -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(3061089928UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    stream.last_ack = 3061091137UL;
    stream.ra_raw_base_seq = 3061091309UL;
    stream.ra_app_base_seq = 3061091309UL;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(3061091319UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    stream.last_ack = 3061091137UL;
    stream.ra_raw_base_seq = 3061091309UL;
    stream.ra_app_base_seq = 3061091309UL;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return 1;
}

/**
 *  \test   Test to make sure we don't send the smsg from toclient to app layer
 *          until the app layer protocol has been detected and one smsg from
 *          toserver side has been sent to app layer.
 *
 * Unittest modified by commit -
 *
 * commit bab1636377bb4f1b7b889f4e3fd594795085eaa4
 * Author: Anoop Saldanha <anoopsaldanha@gmail.com>
 * Date:   Fri Feb 15 18:58:33 2013 +0530
 *
 *     Improved app protocol detection.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpReassembleTest38 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    Port sp;
    Port dp;
    struct in_addr in;
    TcpSession ssn;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    uint8_t httpbuf2[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    uint8_t httpbuf1[] = "HTTP/1.0 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    FLOW_INITIALIZE(&f);
    if (inet_pton(AF_INET, "1.2.3.4", &in) != 1)
        goto end;
    f.src.addr_data32[0] = in.s_addr;
    if (inet_pton(AF_INET, "1.2.3.5", &in) != 1)
        goto end;
    f.dst.addr_data32[0] = in.s_addr;
    sp = 200;
    dp = 220;

    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 9;
    ssn.server.isn = 9;
    ssn.server.last_ack = 60;
    ssn.client.ra_raw_base_seq = ssn.client.ra_app_base_seq = 9;
    ssn.client.isn = 9;
    ssn.client.last_ack = 9;
    f.alproto = ALPROTO_UNKNOWN;

    f.flags |= FLOW_IPV4;
    f.sp = sp;
    f.dp = dp;
    f.protoctx = &ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->payload = httpbuf2;
    p->payload_len = httplen2;
    ssn.state = TCP_ESTABLISHED;

    TcpStream *s = NULL;
    s = &ssn.server;

    SCMutexLock(&f.m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (1): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) > 0) {
        printf("there shouldn't be any stream smsgs in the queue (2): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf1;
    p->payload_len = httplen1;
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(55);
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (3): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("there should one stream smsg in the queue (6): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCMutexUnlock(&f.m);
    SCFree(p);
    return ret;
}

/**
 *  \test   Test to make sure that we don't return the segments until the app
 *          layer proto has been detected and after that remove the processed
 *          segments.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest39 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    f.flags = FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->tcph = &tcph;

    SCMutexLock(&f.m);
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* handshake */
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* partial request */
    uint8_t request1[] = { 0x47, 0x45, };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }


    /* response ack against partial request */
    p->tcph->th_ack = htonl(3);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

    /* complete partial request */
    uint8_t request2[] = {
        0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(3);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request2);
    p->payload = request2;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->toserver_smsg_head != NULL ||
        ssn->toclient_smsg_head != NULL ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 6\n");
        goto end;
    }

    /* response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next != NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 7\n");
        goto end;
    }

    /* response ack from request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next != NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 8\n");
        goto end;
    }

    /* response - acking */
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 9\n");
        goto end;
    }

    /* response ack from request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 10\n");
        goto end;
    }

    /* response - acking the request again*/
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 11\n");
        goto end;
    }

    /*** New Request ***/

    /* partial request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 12\n");
        goto end;
    }


    /* response ack against partial request */
    p->tcph->th_ack = htonl(90);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 13\n");
        goto end;
    }

    /* complete request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(90);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request2);
    p->payload = request2;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list == NULL ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next == NULL ||
        ssn->client.seg_list->next->next->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 14\n");
        goto end;
    }

    /* response ack against second partial request */
    p->tcph->th_ack = htonl(175);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list->next == NULL ||
        ssn->client.seg_list->next->next == NULL ||
        ssn->client.seg_list->next->next->next == NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 15\n");
        goto end;
    }

    if (ssn->toserver_smsg_head == NULL ||
        ssn->toserver_smsg_head->next == NULL ||
        ssn->toserver_smsg_head->next->next != NULL ||
        ssn->toclient_smsg_head == NULL ||
        ssn->toclient_smsg_head->next != NULL) {
        printf("failure 16\n");
        goto end;
    }

    StreamMsgReturnListToPool(ssn->toserver_smsg_head);
    ssn->toserver_smsg_head = ssn->toserver_smsg_tail = NULL;
    StreamMsgReturnListToPool(ssn->toclient_smsg_head);
    ssn->toclient_smsg_head = ssn->toclient_smsg_tail = NULL;

    /* response acking a request */
    p->tcph->th_ack = htonl(175);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list == NULL ||
        ssn->server.seg_list->next != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 15\n");
        goto end;
    }

    /* request acking a response */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(175);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 15\n");
        goto end;
    }


    ret = 1;
end:
    StreamTcpThreadDeinit(&tv, (void *)stt);
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f.m);
    return ret;
}

/**
 *  \test   Test to make sure that we sent all the segments from the initial
 *          segments to app layer until we have detected the app layer proto.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest40 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpInitConfig(TRUE);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 130);

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    uint8_t httpbuf1[] = "P";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "O";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "S";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "T \r\n";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */

    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 9;
    ssn.server.isn = 9;
    ssn.server.last_ack = 10;
    ssn.client.ra_raw_base_seq = ssn.client.ra_app_base_seq = 9;
    ssn.client.isn = 9;
    ssn.client.last_ack = 10;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(10);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->payload = httpbuf1;
    p->payload_len = httplen1;
    ssn.state = TCP_ESTABLISHED;

    TcpStream *s = NULL;
    s = &ssn.client;

    SCMutexLock(&f->m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (1): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOCLIENT) > 0) {
        printf("there shouldn't be any stream smsgs in the queue, as we didn't"
                " processed any smsg from toserver side till yet (2): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    s = &ssn.server;
    ssn.server.last_ack = 11;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (3): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = httpbuf3;
    p->payload_len = httplen3;
    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(55);
    s = &ssn.client;
    ssn.client.last_ack = 55;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (5): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(55);
    tcph.th_ack = htonl(12);
    s = &ssn.server;
    ssn.server.last_ack = 12;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (6): ");
        goto end;
    }

    /* check is have the segment in the list and flagged or not */
    if (ssn.client.seg_list == NULL ||
        (ssn.client.seg_list->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED))
    {
        printf("the list is NULL or the processed segment has not been flaged (7): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = httpbuf4;
    p->payload_len = httplen4;
    tcph.th_seq = htonl(12);
    tcph.th_ack = htonl(100);
    s = &ssn.client;
    ssn.client.last_ack = 100;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (10): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(100);
    tcph.th_ack = htonl(13);
    s = &ssn.server;
    ssn.server.last_ack = 13;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (11): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = httpbuf5;
    p->payload_len = httplen5;
    tcph.th_seq = htonl(13);
    tcph.th_ack = htonl(145);
    s = &ssn.client;
    ssn.client.last_ack = 145;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (14): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(145);
    tcph.th_ack = htonl(16);
    s = &ssn.server;
    ssn.server.last_ack = 16;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (15): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) == 0) {
        printf("there should be a stream smsgs in the queue, as we have detected"
                " the app layer protocol and one smsg from toserver side has "
                "been sent (16): ");
        goto end;
    }

    if (f->alproto != ALPROTO_HTTP) {
        printf("app layer proto has not been detected (18): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/**
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest43 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    uint8_t httpbuf1[] = "/ HTTP/1.0\r\nUser-Agent: Victor/1.0";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    uint8_t httpbuf3[] = "W2dyb3VwMV0NCnBob25lMT1wMDB3ODgyMTMxMzAyMTINCmxvZ2lu"
                         "MT0NCnBhc3N3b3JkMT0NCnBob25lMj1wMDB3ODgyMTMxMzAyMTIN"
                         "CmxvZ2luMj0NCnBhc3N3b3JkMj0NCnBob25lMz0NCmxvZ2luMz0N"
                         "CnBhc3N3b3JkMz0NCnBob25lND0NCmxvZ2luND0NCnBhc3N3b3Jk"
                         "ND0NCnBob25lNT0NCmxvZ2luNT0NCnBhc3N3b3JkNT0NCnBob25l"
                         "Nj0NCmxvZ2luNj0NCnBhc3N3b3JkNj0NCmNhbGxfdGltZTE9MzIN"
                         "CmNhbGxfdGltZTI9MjMyDQpkYXlfbGltaXQ9NQ0KbW9udGhfbGlt"
                         "aXQ9MTUNCltncm91cDJdDQpwaG9uZTE9DQpsb2dpbjE9DQpwYXNz"
                         "d29yZDE9DQpwaG9uZTI9DQpsb2dpbjI9DQpwYXNzd29yZDI9DQpw"
                         "aG9uZT\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 9;
    ssn.server.isn = 9;
    ssn.server.last_ack = 600;
    ssn.client.ra_raw_base_seq = ssn.client.ra_app_base_seq = 9;
    ssn.client.isn = 9;
    ssn.client.last_ack = 600;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(10);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOCLIENT;

    p->payload = httpbuf2;
    p->payload_len = httplen2;
    ssn.state = TCP_ESTABLISHED;

    TcpStream *s = NULL;
    s = &ssn.server;

    SCMutexLock(&f->m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (1): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) > 0) {
        printf("there shouldn't be any stream smsgs in the queue (2): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = httpbuf1;
    p->payload_len = httplen1;
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(55);
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (3): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOCLIENT) > 0) {
        printf("there shouldn't be any stream smsgs in the queue, as we didn't"
                " processed any smsg from toserver side till yet (4): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(55);
    tcph.th_ack = htonl(44);
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (5): ");
        goto end;
    }
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn.client)) {
        printf("app layer detected flag isn't set, it should be (8): ");
        goto end;
    }

    /* This packets induces a packet gap and also shows why we need to
       process the current segment completely, even if it results in sending more
       than one smsg to the app layer. If we don't send more than one smsg in
       this case, then the first segment of lentgh 34 bytes will be sent to
       app layer and protocol can not be detected in that message and moreover
       the segment lentgh is less than the max. signature size for protocol
       detection, so this will keep looping !! */
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = httpbuf3;
    p->payload_len = httplen3;
    tcph.th_seq = htonl(54);
    tcph.th_ack = htonl(100);
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (9): ");
        goto end;
    }

    /* Check if we have stream smsgs in queue */
    if (UtSsnSmsgCnt(&ssn, STREAM_TOCLIENT) > 0) {
        printf("there shouldn't be any stream smsgs in the queue, as we didn't"
                " detected the app layer protocol till yet (10): ");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload = httpbuf2;
    p->payload_len = httplen2;
    tcph.th_seq = htonl(100);
    tcph.th_ack = htonl(53);
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet (11): ");
        goto end;
    }
    /* the flag should be set, as the smsg scanned size has crossed the max.
       signature size for app proto detection */
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn.client)) {
        printf("app layer detected flag is not set, it should be (14): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/** \test   Test the memcap incrementing/decrementing and memcap check */
static int StreamTcpReassembleTest44(void)
{
    uint8_t ret = 0;
    StreamTcpInitConfig(TRUE);
    uint32_t memuse = SC_ATOMIC_GET(ra_memuse);

    StreamTcpReassembleIncrMemuse(500);
    if (SC_ATOMIC_GET(ra_memuse) != (memuse+500)) {
        printf("failed in incrementing the memory");
        goto end;
    }

    StreamTcpReassembleDecrMemuse(500);
    if (SC_ATOMIC_GET(ra_memuse) != memuse) {
        printf("failed in decrementing the memory");
        goto end;
    }

    if (StreamTcpReassembleCheckMemcap(500) != 1) {
        printf("failed in validating the memcap");
        goto end;
    }

    if (StreamTcpReassembleCheckMemcap((memuse + stream_config.reassembly_memcap)) != 0) {
        printf("failed in validating the memcap");
        goto end;
    }

    StreamTcpFreeConfig(TRUE);

    if (SC_ATOMIC_GET(ra_memuse) != 0) {
        printf("failed in clearing the memory");
        goto end;
    }

    ret = 1;
    return ret;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test to make sure that reassembly_depth is enforced.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest45 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));

    uint8_t httpbuf1[] = "/ HTTP/1.0\r\nUser-Agent: Victor/1.0";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    STREAMTCP_SET_RA_BASE_SEQ(&ssn.server, 9);
    ssn.server.isn = 9;
    ssn.server.last_ack = 60;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.client, 9);
    ssn.client.isn = 9;
    ssn.client.last_ack = 9;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOCLIENT;

    p->payload = httpbuf1;
    p->payload_len = httplen1;
    ssn.state = TCP_ESTABLISHED;

    /* set the default value of reassembly depth, as there is no config file */
    stream_config.reassembly_depth = httplen1 + 1;

    TcpStream *s = NULL;
    s = &ssn.server;

    SCMutexLock(&f->m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toclient packet: ");
        goto end;
    }

    /* Check if we have flags set or not */
    if (s->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        printf("there shouldn't be a noreassembly flag be set: ");
        goto end;
    }
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.server, ssn.server.isn + httplen1);

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = httplen1;
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet: ");
        goto end;
    }

    /* Check if we have flags set or not */
    if (s->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        printf("there shouldn't be a noreassembly flag be set: ");
        goto end;
    }
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.client, ssn.client.isn + httplen1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = httplen1;
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet: ");
        goto end;
    }

    /* Check if we have flags set or not */
    if (!(s->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("the noreassembly flags should be set, "
                "p.payload_len %"PRIu16" stream_config.reassembly_"
                "depth %"PRIu32": ", p->payload_len,
                stream_config.reassembly_depth);
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/**
 *  \test   Test the undefined config value of reassembly depth.
 *          the default value of 0 will be loaded and stream will be reassembled
 *          until the session ended
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest46 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    ThreadVars tv;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof (ThreadVars));

    uint8_t httpbuf1[] = "/ HTTP/1.0\r\nUser-Agent: Victor/1.0";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    STREAMTCP_SET_RA_BASE_SEQ(&ssn.server, 9);
    ssn.server.isn = 9;
    ssn.server.last_ack = 60;
    ssn.server.next_seq = ssn.server.isn;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.client, 9);
    ssn.client.isn = 9;
    ssn.client.last_ack = 9;
    ssn.client.next_seq = ssn.client.isn;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOCLIENT;

    p->payload = httpbuf1;
    p->payload_len = httplen1;
    ssn.state = TCP_ESTABLISHED;

    stream_config.reassembly_depth = 0;

    TcpStream *s = NULL;
    s = &ssn.server;

    SCMutexLock(&f->m);
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toclient packet\n");
        goto end;
    }

    /* Check if we have flags set or not */
    if ((ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("there shouldn't be any no reassembly flag be set \n");
        goto end;
    }
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.server, ssn.server.isn + httplen1);

    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = httplen1;
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    /* Check if we have flags set or not */
    if ((ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("there shouldn't be any no reassembly flag be set \n");
        goto end;
    }
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.client, ssn.client.isn + httplen1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = httplen1;
    tcph.th_seq = htonl(10 + httplen1);
    tcph.th_ack = htonl(20 + httplen1);
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    /* Check if we have flags set or not */
    if ((ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("the no_reassembly flags should not be set, "
                "p->payload_len %"PRIu16" stream_config.reassembly_"
                "depth %"PRIu32": ", p->payload_len,
                stream_config.reassembly_depth);
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/**
 *  \test   Test to make sure we detect the sequence wrap around and continue
 *          stream reassembly properly.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest47 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    ThreadVars tv;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof (ThreadVars));

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 0);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 0);

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    uint8_t httpbuf1[] = "GET /EVILSUFF HTTP/1.1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    ssn.server.ra_raw_base_seq = ssn.server.ra_app_base_seq = 572799781UL;
    ssn.server.isn = 572799781UL;
    ssn.server.last_ack = 572799782UL;
    ssn.client.ra_raw_base_seq = ssn.client.ra_app_base_seq = 4294967289UL;
    ssn.client.isn = 4294967289UL;
    ssn.client.last_ack = 21;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    ssn.state = TCP_ESTABLISHED;
    TcpStream *s = NULL;
    uint8_t cnt = 0;

    SCMutexLock(&f->m);
    for (cnt=0; cnt < httplen1; cnt++) {
        tcph.th_seq = htonl(ssn.client.isn + 1 + cnt);
        tcph.th_ack = htonl(572799782UL);
        tcph.th_flags = TH_ACK|TH_PUSH;
        p->tcph = &tcph;
        p->flowflags = FLOW_PKT_TOSERVER;
        p->payload = &httpbuf1[cnt];
        p->payload_len = 1;
        s = &ssn.client;

        if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
            printf("failed in segments reassembly, while processing toserver "
                    "packet\n");
            goto end;
        }

        p->flowflags = FLOW_PKT_TOCLIENT;
        p->payload = NULL;
        p->payload_len = 0;
        tcph.th_seq = htonl(572799782UL);
        tcph.th_ack = htonl(ssn.client.isn + 1 + cnt);
        tcph.th_flags = TH_ACK;
        p->tcph = &tcph;
        s = &ssn.server;

        if (StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1) {
            printf("failed in segments reassembly, while processing toserver "
                    "packet\n");
            goto end;
        }
    }

    if (f->alproto != ALPROTO_HTTP) {
        printf("App layer protocol (HTTP) should have been detected\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/** \test 3 in order segments in inline reassembly */
static int StreamTcpReassembleInlineTest01(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload[] = "AAAAABBBBBCCCCC";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload, 15) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test 3 in order segments, then reassemble, add one more and reassemble again.
 *        test the sliding window reassembly.
 */
static int StreamTcpReassembleInlineTest02(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "AAAAABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 15) == 0)
        goto end;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed 2: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message: ");
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 20) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test 3 in order segments, then reassemble, add one more and reassemble again.
 *        test the sliding window reassembly with a small window size so that we
 *        cutting off at the start (left edge)
 */
static int StreamTcpReassembleInlineTest03(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 15;

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "BBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message 1: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 15) == 0)
        goto end;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(17);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed 2: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected two stream messages: ");
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 15) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test 3 in order segments, then reassemble, add one more and reassemble again.
 *        test the sliding window reassembly with a small window size so that we
 *        cutting off at the start (left edge) with small packet overlap.
 */
static int StreamTcpReassembleInlineTest04(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 16;

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "ABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 15) == 0)
        goto end;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(17);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed 2: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message: ");
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 16) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test with a GAP we should have 2 smsgs */
static int StreamTcpReassembleInlineTest05(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload1[] = "AAAAABBBBB";
    uint8_t stream_payload2[] = "DDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    ssn.client.next_seq = 12;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }

    p->tcph->th_seq = htonl(17);

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 10) == 0)
        goto end;

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 5) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test with a GAP we should have 2 smsgs, with filling the GAP later */
static int StreamTcpReassembleInlineTest06(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload1[] = "AAAAABBBBB";
    uint8_t stream_payload2[] = "DDDDD";
    uint8_t stream_payload3[] = "AAAAABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    ssn.client.next_seq = 12;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }

    p->tcph->th_seq = htonl(17);

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected two stream messages: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 10) == 0)
        goto end;

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 5) == 0)
        goto end;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 3) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next->next;
    if (UtTestSmsg(smsg, stream_payload3, 20) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test with a GAP we should have 2 smsgs, with filling the GAP later, small
 *        window */
static int StreamTcpReassembleInlineTest07(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 16;

    uint8_t stream_payload1[] = "ABBBBB";
    uint8_t stream_payload2[] = "DDDDD";
    uint8_t stream_payload3[] = "AAAAABBBBBCCCCCD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    ssn.client.next_seq = 12;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }

    p->tcph->th_seq = htonl(17);

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 6) == 0)
        goto end;

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 5) == 0)
        goto end;

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 3) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next->next;
    if (UtTestSmsg(smsg, stream_payload3, 16) == 0)
        goto end;

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test 3 in order segments, then reassemble, add one more and reassemble again.
 *        test the sliding window reassembly with a small window size so that we
 *        cutting off at the start (left edge). Test if the first segment is
 *        removed from the list.
 */
static int StreamTcpReassembleInlineTest08(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 15;
    ssn.client.flags |= STREAMTCP_STREAM_FLAG_GAP;

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "BBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 15) == 0)
        goto end;

    if (ssn.client.ra_raw_base_seq != 16) {
        printf("ra_raw_base_seq %"PRIu32", expected 16: ", ssn.client.ra_raw_base_seq);
        goto end;
    }

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(17);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed 2: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 15) == 0)
        goto end;

    if (ssn.client.ra_raw_base_seq != 21) {
        printf("ra_raw_base_seq %"PRIu32", expected 21: ", ssn.client.ra_raw_base_seq);
        goto end;
    }

    if (ssn.client.seg_list->seq != 7) {
        printf("expected segment 2 (seq 7) to be first in the list, got seq %"PRIu32": ", ssn.client.seg_list->seq);
        goto end;
    }

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test 3 in order segments, then reassemble, add one more and reassemble again.
 *        test the sliding window reassembly with a small window size so that we
 *        cutting off at the start (left edge). Test if the first segment is
 *        removed from the list.
 */
static int StreamTcpReassembleInlineTest09(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 20;
    ssn.client.flags |= STREAMTCP_STREAM_FLAG_GAP;

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "DDDDD";
    uint8_t stream_payload3[] = "AAAAABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(17);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 12;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected 2 stream message2, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 10) == 0)
        goto end;

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 5) == 0)
        goto end;

    if (ssn.client.ra_raw_base_seq != 11) {
        printf("ra_raw_base_seq %"PRIu32", expected 11: ", ssn.client.ra_raw_base_seq);
        goto end;
    }

    /* close the GAP and see if we properly reassemble and update ra_base_seq */
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

    r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed 2: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 3) {
        printf("expected 3 stream messages: ");
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next->next;
    if (UtTestSmsg(smsg, stream_payload3, 20) == 0)
        goto end;

    if (ssn.client.ra_raw_base_seq != 21) {
        printf("ra_raw_base_seq %"PRIu32", expected 21: ", ssn.client.ra_raw_base_seq);
        goto end;
    }

    if (ssn.client.seg_list->seq != 2) {
        printf("expected segment 1 (seq 2) to be first in the list, got seq %"PRIu32": ", ssn.client.seg_list->seq);
        goto end;
    }

    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test App Layer reassembly.
 */
static int StreamTcpReassembleInlineTest10(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 1);
    ssn.server.last_ack = 2;
    StreamTcpUTSetupStream(&ssn.client, 1);
    ssn.client.last_ack = 2;

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    uint8_t stream_payload1[] = "GE";
    uint8_t stream_payload2[] = "T /";
    uint8_t stream_payload3[] = "HTTP/1.0\r\n\r\n";

    p = UTHBuildPacketReal(stream_payload3, 12, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(7);
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    SCMutexLock(&f->m);
    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server,  2, stream_payload1, 2) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    ssn.server.next_seq = 4;

    int r = StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p);
    if (r < 0) {
        printf("StreamTcpReassembleAppLayer failed: ");
        goto end;
    }

    /* ssn.server.ra_app_base_seq should be isn here. */
    if (ssn.server.ra_app_base_seq != 1 || ssn.server.ra_app_base_seq != ssn.server.isn) {
        printf("expected ra_app_base_seq 1, got %u: ", ssn.server.ra_app_base_seq);
        goto end;
    }

    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server,  4, stream_payload2, 3) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server,  7, stream_payload3, 12) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.server.next_seq = 19;

    r = StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p);
    if (r < 0) {
        printf("StreamTcpReassembleAppLayer failed: ");
        goto end;
    }

    if (ssn.server.ra_app_base_seq != 18) {
        printf("expected ra_app_base_seq 18, got %u: ", ssn.server.ra_app_base_seq);
        goto end;
    }

    ret = 1;
end:
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    SCMutexUnlock(&f->m);
    UTHFreeFlow(f);
    return ret;
}

/** \test test insert with overlap
 */
static int StreamTcpReassembleInsertTest01(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        printf("couldn't get a packet: ");
        goto end;
    }
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    SCMutexLock(&f.m);
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 14, 'D', 2) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 16, 'D', 6) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 5: ");
        goto end;
    }
    ssn.client.next_seq = 21;

    int r = StreamTcpReassembleInlineRaw(ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message: ");
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 20) == 0)
        goto end;

    if (ssn.client.ra_raw_base_seq != 21) {
        printf("ra_raw_base_seq %"PRIu32", expected 21: ", ssn.client.ra_raw_base_seq);
        goto end;
    }
    ret = 1;
end:
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test test insert with overlaps
 */
static int StreamTcpReassembleInsertTest02(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);

    int i;
    for (i = 2; i < 10; i++) {
        int len;
        len = i % 2;
        if (len == 0)
            len = 1;
        int seq;
        seq = i * 10;
        if (seq < 2)
            seq = 2;

        if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  seq, 'A', len) == -1) {
            printf("failed to add segment 1: ");
            goto end;
        }
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'B', 1024) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

/** \test test insert with overlaps
 */
static int StreamTcpReassembleInsertTest03(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 1024) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }

    int i;
    for (i = 2; i < 10; i++) {
        int len;
        len = i % 2;
        if (len == 0)
            len = 1;
        int seq;
        seq = i * 10;
        if (seq < 2)
            seq = 2;

        if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  seq, 'B', len) == -1) {
            printf("failed to add segment 2: ");
            goto end;
        }
    }
    ret = 1;
end:
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

#endif /* UNITTESTS */

/** \brief  The Function Register the Unit tests to test the reassembly engine
 *          for various OS policies.
 */

void StreamTcpReassembleRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpReassembleTest01 -- BSD OS Before Reassembly Test", StreamTcpReassembleTest01, 1);
    UtRegisterTest("StreamTcpReassembleTest02 -- BSD OS At Same Reassembly Test", StreamTcpReassembleTest02, 1);
    UtRegisterTest("StreamTcpReassembleTest03 -- BSD OS After Reassembly Test", StreamTcpReassembleTest03, 1);
    UtRegisterTest("StreamTcpReassembleTest04 -- BSD OS Complete Reassembly Test", StreamTcpReassembleTest04, 1);
    UtRegisterTest("StreamTcpReassembleTest05 -- VISTA OS Before Reassembly Test", StreamTcpReassembleTest05, 1);
    UtRegisterTest("StreamTcpReassembleTest06 -- VISTA OS At Same Reassembly Test", StreamTcpReassembleTest06, 1);
    UtRegisterTest("StreamTcpReassembleTest07 -- VISTA OS After Reassembly Test", StreamTcpReassembleTest07, 1);
    UtRegisterTest("StreamTcpReassembleTest08 -- VISTA OS Complete Reassembly Test", StreamTcpReassembleTest08, 1);
    UtRegisterTest("StreamTcpReassembleTest09 -- LINUX OS Before Reassembly Test", StreamTcpReassembleTest09, 1);
    UtRegisterTest("StreamTcpReassembleTest10 -- LINUX OS At Same Reassembly Test", StreamTcpReassembleTest10, 1);
    UtRegisterTest("StreamTcpReassembleTest11 -- LINUX OS After Reassembly Test", StreamTcpReassembleTest11, 1);
    UtRegisterTest("StreamTcpReassembleTest12 -- LINUX OS Complete Reassembly Test", StreamTcpReassembleTest12, 1);
    UtRegisterTest("StreamTcpReassembleTest13 -- LINUX_OLD OS Before Reassembly Test", StreamTcpReassembleTest13, 1);
    UtRegisterTest("StreamTcpReassembleTest14 -- LINUX_OLD At Same Reassembly Test", StreamTcpReassembleTest14, 1);
    UtRegisterTest("StreamTcpReassembleTest15 -- LINUX_OLD OS After Reassembly Test", StreamTcpReassembleTest15, 1);
    UtRegisterTest("StreamTcpReassembleTest16 -- LINUX_OLD OS Complete Reassembly Test", StreamTcpReassembleTest16, 1);
    UtRegisterTest("StreamTcpReassembleTest17 -- SOLARIS OS Before Reassembly Test", StreamTcpReassembleTest17, 1);
    UtRegisterTest("StreamTcpReassembleTest18 -- SOLARIS At Same Reassembly Test", StreamTcpReassembleTest18, 1);
    UtRegisterTest("StreamTcpReassembleTest19 -- SOLARIS OS After Reassembly Test", StreamTcpReassembleTest19, 1);
    UtRegisterTest("StreamTcpReassembleTest20 -- SOLARIS OS Complete Reassembly Test", StreamTcpReassembleTest20, 1);
    UtRegisterTest("StreamTcpReassembleTest21 -- LAST OS Before Reassembly Test", StreamTcpReassembleTest21, 1);
    UtRegisterTest("StreamTcpReassembleTest22 -- LAST OS At Same Reassembly Test", StreamTcpReassembleTest22, 1);
    UtRegisterTest("StreamTcpReassembleTest23 -- LAST OS After Reassembly Test", StreamTcpReassembleTest23, 1);
    UtRegisterTest("StreamTcpReassembleTest24 -- LAST OS Complete Reassembly Test", StreamTcpReassembleTest24, 1);
    UtRegisterTest("StreamTcpReassembleTest25 -- Gap at Start Reassembly Test", StreamTcpReassembleTest25, 1);
    UtRegisterTest("StreamTcpReassembleTest26 -- Gap at middle Reassembly Test", StreamTcpReassembleTest26, 1);
    UtRegisterTest("StreamTcpReassembleTest27 -- Gap at after  Reassembly Test", StreamTcpReassembleTest27, 1);
    UtRegisterTest("StreamTcpReassembleTest28 -- Gap at Start IDS missed packet Reassembly Test", StreamTcpReassembleTest28, 1);
    UtRegisterTest("StreamTcpReassembleTest29 -- Gap at Middle IDS missed packet Reassembly Test", StreamTcpReassembleTest29, 1);
    UtRegisterTest("StreamTcpReassembleTest30 -- Gap at End IDS missed packet Reassembly Test", StreamTcpReassembleTest30, 1);
    UtRegisterTest("StreamTcpReassembleTest31 -- Fast Track Reassembly Test", StreamTcpReassembleTest31, 1);
    UtRegisterTest("StreamTcpReassembleTest32 -- Bug test", StreamTcpReassembleTest32, 1);
    UtRegisterTest("StreamTcpReassembleTest33 -- Bug test", StreamTcpReassembleTest33, 1);
    UtRegisterTest("StreamTcpReassembleTest34 -- Bug test", StreamTcpReassembleTest34, 1);
    UtRegisterTest("StreamTcpReassembleTest35 -- Bug56 test", StreamTcpReassembleTest35, 1);
    UtRegisterTest("StreamTcpReassembleTest36 -- Bug57 test", StreamTcpReassembleTest36, 1);
    UtRegisterTest("StreamTcpReassembleTest37 -- Bug76 test", StreamTcpReassembleTest37, 1);
    UtRegisterTest("StreamTcpReassembleTest38 -- app proto test", StreamTcpReassembleTest38, 1);
    UtRegisterTest("StreamTcpReassembleTest39 -- app proto test", StreamTcpReassembleTest39, 1);
    UtRegisterTest("StreamTcpReassembleTest40 -- app proto test", StreamTcpReassembleTest40, 1);
    UtRegisterTest("StreamTcpReassembleTest43 -- min smsg size test", StreamTcpReassembleTest43, 1);
    UtRegisterTest("StreamTcpReassembleTest44 -- Memcap Test", StreamTcpReassembleTest44, 1);
    UtRegisterTest("StreamTcpReassembleTest45 -- Depth Test", StreamTcpReassembleTest45, 1);
    UtRegisterTest("StreamTcpReassembleTest46 -- Depth Test", StreamTcpReassembleTest46, 1);
    UtRegisterTest("StreamTcpReassembleTest47 -- TCP Sequence Wraparound Test", StreamTcpReassembleTest47, 1);

    UtRegisterTest("StreamTcpReassembleInlineTest01 -- inline RAW ra", StreamTcpReassembleInlineTest01, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest02 -- inline RAW ra 2", StreamTcpReassembleInlineTest02, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest03 -- inline RAW ra 3", StreamTcpReassembleInlineTest03, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest04 -- inline RAW ra 4", StreamTcpReassembleInlineTest04, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest05 -- inline RAW ra 5 GAP", StreamTcpReassembleInlineTest05, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest06 -- inline RAW ra 6 GAP", StreamTcpReassembleInlineTest06, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest07 -- inline RAW ra 7 GAP", StreamTcpReassembleInlineTest07, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest08 -- inline RAW ra 8 cleanup", StreamTcpReassembleInlineTest08, 1);
    UtRegisterTest("StreamTcpReassembleInlineTest09 -- inline RAW ra 9 GAP cleanup", StreamTcpReassembleInlineTest09, 1);

    UtRegisterTest("StreamTcpReassembleInlineTest10 -- inline APP ra 10", StreamTcpReassembleInlineTest10, 1);

    UtRegisterTest("StreamTcpReassembleInsertTest01 -- insert with overlap", StreamTcpReassembleInsertTest01, 1);
    UtRegisterTest("StreamTcpReassembleInsertTest02 -- insert with overlap", StreamTcpReassembleInsertTest02, 1);
    UtRegisterTest("StreamTcpReassembleInsertTest03 -- insert with overlap", StreamTcpReassembleInsertTest03, 1);

    StreamTcpInlineRegisterTests();
    StreamTcpUtilRegisterTests();
#endif /* UNITTESTS */
}
