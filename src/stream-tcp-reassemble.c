/* Copyright (C) 2007-2016 Open Information Security Foundation
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
#include "util-device.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-list.h"
#include "stream-tcp-util.h"

#include "stream.h"

#include "util-debug.h"
#include "app-layer-protos.h"
#include "app-layer.h"
#include "app-layer-events.h"

#include "detect-engine-state.h"

#include "util-profiling.h"

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

/* Memory use counter */
SC_ATOMIC_DECLARE(uint64_t, ra_memuse);

/* prototypes */
TcpSegment* StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *, uint16_t);
void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);
void StreamTcpReassemblePseudoPacketCreate(TcpStream *, Packet *, PacketQueue *);

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
    TCP_SEG_LEN(seg) = seg->pool_size;
#if 0
    TCP_SEG_PAYLOAD(seg) = SCMalloc(TCP_SEG_LEN(seg));
    if (TCP_SEG_PAYLOAD(seg) == NULL) {
        return 0;
    }
#endif
#ifdef DEBUG
    SCMutexLock(&segment_pool_memuse_mutex);
    segment_pool_memuse += TCP_SEG_LEN(seg);
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

    //SCFree(TCP_SEG_PAYLOAD(seg));
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

static inline bool STREAM_LASTACK_GT_BASESEQ(const TcpStream *stream)
{
    /* last ack not yet initialized */
    if (STREAM_BASE_OFFSET(stream) == 0 && stream->last_ack == 0)
        return false;
    if (SEQ_GT(stream->last_ack, stream->base_seq))
        return true;
    return false;
}

/** \internal
 *  \brief check if segments falls before stream 'offset' */
static inline int SEGMENT_BEFORE_OFFSET(TcpStream *stream, TcpSegment *seg, uint64_t offset)
{
    if (seg->sbseg.stream_offset + seg->sbseg.segment_len <= offset)
        return 1;
    return 0;
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
            if (strcmp("from_mtu", segsize->val) == 0) {
                int mtu = g_default_mtu ? g_default_mtu : DEFAULT_MTU;
                if (mtu < MINIMUM_MTU) {
                    FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT, "invalid mtu %d", mtu);
                    continue;
                }
                pktsize = mtu - 40;
            } else {
                if (ByteExtractStringUint16(&pktsize, 10, strlen(segsize->val),
                            segsize->val) == -1)
                {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "segment packet size "
                            "of %s is invalid", segsize->val);
                    return -1;
                }
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
            SCLogConfig("appended a segment pool for pktsize 65536");
        }
    } else if (npools == 0) {
        int mtu = g_default_mtu;
        if (mtu < MINIMUM_MTU)
            mtu = DEFAULT_MTU;

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
        sizes[6].pktsize = mtu - 40; // min size of ipv4+tcp hdrs
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
            SCLogConfig("segment pool: pktsize %u, prealloc %u",
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
        SCLogConfig("stream.reassembly \"chunk-prealloc\": %u", stream_chunk_prealloc);
    StreamMsgQueuesInit(stream_chunk_prealloc);

    int overlap_diff_data = 0;
    ConfGetBool("stream.reassembly.check-overlap-different-data", &overlap_diff_data);
    if (overlap_diff_data) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }
    if (StreamTcpInlineMode() == TRUE) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }

    /** \todo do this for real */
    stream_config.sbcnf.flags = STREAMING_BUFFER_NOFLAGS;
    stream_config.sbcnf.buf_size = 2048;

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
                SCLogPerf("TCP segment pool of size %u had a peak use of %u segments, "
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
    SCFree(ra_ctx);
    SCReturn;
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
static uint32_t StreamTcpReassembleCheckDepth(TcpSession *ssn, TcpStream *stream,
        uint32_t seq, uint32_t size)
{
    SCEnter();

    /* if the configured depth value is 0, it means there is no limit on
       reassembly depth. Otherwise carry on my boy ;) */
    if (ssn->reassembly_depth == 0) {
        SCReturnUInt(size);
    }

    /* if the final flag is set, we're not accepting anymore */
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        SCReturnUInt(0);
    }

    uint64_t seg_depth;
    if (SEQ_GT(stream->base_seq, seq)) {
        if (SEQ_LEQ(seq+size, stream->base_seq)) {
            SCLogDebug("segment entirely before base_seq, weird: base %u, seq %u, re %u",
                    stream->base_seq, seq, seq+size);
            SCReturnUInt(0);
        }

        seg_depth = STREAM_BASE_OFFSET(stream) + size - (stream->base_seq - seq);
    } else {
        seg_depth = STREAM_BASE_OFFSET(stream) + ((seq + size) - stream->base_seq);
    }

    /* if the base_seq has moved passed the depth window we stop
     * checking and just reject the rest of the packets including
     * retransmissions. Saves us the hassle of dealing with sequence
     * wraps as well */
    SCLogDebug("seq + size %u, base %u, seg_depth %"PRIu64" limit %u", (seq + size),
            stream->base_seq, seg_depth,
            stream_config.reassembly_depth);

    if (seg_depth > (uint64_t)stream_config.reassembly_depth) {
        SCLogDebug("STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
        stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
        SCReturnUInt(0);
    }
    SCLogDebug("NOT STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
    SCLogDebug("%"PRIu64" <= %u", seg_depth, stream_config.reassembly_depth);
#if 0
    SCLogDebug("full depth not yet reached: %"PRIu64" <= %"PRIu32,
            (stream->base_seq_offset + stream->base_seq + size),
            (stream->isn + stream_config.reassembly_depth));
#endif
    if (SEQ_GEQ(seq, stream->isn) && SEQ_LT(seq, (stream->isn + stream_config.reassembly_depth))) {
        /* packet (partly?) fits the depth window */

        if (SEQ_LEQ((seq + size),(stream->isn + 1 + ssn->reassembly_depth))) {
            /* complete fit */
            SCReturnUInt(size);
        } else {
            stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
            /* partial fit, return only what fits */
            uint32_t part = (stream->isn + 1 + ssn->reassembly_depth) - seq;
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
        if (PKT_IS_TOSERVER(p)) {
            ssn->data_first_seen_dir = STREAM_TOSERVER;
        } else {
            ssn->data_first_seen_dir = STREAM_TOCLIENT;
        }
    }

    /* If the OS policy is not set then set the OS policy for this stream */
    if (stream->os_policy == 0) {
        StreamTcpSetOSPolicy(stream, p);
    }

    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) &&
        (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)) {
        SCLogDebug("ssn %p: both app and raw reassembly disabled, not reassembling", ssn);
        SCReturnInt(0);
    }

    /* If we have reached the defined depth for either of the stream, then stop
       reassembling the TCP session */
    uint32_t size = StreamTcpReassembleCheckDepth(ssn, stream, TCP_GET_SEQ(p), p->payload_len);
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

    TCP_SEG_LEN(seg) = size;
    seg->seq = TCP_GET_SEQ(p);

    /* proto detection skipped, but now we do get data. Set event. */
    if (stream->seg_list == NULL &&
        stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED) {

        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
    }

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, seg, p, TCP_GET_SEQ(p), p->payload, p->payload_len) != 0) {
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

    /* check if we have enough data to do raw reassembly */
    if (p->flowflags & FLOW_PKT_TOCLIENT) {
        SCLogDebug("StreamMsgQueueGetMinChunkLen(STREAM_TOSERVER) %"PRIu32,
                StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER));

        uint32_t delta = stream->last_ack - stream->base_seq;
        /* get max absolute offset */
        uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

        int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);

        if ((int64_t)StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER) >
                diff) {
            SCLogDebug("toserver min chunk len not yet reached: "
                    "last_ack %"PRIu32", ra_raw_base_seq %"PRIu32", %"PRIu32" < "
                    "%"PRIu32"", stream->last_ack, stream->base_seq,
                    (stream->last_ack - stream->base_seq),
                    StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOSERVER));
            SCReturnInt(0);
        }
    } else {
        SCLogDebug("StreamMsgQueueGetMinChunkLen(STREAM_TOCLIENT) %"PRIu32,
                StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT));

        uint32_t delta = stream->last_ack - stream->base_seq;
        /* get max absolute offset */
        uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

        int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);

        if ((int64_t)StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT) >
                diff) {
            SCLogDebug("toclient min chunk len not yet reached: "
                    "last_ack %"PRIu32", base_seq %"PRIu32",  %"PRIu32" < "
                    "%"PRIu32"", stream->last_ack, stream->base_seq,
                    (stream->last_ack - stream->base_seq),
                    StreamMsgQueueGetMinChunkLen(FLOW_PKT_TOCLIENT));
            SCReturnInt(0);
        }
    }

    SCReturnInt(1);
}

/**
 *  \brief see what if any work the TCP session still needs
 */
int StreamNeedsReassembly(TcpSession *ssn, int direction)
{
    TcpStream *stream = NULL;
    StreamMsg *head = NULL;
#ifdef DEBUG
    char *dirstr = NULL;
#endif
    /* TODO use STREAM_TOCLIENT/STREAM_TOSERVER */
    if (direction == 0) {
        stream = &ssn->client;
        head = ssn->toserver_smsg_head;
#ifdef DEBUG
        dirstr = "client";
#endif
    } else {
        stream = &ssn->server;
        head = ssn->toclient_smsg_head;
#ifdef DEBUG
        dirstr = "server";
#endif
    }

    int use_app = 1;
    int use_raw = 1;

    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
          (stream->flags & STREAMTCP_STREAM_FLAG_GAP))
    {
        // app is dead
        use_app = 0;
    }

    if (ssn->flags & STREAMTCP_FLAG_DISABLE_RAW) {
        // raw is dead
        use_raw = 0;
    }

    if (stream->seg_list_tail != NULL) {
        uint64_t right_edge = TCP_SEG_OFFSET(stream->seg_list_tail) +
                              TCP_SEG_LEN(stream->seg_list_tail);

        SCLogDebug("%s: list %p app %"PRIu64" (use: %s), raw %"PRIu64" (use: %s). Stream right edge: %"PRIu64,
                dirstr,
                stream->seg_list,
                STREAM_APP_PROGRESS(stream), use_app ? "yes" : "no",
                STREAM_RAW_PROGRESS(stream), use_raw ? "yes" : "no",
                right_edge);

        if (use_raw) {
            if (right_edge > STREAM_RAW_PROGRESS(stream)) {
                SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY", dirstr);
                return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY;
            }
        }
        if (use_app) {
            if (right_edge > STREAM_APP_PROGRESS(stream)) {
                SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY", dirstr);
                return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY;
            }
        }
    } else {
        SCLogDebug("%s: no list", dirstr);
    }

    if (head != NULL) {
        SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION", dirstr);
        return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }

    SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NONE", dirstr);
    return STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
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
            size += (uint64_t)TCP_SEG_LEN(seg);

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

/** \internal
 *
 *  Get buffer, or first part of the buffer if data gaps exist.
 *
 *  \brief get stream data from offset
 *  \param offset stream offset */
static void GetAppBuffer(TcpStream *stream, const uint8_t **data, uint32_t *data_len, uint64_t offset)
{
    const uint8_t *mydata;
    uint32_t mydata_len;

    if (stream->sb->block_list == NULL) {
        SCLogDebug("getting one blob");

        StreamingBufferGetDataAtOffset(stream->sb, &mydata, &mydata_len, offset);

        *data = mydata;
        *data_len = mydata_len;
    } else {
        StreamingBufferBlock *blk = stream->sb->block_list;

        if (blk->offset > offset) {
            SCLogDebug("gap, want data at offset %"PRIu64", got data at %"PRIu64,
                    offset, blk->offset);
            *data = NULL;
            *data_len = 0;

        } else if (offset > blk->offset && offset <= (blk->offset + blk->len)) {
            SCLogDebug("get data from offset %"PRIu64". SBB %"PRIu64"/%u",
                    offset, blk->offset, blk->len);
            StreamingBufferSBBGetDataAtOffset(stream->sb, blk, data, data_len, offset);
            SCLogDebug("data %p, data_len %u", *data, *data_len);
        } else {
            StreamingBufferSBBGetData(stream->sb, blk, data, data_len);
        }
    }
}

/** \internal
 *  \brief get stream buffer and update the app-layer
 *  \retval 0 success
 */
static int ReassembleUpdateAppLayer (ThreadVars *tv,
        TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, TcpStream *stream,
        Packet *p)
{
    const uint64_t app_progress = STREAM_APP_PROGRESS(stream);
    uint64_t last_ack_abs = 0; /* absolute right edge of ack'd data */

    SCLogDebug("app progress %"PRIu64, app_progress);
    SCLogDebug("last_ack %u, base_seq %u", stream->last_ack, stream->base_seq);

    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
        /* get window of data that is acked */
        uint32_t delta = stream->last_ack - stream->base_seq;
        /* get max absolute offset */
        last_ack_abs += delta;
    }

    const uint8_t *mydata;
    uint32_t mydata_len;
    GetAppBuffer(stream, &mydata, &mydata_len, app_progress);
    //PrintRawDataFp(stdout, mydata, mydata_len);

    SCLogDebug("stream %p data in buffer %p of len %u and offset %"PRIu64,
            stream, stream->sb, mydata_len, app_progress);

    /* get window of data that is acked */
    if (StreamTcpInlineMode() == 0 && (p->flags & PKT_PSEUDO_STREAM_END)) {
        //
    } else if (StreamTcpInlineMode() == 0) {
        /* see if the buffer contains unack'd data as well */
        if (app_progress + mydata_len > last_ack_abs) {
            mydata_len = last_ack_abs - app_progress;
            SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                    "data is considered", mydata_len);
        }
    }

    /* update the app-layer */
    int r = AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
            (uint8_t *)mydata, mydata_len,
            StreamGetAppLayerFlags(ssn, stream, p));

    /* see if we can update the progress */
    if (r == 0 && StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream)) {
        if (mydata_len > 0) {
            SCLogDebug("app progress %"PRIu64" increasing with data len %u to %"PRIu64,
                    app_progress, mydata_len, app_progress + mydata_len);

            stream->app_progress_rel += mydata_len;
            SCLogDebug("app progress now %"PRIu64, STREAM_APP_PROGRESS(stream));
        }
    } else {
        SCLogDebug("NOT UPDATED app progress still %"PRIu64, app_progress);
    }

    SCReturnInt(0);
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
                    stream->base_seq == stream->isn+1 &&
                    SEQ_GT(stream->last_ack, stream->isn + ackadd))
                ||
            (stream->seg_list != NULL && /*2*/
                    SEQ_GT(stream->seg_list->seq, stream->base_seq) &&
                    SEQ_LT(stream->seg_list->seq, stream->last_ack)))
        {
            if (stream->seg_list == NULL) {
                SCLogDebug("no segs, last_ack moved fwd so GAP "
                        "(base %u, isn %u, last_ack %u => diff %u) p %"PRIu64,
                        stream->base_seq, stream->isn, stream->last_ack,
                        stream->last_ack - (stream->isn + ackadd), p->pcap_cnt);
            }

            /* send gap signal */
            SCLogDebug("sending GAP to app-layer");
            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    NULL, 0,
                    StreamGetAppLayerFlags(ssn, stream, p)|STREAM_GAP);
            AppLayerProfilingStore(ra_ctx->app_tctx, p);

            /* set a GAP flag and make sure not bothering this stream anymore */
            SCLogDebug("STREAMTCP_STREAM_FLAG_GAP set");
            stream->flags |= STREAMTCP_STREAM_FLAG_GAP;

            StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEQ_GAP);
            StatsIncr(tv, ra_ctx->counter_tcp_reass_gap);

            SCReturnInt(0);
        }
    }

    /* if no segments are in the list or all are already processed,
     * and state is beyond established, we send an empty msg */
    TcpSegment *seg_tail = stream->seg_list_tail;
    if (seg_tail == NULL ||
            SEGMENT_BEFORE_OFFSET(stream, seg_tail, STREAM_APP_PROGRESS(stream)))
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

    /* with all that out of the way, lets update the app-layer */
    ReassembleUpdateAppLayer(tv, ra_ctx, ssn, stream, p);

    SCReturnInt(0);
}

/** \internal
 *  \brief get stream data from offset
 *  \param offset stream offset */
static int GetRawBuffer(TcpStream *stream, const uint8_t **data, uint32_t *data_len,
        StreamingBufferBlock **iter, uint64_t offset, uint64_t *data_offset)
{
    const uint8_t *mydata;
    uint32_t mydata_len;
    if (stream->sb->block_list == NULL) {
        SCLogDebug("getting one blob");

        uint64_t roffset = offset;
        if (offset)
            StreamingBufferGetDataAtOffset(stream->sb, &mydata, &mydata_len, offset);
        else {
            StreamingBufferGetData(stream->sb, &mydata, &mydata_len, &roffset);
        }

        *data = mydata;
        *data_len = mydata_len;
        *data_offset = roffset;
    } else {
        if (*iter == NULL)
            *iter = stream->sb->block_list;
        if (*iter == NULL) {
            *data = NULL;
            *data_len = 0;
            return 0;
        }

        if (offset) {
            while (*iter && ((*iter)->offset + (*iter)->len < offset))
                *iter = (*iter)->next;
            if (*iter == NULL) {
                *data = NULL;
                *data_len = 0;
                *data_offset = 0;
                return 0;
            }
        }

        SCLogDebug("getting multiple blobs. Iter %p, %"PRIu64"/%u (next? %s)", *iter, (*iter)->offset, (*iter)->len, (*iter)->next ? "yes":"no");

        StreamingBufferSBBGetData(stream->sb, (*iter), &mydata, &mydata_len);

        if ((*iter)->offset < offset) {
            uint64_t delta = offset - (*iter)->offset;
            if (delta < mydata_len) {
                *data = mydata + delta;
                *data_len = mydata_len - delta;
                *data_offset = offset;
            } else {
                *data = NULL;
                *data_len = 0;
                *data_offset = 0;
            }

        } else {
            *data = mydata;
            *data_len = mydata_len;
            *data_offset = (*iter)->offset;
        }

        *iter = (*iter)->next;
    }
    return 0;
}

/** \internal
 *  \brief based on the data in the streaming buffer setup StreamMsgs
 */
static int ReassembleRaw(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    StreamingBufferBlock *iter = NULL;
    uint64_t progress = STREAM_RAW_PROGRESS(stream);
    uint64_t last_ack_abs = 0; /* absolute right edge of ack'd data */
    uint64_t right_edge_abs = 0;

    /* get window of data that is acked */
    SCLogDebug("last_ack %u, base_seq %u", stream->last_ack, stream->base_seq);
    uint32_t delta = stream->last_ack - stream->base_seq;
    /* get max absolute offset */
    last_ack_abs = STREAM_BASE_OFFSET(stream) + delta;
    right_edge_abs = last_ack_abs;

    if (StreamTcpInlineMode() == TRUE) {
        uint32_t chunk_size = PKT_IS_TOSERVER(p) ?
            stream_config.reassembly_toserver_chunk_size :
            stream_config.reassembly_toclient_chunk_size;
        SCLogDebug("pkt SEQ %u, payload_len %u; base_seq %u => base_seq_offset %"PRIu64,
                TCP_GET_SEQ(p), p->payload_len,
                stream->base_seq, STREAM_BASE_OFFSET(stream));

        SCLogDebug("progress before adjust %"PRIu64", chunk_size %"PRIu32, progress, chunk_size);

        /* determine the left edge and right edge */
        uint32_t rel_right_edge = TCP_GET_SEQ(p) + p->payload_len;
        uint32_t rel_left_edge = rel_right_edge - chunk_size;
        SCLogDebug("left_edge %"PRIu32", right_edge %"PRIu32", chunk_size %u", rel_left_edge, rel_right_edge, chunk_size);

        if (SEQ_LT(rel_left_edge, stream->base_seq)) {
            rel_left_edge = stream->base_seq;
            rel_right_edge = rel_left_edge + chunk_size;
            SCLogDebug("adjusting left_edge to not be before base_seq: left_edge %u", rel_left_edge);
        }

        progress = STREAM_BASE_OFFSET(stream) + (rel_left_edge - stream->base_seq);
        right_edge_abs = progress + chunk_size;
        SCLogDebug("working with progress %"PRIu64, progress);

        SCLogDebug("left_edge %"PRIu32", right_edge %"PRIu32, rel_left_edge, rel_right_edge);
    }

    /* loop through available buffers. On no packet loss we'll have a single
     * iteration. On missing data we'll walk the blocks */
    while (1) {
        const uint8_t *mydata;
        uint32_t mydata_len;
        uint64_t mydata_offset = 0;

        GetRawBuffer(stream, &mydata, &mydata_len, &iter, progress, &mydata_offset);
        if (mydata_len == 0)
            break;
        //PrintRawDataFp(stdout, mydata, mydata_len);

        SCLogDebug("raw progress %"PRIu64, progress);
        SCLogDebug("stream %p data in buffer %p of len %u and offset %u",
                stream, stream->sb, mydata_len, (uint)progress);

        if (StreamTcpInlineMode() == 0 && (p->flags & PKT_PSEUDO_STREAM_END)) {
            //
        } else if (StreamTcpInlineMode() == FALSE) {
            if (right_edge_abs < progress) {
                SCLogDebug("nothing to do");
                goto end;
            }

            SCLogDebug("delta %u, right_edge_abs %"PRIu64", raw_progress %"PRIu64, delta, right_edge_abs, progress);
            SCLogDebug("raw_progress + mydata_len %"PRIu64", right_edge_abs %"PRIu64, progress + mydata_len, right_edge_abs);

            /* see if the buffer contains unack'd data as well */
            if (progress + mydata_len > last_ack_abs) {
                mydata_len = last_ack_abs - progress;
                SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                        "data is considered", mydata_len);
            }

        /* StreamTcpInlineMode() == TRUE */
        } else {
            if (progress + mydata_len > right_edge_abs) {
                uint32_t delta = (progress + mydata_len) - right_edge_abs;
                SCLogDebug("adjusting mydata_len %u to subtract %u", mydata_len, delta);
                mydata_len -= delta;
            }
        }
        if (mydata_len == 0)
            break;

        SCLogDebug("data %p len %u", mydata, mydata_len);

        /*
        [buffer with segment data]
        ^
        |
        base_seq_offset (0 on start start)
        base_seq (ISN on start start)

        going from 'progress' to SEQ => (progress - base_seq_offset) + base_seq;
        */
#define GET_SEQ_FOR_PROGRESS(stream, progress) \
            (((progress) - STREAM_BASE_OFFSET((stream))) + (stream->base_seq))

        /* we have data. Use it to setup StreamMsg(s) */
        StreamMsg *smsg = NULL;
        uint32_t data_offset = 0;
        uint32_t data_left = mydata_len;
        while (data_left) {
            smsg = StreamMsgGetFromPool();
            if (smsg == NULL)
                break;

            uint32_t copy_len = (data_left > smsg->data_size) ? smsg->data_size : data_left;
            SCLogDebug("copy_len %u, data_left %u", copy_len, data_left);

            memcpy(smsg->data, mydata + data_offset, copy_len);
            smsg->data_len = copy_len;
            smsg->seq = GET_SEQ_FOR_PROGRESS(stream, (mydata_offset + data_offset));
            SCLogDebug("smsg %p seq %u", smsg, smsg->seq);

            BUG_ON(copy_len > data_left);
            data_left -= copy_len;
            BUG_ON(data_left > mydata_len);
            data_offset += copy_len;

            SCLogDebug("smsg %p %u/%u", smsg, smsg->data_len, smsg->data_size);
            //PrintRawDataFp(stdout, smsg->data, smsg->data_len);

            StreamTcpStoreStreamChunk(ssn, smsg, p, StreamTcpInlineMode());
        }

        if (mydata_offset == progress) {
            SCLogDebug("raw progress %"PRIu64" increasing with data len %u to %"PRIu64,
                    progress, mydata_len, STREAM_RAW_PROGRESS(stream) + mydata_len);

            //if (StreamTcpInlineMode() == TRUE) {
            //progress = right_edge_abs;
            //} else {
            progress += mydata_len;
            //}
            SCLogDebug("raw progress now %"PRIu64, progress);

        /* data is beyond the progress we'd like, and before last ack. Gap. */
        } else if (mydata_offset > progress && mydata_offset < last_ack_abs) {
            SCLogDebug("GAP: data is missing from %"PRIu64" (%u bytes), setting to first data we have: %"PRIu64, progress, (uint32_t)(mydata_offset - progress), mydata_offset);
            SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);
            progress = mydata_offset;
            SCLogDebug("raw progress now %"PRIu64, progress);

        } else {
            SCLogDebug("not increasing progress, data gap => mydata_offset "
                       "%"PRIu64" != progress %"PRIu64, mydata_offset, progress);
        }

        if (iter == NULL)
            break;
    }
end:
    if (progress > STREAM_RAW_PROGRESS(stream)) {
        uint32_t slide = progress - STREAM_RAW_PROGRESS(stream);
        stream->raw_progress_rel += slide;
    }

    SCLogDebug("stream raw progress now %"PRIu64, STREAM_RAW_PROGRESS(stream));
    return 0;
}

/**
 *  \brief Update the stream reassembly upon receiving an ACK packet.
 *  \todo this function is too long, we need to break it up. It needs it BAD
 */
int StreamTcpReassembleRaw (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
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
    if (StreamTcpInlineMode() == FALSE &&
            StreamTcpReassembleRawCheckLimit(ssn,stream,p) == 0)
    {
        SCLogDebug("not yet reassembling");
        SCReturnInt(0);
    }

    /* take the data we have, and turn it into StreamMsgs */
    ReassembleRaw(ssn, stream, p);
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
        if (StreamTcpReassembleRaw(tv, ra_ctx, ssn, stream, p) < 0)
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
        if (StreamTcpReassembleRaw(tv, ra_ctx, ssn, stream, p) < 0)
            r = -1;

        if (r < 0) {
            SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
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

        memset(&seg->sbseg, 0, sizeof(seg->sbseg));
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

#define SET_ISN(stream, setseq)             \
    (stream)->isn = (setseq);               \
    (stream)->base_seq = (setseq) + 1

static int UtTestSmsg(StreamMsg *smsg, const uint8_t *buf, uint32_t buf_len)
{
    if (smsg == NULL)
        return 0;

    if (smsg->data_len != buf_len) {
        printf("Got: data_len %u, expected %u\n", smsg->data_len, buf_len);
        PrintRawDataFp(stdout, smsg->data, smsg->data_len);
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

#if 0
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
    SET_ISN(&ssn.client, 10);
    SET_ISN(&ssn.server, 10);

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
#endif

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
    if (StreamingBufferCompareRawData(stream->sb, stream_policy,(uint32_t)sp_size) == 0)
    {
        //PrintRawDataFp(stdout, stream_policy, sp_size);
        return 0;
    }
    return 1;
}

static int VALIDATE(TcpStream *stream, uint8_t *data, uint32_t data_len)
{
    if (StreamingBufferCompareRawData(stream->sb,
                data, data_len) == 0)
    {
        SCReturnInt(0);
    }
    SCLogInfo("OK");
    PrintRawDataFp(stdout, data, data_len);
    return 1;
}

#define MISSED_START(isn)                       \
    TcpReassemblyThreadCtx *ra_ctx = NULL;      \
    TcpSession ssn;                             \
    ThreadVars tv;                              \
    memset(&tv, 0, sizeof(tv));                 \
                                                \
    StreamTcpUTInit(&ra_ctx);                   \
                                                \
    StreamTcpUTSetupSession(&ssn);              \
    StreamTcpUTSetupStream(&ssn.server, (isn)); \
    StreamTcpUTSetupStream(&ssn.client, (isn)); \
                                                \
    TcpStream *stream = &ssn.client;

#define MISSED_END                             \
    PASS

#define MISSED_STEP(seq, seg, seglen, buf, buflen) \
    StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, stream, (seq), (uint8_t *)(seg), (seglen));    \
    FAIL_IF(!(VALIDATE(stream, (uint8_t *)(buf), (buflen))));

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the starting of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest25 (void)
{
    MISSED_START(6);
    MISSED_STEP(10, "BB", 2, "\0\0\0BB", 5);
    MISSED_STEP(12, "CC", 2, "\0\0\0BBCC", 7);
    MISSED_STEP(7, "AAA", 3, "AAABBCC", 7);
    MISSED_END;
}

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the middle of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest26 (void)
{
    MISSED_START(9);
    MISSED_STEP(10, "AAA", 3, "AAA", 3);
    MISSED_STEP(15, "CC", 2, "AAA\0\0CC", 7);
    MISSED_STEP(13, "BB", 2, "AAABBCC", 7);
    MISSED_END;
}

/**
 *  \test   Test the handling of packets missed by both IDS and the end host.
 *          The packet is missed in the end of the stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest27 (void)
{
    MISSED_START(9);
    MISSED_STEP(10, "AAA", 3, "AAA", 3);
    MISSED_STEP(13, "BB", 2, "AAABB", 5);
    MISSED_STEP(15, "CC", 2, "AAABBCC", 7);
    MISSED_END;
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
    MISSED_START(6);
    MISSED_STEP(10, "AAA", 3, "\0\0\0AAA", 6);
    MISSED_STEP(13, "BB", 2, "\0\0\0AAABB", 8);
    ssn.state = TCP_TIME_WAIT;
    MISSED_STEP(15, "CC", 2, "\0\0\0AAABBCC", 10);
    MISSED_END;
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
    MISSED_START(9);
    MISSED_STEP(10, "AAA", 3, "AAA", 3);
    ssn.state = TCP_TIME_WAIT;
    MISSED_STEP(15, "CC", 2, "AAA\0\0CC", 7);
    MISSED_END;
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
    SET_ISN(&stream, 857961230);

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
    SET_ISN(&stream, 3061091309UL);

    /* pre base_seq, so should be rejected */
    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) != -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(3061089928UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    stream.last_ack = 3061091137UL;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &stream, p, &pq) == -1) {
        SCFree(p);
        return 0;
    }

    p->tcph->th_seq = htonl(3061091319UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    stream.last_ack = 3061091137UL;

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

    SET_ISN(&ssn.server, 9);
    ssn.server.last_ack = 60;
    SET_ISN(&ssn.client, 9);
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

    FLOWLOCK_WRLOCK(&f);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    SCLogDebug("StreamTcpIsSetStreamFlagAppProtoDetectionCompleted %s, "
            "StreamTcpIsSetStreamFlagAppProtoDetectionCompleted %s, "
            "f.alproto %u f.alproto_ts %u f.alproto_tc %u",
            StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ? "true" : "false",
            StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ? "true" : "false",
            f.alproto, f.alproto_ts, f.alproto_tc);

    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP)// ||
        //ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED)// ||
        //!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        //!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        //ssn->client.seg_list != NULL ||
        //ssn->server.seg_list == NULL ||
        //ssn->server.seg_list->next != NULL ||
        //ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER)
    {
        printf("failure 15\n");
        goto end;
    }

    StreamTcpPruneSession(&f, STREAM_TOSERVER);
    StreamTcpPruneSession(&f, STREAM_TOCLIENT);

    /* request acking a response */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(175);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (//!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        //!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        //f.alproto != ALPROTO_HTTP ||
        //f.alproto_ts != ALPROTO_HTTP ||
        //f.alproto_tc != ALPROTO_HTTP ||
        //ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->client.seg_list != NULL ||
        ssn->server.seg_list != NULL ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER
        ) {
        printf("failure 16\n");
        abort();
        goto end;
    }


    ret = 1;
end:
    StreamTcpThreadDeinit(&tv, (void *)stt);
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    FLOWLOCK_UNLOCK(&f);
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

    SET_ISN(&ssn.server, 9);
    ssn.server.last_ack = 10;
    SET_ISN(&ssn.client, 9);
    ssn.client.isn = 9;

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

    FLOWLOCK_WRLOCK(f);
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
        SEGMENT_BEFORE_OFFSET(&ssn.client, ssn.client.seg_list, STREAM_APP_PROGRESS(&ssn.client)))
//        (ssn.client.seg_list->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED))
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
    FLOWLOCK_UNLOCK(f);
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

    ssn.server.base_seq= 10;
    ssn.server.isn = 9;
    ssn.server.last_ack = 600;
    ssn.client.base_seq = 10;
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

    FLOWLOCK_WRLOCK(f);
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
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    TcpSession ssn;
    ThreadVars tv;
    memset(&tv, 0, sizeof(tv));
    uint8_t payload[100] = {0};
    uint16_t payload_size = 100;

    StreamTcpUTInit(&ra_ctx);
    stream_config.reassembly_depth = 100;

    StreamTcpUTSetupSession(&ssn);
    ssn.reassembly_depth = 100;
    StreamTcpUTSetupStream(&ssn.server, 100);
    StreamTcpUTSetupStream(&ssn.client, 100);

    int r = StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, &ssn.client, 101, payload, payload_size);
    FAIL_IF(r != 0);
    FAIL_IF(ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY);

    r = StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, &ssn.client, 201, payload, payload_size);
    FAIL_IF(r != 0);
    FAIL_IF(!(ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY));

    StreamTcpUTClearStream(&ssn.server);
    StreamTcpUTClearStream(&ssn.client);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    PASS;
}

/**
 *  \test   Test the unlimited config value of reassembly depth.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpReassembleTest46 (void)
{
    int result = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    TcpSession ssn;
    ThreadVars tv;
    memset(&tv, 0, sizeof(tv));
    uint8_t payload[100] = {0};
    uint16_t payload_size = 100;

    StreamTcpUTInit(&ra_ctx);
    stream_config.reassembly_depth = 0;

    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 100);
    StreamTcpUTSetupStream(&ssn.client, 100);

    int r = StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, &ssn.client, 101, payload, payload_size);
    if (r != 0)
        goto end;
    if (ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        printf("STREAMTCP_STREAM_FLAG_NOREASSEMBLY set: ");
        goto end;
    }

    r = StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, &ssn.client, 201, payload, payload_size);
    if (r != 0)
        goto end;
    if (ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        printf("STREAMTCP_STREAM_FLAG_NOREASSEMBLY set: ");
        goto end;
    }

    result = 1;
end:
    StreamTcpUTClearStream(&ssn.server);
    StreamTcpUTClearStream(&ssn.client);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    return result;
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

    SET_ISN(&ssn.server, 572799781UL);
    ssn.server.last_ack = 572799782UL;

    SET_ISN(&ssn.client, 4294967289UL);
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

    FLOWLOCK_WRLOCK(f);
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
    FLOWLOCK_UNLOCK(f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    FAIL_IF(UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1);

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload, 15) == 0)
        goto end;

    ret = 1;
end:
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1) {
        printf("expected a single stream message 1, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
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

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(&f);
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

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    StreamMsg *smsg = ssn.toserver_smsg_head;
    if (UtTestSmsg(smsg, stream_payload1, 6) == 0) {
        printf("stream_payload1 failed: ");
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next;
    if (UtTestSmsg(smsg, stream_payload2, 5) == 0) {
        printf("stream_payload2 failed: ");
        goto end;
    }

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    if (r < 0) {
        printf("StreamTcpReassembleInlineRaw failed: ");
        goto end;
    }

    if (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 3) {
        printf("expected a single stream message, got %u: ", UtSsnSmsgCnt(&ssn, STREAM_TOSERVER));
        goto end;
    }

    smsg = ssn.toserver_smsg_head->next->next;
    if (UtTestSmsg(smsg, stream_payload3, 16) == 0) {
        printf("stream_payload3 failed: ");
        goto end;
    }

    ret = 1;
end:
    FLOWLOCK_UNLOCK(&f);
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
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    memset(&tv, 0x00, sizeof(tv));
    TcpSession ssn;
    Flow f;
    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    FLOW_INITIALIZE(&f);

    stream_config.reassembly_toserver_chunk_size = 15;
    ssn.client.flags |= STREAMTCP_STREAM_FLAG_GAP;
    f.protoctx = &ssn;

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCC";
    uint8_t stream_payload2[] = "BBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    FAIL_IF(p == NULL);
    p->tcph->th_seq = htonl(12);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1);
    ssn.client.next_seq = 17;

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    FAIL_IF(r < 0);

    FAIL_IF(UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1);
    StreamMsg *smsg = ssn.toserver_smsg_head;
    FAIL_IF(UtTestSmsg(smsg, stream_payload1, 15) == 0);

    FAIL_IF(STREAM_RAW_PROGRESS(&ssn.client) != 15);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1);
    ssn.client.next_seq = 22;
    p->tcph->th_seq = htonl(17);

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    FAIL_IF (r < 0);

    FAIL_IF(UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 2);

    smsg = ssn.toserver_smsg_head->next;
    FAIL_IF(UtTestSmsg(smsg, stream_payload2, 15) == 0);

    FAIL_IF(STREAM_RAW_PROGRESS(&ssn.client) != 20);

    smsg = ssn.toserver_smsg_head;
    StreamMsgReturnToPool(smsg);
    ssn.toserver_smsg_head = ssn.toserver_smsg_head->next;

    StreamTcpPruneSession(&f, STREAM_TOSERVER);

    FAIL_IF (ssn.client.seg_list->seq != 2);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    PASS;
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

    FLOWLOCK_WRLOCK(&f);
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
    ssn.client.last_ack = 10;

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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

    FAIL_IF(STREAM_RAW_PROGRESS(&ssn.client) != 10);

    /* close the GAP and see if we properly reassemble and update base_seq */
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

    r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
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

    FAIL_IF(STREAM_RAW_PROGRESS(&ssn.client) != 20);

    if (ssn.client.seg_list->seq != 2) {
        printf("expected segment 1 (seq 2) to be first in the list, got seq %"PRIu32": ", ssn.client.seg_list->seq);
        goto end;
    }

    ret = 1;
end:
    FLOWLOCK_UNLOCK(&f);
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

    FLOWLOCK_WRLOCK(f);
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
    if (ssn.server.base_seq != 2 || ssn.server.base_seq != ssn.server.isn+1) {
        printf("expected ra_app_base_seq 1, got %u: ", ssn.server.base_seq);
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

    if (STREAM_APP_PROGRESS(&ssn.server) != 17) {
        printf("expected ssn.server.app_progress == 17got %"PRIu64": ",
                STREAM_APP_PROGRESS(&ssn.server));
        goto end;
    }

    ret = 1;
end:
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    FLOWLOCK_UNLOCK(f);
    UTHFreeFlow(f);
    return ret;
}

/** \test test insert with overlap
 */
static int StreamTcpReassembleInsertTest01(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow f;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.client, 1);
    ssn.client.os_policy = OS_POLICY_LAST;
    FLOW_INITIALIZE(&f);

    uint8_t stream_payload1[] = "AAAAABBBBBCCCCCDDDDD";
    uint8_t payload[] = { 'C', 'C', 'C', 'C', 'C' };
    Packet *p = UTHBuildPacketReal(payload, 5, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    FAIL_IF(p == NULL);
    p->tcph->th_seq = htonl(12);
    p->flow = &f;

    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  2, 'A', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client,  7, 'B', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 14, 'D', 2) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 16, 'D', 6) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1);
    ssn.client.next_seq = 21;

    int r = StreamTcpReassembleRaw(&tv, ra_ctx, &ssn, &ssn.client, p);
    FAIL_IF (r < 0);
    FAIL_IF (UtSsnSmsgCnt(&ssn, STREAM_TOSERVER) != 1);
    StreamMsg *smsg = ssn.toserver_smsg_head;
    FAIL_IF(UtTestSmsg(smsg, stream_payload1, 20) == 0);
    FAIL_IF(STREAM_RAW_PROGRESS(&ssn.client) != 20);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    PASS;
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
    UtRegisterTest("StreamTcpReassembleTest25 -- Gap at Start Reassembly Test",
                   StreamTcpReassembleTest25);
    UtRegisterTest("StreamTcpReassembleTest26 -- Gap at middle Reassembly Test",
                   StreamTcpReassembleTest26);
    UtRegisterTest("StreamTcpReassembleTest27 -- Gap at after  Reassembly Test",
                   StreamTcpReassembleTest27);
    UtRegisterTest("StreamTcpReassembleTest28 -- Gap at Start IDS missed packet Reassembly Test",
                   StreamTcpReassembleTest28);
    UtRegisterTest("StreamTcpReassembleTest29 -- Gap at Middle IDS missed packet Reassembly Test",
                   StreamTcpReassembleTest29);
    UtRegisterTest("StreamTcpReassembleTest33 -- Bug test",
                   StreamTcpReassembleTest33);
    UtRegisterTest("StreamTcpReassembleTest34 -- Bug test",
                   StreamTcpReassembleTest34);
    UtRegisterTest("StreamTcpReassembleTest37 -- Bug76 test",
                   StreamTcpReassembleTest37);
    UtRegisterTest("StreamTcpReassembleTest38 -- app proto test",
                   StreamTcpReassembleTest38);
    UtRegisterTest("StreamTcpReassembleTest39 -- app proto test",
                   StreamTcpReassembleTest39);
    UtRegisterTest("StreamTcpReassembleTest40 -- app proto test",
                   StreamTcpReassembleTest40);
    UtRegisterTest("StreamTcpReassembleTest43 -- min smsg size test",
                   StreamTcpReassembleTest43);
    UtRegisterTest("StreamTcpReassembleTest44 -- Memcap Test",
                   StreamTcpReassembleTest44);
    UtRegisterTest("StreamTcpReassembleTest45 -- Depth Test",
                   StreamTcpReassembleTest45);
    UtRegisterTest("StreamTcpReassembleTest46 -- Depth Test",
                   StreamTcpReassembleTest46);
    UtRegisterTest("StreamTcpReassembleTest47 -- TCP Sequence Wraparound Test",
                   StreamTcpReassembleTest47);

    UtRegisterTest("StreamTcpReassembleInlineTest01 -- inline RAW ra",
                   StreamTcpReassembleInlineTest01);
    UtRegisterTest("StreamTcpReassembleInlineTest02 -- inline RAW ra 2",
                   StreamTcpReassembleInlineTest02);
    UtRegisterTest("StreamTcpReassembleInlineTest03 -- inline RAW ra 3",
                   StreamTcpReassembleInlineTest03);
    UtRegisterTest("StreamTcpReassembleInlineTest04 -- inline RAW ra 4",
                   StreamTcpReassembleInlineTest04);
    UtRegisterTest("StreamTcpReassembleInlineTest05 -- inline RAW ra 5 GAP",
                   StreamTcpReassembleInlineTest05);
    UtRegisterTest("StreamTcpReassembleInlineTest06 -- inline RAW ra 6 GAP",
                   StreamTcpReassembleInlineTest06);
    UtRegisterTest("StreamTcpReassembleInlineTest07 -- inline RAW ra 7 GAP",
                   StreamTcpReassembleInlineTest07);
    UtRegisterTest("StreamTcpReassembleInlineTest08 -- inline RAW ra 8 cleanup",
                   StreamTcpReassembleInlineTest08);
    UtRegisterTest("StreamTcpReassembleInlineTest09 -- inline RAW ra 9 GAP cleanup",
                   StreamTcpReassembleInlineTest09);

    UtRegisterTest("StreamTcpReassembleInlineTest10 -- inline APP ra 10",
                   StreamTcpReassembleInlineTest10);

    UtRegisterTest("StreamTcpReassembleInsertTest01 -- insert with overlap",
                   StreamTcpReassembleInsertTest01);
    UtRegisterTest("StreamTcpReassembleInsertTest02 -- insert with overlap",
                   StreamTcpReassembleInsertTest02);
    UtRegisterTest("StreamTcpReassembleInsertTest03 -- insert with overlap",
                   StreamTcpReassembleInsertTest03);

    StreamTcpInlineRegisterTests();
    StreamTcpUtilRegisterTests();
    StreamTcpListRegisterTests();
#endif /* UNITTESTS */
}
