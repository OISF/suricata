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
#include "util-validate.h"

#ifdef DEBUG
static SCMutex segment_pool_memuse_mutex;
static uint64_t segment_pool_memuse = 0;
static uint64_t segment_pool_memcnt = 0;
#endif

static PoolThread *segment_thread_pool = NULL;
/* init only, protect initializing and growing pool */
static SCMutex segment_thread_pool_mutex = SCMUTEX_INITIALIZER;

/* Memory use counter */
SC_ATOMIC_DECLARE(uint64_t, ra_memuse);

/* prototypes */
TcpSegment *StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *);
void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);
void StreamTcpReassemblePseudoPacketCreate(TcpStream *, Packet *, PacketQueue *);

void StreamTcpReassembleInitMemuse(void)
{
    SC_ATOMIC_INIT(ra_memuse);
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
    SCLogDebug("REASSEMBLY %"PRIu64", incr %"PRIu64, StreamTcpReassembleMemuseGlobalCounter(), size);
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
#ifdef UNITTESTS
    uint64_t presize = SC_ATOMIC_GET(ra_memuse);
    if (RunmodeIsUnittests()) {
        BUG_ON(presize > UINT_MAX);
    }
#endif

    (void) SC_ATOMIC_SUB(ra_memuse, size);

#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        uint64_t postsize = SC_ATOMIC_GET(ra_memuse);
        BUG_ON(postsize > presize);
    }
#endif
    SCLogDebug("REASSEMBLY %"PRIu64", decr %"PRIu64, StreamTcpReassembleMemuseGlobalCounter(), size);
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

/* memory functions for the streaming buffer API */

/*
    void *(*Malloc)(size_t size);
*/
static void *ReassembleMalloc(size_t size)
{
    if (StreamTcpReassembleCheckMemcap(size) == 0)
        return NULL;
    void *ptr = SCMalloc(size);
    if (ptr == NULL)
        return NULL;
    StreamTcpReassembleIncrMemuse(size);
    return ptr;
}

/*
    void *(*Calloc)(size_t n, size_t size);
*/
static void *ReassembleCalloc(size_t n, size_t size)
{
    if (StreamTcpReassembleCheckMemcap(n * size) == 0)
        return NULL;
    void *ptr = SCCalloc(n, size);
    if (ptr == NULL)
        return NULL;
    StreamTcpReassembleIncrMemuse(n * size);
    return ptr;
}

/*
    void *(*Realloc)(void *ptr, size_t orig_size, size_t size);
*/
static void *ReassembleRealloc(void *optr, size_t orig_size, size_t size)
{
    if (size > orig_size) {
        if (StreamTcpReassembleCheckMemcap(size - orig_size) == 0)
            return NULL;
    }
    void *nptr = SCRealloc(optr, size);
    if (nptr == NULL)
        return NULL;

    if (size > orig_size) {
        StreamTcpReassembleIncrMemuse(size - orig_size);
    } else {
        StreamTcpReassembleDecrMemuse(orig_size - size);
    }
    return nptr;
}

/*
    void (*Free)(void *ptr, size_t size);
*/
static void ReassembleFree(void *ptr, size_t size)
{
    SCFree(ptr);
    StreamTcpReassembleDecrMemuse(size);
}

/** \brief alloc a tcp segment pool entry */
static void *TcpSegmentPoolAlloc(void)
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

static int TcpSegmentPoolInit(void *data, void *initdata)
{
    TcpSegment *seg = (TcpSegment *) data;

    /* do this before the can bail, so TcpSegmentPoolCleanup
     * won't have uninitialized memory to consider. */
    memset(seg, 0, sizeof (TcpSegment));

    if (StreamTcpReassembleCheckMemcap((uint32_t)sizeof(TcpSegment)) == 0) {
        return 0;
    }

#ifdef DEBUG
    SCMutexLock(&segment_pool_memuse_mutex);
    segment_pool_memuse += sizeof(TcpSegment);
    segment_pool_memcnt++;
    SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexUnlock(&segment_pool_memuse_mutex);
#endif

    StreamTcpReassembleIncrMemuse((uint32_t)sizeof(TcpSegment));
    return 1;
}

/** \brief clean up a tcp segment pool entry */
static void TcpSegmentPoolCleanup(void *ptr)
{
    if (ptr == NULL)
        return;

    StreamTcpReassembleDecrMemuse((uint32_t)sizeof(TcpSegment));

#ifdef DEBUG
    SCMutexLock(&segment_pool_memuse_mutex);
    segment_pool_memuse -= sizeof(TcpSegment);
    segment_pool_memcnt--;
    SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexUnlock(&segment_pool_memuse_mutex);
#endif
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
    PoolThreadReturn(segment_thread_pool, seg);
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

static int StreamTcpReassemblyConfig(char quiet)
{
    uint32_t segment_prealloc = 2048;
    ConfNode *seg = ConfGetNode("stream.reassembly.segment-prealloc");
    if (seg) {
        uint32_t prealloc = 0;
        if (ByteExtractStringUint32(&prealloc, 10, strlen(seg->val), seg->val) == -1)
        {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "segment-prealloc of "
                    "%s is invalid", seg->val);
            return -1;
        }
        segment_prealloc = prealloc;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly \"segment-prealloc\": %u", segment_prealloc);
    stream_config.prealloc_segments = segment_prealloc;

    int overlap_diff_data = 0;
    ConfGetBool("stream.reassembly.check-overlap-different-data", &overlap_diff_data);
    if (overlap_diff_data) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }
    if (StreamTcpInlineMode() == TRUE) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }

    stream_config.sbcnf.flags = STREAMING_BUFFER_NOFLAGS;
    stream_config.sbcnf.buf_size = 2048;
    stream_config.sbcnf.Malloc = ReassembleMalloc;
    stream_config.sbcnf.Calloc = ReassembleCalloc;
    stream_config.sbcnf.Realloc = ReassembleRealloc;
    stream_config.sbcnf.Free = ReassembleFree;

    return 0;
}

int StreamTcpReassembleInit(char quiet)
{
    /* init the memcap/use tracker */
    StreamTcpReassembleInitMemuse();

    if (StreamTcpReassemblyConfig(quiet) < 0)
        return -1;

#ifdef DEBUG
    SCMutexInit(&segment_pool_memuse_mutex, NULL);
#endif
    StatsRegisterGlobalCounter("tcp.reassembly_memuse",
            StreamTcpReassembleMemuseGlobalCounter);
    return 0;
}

void StreamTcpReassembleFree(char quiet)
{
    SCMutexLock(&segment_thread_pool_mutex);
    if (segment_thread_pool != NULL) {
        PoolThreadFree(segment_thread_pool);
        segment_thread_pool = NULL;
    }
    SCMutexUnlock(&segment_thread_pool_mutex);
    SCMutexDestroy(&segment_thread_pool_mutex);

#ifdef DEBUG
    SCLogInfo("segment_pool_memuse %"PRIu64"", segment_pool_memuse);
    SCLogInfo("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
    SCMutexDestroy(&segment_pool_memuse_mutex);
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

    SCMutexLock(&segment_thread_pool_mutex);
    if (segment_thread_pool == NULL) {
        segment_thread_pool = PoolThreadInit(1, /* thread */
                0, /* unlimited */
                stream_config.prealloc_segments,
                sizeof(TcpSegment),
                TcpSegmentPoolAlloc,
                TcpSegmentPoolInit, NULL,
                TcpSegmentPoolCleanup, NULL);
        ra_ctx->segment_thread_pool_id = 0;
        SCLogDebug("pool size %d, thread segment_thread_pool_id %d",
                PoolThreadSize(segment_thread_pool),
                ra_ctx->segment_thread_pool_id);
    } else {
        /* grow segment_thread_pool until we have a element for our thread id */
        ra_ctx->segment_thread_pool_id = PoolThreadGrow(segment_thread_pool,
                0, /* unlimited */
                stream_config.prealloc_segments,
                sizeof(TcpSegment),
                TcpSegmentPoolAlloc,
                TcpSegmentPoolInit, NULL,
                TcpSegmentPoolCleanup, NULL);
        SCLogDebug("pool size %d, thread segment_thread_pool_id %d",
                PoolThreadSize(segment_thread_pool),
                ra_ctx->segment_thread_pool_id);
    }
    SCMutexUnlock(&segment_thread_pool_mutex);
    if (ra_ctx->segment_thread_pool_id < 0 || segment_thread_pool == NULL)
        abort();

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
            DEBUG_VALIDATE_BUG_ON(part > size);
            if (part > size)
                part = size;
            SCReturnUInt(part);
        }
    }

    SCReturnUInt(0);
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
    }
    if (size == 0) {
        SCLogDebug("ssn %p: depth reached, not reassembling", ssn);
        SCReturnInt(0);
    }

    DEBUG_VALIDATE_BUG_ON(size > p->payload_len);
    if (size > p->payload_len)
        size = p->payload_len;

    TcpSegment *seg = StreamTcpGetSegment(tv, ra_ctx);
    if (seg == NULL) {
        SCLogDebug("segment_pool is empty");
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
                                      Packet *p, enum StreamUpdateDir dir)
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

    if (dir == UPDATE_DIR_OPPOSING) {
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
static int StreamTcpReassembleRawCheckLimit(const TcpSession *ssn,
        const TcpStream *stream, const Packet *p)
{
    SCEnter();

    /* if any of these flags is set we always inspect immediately */
#define STREAMTCP_STREAM_FLAG_FLUSH_FLAGS       \
        (   STREAMTCP_STREAM_FLAG_DEPTH_REACHED \
        |   STREAMTCP_STREAM_FLAG_TRIGGER_RAW   \
        |   STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)

    if (stream->flags & STREAMTCP_STREAM_FLAG_FLUSH_FLAGS) {
        if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
            SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_DEPTH_REACHED "
                    "is set, so not expecting any new data segments");
        }
        if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW) {
            SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_TRIGGER_RAW is set");
        }
        if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
            SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED is set, "
                    "so no new segments will be considered");
        }
        SCReturnInt(1);
    }
#undef STREAMTCP_STREAM_FLAG_FLUSH_FLAGS

    /* some states mean we reassemble no matter how much data we have */
    if (ssn->state > TCP_TIME_WAIT)
        SCReturnInt(1);

    if (p->flags & PKT_PSEUDO_STREAM_END)
        SCReturnInt(1);

    /* check if we have enough data to do raw reassembly */
    if (PKT_IS_TOSERVER(p)) {
        if (STREAM_LASTACK_GT_BASESEQ(stream)) {
            uint32_t delta = stream->last_ack - stream->base_seq;
            /* get max absolute offset */
            uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

            int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);
            if ((int64_t)stream_config.reassembly_toserver_chunk_size <= diff) {
                SCReturnInt(1);
            } else {
                SCLogDebug("toserver min chunk len not yet reached: "
                        "last_ack %"PRIu32", ra_raw_base_seq %"PRIu32", %"PRIu32" < "
                        "%"PRIu32"", stream->last_ack, stream->base_seq,
                        (stream->last_ack - stream->base_seq),
                        stream_config.reassembly_toserver_chunk_size);
                SCReturnInt(0);
            }
        }
    } else {
        if (STREAM_LASTACK_GT_BASESEQ(stream)) {
            uint32_t delta = stream->last_ack - stream->base_seq;
            /* get max absolute offset */
            uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

            int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);

            if ((int64_t)stream_config.reassembly_toclient_chunk_size <= diff) {
                SCReturnInt(1);
            } else {
                SCLogDebug("toclient min chunk len not yet reached: "
                        "last_ack %"PRIu32", base_seq %"PRIu32",  %"PRIu32" < "
                        "%"PRIu32"", stream->last_ack, stream->base_seq,
                        (stream->last_ack - stream->base_seq),
                        stream_config.reassembly_toclient_chunk_size);
                SCReturnInt(0);
            }
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief see what if any work the TCP session still needs
 */
int StreamNeedsReassembly(const TcpSession *ssn, uint8_t direction)
{
    const TcpStream *stream = NULL;
#ifdef DEBUG
    const char *dirstr = NULL;
#endif
    if (direction == STREAM_TOSERVER) {
        stream = &ssn->client;
#ifdef DEBUG
        dirstr = "client";
#endif
    } else {
        stream = &ssn->server;
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

    if (stream->flags & STREAMTCP_STREAM_FLAG_DISABLE_RAW) {
        // raw is dead
        use_raw = 0;
    }

    uint64_t right_edge = STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset;

    SCLogDebug("%s: list %p app %"PRIu64" (use: %s), raw %"PRIu64" (use: %s). Stream right edge: %"PRIu64,
            dirstr,
            stream->seg_list,
            STREAM_APP_PROGRESS(stream), use_app ? "yes" : "no",
            STREAM_RAW_PROGRESS(stream), use_raw ? "yes" : "no",
            right_edge);
    if (use_raw) {
        if (right_edge > STREAM_RAW_PROGRESS(stream)) {
            SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION", dirstr);
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
    }
    if (use_app) {
        if (right_edge > STREAM_APP_PROGRESS(stream)) {
            SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION", dirstr);
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
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

    if (stream->sb.block_list == NULL) {
        SCLogDebug("getting one blob");

        StreamingBufferGetDataAtOffset(&stream->sb, &mydata, &mydata_len, offset);

        *data = mydata;
        *data_len = mydata_len;
    } else {
        StreamingBufferBlock *blk = stream->sb.block_list;

        if (blk->offset > offset) {
            SCLogDebug("gap, want data at offset %"PRIu64", "
                    "got data at %"PRIu64". GAP of size %"PRIu64,
                    offset, blk->offset, blk->offset - offset);
            *data = NULL;
            *data_len = blk->offset - offset;

        } else if (offset > blk->offset && offset <= (blk->offset + blk->len)) {
            SCLogDebug("get data from offset %"PRIu64". SBB %"PRIu64"/%u",
                    offset, blk->offset, blk->len);
            StreamingBufferSBBGetDataAtOffset(&stream->sb, blk, data, data_len, offset);
            SCLogDebug("data %p, data_len %u", *data, *data_len);
        } else {
            StreamingBufferSBBGetData(&stream->sb, blk, data, data_len);
        }
    }
}

/** \internal
 *  \brief check to see if we should declare a GAP
 *  Call this when the app layer didn't get data at the requested
 *  offset.
 */
static inline bool CheckGap(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    const uint64_t app_progress = STREAM_APP_PROGRESS(stream);
    uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream);

    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
        /* get window of data that is acked */
        uint32_t delta = stream->last_ack - stream->base_seq;
        DEBUG_VALIDATE_BUG_ON(delta > 10000000ULL && delta > stream->window);
        /* get max absolute offset */
        last_ack_abs += delta;

        int ackadded = (ssn->state >= TCP_FIN_WAIT1) ? 1 : 0;
        last_ack_abs -= ackadded;

        SCLogDebug("last_ack %u abs %"PRIu64, stream->last_ack, last_ack_abs);
        SCLogDebug("next_seq %u", stream->next_seq);

        /* if last_ack_abs is beyond the app_progress data that we haven't seen
         * has been ack'd. This looks like a GAP. */
        if (last_ack_abs > app_progress) {
            /* however, we can accept ACKs a bit too liberally. If last_ack
             * is beyond next_seq, we only consider it a gap now if we do
             * already have data beyond the gap. */
            if (SEQ_GT(stream->last_ack, stream->next_seq)) {
                if (stream->sb.block_list == NULL) {
                    SCLogDebug("packet %"PRIu64": no GAP. "
                            "next_seq %u < last_ack %u, but no data in list",
                            p->pcap_cnt, stream->next_seq, stream->last_ack);
                    return false;
                } else {
                    uint64_t next_seq_abs = STREAM_BASE_OFFSET(stream) + (stream->next_seq - stream->base_seq);
                    StreamingBufferBlock *blk = stream->sb.block_list;
                    if (blk->offset > next_seq_abs && blk->offset < last_ack_abs) {
                        /* ack'd data after the gap */
                        SCLogDebug("packet %"PRIu64": GAP. "
                                "next_seq %u < last_ack %u, but ACK'd data beyond gap.",
                                p->pcap_cnt, stream->next_seq, stream->last_ack);
                        return true;
                    }
                }
            }

            SCLogDebug("packet %"PRIu64": GAP! "
                    "last_ack_abs %"PRIu64" > app_progress %"PRIu64", "
                    "but we have no data.",
                    p->pcap_cnt, last_ack_abs, app_progress);
            return true;
        }
    }
    SCLogDebug("packet %"PRIu64": no GAP. "
            "last_ack_abs %"PRIu64" <= app_progress %"PRIu64,
            p->pcap_cnt, last_ack_abs, app_progress);
    return false;
}

/** \internal
 *  \brief get stream buffer and update the app-layer
 *  \retval 0 success
 */
static int ReassembleUpdateAppLayer (ThreadVars *tv,
        TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, TcpStream *stream,
        Packet *p, enum StreamUpdateDir dir)
{
    uint64_t app_progress = STREAM_APP_PROGRESS(stream);

    SCLogDebug("app progress %"PRIu64, app_progress);
    SCLogDebug("last_ack %u, base_seq %u", stream->last_ack, stream->base_seq);

    const uint8_t *mydata;
    uint32_t mydata_len;

    while (1) {
        GetAppBuffer(stream, &mydata, &mydata_len, app_progress);
        if (mydata == NULL && mydata_len > 0 && CheckGap(ssn, stream, p)) {
            SCLogDebug("sending GAP to app-layer (size: %u)", mydata_len);

            AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                    NULL, mydata_len,
                    StreamGetAppLayerFlags(ssn, stream, p, dir)|STREAM_GAP);
            AppLayerProfilingStore(ra_ctx->app_tctx, p);

            StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEQ_GAP);
            StatsIncr(tv, ra_ctx->counter_tcp_reass_gap);

            stream->app_progress_rel += mydata_len;
            app_progress += mydata_len;
            continue;
        } else if (mydata == NULL || mydata_len == 0) {
            /* Possibly a gap, but no new data. */
            return 0;
        }
        SCLogDebug("%"PRIu64" got %p/%u", p->pcap_cnt, mydata, mydata_len);
        break;
    }

    //PrintRawDataFp(stdout, mydata, mydata_len);

    SCLogDebug("stream %p data in buffer %p of len %u and offset %"PRIu64,
            stream, &stream->sb, mydata_len, app_progress);

    /* get window of data that is acked */
    if (StreamTcpInlineMode() == FALSE) {
        if (p->flags & PKT_PSEUDO_STREAM_END) {
            // fall through, we use all available data
        } else {
            uint64_t last_ack_abs = app_progress; /* absolute right edge of ack'd data */
            if (STREAM_LASTACK_GT_BASESEQ(stream)) {
                /* get window of data that is acked */
                uint32_t delta = stream->last_ack - stream->base_seq;
                DEBUG_VALIDATE_BUG_ON(delta > 10000000ULL && delta > stream->window);
                /* get max absolute offset */
                last_ack_abs += delta;
            }

            /* see if the buffer contains unack'd data as well */
            if (app_progress + mydata_len > last_ack_abs) {
                uint32_t check = mydata_len;
                mydata_len = last_ack_abs - app_progress;
                BUG_ON(mydata_len > check);
                SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                        "data is considered", mydata_len);
            }
        }
    }

    /* update the app-layer */
    int r = AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
            (uint8_t *)mydata, mydata_len,
            StreamGetAppLayerFlags(ssn, stream, p, dir));

    /* see if we can update the progress */
    if (r == 0 && mydata_len > 0 &&
            StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream))
    {
        SCLogDebug("app progress %"PRIu64" increasing with data len %u to %"PRIu64,
                app_progress, mydata_len, app_progress + mydata_len);

        stream->app_progress_rel += mydata_len;
        SCLogDebug("app progress now %"PRIu64, STREAM_APP_PROGRESS(stream));
    } else {
        SCLogDebug("NOT UPDATED app progress still %"PRIu64, app_progress);
    }

    SCReturnInt(0);
}

/**
 *  \brief Update the stream reassembly upon receiving a packet.
 *
 *  For IDS mode, the stream is in the opposite direction of the packet,
 *  as the ACK-packet is ACK'ing the stream.
 *
 *  One of the utilities call by this function AppLayerHandleTCPData(),
 *  has a feature where it will call this very same function for the
 *  stream opposing the stream it is called with.  This shouldn't cause
 *  any issues, since processing of each stream is independent of the
 *  other stream.
 */
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                 TcpSession *ssn, TcpStream *stream,
                                 Packet *p, enum StreamUpdateDir dir)
{
    SCEnter();

    /* this function can be directly called by app layer protocol
     * detection. */
    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
        (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        SCLogDebug("stream no reassembly flag set or app-layer disabled.");
        SCReturnInt(0);
    }

    SCLogDebug("stream->seg_list %p", stream->seg_list);
#ifdef DEBUG
    PrintList(stream->seg_list);
    GetSessionSize(ssn, p);
#endif
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
                                  StreamGetAppLayerFlags(ssn, stream, p, dir));
            AppLayerProfilingStore(ra_ctx->app_tctx, p);

            SCReturnInt(0);
        }
    }

    /* with all that out of the way, lets update the app-layer */
    return ReassembleUpdateAppLayer(tv, ra_ctx, ssn, stream, p, dir);
}

/** \internal
 *  \brief get stream data from offset
 *  \param offset stream offset */
static int GetRawBuffer(TcpStream *stream, const uint8_t **data, uint32_t *data_len,
        StreamingBufferBlock **iter, uint64_t offset, uint64_t *data_offset)
{
    const uint8_t *mydata;
    uint32_t mydata_len;
    if (stream->sb.block_list == NULL) {
        SCLogDebug("getting one blob");

        uint64_t roffset = offset;
        if (offset)
            StreamingBufferGetDataAtOffset(&stream->sb, &mydata, &mydata_len, offset);
        else {
            StreamingBufferGetData(&stream->sb, &mydata, &mydata_len, &roffset);
        }

        *data = mydata;
        *data_len = mydata_len;
        *data_offset = roffset;
    } else {
        if (*iter == NULL)
            *iter = stream->sb.block_list;
        if (*iter == NULL) {
            *data = NULL;
            *data_len = 0;
            *data_offset = 0;
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

        StreamingBufferSBBGetData(&stream->sb, (*iter), &mydata, &mydata_len);

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

/** \brief does the stream engine have data to inspect?
 *
 *  Returns true if there is data to inspect. In IDS case this is
 *  about ACK'd data in the packet's direction.
 *
 *  In the IPS case this is about the packet itself.
 */
bool StreamReassembleRawHasDataReady(TcpSession *ssn, Packet *p)
{
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (stream->seg_list == NULL) {
        return false;
    }

    if (stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY|
                         STREAMTCP_STREAM_FLAG_DISABLE_RAW))
        return false;

    if (StreamTcpInlineMode() == FALSE) {
        if ((STREAM_RAW_PROGRESS(stream) == STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset)) {
            return false;
        }
        if (StreamTcpReassembleRawCheckLimit(ssn, stream, p) == 1) {
            return true;
        }
    } else {
        if (p->payload_len > 0 && (p->flags & PKT_STREAM_ADD)) {
            return true;
        }
    }
    return false;
}

/** \brief update stream engine after detection
 *
 *  Tasked with progressing the 'progress' for Raw reassembly.
 *  2 main scenario's:
 *   1. progress is != 0, so we use this
 *   2. progress is 0, meaning the detect engine didn't touch
 *      raw at all. In this case we need to look into progressing
 *      raw anyway.
 *
 *  Additionally, this function is tasked with disabling raw
 *  reassembly if the app-layer requested to disable it.
 */
void StreamReassembleRawUpdateProgress(TcpSession *ssn, Packet *p, uint64_t progress)
{
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (progress > STREAM_RAW_PROGRESS(stream)) {
        uint32_t slide = progress - STREAM_RAW_PROGRESS(stream);
        stream->raw_progress_rel += slide;
        stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

    /* if app is active and beyond raw, sync raw to app */
    } else if (progress == 0 &&
            STREAM_APP_PROGRESS(stream) > STREAM_RAW_PROGRESS(stream) &&
            !(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) &&
            !(stream->flags & STREAMTCP_STREAM_FLAG_GAP))
    {
        /* if trigger raw is set we sync the 2 trackers */
        if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW)
        {
            uint32_t slide = STREAM_APP_PROGRESS(stream) - STREAM_RAW_PROGRESS(stream);
            stream->raw_progress_rel += slide;
            stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

        /* otherwise mix in the tcp window */
        } else {
            uint64_t tcp_window = stream->window;
            if (tcp_window > 0 && STREAM_APP_PROGRESS(stream) > tcp_window) {
                uint64_t new_raw = STREAM_APP_PROGRESS(stream) - tcp_window;
                if (new_raw > STREAM_RAW_PROGRESS(stream)) {
                    uint32_t slide = new_raw - STREAM_RAW_PROGRESS(stream);
                    stream->raw_progress_rel += slide;
                }
            }
        }
    /* app is dead */
    } else if (progress == 0) {
        uint64_t tcp_window = stream->window;
        uint64_t stream_right_edge = STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset;
        if (tcp_window < stream_right_edge) {
            uint64_t new_raw = stream_right_edge - tcp_window;
            if (new_raw > STREAM_RAW_PROGRESS(stream)) {
                uint32_t slide = new_raw - STREAM_RAW_PROGRESS(stream);
                stream->raw_progress_rel += slide;
            }
        }
        stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

    } else {
        SCLogDebug("p->pcap_cnt %"PRIu64": progress %"PRIu64" app %"PRIu64" raw %"PRIu64" tcp win %"PRIu32,
                p->pcap_cnt, progress, STREAM_APP_PROGRESS(stream),
                STREAM_RAW_PROGRESS(stream), stream->window);
    }

    /* if we were told to accept no more raw data, we can mark raw as
     * disabled now. */
    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
        stream->flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
        SCLogDebug("ssn %p: STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED set, "
            "now that detect ran also set STREAMTCP_STREAM_FLAG_DISABLE_RAW", ssn);
    }

    SCLogDebug("stream raw progress now %"PRIu64, STREAM_RAW_PROGRESS(stream));
}

/** \internal
  * \brief get a buffer around the current packet and run the callback on it
  *
  * The inline/IPS scanning method takes the current payload and wraps it in
  * data from other segments.
  *
  * How much data is inspected is controlled by the available data, chunk_size
  * and the payload size of the packet.
  *
  * Large packets: if payload size is close to the chunk_size, where close is
  * defined as more than 67% of the chunk_size, a larger chunk_size will be
  * used: payload_len + 33% of the chunk_size.
  * If the payload size if equal to or bigger than the chunk_size, we use
  * payload len + 33% of the chunk size.
  */
static int StreamReassembleRawInline(TcpSession *ssn, const Packet *p,
        StreamReassembleRawFunc Callback, void *cb_data, uint64_t *progress_out)
{
    SCEnter();
    int r = 0;

    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (p->payload_len == 0 || (p->flags & PKT_STREAM_ADD) == 0 ||
            (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
    {
        *progress_out = STREAM_RAW_PROGRESS(stream);
        return 0;
    }

    uint32_t chunk_size = PKT_IS_TOSERVER(p) ?
        stream_config.reassembly_toserver_chunk_size :
        stream_config.reassembly_toclient_chunk_size;
    if (chunk_size <= p->payload_len) {
        chunk_size = p->payload_len + (chunk_size / 3);
        SCLogDebug("packet payload len %u, so chunk_size adjusted to %u",
                p->payload_len, chunk_size);
    } else if (((chunk_size / 3 ) * 2) < p->payload_len) {
        chunk_size = p->payload_len + ((chunk_size / 3));
        SCLogDebug("packet payload len %u, so chunk_size adjusted to %u",
                p->payload_len, chunk_size);
    }

    uint64_t packet_leftedge_abs = STREAM_BASE_OFFSET(stream) + (TCP_GET_SEQ(p) - stream->base_seq);
    uint64_t packet_rightedge_abs = packet_leftedge_abs + p->payload_len;
    SCLogDebug("packet_leftedge_abs %"PRIu64", rightedge %"PRIu64,
            packet_leftedge_abs, packet_rightedge_abs);

    const uint8_t *mydata = NULL;
    uint32_t mydata_len = 0;
    uint64_t mydata_offset = 0;
    /* simply return progress from the block we inspected. */
    bool return_progress = false;

    if (stream->sb.block_list == NULL) {
        /* continues block */
        StreamingBufferGetData(&stream->sb, &mydata, &mydata_len, &mydata_offset);
        return_progress = true;

    } else {
        /* find our block */
        StreamingBufferBlock *iter = stream->sb.block_list;
        for ( ; iter != NULL; iter = iter->next) {
            uint64_t iter_re_abs = iter->offset + iter->len;
            DEBUG_VALIDATE_BUG_ON(packet_leftedge_abs < iter->offset &&
                    packet_rightedge_abs > iter->offset &&
                    packet_rightedge_abs < iter_re_abs);

            if (iter->offset <= packet_leftedge_abs && iter_re_abs >= packet_rightedge_abs) {
                StreamingBufferSBBGetData(&stream->sb, iter, &mydata, &mydata_len);
                mydata_offset = iter->offset;
                break;
            }
        }
    }

    /* this can only happen if the segment insert of our current 'p' failed */
    if (mydata == NULL || mydata_len == 0) {
        SCLogDebug("no data: %p/%u", mydata, mydata_len);
        *progress_out = STREAM_RAW_PROGRESS(stream);
        return 0;
    }
    if (mydata_offset >= packet_rightedge_abs ||
        (packet_leftedge_abs >= (mydata_offset + mydata_len))) {
        SCLogDebug("no data overlap: %p/%u", mydata, mydata_len);
        *progress_out = STREAM_RAW_PROGRESS(stream);
        return 0;
    }

    /* adjust buffer to match chunk_size */

    uint64_t mydata_rightedge_abs = mydata_offset + mydata_len;
    SCLogDebug("chunk_size %u mydata_len %u", chunk_size, mydata_len);
    if (mydata_len > chunk_size) {
        uint32_t excess = mydata_len - chunk_size;
        SCLogDebug("chunk_size %u mydata_len %u excess %u", chunk_size, mydata_len, excess);

        if (mydata_rightedge_abs == packet_rightedge_abs) {
            mydata += excess;
            mydata_len -= excess;
            mydata_offset += excess;
            SCLogDebug("cutting front of the buffer with %u", excess);
        } else if (mydata_offset == packet_leftedge_abs) {
            mydata_len -= excess;
            SCLogDebug("cutting tail of the buffer with %u", excess);
        } else {
            uint32_t before = (uint32_t)(packet_leftedge_abs - mydata_offset);
            uint32_t after = (uint32_t)(mydata_rightedge_abs - packet_rightedge_abs);
            SCLogDebug("before %u after %u", before, after);

            if (after >= (chunk_size - p->payload_len) / 2) {
                // more trailing data than we need

                if (before >= (chunk_size - p->payload_len) / 2) {
                    // also more heading data, devide evenly
                    before = after = (chunk_size - p->payload_len) / 2;
                } else {
                    // heading data is less than requested, give the
                    // rest to the trailing data
                    after = (chunk_size - p->payload_len) - before;
                }
            } else {
                // less trailing data than requested

                if (before >= (chunk_size - p->payload_len) / 2) {
                    before = (chunk_size - p->payload_len) - after;
                } else {
                    // both smaller than their requested size
                }
            }

            /* adjust the buffer */
            uint32_t skip = (uint32_t)(packet_leftedge_abs - mydata_offset) - before;
            uint32_t cut = (uint32_t)(mydata_rightedge_abs - packet_rightedge_abs) - after;
            DEBUG_VALIDATE_BUG_ON(skip > mydata_len);
            DEBUG_VALIDATE_BUG_ON(cut > mydata_len);
            DEBUG_VALIDATE_BUG_ON(skip + cut > mydata_len);
            mydata += skip;
            mydata_len -= (skip + cut);
            mydata_offset += skip;
        }
    }

    /* run the callback */
    r = Callback(cb_data, mydata, mydata_len);
    BUG_ON(r < 0);

    if (return_progress) {
        *progress_out = (mydata_offset + mydata_len);
    } else {
        /* several blocks of data, so we need to be a bit more careful:
         * - if last_ack is beyond last progress, move progress forward to last_ack
         * - if our block matches or starts before last ack, return right edge of
         *   our block.
         */
        uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream);
        if (STREAM_LASTACK_GT_BASESEQ(stream)) {
            uint32_t delta = stream->last_ack - stream->base_seq;
            DEBUG_VALIDATE_BUG_ON(delta > 10000000ULL && delta > stream->window);
            /* get max absolute offset */
            last_ack_abs += delta;
        }
        SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);

        if (STREAM_RAW_PROGRESS(stream) < last_ack_abs) {
            if (mydata_offset > last_ack_abs) {
                /* gap between us and last ack, set progress to last ack */
                *progress_out = last_ack_abs;
            } else {
                *progress_out = (mydata_offset + mydata_len);
            }
        } else {
            *progress_out = STREAM_RAW_PROGRESS(stream);
        }
    }
    return r;
}

/** \brief access 'raw' reassembly data.
 *
 *  Access data as tracked by 'raw' tracker. Data is made available to
 *  callback that is passed to this function.
 *
 *  In the case of IDS the callback may be run multiple times if data
 *  contains gaps. It will then be run for each block of data that is
 *  continuous.
 *
 *  The callback should give on of 2 return values:
 *  - 0 ok
 *  - 1 done
 *  The value 1 will break the loop if there is a block list that is
 *  inspected.
 *
 *  This function will return the 'progress' value that has been
 *  consumed until now.
 *
 *  \param ssn tcp session
 *  \param stream tcp stream
 *  \param Callback the function pointer to the callback function
 *  \param cb_data callback data
 *  \param[in] progress_in progress to work from
 *  \param[out] progress_out absolute progress value of the data this
 *                           call handled.
 */
static int StreamReassembleRawDo(TcpSession *ssn, TcpStream *stream,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        const uint64_t progress_in,
                        uint64_t *progress_out, bool eof)
{
    SCEnter();
    int r = 0;

    StreamingBufferBlock *iter = NULL;
    uint64_t progress = progress_in;
    uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream); /* absolute right edge of ack'd data */

    /* get window of data that is acked */
    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
        SCLogDebug("last_ack %u, base_seq %u", stream->last_ack, stream->base_seq);
        uint32_t delta = stream->last_ack - stream->base_seq;
        DEBUG_VALIDATE_BUG_ON(delta > 10000000ULL && delta > stream->window);
        /* get max absolute offset */
        last_ack_abs += delta;
        SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);
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
        SCLogDebug("stream %p data in buffer %p of len %u and offset %"PRIu64,
                stream, &stream->sb, mydata_len, progress);

        if (eof) {
            // inspect all remaining data, ack'd or not
        } else {
            if (last_ack_abs < progress) {
                SCLogDebug("nothing to do");
                goto end;
            }

            SCLogDebug("last_ack_abs %"PRIu64", raw_progress %"PRIu64, last_ack_abs, progress);
            SCLogDebug("raw_progress + mydata_len %"PRIu64", last_ack_abs %"PRIu64, progress + mydata_len, last_ack_abs);

            /* see if the buffer contains unack'd data as well */
            if (progress + mydata_len > last_ack_abs) {
                uint32_t check = mydata_len;
                mydata_len = last_ack_abs - progress;
                BUG_ON(check < mydata_len);
                SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                        "data is considered", mydata_len);
            }

        }
        if (mydata_len == 0)
            break;

        SCLogDebug("data %p len %u", mydata, mydata_len);

        /* we have data. */
        r = Callback(cb_data, mydata, mydata_len);
        BUG_ON(r < 0);

        if (mydata_offset == progress) {
            SCLogDebug("progress %"PRIu64" increasing with data len %u to %"PRIu64,
                    progress, mydata_len, progress_in + mydata_len);

            progress += mydata_len;
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

        if (iter == NULL || r == 1)
            break;
    }
end:
    *progress_out = progress;
    return r;
}

int StreamReassembleRaw(TcpSession *ssn, const Packet *p,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t *progress_out)
{
    /* handle inline seperately as the logic is very different */
    if (StreamTcpInlineMode() == TRUE) {
        return StreamReassembleRawInline(ssn, p, Callback, cb_data, progress_out);
    }

    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if ((stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY|STREAMTCP_STREAM_FLAG_DISABLE_RAW)) ||
        StreamTcpReassembleRawCheckLimit(ssn, stream, p) == 0)
    {
        *progress_out = STREAM_RAW_PROGRESS(stream);
        return 0;
    }

    return StreamReassembleRawDo(ssn, stream, Callback, cb_data,
            STREAM_RAW_PROGRESS(stream), progress_out,
            (p->flags & PKT_PSEUDO_STREAM_END));
}

int StreamReassembleLog(TcpSession *ssn, TcpStream *stream,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t progress_in,
                        uint64_t *progress_out, bool eof)
{
    if (stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
        return 0;

    return StreamReassembleRawDo(ssn, stream, Callback, cb_data,
            progress_in, progress_out, eof);
}

/** \internal
 *  \brief update app layer based on received ACK
 *
 *  \retval r 0 on success, -1 on error
 */
static int StreamTcpReassembleHandleSegmentUpdateACK (ThreadVars *tv,
        TcpReassemblyThreadCtx *ra_ctx, TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();
    SCLogDebug("stream->seg_list %p", stream->seg_list);

    int r = 0;
    if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p, UPDATE_DIR_OPPOSING) < 0)
        r = -1;

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

    /* default IDS: update opposing side (triggered by ACK) */
    enum StreamUpdateDir dir = UPDATE_DIR_OPPOSING;
    /* inline and stream end and flow timeout packets trigger same dir handling */
    if (StreamTcpInlineMode()) {
        dir = UPDATE_DIR_PACKET;
    } else if (p->flags & PKT_PSEUDO_STREAM_END) {
        dir = UPDATE_DIR_PACKET;
    } else if (p->tcph && (p->tcph->th_flags & TH_RST)) { // accepted rst
        dir = UPDATE_DIR_PACKET;
    } else if (p->tcph && (p->tcph->th_flags & TH_FIN) && ssn->state > TCP_TIME_WAIT) {
        dir = UPDATE_DIR_PACKET;
    }

    /* handle ack received */
    if (dir == UPDATE_DIR_OPPOSING &&
        StreamTcpReassembleHandleSegmentUpdateACK(tv, ra_ctx, ssn, opposing_stream, p) != 0)
    {
        SCLogDebug("StreamTcpReassembleHandleSegmentUpdateACK error");
        SCReturnInt(-1);
    }

    /* if this segment contains data, insert it */
    if (p->payload_len > 0 && !(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        SCLogDebug("calling StreamTcpReassembleHandleSegmentHandleData");

        if (StreamTcpReassembleHandleSegmentHandleData(tv, ra_ctx, ssn, stream, p) != 0) {
            SCLogDebug("StreamTcpReassembleHandleSegmentHandleData error");
            SCReturnInt(-1);
        }

        SCLogDebug("packet %"PRIu64" set PKT_STREAM_ADD", p->pcap_cnt);
        p->flags |= PKT_STREAM_ADD;
    } else {
        SCLogDebug("ssn %p / stream %p: not calling StreamTcpReassembleHandleSegmentHandleData:"
                " p->payload_len %u, STREAMTCP_STREAM_FLAG_NOREASSEMBLY %s",
                ssn, stream, p->payload_len,
                (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ? "true" : "false");
    }

    /* in stream inline mode even if we have no data we call the reassembly
     * functions to handle EOF */
    if (dir == UPDATE_DIR_PACKET) {
        SCLogDebug("inline (%s) or PKT_PSEUDO_STREAM_END (%s)",
                StreamTcpInlineMode()?"true":"false",
                (p->flags & PKT_PSEUDO_STREAM_END) ?"true":"false");
        if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p, dir) < 0) {
            SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief get a segment from the pool
 *
 *  \retval seg Segment from the pool or NULL
 */
TcpSegment *StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx)
{
    TcpSegment *seg = (TcpSegment *) PoolThreadGetById(segment_thread_pool, ra_ctx->segment_thread_pool_id);
    SCLogDebug("seg we return is %p", seg);
    if (seg == NULL) {
        /* Increment the counter to show that we are not able to serve the
           segment request due to memcap limit */
        StatsIncr(tv, ra_ctx->counter_tcp_segment_memcap);
    } else {
        seg->next = NULL;
        seg->prev = NULL;

        memset(&seg->sbseg, 0, sizeof(seg->sbseg));
    }

    return seg;
}

/**
 *  \brief Trigger RAW stream reassembly
 *
 *  Used by AppLayerTriggerRawStreamReassembly to trigger RAW stream
 *  reassembly from the applayer, for example upon completion of a
 *  HTTP request.
 *
 *  It sets a flag in the stream so that the next Raw call will return
 *  the data.
 *
 *  \param ssn TcpSession
 */
void StreamTcpReassembleTriggerRawReassembly(TcpSession *ssn, int direction)
{
#ifdef DEBUG
    BUG_ON(ssn == NULL);
#endif

    if (ssn != NULL) {
        if (direction == STREAM_TOSERVER) {
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
        } else {
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
        }

        SCLogDebug("flagged ssn %p for immediate raw reassembly", ssn);
    }
}

#ifdef UNITTESTS
/** unit tests and it's support functions below */

#define SET_ISN(stream, setseq)             \
    (stream)->isn = (setseq);               \
    (stream)->base_seq = (setseq) + 1

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
    if (StreamingBufferCompareRawData(&stream->sb, stream_policy,(uint32_t)sp_size) == 0)
    {
        //PrintRawDataFp(stdout, stream_policy, sp_size);
        return 0;
    }
    return 1;
}

static int VALIDATE(TcpStream *stream, uint8_t *data, uint32_t data_len)
{
    if (StreamingBufferCompareRawData(&stream->sb,
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

#define MISSED_END                              \
    StreamTcpUTClearSession(&ssn);              \
    StreamTcpUTDeinit(ra_ctx);                  \
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
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ssn.client.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);

    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
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

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(40);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 10;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(5);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 30;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    SCFree(p);
    PASS;
}

static int StreamTcpReassembleTest34(void)
{
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ssn.client.os_policy = OS_POLICY_BSD;
    uint8_t packet[1460] = "";

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
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
    SET_ISN(&ssn.client, 857961230);

    p->tcph->th_seq = htonl(857961230);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 304;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(857961534);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(857963582);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(857960946);
    p->tcph->th_ack = htonl(31);
    p->payload_len = 1460;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    SCFree(p);
    PASS;
}

/** \test Test the bug 76 condition */
static int StreamTcpReassembleTest37(void)
{
    TcpSession ssn;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    uint8_t packet[1460] = "";
    PacketQueue pq;
    ThreadVars tv;

    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    memset(&pq,0,sizeof(PacketQueue));
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
    ssn.client.os_policy = OS_POLICY_BSD;

    p->tcph->th_seq = htonl(3061088537UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    ssn.client.last_ack = 3061091137UL;
    SET_ISN(&ssn.client, 3061091309UL);

    /* pre base_seq, so should be rejected */
    FAIL_IF (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) != -1);

    p->tcph->th_seq = htonl(3061089928UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    ssn.client.last_ack = 3061091137UL;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3061091319UL);
    p->tcph->th_ack = htonl(1729548549UL);
    p->payload_len = 1391;
    ssn.client.last_ack = 3061091137UL;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1);

    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    SCFree(p);
    PASS;
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
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (stt));
    memset(&tcph, 0, sizeof (TCPHdr));
    TcpSession *ssn = NULL;

    FLOW_INITIALIZE(&f);
    f.flags = FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->tcph = &tcph;

    FLOWLOCK_WRLOCK(&f);
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    /* handshake */
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = (TcpSession *)f.protoctx;

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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    /* response acking a request */
    p->tcph->th_ack = htonl(175);
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
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
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;
#if 0
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
#endif

    ret = 1;
end:
    StreamTcpSessionClear(ssn);
    StreamTcpUTDeinit(stt.ra_ctx);
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
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpInitConfig(TRUE);
    StreamTcpUTSetupSession(&ssn);

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
    if (f->alproto != ALPROTO_HTTP) {
        printf("app layer proto has not been detected (18): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpUTClearSession(&ssn);
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    FLOWLOCK_UNLOCK(f);
    UTHFreeFlow(f);
    return ret;
}

/** \test   Test the memcap incrementing/decrementing and memcap check */
static int StreamTcpReassembleTest44(void)
{
    StreamTcpInitConfig(TRUE);
    uint32_t memuse = SC_ATOMIC_GET(ra_memuse);
    StreamTcpReassembleIncrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(ra_memuse) != (memuse+500));
    StreamTcpReassembleDecrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(ra_memuse) != memuse);
    FAIL_IF(StreamTcpReassembleCheckMemcap(500) != 1);
    FAIL_IF(StreamTcpReassembleCheckMemcap((1 + memuse + stream_config.reassembly_memcap)) != 0);
    StreamTcpFreeConfig(TRUE);
    FAIL_IF(SC_ATOMIC_GET(ra_memuse) != 0);
    PASS;
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
    FAIL_IF(ssn.client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED);

    r = StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, &ssn.client, 201, payload, payload_size);
    FAIL_IF(r != 0);
    FAIL_IF(!(ssn.client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED));

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
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow *f = NULL;
    TCPHdr tcph;
    TcpSession ssn;
    ThreadVars tv;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpInitConfig(TRUE);
    StreamTcpUTSetupSession(&ssn);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);

    uint8_t httpbuf1[] = "GET /EVILSUFF HTTP/1.1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    SET_ISN(&ssn.server, 572799781UL);
    ssn.server.last_ack = 572799782UL;

    SET_ISN(&ssn.client, 4294967289UL);
    ssn.client.last_ack = 21;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    FAIL_IF(f == NULL);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;

    tcph.th_win = htons(5480);
    ssn.state = TCP_ESTABLISHED;
    TcpStream *s = NULL;
    uint8_t cnt = 0;

    for (cnt=0; cnt < httplen1; cnt++) {
        tcph.th_seq = htonl(ssn.client.isn + 1 + cnt);
        tcph.th_ack = htonl(572799782UL);
        tcph.th_flags = TH_ACK|TH_PUSH;
        p->tcph = &tcph;
        p->flowflags = FLOW_PKT_TOSERVER;
        p->payload = &httpbuf1[cnt];
        p->payload_len = 1;
        s = &ssn.client;

        FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1);

        p->flowflags = FLOW_PKT_TOCLIENT;
        p->payload = NULL;
        p->payload_len = 0;
        tcph.th_seq = htonl(572799782UL);
        tcph.th_ack = htonl(ssn.client.isn + 1 + cnt);
        tcph.th_flags = TH_ACK;
        p->tcph = &tcph;
        s = &ssn.server;

        FAIL_IF(StreamTcpReassembleHandleSegment(&tv, ra_ctx, &ssn, s, p, &pq) == -1);
    }

    FAIL_IF(f->alproto != ALPROTO_HTTP);

    StreamTcpUTClearSession(&ssn);
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    UTHFreeFlow(f);
    PASS;
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
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;
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
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(17);
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
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(17);
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
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 17, 'D', 5) == -1);
    ssn.client.next_seq = 22;
    p->tcph->th_seq = htonl(17);
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

    /* close the GAP and see if we properly reassemble and update base_seq */
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &ssn.client, 12, 'C', 5) == -1) {
        printf("failed to add segment 4: ");
        goto end;
    }
    ssn.client.next_seq = 22;

    p->tcph->th_seq = htonl(12);

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
    ssn.data_first_seen_dir = STREAM_TOSERVER;

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
    p->flowflags = FLOW_PKT_TOSERVER;

    FLOWLOCK_WRLOCK(f);
    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client,  2, stream_payload1, 2) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    ssn.client.next_seq = 4;

    int r = StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET);
    if (r < 0) {
        printf("StreamTcpReassembleAppLayer failed: ");
        goto end;
    }

    /* ssn.server.ra_app_base_seq should be isn here. */
    if (ssn.client.base_seq != 2 || ssn.client.base_seq != ssn.client.isn+1) {
        printf("expected ra_app_base_seq 1, got %u: ", ssn.client.base_seq);
        goto end;
    }

    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client,  4, stream_payload2, 3) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client,  7, stream_payload3, 12) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    ssn.client.next_seq = 19;

    r = StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET);
    if (r < 0) {
        printf("StreamTcpReassembleAppLayer failed: ");
        goto end;
    }

    FAIL_IF_NOT(STREAM_APP_PROGRESS(&ssn.client) == 17);

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

#include "tests/stream-tcp-reassemble.c"
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
    UtRegisterTest("StreamTcpReassembleTest39 -- app proto test",
                   StreamTcpReassembleTest39);
    UtRegisterTest("StreamTcpReassembleTest40 -- app proto test",
                   StreamTcpReassembleTest40);
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
    StreamTcpReassembleRawRegisterTests();
#endif /* UNITTESTS */
}
