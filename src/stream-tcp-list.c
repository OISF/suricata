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

/** \file
 *
 *  Segment list functions for insertions, overlap handling, removal and
 *  more.
 */

#include "suricata-common.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-list.h"
#include "util-streaming-buffer.h"
#include "util-print.h"

//static void PrintList2(TcpSegment *seg);

static void StreamTcpRemoveSegmentFromStream(TcpStream *stream, TcpSegment *seg);

static int check_overlap_different_data = 0;

void StreamTcpReassembleConfigEnableOverlapCheck(void)
{
    check_overlap_different_data = 1;
}

/*
 *  Inserts and overlap handling
 */


/** \internal
 *  \brief insert segment data into the streaming buffer
 *  \param seg segment to store stream offset in
 *  \param data segment data after overlap handling (if any)
 *  \param data_len data length
 */
static inline int InsertSegmentDataCustom(TcpStream *stream, TcpSegment *seg, uint8_t *data, uint16_t data_len)
{
    uint64_t stream_offset;
    uint16_t data_offset;

    if (likely(SEQ_GEQ(seg->seq, stream->base_seq))) {
        stream_offset = STREAM_BASE_OFFSET(stream) + (seg->seq - stream->base_seq);
        data_offset = 0;
    } else {
        /* segment is partly before base_seq */
        data_offset = stream->base_seq - seg->seq;
        stream_offset = STREAM_BASE_OFFSET(stream);
    }

    SCLogDebug("stream %p buffer %p, stream_offset %"PRIu64", "
               "data_offset %"PRIu16", SEQ %u BASE %u, data_len %u",
               stream, stream->sb, stream_offset,
               data_offset, seg->seq, stream->base_seq, data_len);
    BUG_ON(data_offset > data_len);
    if (data_len == data_offset) {
        SCReturnInt(0);
    }

    if (StreamingBufferInsertAt(stream->sb, &seg->sbseg,
                data + data_offset,
                data_len - data_offset,
                stream_offset) != 0) {
        SCReturnInt(-1);
    }
#ifdef DEBUG
    {
        const uint8_t *mydata;
        uint32_t mydata_len;
        uint64_t mydata_offset;
        StreamingBufferGetData(stream->sb, &mydata, &mydata_len, &mydata_offset);

        SCLogDebug("stream %p seg %p data in buffer %p of len %u and offset %u",
                stream, seg, stream->sb, mydata_len, (uint)mydata_offset);
        //PrintRawDataFp(stdout, mydata, mydata_len);
    }
#endif
    SCReturnInt(0);
}

/** \internal
 *  \brief insert the segment into the proper place in the list
 *         don't worry about the data or overlaps
 *
 *         If seq is equal to list seq, keep sorted by biggest segment_len
 *         1. seg 123 len 12
 *         2. seg 123 len 14
 *         3. seg 124 len 1
 * XXX FIXME TODO this list isn't yet sorted this way.
 *
 *  \retval 1 inserted with overlap detected
 *  \retval 0 inserted, no overlap
 *  \retval -1 error
 */
static int DoInsertSegment (TcpStream *stream, TcpSegment *seg, Packet *p)
{
    if (unlikely(stream->sb == NULL)) {
        stream->sb = StreamingBufferInit(&stream_config.sbcnf);
        if (stream->sb == NULL) {
            return -1;
        }
    }

    /* before our base_seq we don't insert it in our list */
    if (SEQ_LEQ((seg->seq + TCP_SEG_LEN(seg)), stream->base_seq))
    {
        SCLogDebug("not inserting: SEQ+payload %"PRIu32", last_ack %"PRIu32", "
                "base_seq %"PRIu32, (seg->seq + TCP_SEG_LEN(seg)),
                stream->last_ack, stream->base_seq);
        StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ);
        return -1;
    }

    /* fast track */
    if (stream->seg_list == NULL) {
        SCLogDebug("empty list, inserting seg %p seq %" PRIu32 ", "
                   "len %" PRIu32 "", seg, seg->seq, TCP_SEG_LEN(seg));
        stream->seg_list = seg;
        seg->prev = NULL;
        stream->seg_list_tail = seg;
        return 0;
    }

    /* insert the segment in the stream list using this fast track, if seg->seq
       is equal or higher than stream->seg_list_tail.*/
    if (SEQ_GEQ(seg->seq, (stream->seg_list_tail->seq +
                    TCP_SEG_LEN(stream->seg_list_tail))))
    {
        SCLogDebug("seg beyond list tail, append");
        stream->seg_list_tail->next = seg;
        seg->prev = stream->seg_list_tail;
        stream->seg_list_tail = seg;
        return 0;
    }

    /* walk the list to see where we can insert the segment.
     * Check if a segment overlaps with us, if so we return 1 to indicate
     * to the caller that we need to handle overlaps. */
    TcpSegment *list_seg;
    for (list_seg = stream->seg_list; list_seg != NULL; list_seg = list_seg->next)
    {
        if (SEQ_LT(seg->seq, list_seg->seq)) {
            if (list_seg->prev != NULL) {
                list_seg->prev->next = seg;
            } else {
                stream->seg_list = seg;
            }
            seg->prev = list_seg->prev;
            seg->next = list_seg;
            list_seg->prev = seg;

            SCLogDebug("inserted %u before %p seq %u", seg->seq, list_seg, list_seg->seq);

            if (seg->prev != NULL) {
                SCLogDebug("previous %u", seg->prev->seq);
            }
            if (seg->next != NULL) {
                SCLogDebug("next %u", seg->next->seq);
            }
            if (seg->prev != NULL && SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg->prev), seg->seq)) {
                SCLogDebug("seg inserted with overlap (before)");
                return 1;
            }
            else if (SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg), seg->next->seq)) {
                SCLogDebug("seg inserted with overlap (after)");
                return 1;
            }

            return 0;
        }
    }
    /* if we got here we didn't insert. Append */
    seg->prev = stream->seg_list_tail;
    stream->seg_list_tail->next = seg;
    stream->seg_list_tail = seg;

    if (seg->prev != NULL && SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg->prev), seg->seq)) {
        SCLogDebug("seg inserted with overlap (before)");
        return 1;
    }

    SCLogDebug("default: append");
    return 0;
}

/** \internal
 *  \brief handle overlap per list segment
 *
 *  For a list segment handle the overlap according to the policy.
 *
 *  The 'buf' parameter points to the memory that will be inserted into
 *  the stream after the overlap checks are complete. As it will
 *  unconditionally overwrite whats in the stream now, the overlap
 *  policies are applied to this buffer. It starts with the 'new' data,
 *  so when the policy states 'old' data has to be used, 'buf' is
 *  updated to contain the 'old' data here.
 *
 *  \param buf stack allocated buffer sized p->payload_len that will be
 *             inserted into the stream buffer
 */
static int DoHandleDataOverlap(TcpStream *stream, TcpSegment *list, TcpSegment *seg, uint8_t *buf, Packet *p)
{
    SCLogDebug("handle overlap for segment %p seq %u len %u re %u, "
            "list segment %p seq %u len %u re %u", seg, seg->seq, p->payload_len, SEG_SEQ_RIGHT_EDGE(seg),
            list, list->seq, TCP_SEG_LEN(list), SEG_SEQ_RIGHT_EDGE(list));

    int data_is_different = 0;
    int use_new_data = 0;

    if (StreamTcpInlineMode()) {
        SCLogDebug("inline mode");
        if (StreamTcpInlineSegmentCompare(stream, p, list) != 0) {
            SCLogDebug("already accepted data not the same as packet data, rewrite packet");
            StreamTcpInlineSegmentReplacePacket(stream, p, list);
            data_is_different = 1;

            /* in inline mode we check for different data unconditionally,
             * but setting events still depends on config */
            if (check_overlap_different_data) {
                StreamTcpSetEvent(p, STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA);
            }
        }

    /* IDS mode */
    } else {
        if (check_overlap_different_data) {
            if (StreamTcpInlineSegmentCompare(stream, p, list) != 0) {
                SCLogDebug("data is different from what is in the list");
                data_is_different = 1;
                StreamTcpSetEvent(p, STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA);
            }
        } else {
            /* if we're not checking, assume it's different */
            data_is_different = 1;
        }

        /* apply overlap policies */

        if (stream->os_policy == OS_POLICY_LAST) {
            /* buf will start with LAST data (from the segment),
             * so if policy is LAST we're now done here. */
            return 0;
        }

        /* start at the same seq */
        if (SEQ_EQ(seg->seq, list->seq)) {
            SCLogDebug("seg starts at list segment");

            if (SEQ_LT(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                SCLogDebug("seg ends before list end, end overlapped by list");
            } else {
                if (SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                    SCLogDebug("seg ends beyond list end, list overlapped and more");
                    switch (stream->os_policy) {
                        case OS_POLICY_LINUX:
                            if (data_is_different) {
                                use_new_data = 1;
                            }
                            break;
                    }
                } else {
                    SCLogDebug("full overlap");
                }

                switch (stream->os_policy) {
                    case OS_POLICY_OLD_LINUX:
                    case OS_POLICY_SOLARIS:
                    case OS_POLICY_HPUX11:
                        if (data_is_different) {
                            use_new_data = 1;
                        }
                        break;
                }
            }

            /* new seg starts before list segment */
        } else if (SEQ_LT(seg->seq, list->seq)) {
            SCLogDebug("seg starts before list segment");

            if (SEQ_LT(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                SCLogDebug("seg ends before list end, end overlapped by list");
            } else {
                if (SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                    SCLogDebug("seg starts before and fully overlaps list and beyond");
                } else {
                    SCLogDebug("seg starts before and fully overlaps list");
                }

                switch (stream->os_policy) {
                    case OS_POLICY_SOLARIS:
                    case OS_POLICY_HPUX11:
                        if (data_is_different) {
                            use_new_data = 1;
                        }
                        break;
                }
            }

            switch (stream->os_policy) {
                case OS_POLICY_BSD:
                case OS_POLICY_HPUX10:
                case OS_POLICY_IRIX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_LINUX:
                case OS_POLICY_MACOS:
                    if (data_is_different) {
                        use_new_data = 1;
                    }
                    break;
            }

            /* new seg starts after list segment */
        } else { //if (SEQ_GT(seg->seq, list->seq)) {
            SCLogDebug("seg starts after list segment");

            if (SEQ_EQ(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                SCLogDebug("seg after and is fully overlapped by list");
            } else if (SEQ_GT(SEG_SEQ_RIGHT_EDGE(seg), SEG_SEQ_RIGHT_EDGE(list))) {
                SCLogDebug("seg starts after list and ends after list");

                switch (stream->os_policy) {
                    case OS_POLICY_SOLARIS:
                    case OS_POLICY_HPUX11:
                        if (data_is_different) {
                            use_new_data = 1;
                        }
                        break;
                }
            } else {
                SCLogDebug("seg starts after list and ends before list end");

            }
        }
    }

    SCLogDebug("data_is_different %s, use_new_data %s",
        data_is_different ? "yes" : "no",
        use_new_data ? "yes" : "no");

    /* if the data is different and we don't want to use the new (seg)
     * data, we have to update buf with the list data */
    if (data_is_different && !use_new_data) {
        /* we need to copy list into seg */
        uint16_t list_offset = 0;
        uint16_t seg_offset = 0;
        uint32_t list_len;
        uint16_t seg_len = p->payload_len;
        uint32_t list_seq = list->seq;

        const uint8_t *list_data;
        StreamingBufferSegmentGetData(stream->sb, &list->sbseg, &list_data, &list_len);
        if (list_data == NULL || list_len == 0)
            return 0;
        BUG_ON(list_len > USHRT_MAX);

        /* if list seg is partially before base_seq, list_len (from stream) and
         * TCP_SEG_LEN(list) will not be the same */
        if (SEQ_GEQ(list->seq, stream->base_seq)) {
            ;
        } else {
            list_seq = stream->base_seq;
            list_len = SEG_SEQ_RIGHT_EDGE(list) - stream->base_seq;
        }

        if (SEQ_LT(seg->seq, list_seq)) {
            seg_offset = list_seq - seg->seq;
            seg_len -= seg_offset;
        } else if (SEQ_GT(seg->seq, list_seq)) {
            list_offset = seg->seq - list_seq;
            list_len -= list_offset;
        }

        if (SEQ_LT(seg->seq + seg_offset + seg_len, list_seq + list_offset + list_len)) {
            list_len -= (list_seq + list_offset + list_len) - (seg->seq + seg_offset + seg_len);
        }
        SCLogDebug("here goes nothing: list %u %u, seg %u %u", list_offset, list_len, seg_offset, seg_len);

        //PrintRawDataFp(stdout, list_data + list_offset, list_len);
        //PrintRawDataFp(stdout, buf + seg_offset, seg_len);

        memcpy(buf + seg_offset, list_data + list_offset, list_len);
        //PrintRawDataFp(stdout, buf, p->payload_len);
    }
    return 0;
}

#define MAX_IP_DATA (uint32_t)(65536 - 40) // min ip header and min tcp header

/** \internal
 *  \brief walk segment list backwards to see if there are overlaps
 *
 *  Walk back from the current segment which is already in the list.
 *  We walk until we can't possibly overlap anymore.
 */
static int DoHandleDataCheckBackwards(TcpStream *stream, TcpSegment *seg, uint8_t *buf, Packet *p)
{
    SCLogDebug("check list backwards: insert data for segment %p seq %u len %u re %u",
            seg, seg->seq, TCP_SEG_LEN(seg), SEG_SEQ_RIGHT_EDGE(seg));

    TcpSegment *list = seg->prev;
    do {
        int overlap = 0;
        if (SEQ_LEQ(SEG_SEQ_RIGHT_EDGE(list), stream->base_seq)) {
            // segment entirely before base_seq
            ;
        } else if (SEQ_LEQ(list->seq + MAX_IP_DATA, seg->seq)) {
            SCLogDebug("list segment too far to the left, no more overlap will be found");
            break;
        } else if (SEQ_GT(SEG_SEQ_RIGHT_EDGE(list), seg->seq)) {
            overlap = 1;
        }

        SCLogDebug("(back) list seg %u len %u re %u overlap? %s", list->seq, TCP_SEG_LEN(list),
                SEG_SEQ_RIGHT_EDGE(list), overlap ? "yes" : "no");

        if (overlap) {
            DoHandleDataOverlap(stream, list, seg, buf, p);
        }

        list = list->prev;
    } while (list != NULL);

    return 0;
}

/** \internal
 *  \brief walk segment list in forward direction to see if there are overlaps
 *
 *  Walk forward from the current segment which is already in the list.
 *  We walk until the next segs start with a SEQ beyond our right edge.
 */
static int DoHandleDataCheckForward(TcpStream *stream, TcpSegment *seg, uint8_t *buf, Packet *p)
{
    uint32_t seg_re = SEG_SEQ_RIGHT_EDGE(seg);

    SCLogDebug("check list forward: insert data for segment %p seq %u len %u re %u",
            seg, seg->seq, TCP_SEG_LEN(seg), seg_re);

    TcpSegment *list = seg->next;
    do {
        int overlap = 0;
        if (SEQ_GT(seg_re, list->seq))
            overlap = 1;
        else if (SEQ_LEQ(seg_re, list->seq)) {
            SCLogDebug("list segment %u too far ahead, "
                    "no more overlaps can happen", list->seq);
            break;
        }

        SCLogDebug("(fwd) list seg %u len %u re %u overlap? %s", list->seq,
                TCP_SEG_LEN(list), SEG_SEQ_RIGHT_EDGE(list), overlap ? "yes" : "no");

        if (overlap) {
            DoHandleDataOverlap(stream, list, seg, buf, p);
        }

        list = list->next;
    } while (list != NULL);

    return 0;
}

static int DoHandleData(TcpStream *stream, TcpSegment *seg, Packet *p)
{
    SCLogDebug("insert data for segment %p seq %u len %u re %u",
            seg, seg->seq, TCP_SEG_LEN(seg), SEG_SEQ_RIGHT_EDGE(seg));

    /* create temporary buffer to contain the data we will insert. Overlap
     * handling may update it. By using this we don't have to track whether
     * parts of the data are already inserted or not. */
    uint8_t buf[p->payload_len];
    memcpy(buf, p->payload, p->payload_len);

    /* new list head  */
    if (seg->next != NULL && seg->prev == NULL) {
        DoHandleDataCheckForward(stream, seg, buf, p);

    /* new list tail */
    } else if (seg->next == NULL && seg->prev != NULL) {
        DoHandleDataCheckBackwards(stream, seg, buf, p);

    /* middle of the list */
    } else if (seg->next != NULL && seg->prev != NULL) {
        DoHandleDataCheckBackwards(stream, seg, buf, p);
        DoHandleDataCheckForward(stream, seg, buf, p);
    }

    /* insert the temp buffer now that we've (possibly) updated
     * it to account for the overlap policies */
    if (InsertSegmentDataCustom(stream, seg, buf, p->payload_len) < 0) {
        return -1;
    }

    return 0;

}

/**
 *  \retval -1 segment not inserted
 *
 *  \param seg segment, this function takes total ownership
 *
 *  In case of error, this function returns the segment to the pool
 */
int StreamTcpReassembleInsertSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpStream *stream, TcpSegment *seg, Packet *p, uint32_t pkt_seq, uint8_t *pkt_data, uint16_t pkt_datalen)
{
    /* insert segment into list. Note: doesn't handle the data */
#ifdef DEBUG
    SCLogDebug("pre insert");
    PrintList(stream->seg_list);
#endif

    int r = DoInsertSegment (stream, seg, p);

#ifdef DEBUG
    SCLogDebug("post insert");
    PrintList(stream->seg_list);
#endif

    if (likely(r == 0)) {
        /* no overlap, straight data insert */
        int res = InsertSegmentDataCustom(stream, seg, pkt_data, pkt_datalen);
        if (res < 0) {
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            SCReturnInt(-1);
        }

    } else if (r == 1) {
        /* now let's consider the data in the overlap case */
        int res = DoHandleData(stream, seg, p);
        if (res < 0) {
            StreamTcpRemoveSegmentFromStream(stream, seg);
            StreamTcpSegmentReturntoPool(seg);
            SCReturnInt(-1);
        }

    } else if (r < 0) {
        StreamTcpSegmentReturntoPool(seg);
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}


/*
 * Pruning & removal
 */


static inline int SegmentInUse(TcpSession *ssn, TcpStream *stream, TcpSegment *seg)
{
    if (stream == &ssn->client && ssn->toserver_smsg_head != NULL) {
        /* not (seg is entirely before first smsg, skip) */
        if (!(SEQ_LEQ(seg->seq + TCP_SEG_LEN(seg), ssn->toserver_smsg_head->seq))) {
            SCReturnInt(1);
        }
    } else if (stream == &ssn->server && ssn->toclient_smsg_head != NULL) {
        /* not (seg is entirely before first smsg, skip) */
        if (!(SEQ_LEQ(seg->seq + TCP_SEG_LEN(seg), ssn->toclient_smsg_head->seq))) {
            SCReturnInt(1);
        }
    }

    /* if proto detect isn't done, we're not returning */
    if (!(stream->flags & STREAMTCP_STREAM_FLAG_GAP)) {
        if (!(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream))) {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}


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
    if (SegmentInUse(ssn, stream, seg)) {
        SCReturnInt(0);
    }

    if (!(StreamingBufferSegmentIsBeforeWindow(stream->sb, &seg->sbseg))) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

static inline uint64_t GetLeftEdge(TcpSession *ssn, TcpStream *stream)
{
    int use_app = 1;
    int use_raw = 1;

    uint64_t left_edge = 0;
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

    if (use_app && use_raw) {
        left_edge = MIN(stream->app_progress, stream->raw_progress);
        SCLogDebug("left_edge %"PRIu64", using both app:%"PRIu64", raw:%"PRIu64,
                left_edge, stream->app_progress, stream->raw_progress);
    } else if (use_app) {
        left_edge = stream->app_progress;
        SCLogDebug("left_edge %"PRIu64", using app:%"PRIu64,
                left_edge, stream->app_progress);
    } else if (use_raw) {
        left_edge = stream->raw_progress;
        SCLogDebug("left_edge %"PRIu64", using raw:%"PRIu64,
                left_edge, stream->raw_progress);
    } else {
        SCLogDebug("left_edge 0, none");
    }

    if (left_edge > 0) {
        /* we know left edge based on the progress values now,
         * lets adjust it to make sure in-use segments still have
         * data */
        TcpSegment *seg;
        for (seg = stream->seg_list; seg != NULL; seg = seg->next)
        {
            if (TCP_SEG_OFFSET(seg) > left_edge) {
                SCLogDebug("seg beyond left_edge, we're done");
                break;
            }

            if (SegmentInUse(ssn, stream, seg)) {
                left_edge = TCP_SEG_OFFSET(seg);
                SCLogDebug("in-use seg before left_edge, adjust to %"PRIu64" and bail", left_edge);
                break;
            }
        }
    }

    return left_edge;
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

/** \brief Remove idle TcpSegments from TcpSession
 *
 *  \param f flow
 *  \param flags direction flags
 */
void StreamTcpPruneSession(Flow *f, uint8_t flags)
{
    SCEnter();

    if (f == NULL || f->protoctx == NULL) {
        SCReturn;
    }

    TcpSession *ssn = f->protoctx;
    TcpStream *stream = NULL;

    if (flags & STREAM_TOSERVER) {
        stream = &ssn->client;
    } else if (flags & STREAM_TOCLIENT) {
        stream = &ssn->server;
    } else {
        SCReturn;
    }

    uint64_t left_edge = GetLeftEdge(ssn, stream);
    if (left_edge) {
        /* in IPS mode we consider the chunk_size when sliding */
        if (StreamTcpInlineMode() == TRUE) {
            uint32_t chunk_size = (flags & STREAM_TOSERVER) ?
                stream_config.reassembly_toserver_chunk_size :
                stream_config.reassembly_toclient_chunk_size;
            if ((uint64_t)chunk_size >= left_edge) {
                left_edge = 0;
            } else {
                left_edge -= chunk_size;
            }
        }

        if (left_edge > STREAM_BASE_OFFSET(stream)) {
            uint32_t slide = left_edge - STREAM_BASE_OFFSET(stream);
            SCLogDebug("buffer sliding %u to offset %"PRIu64, slide, left_edge);
            StreamingBufferSlideToOffset(stream->sb, left_edge);
            stream->base_seq += slide;
            SCLogDebug("stream base_seq %u at stream offset %"PRIu64,
                    stream->base_seq, STREAM_BASE_OFFSET(stream));
        }
    }

    /* loop through the segments and fill one or more msgs */
    TcpSegment *seg = stream->seg_list;

    while (seg != NULL)
    {
        SCLogDebug("seg %p, SEQ %"PRIu32", LEN %"PRIu16", SUM %"PRIu32", FLAGS %02x",
                seg, seg->seq, TCP_SEG_LEN(seg),
                (uint32_t)(seg->seq + TCP_SEG_LEN(seg)), seg->flags);

        if (StreamTcpReturnSegmentCheck(f, ssn, stream, seg) == 0) {
            SCLogDebug("not removing segment");
            break;
        }

        TcpSegment *next_seg = seg->next;
        StreamTcpRemoveSegmentFromStream(stream, seg);
        StreamTcpSegmentReturntoPool(seg);
        seg = next_seg;
        SCLogDebug("removed segment");
        continue;
    }
#ifdef DEBUG
    PrintList(stream->seg_list);
#endif
    SCReturn;
}

/*
 *  Utils
 */

#if 0
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
                    seg->seq, TCP_SEG_LEN(seg), seg, seg->prev, seg->next);

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

        next_seq = seg->seq + TCP_SEG_LEN(seg);
        SCLogDebug("next_seq is now %"PRIu32"", next_seq);
        prev_seg = seg;
        seg = seg->next;
    }
}
#endif

void PrintList(TcpSegment *seg)
{
    TcpSegment *prev_seg = NULL;
//    TcpSegment *head_seg = seg;

    if (seg == NULL)
        return;

    uint32_t next_seq = seg->seq;

    while (seg != NULL) {
        if (SEQ_LT(next_seq,seg->seq)) {
            SCLogDebug("missing segment(s) for %" PRIu32 " bytes of data",
                        (seg->seq - next_seq));
        }

        SCLogDebug("seg %10"PRIu32" len %" PRIu16 ", seg %p, prev %p, next %p, flags 0x%02x",
                    seg->seq, TCP_SEG_LEN(seg), seg, seg->prev, seg->next, seg->flags);

        if (seg->prev != NULL && SEQ_LT(seg->seq,seg->prev->seq)) {
            /* check for SEQ_LT cornercase where a - b is exactly 2147483648,
             * which makes the marco return TRUE in both directions. This is
             * a hack though, we're going to check next how we end up with
             * a segment list with seq differences that big */
            if (!(SEQ_LT(seg->prev->seq,seg->seq))) {
                SCLogDebug("inconsistent list: SEQ_LT(seg->seq,seg->prev->seq)) == "
                        "TRUE, seg->seq %" PRIu32 ", seg->prev->seq %" PRIu32 "",
                        seg->seq, seg->prev->seq);
//                PrintList2(head_seg);
//                abort();
            }
        }

        if (SEQ_LT(seg->seq,next_seq)) {
            SCLogDebug("inconsistent list: SEQ_LT(seg->seq,next_seq)) == TRUE, "
                       "seg->seq %" PRIu32 ", next_seq %" PRIu32 "", seg->seq,
                       next_seq);
//            PrintList2(head_seg);
//            abort();
        }

        if (prev_seg != seg->prev) {
            SCLogDebug("inconsistent list: prev_seg %p != seg->prev %p",
                       prev_seg, seg->prev);
//            PrintList2(head_seg);
            abort();
        }

        next_seq = seg->seq + TCP_SEG_LEN(seg);
        SCLogDebug("next_seq is now %"PRIu32"", next_seq);
        prev_seg = seg;
        seg = seg->next;
    }
}

/*
 *  unittests
 */

#ifdef UNITTESTS
#include "tests/stream-tcp-list.c"
#endif
