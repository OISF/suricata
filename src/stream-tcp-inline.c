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
 * \author Victor Julien <victor@inliniac.net>
 *
 *  Functions for the "inline mode" of the stream engine.
 */

#include "suricata-common.h"
#include "stream-tcp-private.h"
#include "stream-tcp-inline.h"

#include "util-memcmp.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

/** defined in stream-tcp-reassemble.c */
extern int stream_inline;

/**
 *  \brief See if stream engine is operating in inline mode
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int StreamTcpInlineMode(void)
{
    return stream_inline;
}

/**
 *  \brief Compare the shared data portion of two segments
 *
 *  If no data is shared, 0 will be returned.
 *
 *  \param seg1 first segment
 *  \param seg2 second segment
 *
 *  \retval 0 shared data is the same (or no data is shared)
 *  \retval 1 shared data is different
 */
int StreamTcpInlineSegmentCompare(TcpStream *stream, Packet *p, TcpSegment *seg)
{
    SCEnter();

    if (p == NULL || seg == NULL) {
        SCReturnInt(0);
    }

    const uint8_t *seg_data;
    uint32_t seg_datalen;
    StreamingBufferSegmentGetData(stream->sb, &seg->sbseg, &seg_data, &seg_datalen);

    const uint32_t pkt_seq = TCP_GET_SEQ(p);

    if (SEQ_EQ(pkt_seq, seg->seq) && p->payload_len == seg_datalen) {
        int r = SCMemcmp(p->payload, seg_data, seg_datalen);
        SCReturnInt(r);
    } else if (SEQ_GT(pkt_seq, (seg->seq + seg_datalen))) {
        SCReturnInt(0);
    } else if (SEQ_GT(seg->seq, (pkt_seq + p->payload_len))) {
        SCReturnInt(0);
    } else {
        SCLogDebug("p %u (%u), seg2 %u (%u)", pkt_seq,
                p->payload_len, seg->seq, seg_datalen);

        uint32_t pkt_end = pkt_seq + p->payload_len;
        uint32_t seg_end = seg->seq + seg_datalen;
        SCLogDebug("pkt_end %u, seg_end %u", pkt_end, seg_end);

        /* get the minimal seg*_end */
        uint32_t end = (SEQ_GT(pkt_end, seg_end)) ? seg_end : pkt_end;
        /* and the max seq */
        uint32_t seq = (SEQ_LT(pkt_seq, seg->seq)) ? seg->seq : pkt_seq;

        SCLogDebug("seq %u, end %u", seq, end);

        uint16_t pkt_off = seq - pkt_seq;
        uint16_t seg_off = seq - seg->seq;
        SCLogDebug("pkt_off %u, seg_off %u", pkt_off, seg_off);

        uint32_t range = end - seq;
        SCLogDebug("range %u", range);
        BUG_ON(range > 65536);

        if (range) {
            int r = SCMemcmp(p->payload + pkt_off, seg_data + seg_off, range);
            SCReturnInt(r);
        }
        SCReturnInt(0);
    }
}

/**
 *  \brief Replace (part of) the payload portion of a packet by the data
 *         in a TCP segment
 *
 *  \param p Packet
 *  \param seg TCP segment
 *
 *  \todo What about reassembled fragments?
 *  \todo What about unwrapped tunnel packets?
 */
void StreamTcpInlineSegmentReplacePacket(TcpStream *stream, Packet *p, TcpSegment *seg)
{
    SCEnter();

    uint32_t pseq = TCP_GET_SEQ(p);
    uint32_t tseq = seg->seq;

    /* check if segment is within the packet */
    if (tseq + TCP_SEG_LEN(seg) < pseq) {
        SCReturn;
    } else if (pseq + p->payload_len < tseq) {
        SCReturn;
    }

    const uint8_t *seg_data;
    uint32_t seg_datalen;
    StreamingBufferSegmentGetData(stream->sb, &seg->sbseg, &seg_data, &seg_datalen);

    uint32_t pend = pseq + p->payload_len;
    uint32_t tend = tseq + seg_datalen;
    SCLogDebug("pend %u, tend %u", pend, tend);

    /* get the minimal seg*_end */
    uint32_t end = (SEQ_GT(pend, tend)) ? tend : pend;
    /* and the max seq */
    uint32_t seq = (SEQ_LT(pseq, tseq)) ? tseq : pseq;
    SCLogDebug("seq %u, end %u", seq, end);

    uint16_t poff = seq - pseq;
    uint16_t toff = seq - tseq;
    SCLogDebug("poff %u, toff %u", poff, toff);

    uint32_t range = end - seq;
    SCLogDebug("range %u", range);
    BUG_ON(range > 65536);

    if (range) {
        /* update the packets payload. As payload is a ptr to either
         * p->pkt or p->ext_pkt that is updated as well */
        memcpy(p->payload+poff, seg_data+toff, range);

        /* flag as modified so we can reinject / replace after
         * recalculating the checksum */
        p->flags |= PKT_STREAM_MODIFIED;
    }
}

#ifdef UNITTESTS

#include "stream-tcp-util.h"

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

#define INLINE_START(isn)                      \
    Packet *p;                                  \
    TcpReassemblyThreadCtx *ra_ctx = NULL;      \
    TcpSession ssn;                             \
    ThreadVars tv;                              \
    memset(&tv, 0, sizeof(tv));                 \
    \
    StreamTcpUTInit(&ra_ctx);                   \
    StreamTcpUTInitInline();                    \
    \
    StreamTcpUTSetupSession(&ssn);              \
    StreamTcpUTSetupStream(&ssn.server, (isn)); \
    StreamTcpUTSetupStream(&ssn.client, (isn)); \
    \
    TcpStream *stream = &ssn.client;

#define INLINE_END                             \
    StreamTcpUTClearSession(&ssn);              \
    StreamTcpUTDeinit(ra_ctx);                  \
    PASS

#define INLINE_STEP(rseq, seg, seglen, buf, buflen, packet, packetlen) \
    p = UTHBuildPacketReal((uint8_t *)(seg), (seglen), IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);    \
    FAIL_IF(p == NULL); \
    p->tcph->th_seq = htonl(stream->isn + (rseq)); \
    p->tcph->th_ack = htonl(31);  \
    FAIL_IF (StreamTcpReassembleHandleSegmentHandleData(&tv, ra_ctx, &ssn, stream, p) < 0);   \
    FAIL_IF (memcmp(p->payload, packet, MIN((packetlen),p->payload_len)) != 0); \
    UTHFreePacket(p);   \
    FAIL_IF(!(VALIDATE(stream, (uint8_t *)(buf), (buflen))));

/** \test full overlap */
static int StreamTcpInlineTest01(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "AAC", 3, "AAC", 3, "AAC", 3);
    INLINE_STEP(1, "ABC", 3, "AAC", 3, "AAC", 3);
    INLINE_END;
}

/** \test full overlap */
static int StreamTcpInlineTest02(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "ABCDE", 5, "ABCDE", 5, "ABCDE", 5);
    INLINE_STEP(2, "xxx", 3, "ABCDE", 5, "BCD", 3);
    INLINE_END;
}

/** \test partial overlap */
static int StreamTcpInlineTest03(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "ABCDE", 5, "ABCDE", 5, "ABCDE", 5);
    INLINE_STEP(3, "xxxxx", 5, "ABCDExx", 7, "CDExx", 5);
    INLINE_END;
}

/** \test partial overlap */
static int StreamTcpInlineTest04(void)
{
    INLINE_START(0);
    INLINE_STEP(3, "ABCDE", 5, "\0\0ABCDE", 7, "ABCDE", 5);
    INLINE_STEP(1, "xxxxx", 5, "xxABCDE", 7, "xxABC", 5);
    INLINE_END;
}

/** \test no overlap */
static int StreamTcpInlineTest05(void)
{
    INLINE_START(0);
    INLINE_STEP(8, "ABCDE", 5, "\0\0\0\0\0\0\0ABCDE", 12, "ABCDE", 5);
    INLINE_STEP(1, "xxxxx", 5, "xxxxx\0\0ABCDE", 12, "xxxxx", 5);
    INLINE_END;
}

/** \test multiple overlaps */
static int StreamTcpInlineTest06(void)
{
    INLINE_START(0);
    INLINE_STEP(2, "A", 1, "\0A", 2, "A", 1);
    INLINE_STEP(4, "A", 1, "\0A\0A", 4, "A", 1);
    INLINE_STEP(6, "A", 1, "\0A\0A\0A", 6, "A", 1);
    INLINE_STEP(8, "A", 1, "\0A\0A\0A\0A", 8, "A", 1);
    INLINE_STEP(1, "xxxxxxxxx", 9, "xAxAxAxAx", 9, "xAxAxAxAx", 9);
    INLINE_END;
}

/** \test overlap, data not different */
static int StreamTcpInlineTest07(void)
{
    INLINE_START(0);
    INLINE_STEP(3, "ABCDE", 5, "\0\0ABCDE", 7, "ABCDE", 5);
    INLINE_STEP(1, "XXABC", 5, "XXABCDE", 7, "XXABC", 5);
    INLINE_END;
}

static int StreamTcpInlineTest08(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "AAAAA", 5, "AAAAA", 5, "AAAAA", 5);
    INLINE_STEP(1, "BBBBB", 5, "AAAAA", 5, "AAAAA", 5);
    INLINE_STEP(1, "CCCCCCCCCC", 10, "AAAAACCCCC", 10, "AAAAACCCCC", 10);
    INLINE_STEP(10, "X", 1, "AAAAACCCCC", 10, "C", 1);
    INLINE_STEP(11, "X", 1, "AAAAACCCCCX", 11, "X", 1);
    INLINE_END;
}

#endif /* UNITTESTS */

void StreamTcpInlineRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpInlineTest01", StreamTcpInlineTest01);
    UtRegisterTest("StreamTcpInlineTest02", StreamTcpInlineTest02);
    UtRegisterTest("StreamTcpInlineTest03", StreamTcpInlineTest03);
    UtRegisterTest("StreamTcpInlineTest04", StreamTcpInlineTest04);
    UtRegisterTest("StreamTcpInlineTest05", StreamTcpInlineTest05);
    UtRegisterTest("StreamTcpInlineTest06", StreamTcpInlineTest06);
    UtRegisterTest("StreamTcpInlineTest07", StreamTcpInlineTest07);
    UtRegisterTest("StreamTcpInlineTest08", StreamTcpInlineTest08);
#endif /* UNITTESTS */
}

