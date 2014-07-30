/* Copyright (C) 2007-2011 Open Information Security Foundation
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
int StreamTcpInlineSegmentCompare(TcpSegment *seg1, TcpSegment *seg2)
{
    SCEnter();

    if (seg1 == NULL || seg2 == NULL) {
        SCReturnInt(0);
    }

    if (SEQ_EQ(seg1->seq, seg2->seq) && seg1->payload_len == seg2->payload_len) {
        int r = SCMemcmp(seg1->payload, seg2->payload, seg1->payload_len);
#if 0
        if (r) {
            PrintRawDataFp(stdout,seg1->payload,seg1->payload_len);
            PrintRawDataFp(stdout,seg2->payload,seg2->payload_len);
        }
#endif
        SCReturnInt(r);
    } else if (SEQ_GT(seg1->seq, (seg2->seq + seg2->payload_len))) {
        SCReturnInt(0);
    } else if (SEQ_GT(seg2->seq, (seg1->seq + seg1->payload_len))) {
        SCReturnInt(0);
    } else {
        SCLogDebug("seg1 %u (%u), seg2 %u (%u)", seg1->seq,
                seg1->payload_len, seg2->seq, seg2->payload_len);

        uint32_t seg1_end = seg1->seq + seg1->payload_len;
        uint32_t seg2_end = seg2->seq + seg2->payload_len;
        SCLogDebug("seg1_end %u, seg2_end %u", seg1_end, seg2_end);
#if 0
        SCLogDebug("seg1");
        PrintRawDataFp(stdout,seg1->payload,seg1->payload_len);
        SCLogDebug("seg2");
        PrintRawDataFp(stdout,seg2->payload,seg2->payload_len);
#endif
        /* get the minimal seg*_end */
        uint32_t end = (SEQ_GT(seg1_end, seg2_end)) ? seg2_end : seg1_end;
        /* and the max seq */
        uint32_t seq = (SEQ_LT(seg1->seq, seg2->seq)) ? seg2->seq : seg1->seq;

        SCLogDebug("seq %u, end %u", seq, end);

        uint16_t seg1_off = seq - seg1->seq;
        uint16_t seg2_off = seq - seg2->seq;
        SCLogDebug("seg1_off %u, seg2_off %u", seg1_off, seg2_off);

        uint32_t range = end - seq;
        SCLogDebug("range %u", range);
        BUG_ON(range > 65536);

        if (range) {
            int r = SCMemcmp(seg1->payload+seg1_off, seg2->payload+seg2_off, range);
#if 0
            if (r) {
                PrintRawDataFp(stdout,seg1->payload+seg1_off,range);
                PrintRawDataFp(stdout,seg2->payload+seg2_off,range);

                PrintRawDataFp(stdout,seg1->payload,seg1->payload_len);
                PrintRawDataFp(stdout,seg2->payload,seg2->payload_len);
            }
#endif
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
void StreamTcpInlineSegmentReplacePacket(Packet *p, TcpSegment *seg)
{
    SCEnter();

    uint32_t pseq = TCP_GET_SEQ(p);
    uint32_t tseq = seg->seq;

    /* check if segment is within the packet */
    if (tseq + seg->payload_len < pseq) {
        SCReturn;
    } else if (pseq + p->payload_len < tseq) {
        SCReturn;
    } else {
        /** \todo review logic */
        uint32_t pend = pseq + p->payload_len;
        uint32_t tend = tseq + seg->payload_len;
        SCLogDebug("pend %u, tend %u", pend, tend);

        //SCLogDebug("packet");
        //PrintRawDataFp(stdout,p->payload,p->payload_len);
        //SCLogDebug("seg");
        //PrintRawDataFp(stdout,seg->payload,seg->payload_len);

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
            memcpy(p->payload+poff, seg->payload+toff, range);

            /* flag as modified so we can reinject / replace after
             * recalculating the checksum */
            p->flags |= PKT_STREAM_MODIFIED;
        }
    }
}

#ifdef UNITTESTS

/** \test full overlap */
static int StreamTcpInlineTest01(void)
{
    SCEnter();

    uint8_t payload1[] = "AAC"; /* packet */
    uint8_t payload2[] = "ABC"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000000UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000000UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (!(p->flags & PKT_STREAM_MODIFIED)) {
        printf("PKT_STREAM_MODIFIED pkt flag not set: ");
        goto end;
    }

    if (memcmp(p->payload, t->payload, p->payload_len) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Segment:\n");
        PrintRawDataFp(stdout,t->payload,t->payload_len);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt,payload2,sizeof(payload2)-1) != 0) {
        PrintRawDataFp(stdout,pkt,3);
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}

/** \test full overlap */
static int StreamTcpInlineTest02(void)
{
    SCEnter();

    uint8_t payload1[] = "xxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000001UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000000UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (!(p->flags & PKT_STREAM_MODIFIED)) {
        printf("PKT_STREAM_MODIFIED pkt flag not set: ");
        goto end;
    }

    if (memcmp(p->payload, t->payload+1, p->payload_len) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Segment:\n");
        PrintRawDataFp(stdout,t->payload,t->payload_len);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt,payload2+1,sizeof(payload2)-3) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2+1,sizeof(payload2)-3);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}

/** \test partial overlap */
static int StreamTcpInlineTest03(void)
{
    SCEnter();

    uint8_t payload1[] = "xxxxxxxxxxxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000000UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000003UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (!(p->flags & PKT_STREAM_MODIFIED)) {
        printf("PKT_STREAM_MODIFIED pkt flag not set: ");
        goto end;
    }

    if (memcmp(p->payload+3, t->payload, t->payload_len) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Segment:\n");
        PrintRawDataFp(stdout,t->payload,t->payload_len);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1 + 3);
    if (memcmp(pkt,payload2,sizeof(payload2)-1) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2+1,sizeof(payload2)-3);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}

/** \test partial overlap */
static int StreamTcpInlineTest04(void)
{
    SCEnter();

    uint8_t payload1[] = "xxxxxxxxxxxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000003UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000000UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (!(p->flags & PKT_STREAM_MODIFIED)) {
        printf("PKT_STREAM_MODIFIED pkt flag not set: ");
        goto end;
    }

    if (memcmp(p->payload, t->payload+3, 2) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Segment:\n");
        PrintRawDataFp(stdout,t->payload,t->payload_len);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt,payload2+3,2) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2+3,2);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}
/** \test partial overlap */
static int StreamTcpInlineTest05(void)
{
    SCEnter();

    uint8_t payload1[] = "xxxxxxxxxxxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000000UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000010UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (!(p->flags & PKT_STREAM_MODIFIED)) {
        printf("PKT_STREAM_MODIFIED pkt flag not set: ");
        goto end;
    }

    if (memcmp(p->payload+10, t->payload, 2) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Segment:\n");
        PrintRawDataFp(stdout,t->payload,t->payload_len);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt+10,payload2,2) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2,2);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}

/** \test no overlap */
static int StreamTcpInlineTest06(void)
{
    SCEnter();

    uint8_t payload1[] = "xxxxxxxxxxxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000020UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000000UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (p->flags & PKT_STREAM_MODIFIED) {
        printf("PKT_STREAM_MODIFIED pkt flag set, but it shouldn't: ");
        goto end;
    }

    if (memcmp(p->payload, payload1, sizeof(payload1)-1) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Original payload:\n");
        PrintRawDataFp(stdout,payload1,sizeof(payload1)-1);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt,payload1,sizeof(payload1)-1) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2,2);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}

/** \test no overlap */
static int StreamTcpInlineTest07(void)
{
    SCEnter();

    uint8_t payload1[] = "xxxxxxxxxxxx"; /* packet */
    uint8_t payload2[] = "ABCDE"; /* segment */
    int result = 0;
    TcpSegment *t = NULL;

    Packet *p = UTHBuildPacketSrcDstPorts(payload1, sizeof(payload1)-1, IPPROTO_TCP, 1024, 80);
    if (p == NULL || p->tcph == NULL) {
        printf("generating test packet failed: ");
        goto end;
    }
    p->tcph->th_seq = htonl(10000000UL);

    t = SCMalloc(sizeof(TcpSegment));
    if (unlikely(t == NULL)) {
        printf("alloc TcpSegment failed: ");
        goto end;
    }
    memset(t, 0x00, sizeof(TcpSegment));
    t->payload = payload2;
    t->payload_len = sizeof(payload2)-1;
    t->seq = 10000020UL;

    StreamTcpInlineSegmentReplacePacket(p, t);

    if (p->flags & PKT_STREAM_MODIFIED) {
        printf("PKT_STREAM_MODIFIED pkt flag set, but it shouldn't: ");
        goto end;
    }

    if (memcmp(p->payload, payload1, sizeof(payload1)-1) != 0) {
        printf("Packet:\n");
        PrintRawDataFp(stdout,p->payload,p->payload_len);
        printf("Original payload:\n");
        PrintRawDataFp(stdout,payload1,sizeof(payload1)-1);
        printf("payloads didn't match: ");
        goto end;
    }

    uint8_t *pkt = GET_PKT_DATA(p)+(GET_PKT_LEN(p)-sizeof(payload1)+1);
    if (memcmp(pkt,payload1,sizeof(payload1)-1) != 0) {
        printf("Segment:\n");
        PrintRawDataFp(stdout,payload2,2);
        printf("Packet:\n");
        PrintRawDataFp(stdout,pkt,3);
        printf("Packet (full):\n");
        PrintRawDataFp(stdout,GET_PKT_DATA(p),GET_PKT_LEN(p));
        printf("packet data doesn't match: ");
        goto end;
    }

    result = 1;
end:
    if (p != NULL) {
        UTHFreePacket(p);
    }
    if (t != NULL) {
        SCFree(t);
    }
    SCReturnInt(result);
}
#endif /* UNITTESTS */

void StreamTcpInlineRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpInlineTest01", StreamTcpInlineTest01, 1);
    UtRegisterTest("StreamTcpInlineTest02", StreamTcpInlineTest02, 1);
    UtRegisterTest("StreamTcpInlineTest03", StreamTcpInlineTest03, 1);
    UtRegisterTest("StreamTcpInlineTest04", StreamTcpInlineTest04, 1);
    UtRegisterTest("StreamTcpInlineTest05", StreamTcpInlineTest05, 1);
    UtRegisterTest("StreamTcpInlineTest06", StreamTcpInlineTest06, 1);
    UtRegisterTest("StreamTcpInlineTest07", StreamTcpInlineTest07, 1);
#endif /* UNITTESTS */
}

