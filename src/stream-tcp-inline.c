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
int StreamTcpInlineSegmentCompare(const TcpStream *stream,
        const Packet *p, const TcpSegment *seg)
{
    SCEnter();

    if (p == NULL || seg == NULL) {
        SCReturnInt(0);
    }

    const uint8_t *seg_data;
    uint32_t seg_datalen;
    StreamingBufferSegmentGetData(&stream->sb, &seg->sbseg, &seg_data, &seg_datalen);
    if (seg_data == NULL || seg_datalen == 0)
        SCReturnInt(0);

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
void StreamTcpInlineSegmentReplacePacket(const TcpStream *stream,
        Packet *p, const TcpSegment *seg)
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
    StreamingBufferSegmentGetData(&stream->sb, &seg->sbseg, &seg_data, &seg_datalen);

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
#include "tests/stream-tcp-inline.c"
#endif
