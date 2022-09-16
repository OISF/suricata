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
 *  Helper functions for the stream engine.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "ippair.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-memcmp.h"
#include "stream-tcp.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-reassemble.h"
#endif

#include "stream-tcp-util.h"

#ifdef UNITTESTS

/* unittest helper functions */

void StreamTcpUTInit(TcpReassemblyThreadCtx **ra_ctx)
{
    StreamTcpInitConfig(true);
    IPPairInitConfig(true);
    *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
}

void StreamTcpUTDeinit(TcpReassemblyThreadCtx *ra_ctx)
{
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(true);
    stream_config.flags &= ~STREAMTCP_INIT_FLAG_INLINE;
}

void StreamTcpUTInitInline(void) {
    stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
}

void StreamTcpUTSetupSession(TcpSession *ssn)
{
    memset(ssn, 0x00, sizeof(TcpSession));

    StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    ssn->client.sb = x;
    ssn->server.sb = x;
}

void StreamTcpUTClearSession(TcpSession *ssn)
{
    StreamTcpUTClearStream(&ssn->client);
    StreamTcpUTClearStream(&ssn->server);
    StreamTcpSessionCleanup(ssn);
    memset(ssn, 0x00, sizeof(TcpSession));
}

void StreamTcpUTSetupStream(TcpStream *s, uint32_t isn)
{
    memset(s, 0x00, sizeof(TcpStream));

    s->isn = isn;
    STREAMTCP_SET_RA_BASE_SEQ(s, isn);
    s->base_seq = isn+1;

    StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    s->sb = x;
}

void StreamTcpUTClearStream(TcpStream *s)
{
    StreamTcpStreamCleanup(s);
}

/** \brief wrapper for StreamTcpReassembleHandleSegmentHandleData */
int StreamTcpUTAddPayload(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpSession *ssn, TcpStream *stream, uint32_t seq, uint8_t *payload, uint16_t len)
{
    Packet *p = UTHBuildPacketReal(payload, len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        return -1;
    }
    p->tcph->th_seq = htonl(seq);
    p->tcph->th_ack = htonl(31);

    if (StreamTcpReassembleHandleSegmentHandleData(tv, ra_ctx, ssn, stream, p) < 0)
        return -1;

    UTHFreePacket(p);
    return 0;
}

int StreamTcpUTAddSegmentWithPayload(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, uint8_t *payload, uint16_t len)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx);
    if (s == NULL) {
        return -1;
    }

    s->seq = seq;
    TCP_SEG_LEN(s) = len;

    Packet *p = UTHBuildPacketReal(payload, len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        return -1;
    }
    p->tcph->th_seq = htonl(seq);

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p, TCP_GET_SEQ(p), p->payload, p->payload_len) < 0)
        return -1;

    UTHFreePacket(p);
    return 0;
}

int StreamTcpUTAddSegmentWithByte(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, uint8_t byte, uint16_t len)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx);
    if (s == NULL) {
        return -1;
    }

    s->seq = seq;
    TCP_SEG_LEN(s) = len;
    uint8_t buf[len];
    memset(buf, byte, len);

    Packet *p = UTHBuildPacketReal(buf, len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        return -1;
    }
    p->tcph->th_seq = htonl(seq);

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p, TCP_GET_SEQ(p), p->payload, p->payload_len) < 0)
        return -1;
    UTHFreePacket(p);
    return 0;
}

/* tests */

static int StreamTcpUtilTest01(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;

    StreamTcpUTInit(&ra_ctx);

    if (ra_ctx == NULL) {
        printf("ra_ctx is NULL: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}


static int StreamTcpUtilStreamTest01(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    TcpStream stream;
    ThreadVars tv;
    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupStream(&stream, 1);

    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  2, 'A', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  7, 'B', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream, 12, 'C', 5) == -1);

    TcpSegment *seg = RB_MIN(TCPSEG, &stream.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 2);

    seg = TCPSEG_RB_NEXT(seg);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 7);

    seg = TCPSEG_RB_NEXT(seg);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 12);

    StreamTcpUTClearStream(&stream);
    StreamTcpUTDeinit(ra_ctx);
    PASS;
}

static int StreamTcpUtilStreamTest02(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    TcpStream stream;
    ThreadVars tv;
    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupStream(&stream, 1);

    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  7, 'B', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream, 12, 'C', 5) == -1);
    FAIL_IF(StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  2, 'A', 5) == -1);

    TcpSegment *seg = RB_MIN(TCPSEG, &stream.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 2);

    seg = TCPSEG_RB_NEXT(seg);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 7);

    seg = TCPSEG_RB_NEXT(seg);
    FAIL_IF_NULL(seg);
    FAIL_IF(seg->seq != 12);

    StreamTcpUTClearStream(&stream);
    StreamTcpUTDeinit(ra_ctx);
    PASS;
}

#endif

void StreamTcpUtilRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpUtilTest01", StreamTcpUtilTest01);
    UtRegisterTest("StreamTcpUtilStreamTest01", StreamTcpUtilStreamTest01);
    UtRegisterTest("StreamTcpUtilStreamTest02", StreamTcpUtilStreamTest02);
#endif /* UNITTESTS */
}

