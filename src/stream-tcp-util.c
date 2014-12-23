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

#include "stream-tcp-reassemble.h"
#include "stream-tcp-inline.h"
#include "stream-tcp.h"
#include "stream-tcp-util.h"

#include "util-memcmp.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifdef UNITTESTS

/* unittest helper functions */

extern int stream_inline;

void StreamTcpUTInit(TcpReassemblyThreadCtx **ra_ctx)
{
    StreamTcpInitConfig(TRUE);
    *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
}

void StreamTcpUTDeinit(TcpReassemblyThreadCtx *ra_ctx)
{
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    StreamTcpFreeConfig(TRUE);
    stream_inline = 0;
}

void StreamTcpUTInitInline(void) {
    stream_inline = 1;
}

void StreamTcpUTSetupSession(TcpSession *ssn)
{
    memset(ssn, 0x00, sizeof(TcpSession));
}

void StreamTcpUTClearSession(TcpSession *ssn)
{
    StreamTcpUTClearStream(&ssn->client);
    StreamTcpUTClearStream(&ssn->server);
}

void StreamTcpUTSetupStream(TcpStream *s, uint32_t isn)
{
    memset(s, 0x00, sizeof(TcpStream));

    s->isn = isn;
    STREAMTCP_SET_RA_BASE_SEQ(s, isn);
}

void StreamTcpUTClearStream(TcpStream *s)
{
    StreamTcpReturnStreamSegments(s);
}

int StreamTcpUTAddSegmentWithPayload(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, uint8_t *payload, uint16_t len)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx, len);
    if (s == NULL) {
        return -1;
    }

    s->seq = seq;
    s->payload_len = len;
    memcpy(s->payload, payload, len);

    Packet *p = UTHBuildPacketReal(s->payload, s->payload_len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        return -1;
    }
    p->tcph->th_seq = htonl(seq);

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p) < 0)
        return -1;

    UTHFreePacket(p);
    return 0;
}

int StreamTcpUTAddSegmentWithByte(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, uint8_t byte, uint16_t len)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx, len);
    if (s == NULL) {
        return -1;
    }

    s->seq = seq;
    s->payload_len = len;
    memset(s->payload, byte, len);

    Packet *p = UTHBuildPacketReal(s->payload, s->payload_len, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (p == NULL) {
        return -1;
    }
    p->tcph->th_seq = htonl(seq);

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p) < 0)
        return -1;
    UTHFreePacket(p);
    return 0;
}

/* tests */

int StreamTcpUtilTest01(void)
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


int StreamTcpUtilStreamTest01(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpStream stream;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupStream(&stream, 1);

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }

    TcpSegment *seg = stream.seg_list;
    if (seg->seq != 2) {
        printf("first seg in the list should have seq 2: ");
        goto end;
    }

    seg = seg->next;
    if (seg->seq != 7) {
        printf("first seg in the list should have seq 7: ");
        goto end;
    }

    seg = seg->next;
    if (seg->seq != 12) {
        printf("first seg in the list should have seq 12: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpUTClearStream(&stream);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

int StreamTcpUtilStreamTest02(void)
{
    int ret = 0;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpStream stream;

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTSetupStream(&stream, 1);

    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  7, 'B', 5) == -1) {
        printf("failed to add segment 2: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream, 12, 'C', 5) == -1) {
        printf("failed to add segment 3: ");
        goto end;
    }
    if (StreamTcpUTAddSegmentWithByte(&tv, ra_ctx, &stream,  2, 'A', 5) == -1) {
        printf("failed to add segment 1: ");
        goto end;
    }

    TcpSegment *seg = stream.seg_list;
    if (seg->seq != 2) {
        printf("first seg in the list should have seq 2: ");
        goto end;
    }

    seg = seg->next;
    if (seg->seq != 7) {
        printf("first seg in the list should have seq 7: ");
        goto end;
    }

    seg = seg->next;
    if (seg->seq != 12) {
        printf("first seg in the list should have seq 12: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpUTClearStream(&stream);
    StreamTcpUTDeinit(ra_ctx);
    return ret;
}

#endif

void StreamTcpUtilRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpUtilTest01", StreamTcpUtilTest01, 1);
    UtRegisterTest("StreamTcpUtilStreamTest01", StreamTcpUtilStreamTest01, 1);
    UtRegisterTest("StreamTcpUtilStreamTest02", StreamTcpUtilStreamTest02, 1);
#endif /* UNITTESTS */
}

