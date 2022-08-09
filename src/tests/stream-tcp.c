/* Copyright (C) 2007-2021 Open Information Security Foundation
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

#include "../suricata-common.h"
#include "../stream-tcp-private.h"
#include "../stream-tcp.h"
#include "../stream-tcp-reassemble.h"
#include "../stream-tcp-inline.h"
#include "../stream-tcp-list.h"
#include "../stream-tcp-util.h"
#include "../util-streaming-buffer.h"
#include "../util-print.h"
#include "../util-unittest.h"

#define SET_ISN(stream, setseq)                                                                    \
    (stream)->isn = (setseq);                                                                      \
    (stream)->base_seq = (setseq) + 1

/**
 *  \test   Test the allocation of TCP session for a given packet from the
 *          ssn_pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest01(void)
{
    StreamTcpThread stt;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    memset(&f, 0, sizeof(Flow));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    TcpSession *ssn = StreamTcpNewSession(p, 0);
    if (ssn == NULL) {
        printf("Session can not be allocated: ");
        goto end;
    }
    f.protoctx = ssn;

    if (f.alparser != NULL) {
        printf("AppLayer field not set to NULL: ");
        goto end;
    }
    if (ssn->state != 0) {
        printf("TCP state field not set to 0: ");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the deallocation of TCP session for a given packet and return
 *          the memory back to ssn_pool and corresponding segments to segment
 *          pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest02(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(pq));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    StreamTcpSessionClear(p->flow->protoctx);
    // StreamTcpUTClearSession(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we missed the initial
 *          SYN packet of the session. The session is setup only if midstream
 *          sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest03(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(pq));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 20 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the initial
 *          SYN/ACK packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest04(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(pq));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;

    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(9);
    p->tcph->th_ack = htonl(19);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 10 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 20)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the initial
 *          3WHS packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest05(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(13);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(16);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, 4); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 16 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we have seen only the
 *          FIN, RST packets packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest06(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    TcpSession ssn;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_flags = TH_FIN;
    p->tcph = &tcph;

    /* StreamTcpPacket returns -1 on unsolicited FIN */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed: ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't: ");
        goto end;
    }

    p->tcph->th_flags = TH_RST;
    /* StreamTcpPacket returns -1 on unsolicited RST */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed (2): ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't (2): ");
        goto end;
    }

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the working on PAWS. The packet will be dropped by stream, as
 *          its timestamp is old, although the segment is in the window.
 */

static int StreamTcpTest07(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = { 0x42 };
    PacketQueueNoLock pq;

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = true;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = true;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 2;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) != -1);

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->client.next_seq != 11);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the working on PAWS. The packet will be accepted by engine as
 *          the timestamp is valid and it is in window.
 */

static int StreamTcpTest08(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = { 0x42 };

    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = true;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = true;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(20);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 12;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->client.next_seq != 12);

    StreamTcpSessionClear(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the working of No stream reassembly flag. The stream will not
 *          reassemble the segment if the flag is set.
 */

static int StreamTcpTest09(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = { 0x42 };

    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = true;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(12);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(p->flow->protoctx == NULL);

    StreamTcpSetSessionNoReassemblyFlag(((TcpSession *)(p->flow->protoctx)), 0);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    TcpSession *ssn = p->flow->protoctx;
    FAIL_IF_NULL(ssn);
    TcpSegment *seg = RB_MIN(TCPSEG, &ssn->client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCPSEG_RB_NEXT(seg) != NULL);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we see all the packets in that stream from start.
 */

static int StreamTcpTest10(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.async_oneside = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF_NOT(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED);

    FAIL_IF(!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC));

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11);

    StreamTcpSessionClear(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN packet of that stream.
 */

static int StreamTcpTest11(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.async_oneside = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->tcph = &tcph;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(2);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC));

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED);

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->server.last_ack != 2 &&
            ((TcpSession *)(p->flow->protoctx))->client.next_seq != 1);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest12(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %" PRIu32 " match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *          Later, we start to receive the packet from other end stream too.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest13(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(9);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 9 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 14) {
        printf("failed in seq %" PRIu32 " match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string = "%YAML 1.1\n"
                                       "---\n"
                                       "\n"
                                       "default-log-dir: /var/log/eidps\n"
                                       "\n"
                                       "logging:\n"
                                       "\n"
                                       "  default-log-level: debug\n"
                                       "\n"
                                       "  default-format: \"<%t> - <%l>\"\n"
                                       "\n"
                                       "  default-startup-message: Your IDS has started.\n"
                                       "\n"
                                       "  default-output-filter:\n"
                                       "\n"
                                       "host-os-policy:\n"
                                       "\n"
                                       " windows: 192.168.0.1\n"
                                       "\n"
                                       " linux: 192.168.0.2\n"
                                       "\n";
/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string1 = "%YAML 1.1\n"
                                        "---\n"
                                        "\n"
                                        "default-log-dir: /var/log/eidps\n"
                                        "\n"
                                        "logging:\n"
                                        "\n"
                                        "  default-log-level: debug\n"
                                        "\n"
                                        "  default-format: \"<%t> - <%l>\"\n"
                                        "\n"
                                        "  default-startup-message: Your IDS has started.\n"
                                        "\n"
                                        "  default-output-filter:\n"
                                        "\n"
                                        "host-os-policy:\n"
                                        "\n"
                                        " windows: 192.168.0.0/24,"
                                        "192.168.1.1\n"
                                        "\n"
                                        " linux: 192.168.1.0/24,"
                                        "192.168.0.1\n"
                                        "\n";

/**
 *  \brief  Function to parse the dummy conf string and get the value of IP
 *          address for the corresponding OS policy type.
 *
 *  \param  conf_val_name   Name of the OS policy type
 *  \retval returns IP address as string on success and NULL on failure
 */
static const char *StreamTcpParseOSPolicy(char *conf_var_name)
{
    SCEnter();
    char conf_var_type_name[15] = "host-os-policy";
    char *conf_var_full_name = NULL;
    const char *conf_var_value = NULL;

    if (conf_var_name == NULL)
        goto end;

    /* the + 2 is for the '.' and the string termination character '\0' */
    conf_var_full_name = (char *)SCMalloc(strlen(conf_var_type_name) + strlen(conf_var_name) + 2);
    if (conf_var_full_name == NULL)
        goto end;

    if (snprintf(conf_var_full_name, strlen(conf_var_type_name) + strlen(conf_var_name) + 2,
                "%s.%s", conf_var_type_name, conf_var_name) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Error in making the conf full name");
        goto end;
    }

    if (ConfGet(conf_var_full_name, &conf_var_value) != 1) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Error in getting conf value for conf name %s",
                conf_var_full_name);
        goto end;
    }

    SCLogDebug("Value obtained from the yaml conf file, for the var "
               "\"%s\" is \"%s\"",
            conf_var_name, conf_var_value);

end:
    if (conf_var_full_name != NULL)
        SCFree(conf_var_full_name);
    SCReturnCharPtr(conf_var_value);
}
/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest14(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.0.2");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %" PRIu32 ""
               " server.next_seq %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy != OS_POLICY_WINDOWS &&
            ((TcpSession *)(p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX) {
        printf("failed in setting up OS policy, client.os_policy: %" PRIu8 ""
               " should be %" PRIu8 " and server.os_policy: %" PRIu8 ""
               " should be %" PRIu8 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy, (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest01(void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(21);
    p->tcph->th_ack = htonl(10);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK, but the SYN/ACK does
 *          not have the right SEQ
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest02(void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("SYN/ACK pkt not rejected but it should have: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK: however the SYN/ACK and ACK
 *          are part of a normal 3WHS
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest03(void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(31);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest15(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    addr.s_addr = inet_addr("192.168.0.20");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.20");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %" PRIu32 ""
               " server.next_seq %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy != OS_POLICY_WINDOWS &&
            ((TcpSession *)(p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX) {
        printf("failed in setting up OS policy, client.os_policy: %" PRIu8 ""
               " should be %" PRIu8 " and server.os_policy: %" PRIu8 ""
               " should be %" PRIu8 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy, (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest16(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %" PRIu32 ""
               " server.next_seq %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy != OS_POLICY_LINUX &&
            ((TcpSession *)(p->flow->protoctx))->server.os_policy != OS_POLICY_WINDOWS) {
        printf("failed in setting up OS policy, client.os_policy: %" PRIu8 ""
               " should be %" PRIu8 " and server.os_policy: %" PRIu8 ""
               " should be %" PRIu8 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy, (uint8_t)OS_POLICY_WINDOWS);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1". To check the setting of
 *          Default os policy
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest17(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("10.1.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.midstream) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %" PRIu32 ""
               " server.next_seq %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy != OS_POLICY_LINUX &&
            ((TcpSession *)(p->flow->protoctx))->server.os_policy != OS_POLICY_DEFAULT) {
        printf("failed in setting up OS policy, client.os_policy: %" PRIu8 ""
               " should be %" PRIu8 " and server.os_policy: %" PRIu8 ""
               " should be %" PRIu8 "\n",
                ((TcpSession *)(p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy, (uint8_t)OS_POLICY_DEFAULT);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the various OS policies based on different IP addresses from
            configuration defined in 'dummy_conf_string1' */
static int StreamTcpTest18(void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS)
        goto end;

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            configuration defined in 'dummy_conf_string1' */
static int StreamTcpTest19(void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS) {
        printf("expected os_policy: %" PRIu8 " but received %" PRIu8 ": ",
                (uint8_t)OS_POLICY_WINDOWS, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            configuration defined in 'dummy_conf_string1' */
static int StreamTcpTest20(void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "linux";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %" PRIu8 " but received %" PRIu8 "\n", (uint8_t)OS_POLICY_LINUX,
                stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            configuration defined in 'dummy_conf_string1' */
static int StreamTcpTest21(void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "linux";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %" PRIu8 " but received %" PRIu8 "\n", (uint8_t)OS_POLICY_LINUX,
                stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            configuration defined in 'dummy_conf_string1' */
static int StreamTcpTest22(void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("123.231.2.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_DEFAULT) {
        printf("expected os_policy: %" PRIu8 " but received %" PRIu8 "\n",
                (uint8_t)OS_POLICY_DEFAULT, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest23(void)
{
    StreamTcpThread stt;
    TcpSession ssn;
    Flow f;
    TCPHdr tcph;
    uint8_t packet[1460] = "";
    ThreadVars tv;
    PacketQueueNoLock pq;

    Packet *p = PacketGetFromAlloc();
    FAIL_IF(p == NULL);

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&tv, 0, sizeof(ThreadVars));

    StreamTcpUTInit(&stt.ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    SET_ISN(&ssn.client, 3184324452UL);

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419609UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 6;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    TcpSegment *seg = RB_MAX(TCPSEG, &ssn.client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCP_SEG_LEN(seg) != 2);

    StreamTcpUTClearSession(&ssn);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) > 0);
    PASS;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest24(void)
{
    StreamTcpThread stt;
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(p == NULL);
    Flow f;
    TCPHdr tcph;
    uint8_t packet[1460] = "";
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    StreamTcpUTInit(&stt.ra_ctx);
    StreamTcpUTSetupSession(&ssn);

    memset(&f, 0, sizeof(Flow));
    memset(&tcph, 0, sizeof(TCPHdr));
    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    // ssn.client.ra_app_base_seq = ssn.client.ra_raw_base_seq = ssn.client.last_ack = 3184324453UL;
    SET_ISN(&ssn.client, 3184324453UL);

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 4;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419633UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419657UL);
    p->payload_len = 4;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    TcpSegment *seg = RB_MAX(TCPSEG, &ssn.client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCP_SEG_LEN(seg) != 4);

    StreamTcpUTClearSession(&ssn);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) > 0);
    PASS;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest25(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest26(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest27(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the memcap incrementing/decrementing and memcap check */
static int StreamTcpTest28(void)
{
    StreamTcpThread stt;
    StreamTcpUTInit(&stt.ra_ctx);

    uint32_t memuse = SC_ATOMIC_GET(st_memuse);

    StreamTcpIncrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) != (memuse + 500));

    StreamTcpDecrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) != memuse);

    FAIL_IF(StreamTcpCheckMemcap(500) != 1);

    FAIL_IF(StreamTcpCheckMemcap((memuse + SC_ATOMIC_GET(stream_config.memcap))) != 0);

    StreamTcpUTDeinit(stt.ra_ctx);

    FAIL_IF(SC_ATOMIC_GET(st_memuse) != 0);
    PASS;
}

#if 0
/**
 *  \test   Test the resetting of the sesison with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest29(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t packet[1460] = "";
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(true);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = packet;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    tcpvars.hlen = 20;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 119197101;
    ssn.server.window = 5184;
    ssn.server.next_win = 5184;
    ssn.server.last_ack = 119197101;
    ssn.server.ra_base_seq = 119197101;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 4;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(119197102);
    p.tcph->th_ack = htonl(15);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the ssn.state should be TCP_ESTABLISHED(%"PRIu8"), not %"PRIu8""
                "\n", TCP_ESTABLISHED, ssn.state);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(true);
    return result;
}

/**
 *  \test   Test the overlapping of the packet with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest30(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t payload[9] = "AAAAAAAAA";
    uint8_t payload1[9] = "GET /EVIL";
    uint8_t expected_content[9] = { 0x47, 0x45, 0x54, 0x20, 0x2f, 0x45, 0x56,
                                    0x49, 0x4c };
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(true);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = payload;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload = payload1;
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(20);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (StreamTcpCheckStreamContents(expected_content, 9, &ssn.client) != 1) {
        printf("the contents are not as expected(GET /EVIL), contents are: ");
        PrintRawDataFp(stdout, ssn.client.seg_list->payload, 9);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(true);
    return result;
}

/**
 *  \test   Test the multiple SYN packet handling with bad checksum and timestamp
 *          value. Engine should drop the bad checksum packet and establish
 *          TCP session correctly.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest31(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;
    TCPOpt tcpopt;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    memset(&tcpopt, 0, sizeof (TCPOpt));
    int result = 1;

    StreamTcpInitConfig(true);

    FLOW_INITIALIZE(&f);
    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_LINUX;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    p.tcpvars.ts = &tcpopt;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 100;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 10;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    ssn.flags |= STREAMTCP_FLAG_TIMESTAMP;
    tcph.th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(11);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079941);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr1;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the should have been changed to TCP_ESTABLISHED!!\n ");
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(true);
    return result;
}

/**
 *  \test   Test the initialization of tcp streams with ECN & CWR flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest32(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(true);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK | TH_ECN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_flags = TH_ACK;
    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISHED\n");
        goto end;
    }
    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(true);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the same
 *          ports have been used to start the new session after resetting the
 *          previous session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest33 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(true);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_CLOSED) {
        printf("Tcp session should have been closed\n");
        goto end;
    }

    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_seq = htonl(1);
    p.tcph->th_ack = htonl(2);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been ESTABLISHED\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(true);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the PUSH flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest34 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_PUSH;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(true);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been established\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(true);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the URG flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest35 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_URG;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(true);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been established\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(true);
    return ret;
}

/**
 *  \test   Test the processing of PSH and URG flag in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest36(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(true);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISHED\n");
        goto end;
    }

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_URG;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->client.next_seq != 4) {
        printf("the ssn->client.next_seq should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)p.flow->protoctx)->client.next_seq);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(true);
    return ret;
}
#endif

/**
 *  \test   Test the processing of out of order FIN packets in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest37(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);

    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISHED\n");
        goto end;
    }

    p->tcph->th_ack = htonl(2);
    p->tcph->th_seq = htonl(4);
    p->tcph->th_flags = TH_ACK | TH_FIN;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_CLOSE_WAIT) {
        printf("the TCP state should be TCP_CLOSE_WAIT\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_ACK;
    p->payload_len = 0;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    TcpStream *stream = &(((TcpSession *)p->flow->protoctx)->client);
    FAIL_IF(STREAM_RAW_PROGRESS(stream) != 0); // no detect no progress update

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest38(void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[128];
    TCPHdr tcph;
    PacketQueueNoLock pq;

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(29847);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 1 as the previous sent ACK value is out of
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 1) {
        printf("the server.last_ack should be 1, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 127, 128); /*AAA*/
    p->payload = payload;
    p->payload_len = 127;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 128) {
        printf("the server.next_seq should be 128, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(256); // in window, but beyond next_seq
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256, as the previous sent ACK value
       is inside window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 1, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(128);
    p->tcph->th_seq = htonl(8);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 256, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack and update the next_seq after loosing the .
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest39(void)
{
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    PacketQueueNoLock pq;

    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&pq, 0, sizeof(PacketQueueNoLock));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 4) {
        printf("the server.next_seq should be 4, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 4 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 4) {
        printf("the server.last_ack should be 4, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_seq = htonl(4);
    p->tcph->th_ack = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* next_seq value should be 2987 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 7) {
        printf("the server.next_seq should be 7, but it is %" PRIu32 "\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick first */
static int StreamTcpTest42(void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    TcpSession *ssn;

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(501);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 500) {
        SCLogDebug("ssn->server.isn %" PRIu32 " != %" PRIu32 "", ssn->server.isn, 500);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %" PRIu32 " != %" PRIu32 "", ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick second */
static int StreamTcpTest43(void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    TcpSession *ssn;

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %" PRIu32 " != %" PRIu32 "", ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %" PRIu32 " != %" PRIu32 "", ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick neither */
static int StreamTcpTest44(void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    TcpSession *ssn;

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(3001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_SYN_RECV) {
        SCLogDebug("state not TCP_SYN_RECV");
        goto end;
    }

    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %" PRIu32 " != %" PRIu32 "", ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, over the limit */
static int StreamTcpTest45(void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    TcpSession *ssn;

    memset(&pq, 0, sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.max_synack_queued = 2;

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(2000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(3000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %" PRIu32 " != %" PRIu32 "", ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %" PRIu32 " != %" PRIu32 "", ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

void StreamTcpRegisterTests(void)
{
    UtRegisterTest("StreamTcpTest01 -- TCP session allocation", StreamTcpTest01);
    UtRegisterTest("StreamTcpTest02 -- TCP session deallocation", StreamTcpTest02);
    UtRegisterTest("StreamTcpTest03 -- SYN missed MidStream session", StreamTcpTest03);
    UtRegisterTest("StreamTcpTest04 -- SYN/ACK missed MidStream session", StreamTcpTest04);
    UtRegisterTest("StreamTcpTest05 -- 3WHS missed MidStream session", StreamTcpTest05);
    UtRegisterTest("StreamTcpTest06 -- FIN, RST message MidStream session", StreamTcpTest06);
    UtRegisterTest("StreamTcpTest07 -- PAWS invalid timestamp", StreamTcpTest07);
    UtRegisterTest("StreamTcpTest08 -- PAWS valid timestamp", StreamTcpTest08);
    UtRegisterTest("StreamTcpTest09 -- No Client Reassembly", StreamTcpTest09);
    UtRegisterTest("StreamTcpTest10 -- No missed packet Async stream", StreamTcpTest10);
    UtRegisterTest("StreamTcpTest11 -- SYN missed Async stream", StreamTcpTest11);
    UtRegisterTest("StreamTcpTest12 -- SYN/ACK missed Async stream", StreamTcpTest12);
    UtRegisterTest("StreamTcpTest13 -- opposite stream packets for Async "
                   "stream",
            StreamTcpTest13);
    UtRegisterTest("StreamTcp4WHSTest01", StreamTcp4WHSTest01);
    UtRegisterTest("StreamTcp4WHSTest02", StreamTcp4WHSTest02);
    UtRegisterTest("StreamTcp4WHSTest03", StreamTcp4WHSTest03);
    UtRegisterTest("StreamTcpTest14 -- setup OS policy", StreamTcpTest14);
    UtRegisterTest("StreamTcpTest15 -- setup OS policy", StreamTcpTest15);
    UtRegisterTest("StreamTcpTest16 -- setup OS policy", StreamTcpTest16);
    UtRegisterTest("StreamTcpTest17 -- setup OS policy", StreamTcpTest17);
    UtRegisterTest("StreamTcpTest18 -- setup OS policy", StreamTcpTest18);
    UtRegisterTest("StreamTcpTest19 -- setup OS policy", StreamTcpTest19);
    UtRegisterTest("StreamTcpTest20 -- setup OS policy", StreamTcpTest20);
    UtRegisterTest("StreamTcpTest21 -- setup OS policy", StreamTcpTest21);
    UtRegisterTest("StreamTcpTest22 -- setup OS policy", StreamTcpTest22);
    UtRegisterTest("StreamTcpTest23 -- stream memory leaks", StreamTcpTest23);
    UtRegisterTest("StreamTcpTest24 -- stream memory leaks", StreamTcpTest24);
    UtRegisterTest("StreamTcpTest25 -- test ecn/cwr sessions", StreamTcpTest25);
    UtRegisterTest("StreamTcpTest26 -- test ecn/cwr sessions", StreamTcpTest26);
    UtRegisterTest("StreamTcpTest27 -- test ecn/cwr sessions", StreamTcpTest27);
    UtRegisterTest("StreamTcpTest28 -- Memcap Test", StreamTcpTest28);

#if 0 /* VJ 2010/09/01 disabled since they blow up on Fedora and Fedora is                         \
       * right about blowing up. The checksum functions are not used properly                      \
       * in the tests. */
    UtRegisterTest("StreamTcpTest29 -- Badchecksum Reset Test", StreamTcpTest29, 1);
    UtRegisterTest("StreamTcpTest30 -- Badchecksum Overlap Test", StreamTcpTest30, 1);
    UtRegisterTest("StreamTcpTest31 -- MultipleSyns Test", StreamTcpTest31, 1);
    UtRegisterTest("StreamTcpTest32 -- Bogus CWR Test", StreamTcpTest32, 1);
    UtRegisterTest("StreamTcpTest33 -- RST-SYN Again Test", StreamTcpTest33, 1);
    UtRegisterTest("StreamTcpTest34 -- SYN-PUSH Test", StreamTcpTest34, 1);
    UtRegisterTest("StreamTcpTest35 -- SYN-URG Test", StreamTcpTest35, 1);
    UtRegisterTest("StreamTcpTest36 -- PUSH-URG Test", StreamTcpTest36, 1);
#endif
    UtRegisterTest("StreamTcpTest37 -- Out of order FIN Test", StreamTcpTest37);

    UtRegisterTest("StreamTcpTest38 -- validate ACK", StreamTcpTest38);
    UtRegisterTest("StreamTcpTest39 -- update next_seq", StreamTcpTest39);

    UtRegisterTest("StreamTcpTest42 -- SYN/ACK queue", StreamTcpTest42);
    UtRegisterTest("StreamTcpTest43 -- SYN/ACK queue", StreamTcpTest43);
    UtRegisterTest("StreamTcpTest44 -- SYN/ACK queue", StreamTcpTest44);
    UtRegisterTest("StreamTcpTest45 -- SYN/ACK queue", StreamTcpTest45);

    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();

    StreamTcpSackRegisterTests();
}
