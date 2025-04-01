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
#include "../util-unittest-helper.h"

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
    TCPHdr tcph;
    memset(&tcph, 0, sizeof(TCPHdr));
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetTCPHdr(p, &tcph);
    Flow f;
    memset(&f, 0, sizeof(Flow));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    StreamTcpUTInit(&stt.ra_ctx);
    TcpSession *ssn = StreamTcpNewSession(NULL, &stt, p, 0);
    FAIL_IF_NULL(ssn);
    f.protoctx = ssn;
    FAIL_IF_NOT_NULL(f.alparser);
    FAIL_IF_NOT(ssn->state == 0);
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(6);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(19);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    UTHSetTCPHdr(p, &tcph);

    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(9);
    tcph.th_ack = htonl(19);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    UTHSetTCPHdr(p, &tcph);

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(13);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(19);
    tcph.th_ack = htonl(16);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    UTHSetTCPHdr(p, &tcph);

    /* StreamTcpPacket returns -1 on unsolicited FIN */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed: ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't: ");
        goto end;
    }

    tcph.th_flags = TH_RST;
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
    UTHSetTCPHdr(p, &tcph);

    p->l4.vars.tcp.ts_set = true;
    p->l4.vars.tcp.ts_val = 10;
    p->l4.vars.tcp.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->l4.vars.tcp.ts_val = 2;

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
    UTHSetTCPHdr(p, &tcph);

    p->l4.vars.tcp.ts_set = true;
    p->l4.vars.tcp.ts_val = 10;
    p->l4.vars.tcp.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->l4.vars.tcp.ts_val = 12;

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
    UTHSetTCPHdr(p, &tcph);

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(12);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(p->flow->protoctx == NULL);

    StreamTcpSetSessionNoReassemblyFlag(((TcpSession *)(p->flow->protoctx)), 0);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    stream_config.async_oneside = true;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    UTHSetTCPHdr(p, &tcph);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(6);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    /* spurious retransmission */
    FAIL_IF_NOT(StreamTcpPacket(&tv, p, &stt, &pq) == 0);

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
    stream_config.async_oneside = true;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    UTHSetTCPHdr(p, &tcph);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    tcph.th_seq = htonl(2);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    TcpSession *ssn = p->flow->protoctx;
    FAIL_IF((ssn->flags & STREAMTCP_FLAG_ASYNC) == 0);
    FAIL_IF(ssn->state != TCP_ESTABLISHED);

    FAIL_IF(ssn->server.last_ack != 11);
    FAIL_IF(ssn->client.next_seq != 14);

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
    UTHSetTCPHdr(p, &tcph);
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(6);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.async_oneside) {
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
    UTHSetTCPHdr(p, &tcph);
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(6);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (!stream_config.async_oneside) {
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

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(9);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
        SCLogError("Error in making the conf full name");
        goto end;
    }

    if (SCConfGet(conf_var_full_name, &conf_var_value) != 1) {
        SCLogError("Error in getting conf value for conf name %s", conf_var_full_name);
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

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
    UTHSetTCPHdr(p, &tcph);
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    UTHSetIPV4Hdr(p, &ipv4h);

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(15);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(14);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.0.2");
    tcph.th_seq = htonl(25);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(24);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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
    UTHSetTCPHdr(p, &tcph);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(21);
    tcph.th_ack = htonl(10);
    tcph.th_flags = TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    tcph.th_seq = htonl(30);
    tcph.th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    tcph.th_flags = TH_SYN | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    tcph.th_seq = htonl(30);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(11);
    tcph.th_ack = htonl(31);
    tcph.th_flags = TH_ACK;
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

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
    UTHSetTCPHdr(p, &tcph);
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    UTHSetIPV4Hdr(p, &ipv4h);

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(15);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(14);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.20");
    tcph.th_seq = htonl(25);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(24);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

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
    UTHSetTCPHdr(p, &tcph);
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    UTHSetIPV4Hdr(p, &ipv4h);

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(15);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(14);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.1");
    tcph.th_seq = htonl(25);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(24);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

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
    UTHSetTCPHdr(p, &tcph);
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    UTHSetIPV4Hdr(p, &ipv4h);

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(20);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(15);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(14);
    tcph.th_ack = htonl(23);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("10.1.1.1");
    tcph.th_seq = htonl(25);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_seq = htonl(24);
    tcph.th_ack = htonl(13);
    tcph.th_flags = TH_ACK | TH_PUSH;
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ipv4h);
    addr.s_addr = inet_addr("192.168.1.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS)
        goto end;

    ret = 1;
end:
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ipv4h);
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ipv4h);
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ipv4h);
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    /* Load the config string into parser */
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ipv4h);
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
    SCConfDeInit();
    SCConfRestoreContextBackup();
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF(p == NULL);

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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    SET_ISN(&ssn.client, 3184324452UL);

    tcph.th_seq = htonl(3184324453UL);
    tcph.th_ack = htonl(3373419609UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

    tcph.th_seq = htonl(3184324455UL);
    tcph.th_ack = htonl(3373419621UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

    tcph.th_seq = htonl(3184324453UL);
    tcph.th_ack = htonl(3373419621UL);
    p->payload_len = 6;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    // ssn.client.ra_app_base_seq = ssn.client.ra_raw_base_seq = ssn.client.last_ack = 3184324453UL;
    SET_ISN(&ssn.client, 3184324453UL);

    tcph.th_seq = htonl(3184324455UL);
    tcph.th_ack = htonl(3373419621UL);
    p->payload_len = 4;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

    tcph.th_seq = htonl(3184324459UL);
    tcph.th_ack = htonl(3373419633UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

    tcph.th_seq = htonl(3184324459UL);
    tcph.th_ack = htonl(3373419657UL);
    p->payload_len = 4;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p) == -1);

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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;
    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(6);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(6);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(6);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISHED\n");
        goto end;
    }

    tcph.th_ack = htonl(2);
    tcph.th_seq = htonl(4);
    tcph.th_flags = TH_ACK | TH_FIN;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_CLOSE_WAIT) {
        printf("the TCP state should be TCP_CLOSE_WAIT\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    tcph.th_ack = htonl(4);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(29847);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
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

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_PUSH | TH_ACK;
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

    tcph.th_ack = htonl(256); // in window, but beyond next_seq
    tcph.th_seq = htonl(5);
    tcph.th_flags = TH_PUSH | TH_ACK;
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

    tcph.th_ack = htonl(128);
    tcph.th_seq = htonl(8);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    p->flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    tcph.th_ack = htonl(1);
    tcph.th_seq = htonl(1);
    tcph.th_flags = TH_PUSH | TH_ACK;
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

    tcph.th_ack = htonl(4);
    tcph.th_seq = htonl(2);
    tcph.th_flags = TH_PUSH | TH_ACK;
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

    tcph.th_seq = htonl(4);
    tcph.th_ack = htonl(5);
    tcph.th_flags = TH_PUSH | TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(500);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(1000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    tcph.th_ack = htonl(501);
    tcph.th_seq = htonl(101);
    tcph.th_flags = TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(500);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(1000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    tcph.th_ack = htonl(1001);
    tcph.th_seq = htonl(101);
    tcph.th_flags = TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(500);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(1000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    tcph.th_ack = htonl(3001);
    tcph.th_seq = htonl(101);
    tcph.th_flags = TH_ACK;
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
    UTHSetTCPHdr(p, &tcph);
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(500);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(1000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(2000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    tcph.th_seq = htonl(3000);
    tcph.th_ack = htonl(101);
    tcph.th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    /* ACK */
    tcph.th_ack = htonl(1001);
    tcph.th_seq = htonl(101);
    tcph.th_flags = TH_ACK;
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
