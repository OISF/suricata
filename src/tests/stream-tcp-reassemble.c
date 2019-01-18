/* Copyright (C) 2007-2017 Open Information Security Foundation
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

struct TestReassembleRawCallbackData {
    const uint8_t *expect_data;
    const uint32_t expect_data_len;
};

static int TestReassembleRawCallback(void *cb_data, const uint8_t *data, const uint32_t data_len)
{
    struct TestReassembleRawCallbackData *cb = cb_data;

    SCLogNotice("have %u expect %u", data_len, cb->expect_data_len);

    if (data_len == cb->expect_data_len &&
        memcmp(data, cb->expect_data, data_len) == 0) {
        return 1;
    } else {
        SCLogNotice("data mismatch. Expected:");
        PrintRawDataFp(stdout, cb->expect_data, cb->expect_data_len);
        SCLogNotice("Got:");
        PrintRawDataFp(stdout, data, data_len);
        return -1;
    }
}

static int TestReassembleRawValidate(TcpSession *ssn, Packet *p,
        const uint8_t *data, const uint32_t data_len)
{
    struct TestReassembleRawCallbackData cb = { data, data_len };
    uint64_t progress = 0;
    int r = StreamReassembleRaw(ssn, p, TestReassembleRawCallback, &cb, &progress, false);
    if (r == 1) {
        StreamReassembleRawUpdateProgress(ssn, p, progress);
    }
    SCLogNotice("r %d", r);
    return r;
}

#define RAWREASSEMBLY_START(isn)                \
    TcpReassemblyThreadCtx *ra_ctx = NULL;      \
    TcpSession ssn;                             \
    ThreadVars tv;                              \
    memset(&tv, 0, sizeof(tv));                 \
    Packet *p = NULL;                           \
    \
                                                \
    StreamTcpUTInit(&ra_ctx);                   \
    StreamTcpUTInitInline();                    \
    stream_config.reassembly_toserver_chunk_size = 9;   \
    stream_config.reassembly_toclient_chunk_size = 9;   \
    StreamTcpUTSetupSession(&ssn);              \
    StreamTcpUTSetupStream(&ssn.server, (isn)); \
    StreamTcpUTSetupStream(&ssn.client, (isn)); \
    ssn.server.last_ack = (isn) + 1;            \
    ssn.client.last_ack = (isn) + 1;            \
                                                \
    TcpStream *stream = &ssn.client;

#define RAWREASSEMBLY_END                       \
    StreamTcpUTClearSession(&ssn);              \
    StreamTcpUTDeinit(ra_ctx);                  \
    PASS

#define RAWREASSEMBLY_STEP(seq, seg, seglen, buf, buflen)   \
    p = PacketGetFromAlloc();                               \
    FAIL_IF_NULL(p);                                        \
    {                                                       \
        SCLogNotice("SEQ %u block of %u", (seq), (seglen)); \
        p->flowflags = FLOW_PKT_TOSERVER;                   \
        TCPHdr tcphdr;                                      \
        memset(&tcphdr, 0, sizeof(tcphdr));                 \
        p->tcph = &tcphdr;                                  \
        p->tcph->th_seq = htonl((seq));                     \
        p->tcph->th_ack = htonl(10);                        \
        p->payload_len = (seglen);                          \
                                                            \
        FAIL_IF(StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, stream, (seq), (uint8_t *)(seg), (seglen)) != 0);    \
        p->flags |= PKT_STREAM_ADD;                         \
        FAIL_IF(!(TestReassembleRawValidate(&ssn, p, (uint8_t *)(buf), (buflen))));   \
    }\
    PacketFree(p);

#define RAWREASSEMBLY_STEP_WITH_PROGRESS(seq, seg, seglen, buf, buflen, lastack, progress) \
    stream->last_ack = (lastack);                               \
    RAWREASSEMBLY_STEP((seq),(seg),(seglen),(buf),(buflen));    \
    FAIL_IF(STREAM_RAW_PROGRESS(stream) != (progress));

static int StreamTcpReassembleRawTest01 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAA", 3, "AAA", 3);
    RAWREASSEMBLY_STEP(5, "BBB", 3, "AAABBB", 6);
    RAWREASSEMBLY_STEP(8, "CCC", 3, "AAABBBCCC", 9);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest02 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAA", 3, "AAA", 3);
    RAWREASSEMBLY_STEP(5, "BBB", 3, "AAABBB", 6);
    RAWREASSEMBLY_STEP(11,"DDD", 3, "DDD", 3);
    RAWREASSEMBLY_STEP(8, "CCC", 3, "BBBCCCDDD", 9);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest03 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAA", 3, "AAA", 3);
    RAWREASSEMBLY_STEP(11,"DDD", 3, "DDD", 3);
    RAWREASSEMBLY_STEP(8, "CCC", 3, "CCCDDD", 6);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest04 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAAAA", 5, "AAAAA", 5);
    RAWREASSEMBLY_STEP(10,"CCCCC", 5, "CCCCC", 5);
    RAWREASSEMBLY_STEP(7, "BBB", 3, "AAABBBCCC", 9);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest05 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAAAA", 5, "AAAAA", 5);
    RAWREASSEMBLY_STEP(10,"CCCCC", 5, "CCCCC", 5);
    RAWREASSEMBLY_STEP(2, "EEEEEEEEEEEEE", 13, "AAAAAEEECCCCC", 13);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest06 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAAAA", 5, "AAAAA", 5);
    RAWREASSEMBLY_STEP(16,"CCCCC", 5, "CCCCC", 5);
    RAWREASSEMBLY_STEP(7, "BBBBBBBBB", 9, "ABBBBBBBBBC", 11);
    RAWREASSEMBLY_STEP(21,"DDDDDDDDDD",10,"CCCDDDDDDDDDD", 13);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest07 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP(2, "AAAAAAA", 7, "AAAAAAA", 7);
    RAWREASSEMBLY_STEP(9, "BBBBBBB", 7, "AAABBBBBBB", 10);
    RAWREASSEMBLY_STEP(16,"C", 1, "ABBBBBBBC", 9);
    RAWREASSEMBLY_STEP(17,"DDDDDDDD",8,"BBCDDDDDDDD", 11);
    RAWREASSEMBLY_END;
}

static int StreamTcpReassembleRawTest08 (void)
{
    RAWREASSEMBLY_START(1);
    RAWREASSEMBLY_STEP_WITH_PROGRESS(2, "AAA", 3, "AAA", 3, 3, 3);
    RAWREASSEMBLY_STEP_WITH_PROGRESS(8, "CCC", 3, "CCC", 3, 3, 3);
    // segment lost, last_ack updated
    RAWREASSEMBLY_STEP_WITH_PROGRESS(11, "DDD", 3, "CCCDDD", 6, 8, 12);
    RAWREASSEMBLY_END;
}

static void StreamTcpReassembleRawRegisterTests(void)
{
    UtRegisterTest("StreamTcpReassembleRawTest01",
                   StreamTcpReassembleRawTest01);
    UtRegisterTest("StreamTcpReassembleRawTest02",
                   StreamTcpReassembleRawTest02);
    UtRegisterTest("StreamTcpReassembleRawTest03",
                   StreamTcpReassembleRawTest03);
    UtRegisterTest("StreamTcpReassembleRawTest04",
                   StreamTcpReassembleRawTest04);
    UtRegisterTest("StreamTcpReassembleRawTest05",
                   StreamTcpReassembleRawTest05);
    UtRegisterTest("StreamTcpReassembleRawTest06",
                   StreamTcpReassembleRawTest06);
    UtRegisterTest("StreamTcpReassembleRawTest07",
                   StreamTcpReassembleRawTest07);
    UtRegisterTest("StreamTcpReassembleRawTest08",
                   StreamTcpReassembleRawTest08);
}
