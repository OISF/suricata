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

#define OVERLAP_START(isn, policy)              \
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
    TcpStream *stream = &ssn.client;            \
    stream->os_policy = (policy);

#define OVERLAP_END                             \
    StreamTcpUTClearSession(&ssn);              \
    StreamTcpUTDeinit(ra_ctx);                  \
    PASS

#define OVERLAP_STEP(rseq, seg, seglen, buf, buflen) \
    StreamTcpUTAddPayload(&tv, ra_ctx, &ssn, stream, stream->isn + (rseq), (uint8_t *)(seg), (seglen));    \
    FAIL_IF(!(VALIDATE(stream, (uint8_t *)(buf), (buflen))));

static int OverlapBSD(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_BSD);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    /* AA not overwritten, gap filled and B overwritten because 'starts before' */
    OVERLAP_STEP(3, "JJJJ", 4, "\0AAAJJBCCC\0D\0\0EEFFFGGHHI", 24);
    /* no-op, overlaps CCC which takes precedence */
    OVERLAP_STEP(8, "KKK", 3, "\0AAAJJBCCC\0D\0\0EEFFFGGHHI", 24);
    /* LLL fills gaps and replaces D as it starts before */
    OVERLAP_STEP(11, "LLL", 3, "\0AAAJJBCCCLLL\0EEFFFGGHHI", 24);
    /* MMM fills gap and replaces EE as it starts before */
    OVERLAP_STEP(14, "MMM", 3, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(18, "N", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(21, "O", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(22, "P", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no replace of I as it starts the same */
    OVERLAP_STEP(24, "QQ", 2, "\0AAAJJBCCCLLLMMMFFFGGHHIQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AAAJJBCCCLLLMMMFFFGGHHIQ", 25);

    OVERLAP_END;
}

static int OverlapBSDBefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_BSD);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AA\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JJJJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JJJJ\0\0\0LLL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JJJJ\0\0\0LLLMMM", 13);

    OVERLAP_END;
}

static int OverlapBSDSame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_BSD);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    /* ignored as 'starts the same' */
    OVERLAP_STEP(1, "KKK", 3, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    /* original data not overwritten as it starts on the same seq */
    OVERLAP_STEP(1, "LLLL", 4, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);

    OVERLAP_END;
}

static int OverlapBSDAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_BSD);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(17, "N", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);

    OVERLAP_END;
}

static int OverlapVISTA(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_VISTA);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    /* AA not overwritten, gap filled and B not overwritten */
    OVERLAP_STEP(3, "JJJJ", 4, "\0AAAJBBCCC\0D\0\0EEFFFGGHHI", 24);
    /* no-op, overlaps CCC which takes precedence */
    OVERLAP_STEP(8, "KKK", 3, "\0AAAJBBCCC\0D\0\0EEFFFGGHHI", 24);
    /* LLL fills gaps only */
    OVERLAP_STEP(11, "LLL", 3, "\0AAAJBBCCCLDL\0EEFFFGGHHI", 24);
    /* MMM fills gap only */
    OVERLAP_STEP(14, "MMM", 3, "\0AAAJBBCCCLDLMEEFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(18, "N", 1, "\0AAAJBBCCCLDLMEEFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(21, "O", 1, "\0AAAJBBCCCLDLMEEFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(22, "P", 1, "\0AAAJBBCCCLDLMEEFFFGGHHI", 24);
    /* no replace of I */
    OVERLAP_STEP(24, "QQ", 2, "\0AAAJBBCCCLDLMEEFFFGGHHIQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AAAJBBCCCLDLMEEFFFGGHHIQ", 25);

    OVERLAP_END;
}

static int OverlapVISTABefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_VISTA);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AB\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JABJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JABJ\0\0\0LDL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JABJ\0\0\0LDLMEE", 13);

    OVERLAP_END;
}

static int OverlapVISTASame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_VISTA);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "KKK", 3, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "LLLL", 4, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "CCCL\0\0\0\0\0\0\0\0\0\0HHII", 18);

    OVERLAP_END;
}

static int OverlapVISTAAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_VISTA);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(17, "N", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);

    OVERLAP_END;
}

static int OverlapLINUX(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LINUX);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    /* AA not overwritten, gap filled and B not overwritten */
    OVERLAP_STEP(3, "JJJJ", 4, "\0AAAJJBCCC\0D\0\0EEFFFGGHHI", 24);
    /* no-op, overlaps CCC which takes precedence */
    OVERLAP_STEP(8, "KKK", 3, "\0AAAJJBCCC\0D\0\0EEFFFGGHHI", 24);
    /* LLL fills gaps and replaces as begins before */
    OVERLAP_STEP(11, "LLL", 3, "\0AAAJJBCCCLLL\0EEFFFGGHHI", 24);
    /* MMM fills gap and replaces EE as it begins before */
    OVERLAP_STEP(14, "MMM", 3, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(18, "N", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(21, "O", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(22, "P", 1, "\0AAAJJBCCCLLLMMMFFFGGHHI", 24);
    /* replaces of I as begins the same, ends after*/
    OVERLAP_STEP(24, "QQ", 2, "\0AAAJJBCCCLLLMMMFFFGGHHQQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AAAJJBCCCLLLMMMFFFGGHHQQ", 25);

    OVERLAP_END;
}

static int OverlapLINUXBefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LINUX);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AA\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JJJJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JJJJ\0\0\0LLL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JJJJ\0\0\0LLLMMM", 13);

    OVERLAP_END;
}

static int OverlapLINUXSame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LINUX);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "KKK", 3, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "LLLL", 4, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);

    OVERLAP_END;
}

static int OverlapLINUXAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LINUX);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(17, "N", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);

    OVERLAP_END;
}

static int OverlapLINUXOLD(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_OLD_LINUX);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    /* AA not overwritten as it starts before, gap filled and B overwritten */
    OVERLAP_STEP(3, "JJJJ", 4, "\0AAAJJBCCC\0D\0\0EEFFFGGHHI", 24);
    /* replace CCC */
    OVERLAP_STEP(8, "KKK", 3, "\0AAAJJBKKK\0D\0\0EEFFFGGHHI", 24);
    /* LLL fills gaps and replaces as begins before */
    OVERLAP_STEP(11, "LLL", 3, "\0AAAJJBKKKLLL\0EEFFFGGHHI", 24);
    /* MMM fills gap and replaces EE as it begins before */
    OVERLAP_STEP(14, "MMM", 3, "\0AAAJJBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(18, "N", 1, "\0AAAJJBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(21, "O", 1, "\0AAAJJBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(22, "P", 1, "\0AAAJJBKKKLLLMMMFFFGGHHI", 24);
    /* replaces of I as begins the same, ends after*/
    OVERLAP_STEP(24, "QQ", 2, "\0AAAJJBKKKLLLMMMFFFGGHHQQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AAAJJBKKKLLLMMMFFFGGHHQQ", 25);

    OVERLAP_END;
}

static int OverlapLINUXOLDBefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_OLD_LINUX);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AA\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JJJJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JJJJ\0\0\0LLL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JJJJ\0\0\0LLLMMM", 13);

    OVERLAP_END;
}

static int OverlapLINUXOLDSame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_OLD_LINUX);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "KKK", 3, "KKK\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "LLLL", 4, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "LLLL\0\0\0\0\0\0\0\0\0\0QQII", 18);

    OVERLAP_END;
}

static int OverlapLINUXOLDAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_OLD_LINUX);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(17, "N", 1, "AAJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);

    OVERLAP_END;
}

static int OverlapSOLARIS(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_SOLARIS);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    OVERLAP_STEP(3, "JJJJ", 4, "\0AJJJBBCCC\0D\0\0EEFFFGGHHI", 24);
    /* replace CCC */
    OVERLAP_STEP(8, "KKK", 3, "\0AJJJBBKKK\0D\0\0EEFFFGGHHI", 24);
    /* LLL fills gaps and replaces as begins before */
    OVERLAP_STEP(11, "LLL", 3, "\0AJJJBBKKKLLL\0EEFFFGGHHI", 24);
    /* MMM fills gap and replaces EE as it begins before */
    OVERLAP_STEP(14, "MMM", 3, "\0AJJJBBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(18, "N", 1, "\0AJJJBBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(21, "O", 1, "\0AJJJBBKKKLLLMMMFFFGGHHI", 24);
    /* no op */
    OVERLAP_STEP(22, "P", 1, "\0AJJJBBKKKLLLMMMFFFGGHHI", 24);
    /* replaces of I as begins the same, ends after*/
    OVERLAP_STEP(24, "QQ", 2, "\0AJJJBBKKKLLLMMMFFFGGHHQQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AJJJBBKKKLLLMMMFFFGGHHQQ", 25);

    OVERLAP_END;
}

static int OverlapSOLARISBefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_SOLARIS);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AA\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JJJJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JJJJ\0\0\0LLL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JJJJ\0\0\0LLLMMM", 13);

    OVERLAP_END;
}

static int OverlapSOLARISSame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_SOLARIS);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "KKK", 3, "KKK\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "LLLL", 4, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "LLLL\0\0\0\0\0\0\0\0\0\0QQII", 18);

    OVERLAP_END;
}

static int OverlapSOLARISAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_SOLARIS);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(17, "N", 1, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);

    OVERLAP_END;
}

static int OverlapLAST(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LAST);

    OVERLAP_STEP(2, "AAA", 3, "\0AAA", 4);
    OVERLAP_STEP(6, "BB", 2, "\0AAA\0BB", 7);
    OVERLAP_STEP(8, "CCC", 3, "\0AAA\0BBCCC", 10);
    OVERLAP_STEP(12, "D", 1, "\0AAA\0BBCCC\0D", 12);
    OVERLAP_STEP(15, "EE", 2, "\0AAA\0BBCCC\0D\0\0EE", 16);
    OVERLAP_STEP(17, "FFF", 3, "\0AAA\0BBCCC\0D\0\0EEFFF", 19);
    OVERLAP_STEP(20, "GG", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGG", 21);
    OVERLAP_STEP(22, "HH", 2, "\0AAA\0BBCCC\0D\0\0EEFFFGGHH", 23);
    OVERLAP_STEP(24, "I", 1, "\0AAA\0BBCCC\0D\0\0EEFFFGGHHI", 24);
    OVERLAP_STEP(3, "JJJJ", 4, "\0AJJJJBCCC\0D\0\0EEFFFGGHHI", 24);
    OVERLAP_STEP(8, "KKK", 3, "\0AJJJJBKKK\0D\0\0EEFFFGGHHI", 24);
    OVERLAP_STEP(11, "LLL", 3, "\0AJJJJBKKKLLL\0EEFFFGGHHI", 24);
    OVERLAP_STEP(14, "MMM", 3, "\0AJJJJBKKKLLLMMMFFFGGHHI", 24);
    OVERLAP_STEP(18, "N", 1, "\0AJJJJBKKKLLLMMMFNFGGHHI", 24);
    OVERLAP_STEP(21, "O", 1, "\0AJJJJBKKKLLLMMMFNFGOHHI", 24);
    OVERLAP_STEP(22, "P", 1, "\0AJJJJBKKKLLLMMMFNFGOPHI", 24);
    OVERLAP_STEP(24, "QQ", 2, "\0AJJJJBKKKLLLMMMFNFGOPHQQ", 25);
    OVERLAP_STEP(1, "0", 1, "0AJJJJBKKKLLLMMMFNFGOPHQQ", 25);

    OVERLAP_END;
}

static int OverlapLASTBefore(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LAST);

    OVERLAP_STEP(3, "B", 1, "\0\0B", 3);
    OVERLAP_STEP(9, "D", 1, "\0\0B\0\0\0\0\0D", 9);
    OVERLAP_STEP(12, "EE", 2, "\0\0B\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(2, "AA", 2, "\0AA\0\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(1, "JJJJ", 4, "JJJJ\0\0\0\0D\0\0EE", 13);
    OVERLAP_STEP(8, "LLL", 3, "JJJJ\0\0\0LLL\0EE", 13);
    OVERLAP_STEP(11,"MMM", 3, "JJJJ\0\0\0LLLMMM", 13);

    OVERLAP_END;
}

static int OverlapLASTSame(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LAST);

    OVERLAP_STEP(1, "CCC", 3, "CCC", 3);
    OVERLAP_STEP(15, "HH", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HH", 16);
    OVERLAP_STEP(17, "II", 2, "CCC\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "KKK", 3, "KKK\0\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(1, "LLLL", 4, "LLLL\0\0\0\0\0\0\0\0\0\0HHII", 18);
    OVERLAP_STEP(15, "P", 1, "LLLL\0\0\0\0\0\0\0\0\0\0PHII", 18);
    OVERLAP_STEP(15, "QQ", 2, "LLLL\0\0\0\0\0\0\0\0\0\0QQII", 18);

    OVERLAP_END;
}

static int OverlapLASTAfter(uint32_t isn)
{
    OVERLAP_START(isn, OS_POLICY_LAST);

    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(16, "FFF", 3, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFF", 18);
    OVERLAP_STEP(19, "GG", 2, "AA\0\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(2, "JJ", 2, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGG", 20);
    OVERLAP_STEP(20, "O", 1, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FFFGO", 20);
    OVERLAP_STEP(17, "N", 1, "AJJ\0\0\0\0\0\0\0\0\0\0\0\0FNFGO", 20);

    OVERLAP_END;
}

/** \test BSD policy
 */
static int StreamTcpReassembleTest01(void)
{
    FAIL_IF(OverlapBSD(0) == 0);
    OverlapBSDBefore(0);
    OverlapBSDSame(0);
    OverlapBSDAfter(0);

    OverlapBSD(1);
    OverlapBSDBefore(1);
    OverlapBSDSame(1);
    OverlapBSDAfter(1);

    OverlapBSD(UINT_MAX);
    OverlapBSDBefore(UINT_MAX);
    OverlapBSDSame(UINT_MAX);
    OverlapBSDAfter(UINT_MAX);

    OverlapBSD(UINT_MAX - 10);
    OverlapBSDBefore(UINT_MAX - 10);
    OverlapBSDSame(UINT_MAX - 10);
    OverlapBSDAfter(UINT_MAX - 10);
    return 1;
}


/** \test Vista Policy
 */
static int StreamTcpReassembleTest02(void)
{
    OverlapVISTA(0);
    OverlapVISTABefore(0);
    OverlapVISTASame(0);
    OverlapVISTAAfter(0);

    OverlapVISTA(1);
    OverlapVISTABefore(1);
    OverlapVISTASame(1);
    OverlapVISTAAfter(1);

    OverlapVISTA(UINT_MAX);
    OverlapVISTABefore(UINT_MAX);
    OverlapVISTASame(UINT_MAX);
    OverlapVISTAAfter(UINT_MAX);

    OverlapVISTA(UINT_MAX - 10);
    OverlapVISTABefore(UINT_MAX - 10);
    OverlapVISTASame(UINT_MAX - 10);
    OverlapVISTAAfter(UINT_MAX - 10);
    return 1;
}


/** \test Linux policy
 */
static int StreamTcpReassembleTest03(void)
{
    OverlapLINUX(0);
    OverlapLINUXBefore(0);
    OverlapLINUXSame(0);
    OverlapLINUXAfter(0);

    OverlapLINUX(1);
    OverlapLINUXBefore(1);
    OverlapLINUXSame(1);
    OverlapLINUXAfter(1);

    OverlapLINUX(UINT_MAX);
    OverlapLINUXBefore(UINT_MAX);
    OverlapLINUXSame(UINT_MAX);
    OverlapLINUXAfter(UINT_MAX);

    OverlapLINUX(UINT_MAX - 10);
    OverlapLINUXBefore(UINT_MAX - 10);
    OverlapLINUXSame(UINT_MAX - 10);
    OverlapLINUXAfter(UINT_MAX - 10);
    return 1;
}

/** \test policy Linux old
 */
static int StreamTcpReassembleTest04(void)
{
    OverlapLINUXOLD(0);
    OverlapLINUXOLDBefore(0);
    OverlapLINUXOLDSame(0);
    OverlapLINUXOLDAfter(0);

    OverlapLINUXOLD(1);
    OverlapLINUXOLDBefore(1);
    OverlapLINUXOLDSame(1);
    OverlapLINUXOLDAfter(1);

    OverlapLINUXOLD(UINT_MAX);
    OverlapLINUXOLDBefore(UINT_MAX);
    OverlapLINUXOLDSame(UINT_MAX);
    OverlapLINUXOLDAfter(UINT_MAX);

    OverlapLINUXOLD(UINT_MAX - 10);
    OverlapLINUXOLDBefore(UINT_MAX - 10);
    OverlapLINUXOLDSame(UINT_MAX - 10);
    OverlapLINUXOLDAfter(UINT_MAX - 10);
    return 1;
}

/** \test Solaris policy
 */
static int StreamTcpReassembleTest05(void)
{
    OverlapSOLARIS(0);
    OverlapSOLARISBefore(0);
    OverlapSOLARISSame(0);
    OverlapSOLARISAfter(0);

    OverlapSOLARIS(1);
    OverlapSOLARISBefore(1);
    OverlapSOLARISSame(1);
    OverlapSOLARISAfter(1);

    OverlapSOLARIS(UINT_MAX);
    OverlapSOLARISBefore(UINT_MAX);
    OverlapSOLARISSame(UINT_MAX);
    OverlapSOLARISAfter(UINT_MAX);

    OverlapSOLARIS(UINT_MAX - 10);
    OverlapSOLARISBefore(UINT_MAX - 10);
    OverlapSOLARISSame(UINT_MAX - 10);
    OverlapSOLARISAfter(UINT_MAX - 10);
    return 1;
}

/** \test policy 'last'
 */
static int StreamTcpReassembleTest06(void)
{
    OverlapLAST(0);
    OverlapLASTBefore(0);
    OverlapLASTSame(0);
    OverlapLASTAfter(0);

    OverlapLAST(1);
    OverlapLASTBefore(1);
    OverlapLASTSame(1);
    OverlapLASTAfter(1);

    OverlapLAST(UINT_MAX);
    OverlapLASTBefore(UINT_MAX);
    OverlapLASTSame(UINT_MAX);
    OverlapLASTAfter(UINT_MAX);

    OverlapLAST(UINT_MAX - 10);
    OverlapLASTBefore(UINT_MAX - 10);
    OverlapLASTSame(UINT_MAX - 10);
    OverlapLASTAfter(UINT_MAX - 10);
    return 1;
}

static int StreamTcpReassembleTest30 (void)
{
    OVERLAP_START(9, OS_POLICY_BSD);
    OVERLAP_STEP(3, "BBB", 3, "\0\0BBB", 5);
    OVERLAP_STEP(1, "AA", 2, "AABBB", 5);
    OVERLAP_END;
}

static int StreamTcpReassembleTest31 (void)
{
    OVERLAP_START(9, OS_POLICY_BSD);
    OVERLAP_STEP(1, "AA", 2, "AA", 2);
    OVERLAP_STEP(3, "BBB", 3, "AABBB", 5);
    OVERLAP_END;
}

static int StreamTcpReassembleTest32(void)
{
    OVERLAP_START(0, OS_POLICY_BSD);
    OVERLAP_STEP(11, "AAAAAAAAAA", 10, "\0\0\0\0\0\0\0\0\0\0AAAAAAAAAA", 20);
    OVERLAP_STEP(21, "BBBBBBBBBB", 10, "\0\0\0\0\0\0\0\0\0\0AAAAAAAAAABBBBBBBBBB", 30);
    OVERLAP_STEP(41, "CCCCCCCCCC", 10, "\0\0\0\0\0\0\0\0\0\0AAAAAAAAAABBBBBBBBBB\0\0\0\0\0\0\0\0\0\0CCCCCCCCCC", 50);
    OVERLAP_STEP(6,  "aaaaaaaaaaaaaaaaaaaa", 20, "\0\0\0\0\0aaaaaaaaaaaaaaaaaaaaBBBBB\0\0\0\0\0\0\0\0\0\0CCCCCCCCCC", 50);
    OVERLAP_STEP(1,  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 50, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 50);
    OVERLAP_END;
}

void StreamTcpListRegisterTests(void)
{
    UtRegisterTest("StreamTcpReassembleTest01 -- BSD policy",
            StreamTcpReassembleTest01);
    UtRegisterTest("StreamTcpReassembleTest02 -- VISTA policy",
            StreamTcpReassembleTest02);
    UtRegisterTest("StreamTcpReassembleTest03 -- LINUX policy",
            StreamTcpReassembleTest03);
    UtRegisterTest("StreamTcpReassembleTest04 -- LINUX-OLD policy",
            StreamTcpReassembleTest04);
    UtRegisterTest("StreamTcpReassembleTest05 -- SOLARIS policy",
            StreamTcpReassembleTest05);
    UtRegisterTest("StreamTcpReassembleTest06 -- LAST policy",
            StreamTcpReassembleTest06);

    UtRegisterTest("StreamTcpReassembleTest30",
            StreamTcpReassembleTest30);
    UtRegisterTest("StreamTcpReassembleTest31",
            StreamTcpReassembleTest31);
    UtRegisterTest("StreamTcpReassembleTest32",
            StreamTcpReassembleTest32);

}
