/* Copyright (C) 2026 Open Information Security Foundation
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

#include "../detect.h"
#include "../detect-engine.h"
#include "../detect-parse.h"

#include "../detect-sctp-chunk-type.h"

#include "../util-unittest.h"

static int DetectSCTPChunkTypeParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* valid: match INIT chunk type */
    FAIL_IF_NULL(DetectEngineAppendSig(de_ctx, "alert sctp any any -> any any "
                                               "(msg:\"test\"; sctp.chunk_type:1; sid:1;)"));

    /* invalid: non-numeric value */
    FAIL_IF_NOT_NULL(DetectEngineAppendSig(de_ctx, "alert sctp any any -> any any "
                                                   "(msg:\"test\"; sctp.chunk_type:foo; sid:2;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test match on a non-first chunk: bundled [DATA, SACK], match sctp.chunk_type:3 */
static int DetectSCTPChunkTypeMatchNonFirstTest(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x01, /* vtag=1 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        /* DATA chunk: type=0x00, flags=0x03, len=20 */
        0x00, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, /* TSN=0 */
        0x00, 0x01, 0x00, 0x00,                         /* stream_id=1, stream_seq=0 */
        0x00, 0x00, 0x00, 0x00,                         /* PPID=0 */
        0x41, 0x42, 0x43, 0x44,                         /* data="ABCD" */
        /* SACK chunk: type=0x03, flags=0x00, len=16 */
        0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF_NOT(PacketIsSCTP(p));

    FAIL_IF(p->l4.vars.sctp.chunk_types[0] != SCTP_CHUNK_TYPE_DATA);
    FAIL_IF(p->l4.vars.sctp.chunk_types[1] != SCTP_CHUNK_TYPE_SACK);

    DetectU8Data *data = DetectU8Parse("3");
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(DetectSCTPChunkTypeMatch(NULL, p, NULL, (const SigMatchCtx *)data) == 1);
    DetectSCTPChunkTypeFree(NULL, data);

    data = DetectU8Parse("7");
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(DetectSCTPChunkTypeMatch(NULL, p, NULL, (const SigMatchCtx *)data) == 0);
    DetectSCTPChunkTypeFree(NULL, data);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

void DetectSCTPChunkTypeRegisterTests(void)
{
    UtRegisterTest("DetectSCTPChunkTypeParseTest01", DetectSCTPChunkTypeParseTest01);
    UtRegisterTest("DetectSCTPChunkTypeMatchNonFirstTest", DetectSCTPChunkTypeMatchNonFirstTest);
}
