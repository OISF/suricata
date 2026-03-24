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

/**
 * \file
 *
 * Implements sctp.chunk_cnt keyword
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-sctp-chunk-cnt.h"
#include "detect-engine-uint.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectSCTPChunkCntMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectSCTPChunkCntSetup(DetectEngineCtx *, Signature *, const char *);
void DetectSCTPChunkCntFree(DetectEngineCtx *, void *);

static int PrefilterSetupSCTPChunkCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterSCTPChunkCntIsPrefilterable(const Signature *s);

#ifdef UNITTESTS
void DetectSCTPChunkCntRegisterTests(void);
#endif

void DetectSCTPChunkCntRegister(void)
{
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].name = "sctp.chunk_cnt";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].desc = "match on the SCTP chunk count";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].url = "/rules/header-keywords.html#sctp-chunk-cnt";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Match = DetectSCTPChunkCntMatch;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Setup = DetectSCTPChunkCntSetup;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Free = DetectSCTPChunkCntFree;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].flags = SIGMATCH_INFO_UINT8;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].SupportsPrefilter = PrefilterSCTPChunkCntIsPrefilterable;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].SetupPrefilter = PrefilterSetupSCTPChunkCnt;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].RegisterTests = DetectSCTPChunkCntRegisterTests;
#endif
}

static int DetectSCTPChunkCntMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!PacketIsSCTP(p)) {
        return 0;
    }

    uint8_t val = p->l4.vars.sctp.chunk_cnt;
    const DetectU8Data *data = (const DetectU8Data *)ctx;
    return DetectU8Match(val, data);
}

static int DetectSCTPChunkCntSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    DetectU8Data *data = DetectU8Parse(str);
    if (data == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_SCTP_CHUNK_CNT, (SigMatchCtx *)data,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectSCTPChunkCntFree(de_ctx, data);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

void DetectSCTPChunkCntFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectU8Data *data = (DetectU8Data *)ptr;
    SCDetectU8Free(data);
}

static void PrefilterPacketSCTPChunkCntMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (PacketIsSCTP(p)) {
        uint8_t val = p->l4.vars.sctp.chunk_cnt;
        const PrefilterPacketU8HashCtx *h = pectx;
        const SigsArray *sa = h->array[val];
        if (sa) {
            PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
        }
    }
}

static int PrefilterSetupSCTPChunkCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_SCTP_CHUNK_CNT,
            SIG_MASK_REQUIRE_REAL_PKT, PrefilterPacketU8Set, PrefilterPacketU8Compare,
            PrefilterPacketSCTPChunkCntMatch);
}

static bool PrefilterSCTPChunkCntIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_SCTP_CHUNK_CNT);
}

#ifdef UNITTESTS
#include "tests/detect-sctp-chunk-cnt.c"
#endif
