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
#include "util-debug.h"

static int DetectSCTPChunkCntMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectSCTPChunkCntSetup(DetectEngineCtx *, Signature *, const char *);
void DetectSCTPChunkCntFree(DetectEngineCtx *, void *);

static int PrefilterSetupSCTPChunkCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterSCTPChunkCntIsPrefilterable(const Signature *s);

void DetectSCTPChunkCntRegister(void)
{
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].name = "sctp.chunk_cnt";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].desc = "match on the SCTP chunk count";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].url = "/rules/sctp-keywords.html#sctp-chunk-cnt";
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Match = DetectSCTPChunkCntMatch;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Setup = DetectSCTPChunkCntSetup;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].Free = DetectSCTPChunkCntFree;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].flags = SIGMATCH_INFO_UINT16;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].SupportsPrefilter = PrefilterSCTPChunkCntIsPrefilterable;
    sigmatch_table[DETECT_SCTP_CHUNK_CNT].SetupPrefilter = PrefilterSetupSCTPChunkCnt;
}

static int DetectSCTPChunkCntMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!PacketIsSCTP(p)) {
        return 0;
    }

    uint16_t val = p->l4.vars.sctp.chunk_cnt;
    const DetectU16Data *data = (const DetectU16Data *)ctx;
    return DetectU16Match(val, data);
}

static int DetectSCTPChunkCntSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectU16Data *data = DetectU16Parse(str);
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
    DetectU16Data *data = (DetectU16Data *)ptr;
    SCDetectU16Free(data);
}

static void PrefilterPacketSCTPChunkCntMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (PacketIsSCTP(p)) {
        uint16_t val = p->l4.vars.sctp.chunk_cnt;
        const PrefilterPacketHeaderCtx *ctx = pectx;
        DetectU16Data du16;
        du16.mode = ctx->v1.u8[0];
        du16.arg1 = ctx->v1.u16[1];
        du16.arg2 = ctx->v1.u16[2];
        if (DetectU16Match(val, &du16)) {
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
        }
    }
}

static int PrefilterSetupSCTPChunkCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_SCTP_CHUNK_CNT, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU16Set, PrefilterPacketU16Compare, PrefilterPacketSCTPChunkCntMatch);
}

static bool PrefilterSCTPChunkCntIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_SCTP_CHUNK_CNT);
}
