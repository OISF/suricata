/* Copyright (C) 2023 Open Information Security Foundation
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

#include "suricata-common.h"
#include "rust.h"
#include "detect-flow-pkts.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

static int DetectFlowPktsToClientMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }
    uint32_t nb = p->flow->tosrcpktcnt;

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(nb, du32);
}

static void DetectFlowPktsToClientFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

static int DetectFlowPktsToClientSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_PKTS_TO_CLIENT, (SigMatchCtx *)du32,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowPktsToClientFree(de_ctx, du32);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketFlowPktsToClientMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU32Data du32;
    du32.mode = ctx->v1.u8[0];
    du32.arg1 = ctx->v1.u32[1];
    du32.arg2 = ctx->v1.u32[2];
    if (DetectFlowPktsToClientMatch(det_ctx, p, NULL, (const SigMatchCtx *)&du32)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFlowPktsToClient(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW_PKTS_TO_CLIENT,
            SIG_MASK_REQUIRE_FLOW, PrefilterPacketU32Set, PrefilterPacketU32Compare,
            PrefilterPacketFlowPktsToClientMatch);
}

static bool PrefilterFlowPktsToClientIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_FLOW_PKTS_TO_CLIENT);
}

void DetectFlowPktsToClientRegister(void)
{
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].name = "flow.pkts_toclient";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].desc = "match flow number of packets to client";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].url = "/rules/flow-keywords.html#flow-pkts_toclient";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Match = DetectFlowPktsToClientMatch;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Setup = DetectFlowPktsToClientSetup;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Free = DetectFlowPktsToClientFree;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].SupportsPrefilter =
            PrefilterFlowPktsToClientIsPrefilterable;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].SetupPrefilter = PrefilterSetupFlowPktsToClient;
}

static int DetectFlowPktsToServerMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }
    uint32_t nb = p->flow->todstpktcnt;

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(nb, du32);
}

static void DetectFlowPktsToServerFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

static int DetectFlowPktsToServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_PKTS_TO_SERVER, (SigMatchCtx *)du32,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowPktsToServerFree(de_ctx, du32);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketFlowPktsToServerMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU32Data du32;
    du32.mode = ctx->v1.u8[0];
    du32.arg1 = ctx->v1.u32[1];
    du32.arg2 = ctx->v1.u32[2];
    if (DetectFlowPktsToServerMatch(det_ctx, p, NULL, (const SigMatchCtx *)&du32)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFlowPktsToServer(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW_PKTS_TO_SERVER,
            SIG_MASK_REQUIRE_FLOW, PrefilterPacketU32Set, PrefilterPacketU32Compare,
            PrefilterPacketFlowPktsToServerMatch);
}

static bool PrefilterFlowPktsToServerIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_FLOW_PKTS_TO_SERVER);
}

void DetectFlowPktsToServerRegister(void)
{
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].name = "flow.pkts_toserver";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].desc = "match flow number of packets to server";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].url = "/rules/flow-keywords.html#flow-pkts_toserver";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Match = DetectFlowPktsToServerMatch;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Setup = DetectFlowPktsToServerSetup;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Free = DetectFlowPktsToServerFree;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].SupportsPrefilter =
            PrefilterFlowPktsToServerIsPrefilterable;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].SetupPrefilter = PrefilterSetupFlowPktsToServer;
}

static int DetectFlowBytesToClientMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }
    uint64_t nb = p->flow->tosrcbytecnt;

    const DetectU64Data *du64 = (const DetectU64Data *)ctx;
    return DetectU64Match(nb, du64);
}

static void DetectFlowBytesToClientFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
}

static int DetectFlowBytesToClientSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_BYTES_TO_CLIENT, (SigMatchCtx *)du64,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowBytesToClientFree(de_ctx, du64);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

void DetectFlowBytesToClientRegister(void)
{
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].name = "flow.bytes_toclient";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].desc = "match flow number of bytes to client";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].url =
            "/rules/flow-keywords.html#flow-bytes_toclient";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Match = DetectFlowBytesToClientMatch;
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Setup = DetectFlowBytesToClientSetup;
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Free = DetectFlowBytesToClientFree;
}

static int DetectFlowBytesToServerMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }
    uint64_t nb = p->flow->todstbytecnt;

    const DetectU64Data *du64 = (const DetectU64Data *)ctx;
    return DetectU64Match(nb, du64);
}

static void DetectFlowBytesToServerFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
}

static int DetectFlowBytesToServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_BYTES_TO_SERVER, (SigMatchCtx *)du64,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowBytesToServerFree(de_ctx, du64);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

void DetectFlowBytesToServerRegister(void)
{
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].name = "flow.bytes_toserver";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].desc = "match flow number of bytes to server";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].url =
            "/rules/flow-keywords.html#flow-bytes_toserver";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Match = DetectFlowBytesToServerMatch;
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Setup = DetectFlowBytesToServerSetup;
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Free = DetectFlowBytesToServerFree;
}
