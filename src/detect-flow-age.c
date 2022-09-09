/* Copyright (C) 2022 Open Information Security Foundation
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
#include "detect-flow-age.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

static int DetectFlowAgeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }
    uint32_t age = p->flow->lastts.tv_sec - p->flow->startts.tv_sec;

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(age, du32);
}

static void DetectFlowAgeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

static int DetectFlowAgeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectFlowAgeFree(de_ctx, du32);
        return -1;
    }

    sm->type = DETECT_FLOW_AGE;
    sm->ctx = (SigMatchCtx *)du32;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketFlowAgeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU32Data du32;
    du32.mode = ctx->v1.u8[0];
    du32.arg1 = ctx->v1.u32[1];
    du32.arg2 = ctx->v1.u32[2];
    if (DetectFlowAgeMatch(det_ctx, p, NULL, (const SigMatchCtx *)&du32)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFlowAge(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW_AGE, PrefilterPacketU32Set,
            PrefilterPacketU32Compare, PrefilterPacketFlowAgeMatch);
}

static bool PrefilterFlowAgeIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_FLOW_AGE);
}

void DetectFlowAgeRegister(void)
{
    sigmatch_table[DETECT_FLOW_AGE].name = "flow.age";
    sigmatch_table[DETECT_FLOW_AGE].desc = "match flow age";
    sigmatch_table[DETECT_FLOW_AGE].url = "/rules/flow-keywords.html#flow-age";
    sigmatch_table[DETECT_FLOW_AGE].Match = DetectFlowAgeMatch;
    sigmatch_table[DETECT_FLOW_AGE].Setup = DetectFlowAgeSetup;
    sigmatch_table[DETECT_FLOW_AGE].Free = DetectFlowAgeFree;
    sigmatch_table[DETECT_FLOW_AGE].SupportsPrefilter = PrefilterFlowAgeIsPrefilterable;
    sigmatch_table[DETECT_FLOW_AGE].SetupPrefilter = PrefilterSetupFlowAge;
}
