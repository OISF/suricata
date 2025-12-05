/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 *
 * Elephant flow detection.
 */

#include "suricata-common.h"
#include "rust.h"
#include "flow.h"
#include "detect-flow-elephant.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-parse.h"

static int DetectFlowElephantMatchAux(Packet *p, const DetectFlowDir *fdir)
{
    bool flow_toserver_iselephant = p->flow->flags & FLOW_IS_ELEPHANT_TOSERVER ? true : false;
    bool flow_toclient_iselephant = p->flow->flags & FLOW_IS_ELEPHANT_TOCLIENT ? true : false;

    if (*fdir == DETECT_FLOW_TOSERVER) {
        return flow_toserver_iselephant;
    } else if (*fdir == DETECT_FLOW_TOCLIENT) {
        return flow_toclient_iselephant;
    } else if (*fdir == DETECT_FLOW_TOEITHER) {
        return flow_toserver_iselephant || flow_toclient_iselephant;
    } else if (*fdir == DETECT_FLOW_TOBOTH) {
        return flow_toserver_iselephant && flow_toclient_iselephant;
    }

    SCLogError("Invalid direction argument");
    return -1;
}

static int DetectFlowElephantMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }

    DetectFlowDir *fdir = (DetectFlowDir *)ctx;

    return DetectFlowElephantMatchAux(p, fdir);
}

static int DetectFlowElephantSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlowDir *fdir = SCDetectFlowDir(rawstr);
    if (fdir == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_ELEPHANT, (SigMatchCtx *)fdir,
                DETECT_SM_LIST_MATCH) == NULL) {
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void DetectFlowElephantFree(DetectEngineCtx *de_ctx, void *dfd)
{
    SCDetectFlowDirFree(dfd);
}

/* prefilter code */

static void PrefilterPacketFlowElephantMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (p->flow == NULL)
        return;

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectFlowDir dfd = ctx->v1.u8[0];
    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (DetectFlowElephantMatchAux(p, &dfd)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketFlowElephantSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectFlowDir *a = smctx;
    v->u8[0] = *a;
}

static bool PrefilterPacketFlowElephantCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectFlowDir *a = smctx;
    if (v.u8[0] == *a)
        return true;
    return false;
}

static int PrefilterSetupFlowElephant(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW_ELEPHANT, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketFlowElephantSet, PrefilterPacketFlowElephantCompare,
            PrefilterPacketFlowElephantMatch);
}

static bool PrefilterFlowElephantIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_FLOW_ELEPHANT);
}

void DetectFlowElephantRegister(void)
{
    sigmatch_table[DETECT_FLOW_ELEPHANT].name = "flow.elephant";
    sigmatch_table[DETECT_FLOW_ELEPHANT].desc = "match elephant flow";
    sigmatch_table[DETECT_FLOW_ELEPHANT].url = "/rules/flow-keywords.html#flow-elephant";
    sigmatch_table[DETECT_FLOW_ELEPHANT].Match = DetectFlowElephantMatch;
    sigmatch_table[DETECT_FLOW_ELEPHANT].Setup = DetectFlowElephantSetup;
    sigmatch_table[DETECT_FLOW_ELEPHANT].Free = DetectFlowElephantFree;
    sigmatch_table[DETECT_FLOW_ELEPHANT].SupportsPrefilter = PrefilterFlowElephantIsPrefilterable;
    sigmatch_table[DETECT_FLOW_ELEPHANT].SetupPrefilter = PrefilterSetupFlowElephant;
}
