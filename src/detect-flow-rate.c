/* Copyright (C) 2024 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "rust.h"
#include "detect-flow-rate.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

static int DetectFlowRateMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }

    uint64_t age = SCTIME_SECS(p->flow->lastts) - SCTIME_SECS(p->flow->startts);
    uint64_t rate = (p->flow->tosrcbytecnt + p->flow->todstbytecnt) / age;

    const DetectFlowRate *expected = (const DetectFlowRate *)ctx;
    return DetectU64Match(rate, expected->rate);
}

static int DetectFlowRateSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    DetectFlowRate *fr = SCCalloc(1, sizeof(DetectFlowRate));
    if (fr == NULL)
        return -1;

    fr->rate = du64;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOW_RATE, (SigMatchCtx *)fr, DETECT_SM_LIST_MATCH) == NULL) {
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void DetectFlowRateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlowRate *fr = (DetectFlowRate *)ptr;
    if (fr != NULL) {
        rs_detect_u64_free(fr->rate);
        SCFree(fr);
    }
}

void DetectFlowRateRegister(void)
{
    sigmatch_table[DETECT_FLOW_RATE].name = "flow.rate";
    sigmatch_table[DETECT_FLOW_RATE].desc = "match flow rate";
    sigmatch_table[DETECT_FLOW_RATE].url = "/rules/flow-keywords.html#flow-rate";
    sigmatch_table[DETECT_FLOW_RATE].Match = DetectFlowRateMatch;
    sigmatch_table[DETECT_FLOW_RATE].Setup = DetectFlowRateSetup;
    sigmatch_table[DETECT_FLOW_RATE].Free = DetectFlowRateFree;
}
