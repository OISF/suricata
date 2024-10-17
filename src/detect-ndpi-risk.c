/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
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
 * \author Luca Deri <deri@ntop.org>
 * \author Alfredo Cardigliano <cardigliano@ntop.org>
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-parse.h"
#include "detect-ndpi-risk.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifdef HAVE_NDPI

#ifdef UNITTESTS
static void DetectnDPIRiskRegisterTests(void);
#endif

typedef struct DetectnDPIRiskData_ {
    ndpi_risk risk_mask; /* uint64 */
    uint8_t negated;
} DetectnDPIRiskData;

static int DetectnDPIRiskPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    bool r;
    const DetectnDPIRiskData *data = (const DetectnDPIRiskData *)ctx;

    if (!p->flow->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi risks not yet detected", p->pcap_cnt);
        SCReturnInt(0);
    }

    const Flow *f = p->flow;
    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", p->pcap_cnt);
        SCReturnInt(0);
    }

    r = ((f->ndpi_flow->risk & data->risk_mask) == data->risk_mask);
    r = r ^ data->negated;

    if (r) {
        SCLogDebug("ndpi risks match on risk bitmap =  %" PRIu64 " (matching bitmap %" PRIu64 ")",
                f->ndpi_flow->risk, data->risk_mask);
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

static DetectnDPIRiskData *DetectnDPIRiskParse(const char *arg, bool negate)
{
    DetectnDPIRiskData *data;
    struct ndpi_detection_module_struct *ndpi_struct;
    ndpi_risk risk_mask;
    NDPI_PROTOCOL_BITMASK all;

    /* convert list of risk names (string) to mask */
    ndpi_struct = ndpi_init_detection_module(NULL);
    if (unlikely(ndpi_struct == NULL))
        return NULL;

    ndpi_struct = ndpi_init_detection_module(NULL);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    ndpi_finalize_initialization(ndpi_struct);

    if (isdigit(arg[0]))
        risk_mask = atoll(arg);
    else {
        char *dup = SCStrdup(arg), *tmp, *token;

        NDPI_ZERO_BIT(risk_mask);

        if (dup != NULL) {
            token = strtok_r(dup, ",", &tmp);

            while (token != NULL) {
                ndpi_risk_enum risk_id = ndpi_code2risk(token);
                if (risk_id >= NDPI_MAX_RISK) {
                    SCLogError("unrecognized risk '%s', "
                               "please check ndpiReader -H for valid risk codes",
                            token);
                    return NULL;
                }
                NDPI_SET_BIT(risk_mask, risk_id);
                token = strtok_r(NULL, ",", &tmp);
            }

            SCFree(dup);
        }
    }

    data = SCMalloc(sizeof(DetectnDPIRiskData));
    if (unlikely(data == NULL))
        return NULL;

    data->risk_mask = risk_mask;
    data->negated = negate;

    return data;
}

static bool HasConflicts(const DetectnDPIRiskData *us, const DetectnDPIRiskData *them)
{
    /* check for duplicate */
    if (us->risk_mask == them->risk_mask)
        return true;

    return false;
}

static int DetectnDPIRiskSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectnDPIRiskData *data = NULL;

    data = DetectnDPIRiskParse(arg, s->init_data->negated);
    if (data == NULL)
        goto error;

    SigMatch *tsm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; tsm != NULL; tsm = tsm->next) {
        if (tsm->type == DETECT_NDPI_RISK) {
            const DetectnDPIRiskData *them = (const DetectnDPIRiskData *)tsm->ctx;

            if (HasConflicts(data, them)) {
                SCLogError("can't mix "
                           "positive ndpi-risk match with negated");
                goto error;
            }
        }
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_NDPI_RISK, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static void DetectnDPIRiskFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/** \internal
 *    \brief prefilter function for risk matching
 */
static void PrefilterPacketnDPIRiskMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (p->flow == NULL || !p->flow->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": no flow, no ndpi detection", p->pcap_cnt);
        SCReturn;
    }

    Flow *f = p->flow;
    bool negated = (bool)ctx->v1.u8[9];
    ndpi_risk risk_mask = ctx->v1.u64[0];
    bool ret = ((f->ndpi_flow->risk & risk_mask) == risk_mask) ? true : false;

    if (ret ^ negated) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketnDPIRiskSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectnDPIRiskData *a = smctx;

    v->u64[0] = a->risk_mask;
    v->u8[9] = (uint8_t)a->negated;
}

static bool PrefilterPacketnDPIRiskCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectnDPIRiskData *a = smctx;
    ndpi_risk p = v.u64[0];
    bool negated = (bool)v.u8[9];
    bool ret;

    ret = ((a->risk_mask & p) == p) ? true : false;
    return (ret ^ negated);
}

static int PrefilterSetupnDPIRisk(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_NDPI_RISK, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketnDPIRiskSet, PrefilterPacketnDPIRiskCompare,
            PrefilterPacketnDPIRiskMatch);
}

static bool PrefilternDPIRiskIsPrefilterable(const Signature *s)
{
    if (s->type == SIG_TYPE_PDONLY) {
        SCLogDebug("prefilter on PD %u", s->id);
        return true;
    }
    return false;
}

void DetectnDPIRiskRegister(void)
{
    sigmatch_table[DETECT_NDPI_RISK].name = "ndpi-risk";
    sigmatch_table[DETECT_NDPI_RISK].desc = "match on the detected nDPI risk";
    sigmatch_table[DETECT_NDPI_RISK].url = "/rules/ndpi-risk.html";
    sigmatch_table[DETECT_NDPI_RISK].Match = DetectnDPIRiskPacketMatch;
    sigmatch_table[DETECT_NDPI_RISK].Setup = DetectnDPIRiskSetup;
    sigmatch_table[DETECT_NDPI_RISK].Free = DetectnDPIRiskFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_NDPI_RISK].RegisterTests = DetectnDPIRiskRegisterTests;
#endif
    sigmatch_table[DETECT_NDPI_RISK].flags = (SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION);

    sigmatch_table[DETECT_NDPI_RISK].SetupPrefilter = PrefilterSetupnDPIRisk;
    sigmatch_table[DETECT_NDPI_RISK].SupportsPrefilter = PrefilternDPIRiskIsPrefilterable;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS

static int DetectnDPIRiskTest01(void)
{
    DetectnDPIRiskData *data = DetectnDPIRiskParse("NDPI_PROBING_ATTEMPT", false);
    FAIL_IF_NULL(data);
    FAIL_IF(!(NDPI_ISSET_BIT(data->risk_mask, NDPI_PROBING_ATTEMPT)));
    FAIL_IF(data->negated != 0);
    DetectnDPIRiskFree(NULL, data);
    PASS;
}

static int DetectnDPIRiskTest02(void)
{
    DetectnDPIRiskData *data = DetectnDPIRiskParse("NDPI_PROBING_ATTEMPT", true);
    FAIL_IF_NULL(data);
    FAIL_IF(!(NDPI_ISSET_BIT(data->risk_mask, NDPI_PROBING_ATTEMPT)));
    FAIL_IF(data->negated == 0);
    DetectnDPIRiskFree(NULL, data);
    PASS;
}

static int DetectnDPIRiskTest03(void)
{
    Signature *s = NULL;
    DetectnDPIRiskData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(ndpi-risk:NDPI_PROBING_ATTEMPT; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectnDPIRiskData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF(!(NDPI_ISSET_BIT(data->risk_mask, NDPI_PROBING_ATTEMPT)));
    FAIL_IF(data->negated);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectnDPIRiskTest04(void)
{
    Signature *s = NULL;
    DetectnDPIRiskData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(ndpi-risk:!NDPI_PROBING_ATTEMPT; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectnDPIRiskData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NULL(data);

    FAIL_IF(!(NDPI_ISSET_BIT(data->risk_mask, NDPI_PROBING_ATTEMPT)));
    FAIL_IF(data->negated == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectnDPIRiskRegisterTests(void)
{
    UtRegisterTest("DetectnDPIRiskTest01", DetectnDPIRiskTest01);
    UtRegisterTest("DetectnDPIRiskTest02", DetectnDPIRiskTest02);
    UtRegisterTest("DetectnDPIRiskTest03", DetectnDPIRiskTest03);
    UtRegisterTest("DetectnDPIRiskTest04", DetectnDPIRiskTest04);
}

#endif /* UNITTESTS */

#endif /* HAVE_NDPI */
