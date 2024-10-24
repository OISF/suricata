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
#include "detect-ndpi-protocol.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifdef HAVE_NDPI

#ifdef UNITTESTS
static void DetectnDPIProtocolRegisterTests(void);
#endif

typedef struct DetectnDPIProtocolData_ {
    ndpi_master_app_protocol l7_protocol;
    uint8_t negated;
} DetectnDPIProtocolData;

static int DetectnDPIProtocolPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    bool r;
    const DetectnDPIProtocolData *data = (const DetectnDPIProtocolData *)ctx;

    /* if the sig is PD-only we only match when PD packet flags are set */
    /*
    if (s->type == SIG_TYPE_PDONLY &&
            (p->flags & (PKT_PROTO_DETECT_TS_DONE | PKT_PROTO_DETECT_TC_DONE)) == 0) {
        SCLogDebug("packet %"PRIu64": flags not set", p->pcap_cnt);
        SCReturnInt(0);
    }
    */

    if (!p->flow->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi protocol not yet detected", p->pcap_cnt);
        SCReturnInt(0);
    }

    const Flow *f = p->flow;
    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", p->pcap_cnt);
        SCReturnInt(0);
    }

    r = ndpi_is_proto_equals(f->detected_l7_protocol.proto, data->l7_protocol, false);
    r = r ^ data->negated;

    if (r) {
        SCLogDebug("ndpi protocol match on protocol = %u.%u (match %u)",
                f->detected_l7_protocol.app_protocol, f->detected_l7_protocol.master_protocol,
                data->l7_protocol);
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

static DetectnDPIProtocolData *DetectnDPIProtocolParse(const char *arg, bool negate)
{
    DetectnDPIProtocolData *data;
    struct ndpi_detection_module_struct *ndpi_struct;
    ndpi_master_app_protocol l7_protocol;
    char *l7_protocol_name = (char *)arg;
    NDPI_PROTOCOL_BITMASK all;

    /* convert protocol name (string) to ID */
    ndpi_struct = ndpi_init_detection_module(NULL);
    if (unlikely(ndpi_struct == NULL))
        return NULL;

    ndpi_struct = ndpi_init_detection_module(NULL);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    ndpi_finalize_initialization(ndpi_struct);

    l7_protocol = ndpi_get_protocol_by_name(ndpi_struct, l7_protocol_name);
    ndpi_exit_detection_module(ndpi_struct);

    if (ndpi_is_proto_unknown(l7_protocol)) {
        SCLogError("failure parsing nDPI protocol '%s'", l7_protocol_name);
        return NULL;
    }

    data = SCMalloc(sizeof(DetectnDPIProtocolData));
    if (unlikely(data == NULL))
        return NULL;

    memcpy(&data->l7_protocol, &l7_protocol, sizeof(ndpi_master_app_protocol));
    data->negated = negate;

    return data;
}

static bool HasConflicts(const DetectnDPIProtocolData *us, const DetectnDPIProtocolData *them)
{
    /* check for mix of negated and non negated */
    if (them->negated ^ us->negated)
        return true;

    /* check for multiple non-negated */
    if (!us->negated)
        return true;

    /* check for duplicate */
    if (ndpi_is_proto_equals(us->l7_protocol, them->l7_protocol, true))
        return true;

    return false;
}

static int DetectnDPIProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectnDPIProtocolData *data = NULL;

    data = DetectnDPIProtocolParse(arg, s->init_data->negated);
    if (data == NULL)
        goto error;

    SigMatch *tsm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; tsm != NULL; tsm = tsm->next) {
        if (tsm->type == DETECT_NDPI_PROTOCOL) {
            const DetectnDPIProtocolData *them = (const DetectnDPIProtocolData *)tsm->ctx;

            if (HasConflicts(data, them)) {
                SCLogError("can't mix "
                           "positive ndpi-protocol match with negated");
                goto error;
            }
        }
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_NDPI_PROTOCOL, (SigMatchCtx *)data,
                DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static void DetectnDPIProtocolFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/** \internal
 *  \brief prefilter function for protocol detect matching
 */
static void PrefilterPacketnDPIProtocolMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (p->flow == NULL || !p->flow->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": no flow, no ndpi detection", p->pcap_cnt);
        SCReturn;
    }

    Flow *f = p->flow;
    bool negated = (bool)ctx->v1.u8[4];

    if (!ndpi_is_proto_unknown(f->detected_l7_protocol.proto)) {
        ndpi_master_app_protocol p = { ctx->v1.u16[0], ctx->v1.u16[1] };

        if (ndpi_is_proto_equals(f->detected_l7_protocol.proto, p, false) ^ negated) {
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
        }
    }
}

static void PrefilterPacketnDPIProtocolSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectnDPIProtocolData *a = smctx;

    v->u16[0] = a->l7_protocol.master_protocol;
    v->u16[1] = a->l7_protocol.app_protocol;
    v->u8[4] = (uint8_t)a->negated;
}

static bool PrefilterPacketnDPIProtocolCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectnDPIProtocolData *a = smctx;
    ndpi_master_app_protocol p = { v.u16[0], v.u16[1] };
    bool negated = (bool)v.u8[4];

    return (ndpi_is_proto_equals(a->l7_protocol, p, false) ^ negated);
}

static int PrefilterSetupnDPIProtocol(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_NDPI_PROTOCOL, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketnDPIProtocolSet, PrefilterPacketnDPIProtocolCompare,
            PrefilterPacketnDPIProtocolMatch);
}

static bool PrefilternDPIProtocolIsPrefilterable(const Signature *s)
{
    if (s->type == SIG_TYPE_PDONLY) {
        SCLogDebug("prefilter on PD %u", s->id);
        return true;
    }
    return false;
}

void DetectnDPIProtocolRegister(void)
{
    sigmatch_table[DETECT_NDPI_PROTOCOL].name = "ndpi-protocol";
    sigmatch_table[DETECT_NDPI_PROTOCOL].desc = "match on the detected nDPI protocol";
    sigmatch_table[DETECT_NDPI_PROTOCOL].url = "/rules/ndpi-protocol.html";
    sigmatch_table[DETECT_NDPI_PROTOCOL].Match = DetectnDPIProtocolPacketMatch;
    sigmatch_table[DETECT_NDPI_PROTOCOL].Setup = DetectnDPIProtocolSetup;
    sigmatch_table[DETECT_NDPI_PROTOCOL].Free = DetectnDPIProtocolFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_NDPI_PROTOCOL].RegisterTests = DetectnDPIProtocolRegisterTests;
#endif
    sigmatch_table[DETECT_NDPI_PROTOCOL].flags =
            (SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION);

    sigmatch_table[DETECT_NDPI_PROTOCOL].SetupPrefilter = PrefilterSetupnDPIProtocol;
    sigmatch_table[DETECT_NDPI_PROTOCOL].SupportsPrefilter = PrefilternDPIProtocolIsPrefilterable;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS

static int DetectnDPIProtocolTest01(void)
{
    DetectnDPIProtocolData *data = DetectnDPIProtocolParse("HTTP", false);
    FAIL_IF_NULL(data);
    FAIL_IF(data->l7_protocol.master_protocol != NDPI_PROTOCOL_HTTP);
    FAIL_IF(data->negated != 0);
    DetectnDPIProtocolFree(NULL, data);
    PASS;
}

static int DetectnDPIProtocolTest02(void)
{
    DetectnDPIProtocolData *data = DetectnDPIProtocolParse("HTTP", true);
    FAIL_IF_NULL(data);
    FAIL_IF(data->l7_protocol.master_protocol != NDPI_PROTOCOL_HTTP);
    FAIL_IF(data->negated == 0);
    DetectnDPIProtocolFree(NULL, data);
    PASS;
}

static int DetectnDPIProtocolTest03(void)
{
    Signature *s = NULL;
    DetectnDPIProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(ndpi-protocol:HTTP; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectnDPIProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF(data->l7_protocol.master_protocol != NDPI_PROTOCOL_HTTP);
    FAIL_IF(data->negated);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectnDPIProtocolTest04(void)
{
    Signature *s = NULL;
    DetectnDPIProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(ndpi-protocol:!HTTP; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectnDPIProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF(data->l7_protocol.master_protocol != NDPI_PROTOCOL_HTTP);
    FAIL_IF(data->negated == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectnDPIProtocolRegisterTests(void)
{
    UtRegisterTest("DetectnDPIProtocolTest01", DetectnDPIProtocolTest01);
    UtRegisterTest("DetectnDPIProtocolTest02", DetectnDPIProtocolTest02);
    UtRegisterTest("DetectnDPIProtocolTest03", DetectnDPIProtocolTest03);
    UtRegisterTest("DetectnDPIProtocolTest04", DetectnDPIProtocolTest04);
}
#endif /* UNITTESTS */

#endif /* HAVE_NDPI */
