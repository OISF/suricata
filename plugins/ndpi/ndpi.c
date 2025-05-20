/* Copyright (C) 2024-2025 Open Information Security Foundation
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

/* License note: While this "glue" code to the nDPI library is GPLv2,
 * nDPI is itself LGPLv3 which is known to be incompatible with the
 * GPLv2. */

#include "suricata-common.h"
#include "suricata-plugin.h"

#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "flow-callbacks.h"
#include "flow-storage.h"
#include "output-eve.h"
#include "thread-callbacks.h"
#include "thread-storage.h"
#include "util-debug.h"

#include "ndpi_api.h"

static ThreadStorageId thread_storage_id = { .id = -1 };
static FlowStorageId flow_storage_id = { .id = -1 };
static int ndpi_protocol_keyword_id = -1;
static int ndpi_risk_keyword_id = -1;

struct NdpiThreadContext {
    struct ndpi_detection_module_struct *ndpi;
};

struct NdpiFlowContext {
    struct ndpi_flow_struct *ndpi_flow;
    ndpi_protocol detected_l7_protocol;
    bool detection_completed;
};

typedef struct DetectnDPIProtocolData_ {
    ndpi_master_app_protocol l7_protocol;
    bool negated;
} DetectnDPIProtocolData;

typedef struct DetectnDPIRiskData_ {
    ndpi_risk risk_mask; /* uint64 */
    bool negated;
} DetectnDPIRiskData;

static void ThreadStorageFree(void *ptr)
{
    SCLogDebug("Free'ing nDPI thread storage");
    struct NdpiThreadContext *context = ptr;
    ndpi_exit_detection_module(context->ndpi);
    SCFree(context);
}

static void FlowStorageFree(void *ptr)
{
    struct NdpiFlowContext *ctx = ptr;
    ndpi_flow_free(ctx->ndpi_flow);
    SCFree(ctx);
}

static void OnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *_data)
{
    struct NdpiFlowContext *flowctx = SCCalloc(1, sizeof(*flowctx));
    if (flowctx == NULL) {
        FatalError("Failed to allocate nDPI flow context");
    }

    flowctx->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flowctx->ndpi_flow == NULL) {
        FatalError("Failed to allocate nDPI flow");
    }

    memset(flowctx->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    flowctx->detection_completed = false;
    FlowSetStorageById(f, flow_storage_id, flowctx);
}

static void OnFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *_data)
{
    struct NdpiThreadContext *threadctx = ThreadGetStorageById(tv, thread_storage_id);
    struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
    uint16_t ip_len = 0;
    void *ip_ptr = NULL;

    if (!threadctx->ndpi || !flowctx->ndpi_flow) {
        return;
    }

    /* Ignore packets that have a different protocol than the
     * flow. This can happen with ICMP unreachable packets. */
    if (p->proto != f->proto) {
        return;
    }

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        ip_len = IPV4_GET_RAW_IPLEN(ip4h);
        ip_ptr = (void *)PacketGetIPv4(p);
    } else if (PacketIsIPv6(p)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        ip_len = IPV6_HEADER_LEN + IPV6_GET_RAW_PLEN(ip6h);
        ip_ptr = (void *)PacketGetIPv6(p);
    }

    if (!flowctx->detection_completed && ip_ptr != NULL && ip_len > 0) {
        uint64_t time_ms = ((uint64_t)p->ts.secs) * 1000 + p->ts.usecs / 1000;

        SCLogDebug("Performing nDPI detection...");

        flowctx->detected_l7_protocol = ndpi_detection_process_packet(
                threadctx->ndpi, flowctx->ndpi_flow, ip_ptr, ip_len, time_ms, NULL);

        if (ndpi_is_protocol_detected(flowctx->detected_l7_protocol) != 0) {
            if (!ndpi_is_proto_unknown(flowctx->detected_l7_protocol.proto)) {
                if (!ndpi_extra_dissection_possible(threadctx->ndpi, flowctx->ndpi_flow))
                    flowctx->detection_completed = true;
            }
        } else {
            uint16_t max_num_pkts = (f->proto == IPPROTO_UDP) ? 8 : 24;

            if ((f->todstpktcnt + f->tosrcpktcnt) > max_num_pkts) {
                uint8_t proto_guessed;

                flowctx->detected_l7_protocol =
                        ndpi_detection_giveup(threadctx->ndpi, flowctx->ndpi_flow, &proto_guessed);
                flowctx->detection_completed = true;
            }
        }

        if (SCLogDebugEnabled() && flowctx->detection_completed) {
            SCLogDebug("Detected protocol: %s | app protocol: %s | category: %s",
                    ndpi_get_proto_name(
                            threadctx->ndpi, flowctx->detected_l7_protocol.proto.master_protocol),
                    ndpi_get_proto_name(
                            threadctx->ndpi, flowctx->detected_l7_protocol.proto.app_protocol),
                    ndpi_category_get_name(
                            threadctx->ndpi, flowctx->detected_l7_protocol.category));
        }
    }
}

static void OnFlowFinish(ThreadVars *tv, Flow *f, void *_data)
{
    /* Nothing to do here, the storage API has taken care of cleaning
     * up storage, just here for example purposes. */
    SCLogDebug("Flow %p is now finished", f);
}

static void OnThreadInit(ThreadVars *tv, void *_data)
{
    struct NdpiThreadContext *context = SCCalloc(1, sizeof(*context));
    if (context == NULL) {
        FatalError("Failed to allocate nDPI thread context");
    }
    context->ndpi = ndpi_init_detection_module(NULL);
    if (context->ndpi == NULL) {
        FatalError("Failed to initialize nDPI detection module");
    }
    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);
    ndpi_finalize_initialization(context->ndpi);
    ThreadSetStorageById(tv, thread_storage_id, context);
}

static int DetectnDPIProtocolPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const Flow *f = p->flow;
    struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
    const DetectnDPIProtocolData *data = (const DetectnDPIProtocolData *)ctx;

    SCEnter();

    /* if the sig is PD-only we only match when PD packet flags are set */
    /*
    if (s->type == SIG_TYPE_PDONLY &&
            (p->flags & (PKT_PROTO_DETECT_TS_DONE | PKT_PROTO_DETECT_TC_DONE)) == 0) {
        SCLogDebug("packet %"PRIu64": flags not set", p->pcap_cnt);
        SCReturnInt(0);
    }
    */

    if (!flowctx->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi protocol not yet detected", p->pcap_cnt);
        SCReturnInt(0);
    }

    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", p->pcap_cnt);
        SCReturnInt(0);
    }

    bool r = ndpi_is_proto_equals(flowctx->detected_l7_protocol.proto, data->l7_protocol, false);
    r = r ^ data->negated;

    if (r) {
        SCLogDebug("ndpi protocol match on protocol = %u.%u (match %u)",
                flowctx->detected_l7_protocol.proto.app_protocol,
                flowctx->detected_l7_protocol.proto.master_protocol,
                data->l7_protocol.app_protocol);
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

static bool nDPIProtocolDataHasConflicts(
        const DetectnDPIProtocolData *us, const DetectnDPIProtocolData *them)
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
    DetectnDPIProtocolData *data = DetectnDPIProtocolParse(arg, s->init_data->negated);
    if (data == NULL)
        goto error;

    SigMatch *tsm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; tsm != NULL; tsm = tsm->next) {
        if (tsm->type == ndpi_protocol_keyword_id) {
            const DetectnDPIProtocolData *them = (const DetectnDPIProtocolData *)tsm->ctx;

            if (nDPIProtocolDataHasConflicts(data, them)) {
                SCLogError("can't mix "
                           "positive ndpi-protocol match with negated");
                goto error;
            }
        }
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, ndpi_protocol_keyword_id, (SigMatchCtx *)data,
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

static int DetectnDPIRiskPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const Flow *f = p->flow;
    struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
    const DetectnDPIRiskData *data = (const DetectnDPIRiskData *)ctx;

    SCEnter();

    if (!flowctx->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi risks not yet detected", p->pcap_cnt);
        SCReturnInt(0);
    }

    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", p->pcap_cnt);
        SCReturnInt(0);
    }

    bool r = ((flowctx->ndpi_flow->risk & data->risk_mask) == data->risk_mask);
    r = r ^ data->negated;

    if (r) {
        SCLogDebug("ndpi risks match on risk bitmap =  %" PRIu64 " (matching bitmap %" PRIu64 ")",
                flowctx->ndpi_flow->risk, data->risk_mask);
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

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    ndpi_finalize_initialization(ndpi_struct);
    ndpi_exit_detection_module(ndpi_struct);

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

static bool nDPIRiskDataHasConflicts(const DetectnDPIRiskData *us, const DetectnDPIRiskData *them)
{
    /* check for duplicate */
    if (us->risk_mask == them->risk_mask)
        return true;

    return false;
}

static int DetectnDPIRiskSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectnDPIRiskData *data = DetectnDPIRiskParse(arg, s->init_data->negated);
    if (data == NULL)
        goto error;

    SigMatch *tsm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; tsm != NULL; tsm = tsm->next) {
        if (tsm->type == ndpi_risk_keyword_id) {
            const DetectnDPIRiskData *them = (const DetectnDPIRiskData *)tsm->ctx;

            if (nDPIRiskDataHasConflicts(data, them)) {
                SCLogError("can't mix "
                           "positive ndpi-risk match with negated");
                goto error;
            }
        }
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, ndpi_risk_keyword_id, (SigMatchCtx *)data,
                DETECT_SM_LIST_MATCH) == NULL) {
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

static void EveCallback(ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *jb, void *data)
{
    /* Adding ndpi info to EVE requires a flow. */
    if (f == NULL) {
        return;
    }

    struct NdpiThreadContext *threadctx = ThreadGetStorageById(tv, thread_storage_id);
    struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
    ndpi_serializer serializer;
    char *buffer;
    uint32_t buffer_len;

    SCLogDebug("EveCallback: tv=%p, p=%p, f=%p", tv, p, f);

    ndpi_init_serializer(&serializer, ndpi_serialization_format_inner_json);

    /* Use ndpi_dpi2json to get a JSON with nDPI metadata */
    ndpi_dpi2json(threadctx->ndpi, flowctx->ndpi_flow, flowctx->detected_l7_protocol, &serializer);

    buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

    /* Inject the nDPI JSON to the JsonBuilder */
    SCJbSetFormatted(jb, buffer);

    ndpi_term_serializer(&serializer);
}

static void NdpInitRiskKeyword(void)
{
    /* SCSigTableAppLiteElmt and SCDetectHelperKeywordRegister don't yet
     * support all the fields required to register the nDPI keywords,
     * missing the (packet) Match callback,
     * so we'll just register with an empty keyword specifier to get
     * the ID, then fill in the ID. */
    ndpi_protocol_keyword_id = SCDetectHelperNewKeywordId();
    SCLogDebug("Registered new ndpi-protocol keyword with ID %" PRIu32, ndpi_protocol_keyword_id);

    sigmatch_table[ndpi_protocol_keyword_id].name = "ndpi-protocol";
    sigmatch_table[ndpi_protocol_keyword_id].desc = "match on the detected nDPI protocol";
    sigmatch_table[ndpi_protocol_keyword_id].url = "/rules/ndpi-protocol.html";
    sigmatch_table[ndpi_protocol_keyword_id].Match = DetectnDPIProtocolPacketMatch;
    sigmatch_table[ndpi_protocol_keyword_id].Setup = DetectnDPIProtocolSetup;
    sigmatch_table[ndpi_protocol_keyword_id].Free = DetectnDPIProtocolFree;
    sigmatch_table[ndpi_protocol_keyword_id].flags =
            (SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION);

    ndpi_risk_keyword_id = SCDetectHelperNewKeywordId();
    SCLogDebug("Registered new ndpi-risk keyword with ID %" PRIu32, ndpi_risk_keyword_id);

    sigmatch_table[ndpi_risk_keyword_id].name = "ndpi-risk";
    sigmatch_table[ndpi_risk_keyword_id].desc = "match on the detected nDPI risk";
    sigmatch_table[ndpi_risk_keyword_id].url = "/rules/ndpi-risk.html";
    sigmatch_table[ndpi_risk_keyword_id].Match = DetectnDPIRiskPacketMatch;
    sigmatch_table[ndpi_risk_keyword_id].Setup = DetectnDPIRiskSetup;
    sigmatch_table[ndpi_risk_keyword_id].Free = DetectnDPIRiskFree;
    sigmatch_table[ndpi_risk_keyword_id].flags =
            (SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION);
}

static void NdpiInit(void)
{
    SCLogDebug("Initializing nDPI plugin");

    /* Register thread storage. */
    thread_storage_id = ThreadStorageRegister("ndpi", sizeof(void *), NULL, ThreadStorageFree);
    if (thread_storage_id.id < 0) {
        FatalError("Failed to register nDPI thread storage");
    }

    /* Register flow storage. */
    flow_storage_id = FlowStorageRegister("ndpi", sizeof(void *), NULL, FlowStorageFree);
    if (flow_storage_id.id < 0) {
        FatalError("Failed to register nDPI flow storage");
    }

    /* Register flow lifecycle callbacks. */
    SCFlowRegisterInitCallback(OnFlowInit, NULL);
    SCFlowRegisterUpdateCallback(OnFlowUpdate, NULL);

    /* Not needed for nDPI, but exists for completeness. */
    SCFlowRegisterFinishCallback(OnFlowFinish, NULL);

    /* Register thread init callback. */
    SCThreadRegisterInitCallback(OnThreadInit, NULL);

    /* Register an EVE callback. */
    SCEveRegisterCallback(EveCallback, NULL);

    NdpInitRiskKeyword();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "ndpi",
    .author = "Luca Deri",
    .license = "GPLv3",
    .Init = NdpiInit,

};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
