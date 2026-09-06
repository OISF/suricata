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

#include "conf.h"
#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "flow.h"
#include "flow-callbacks.h"
#include "flow-storage.h"
#include "output-eve.h"
#include "thread-callbacks.h"
#include "thread-storage.h"
#include "util-debug.h"

#include "ndpi_api.h"

static SCThreadStorageId thread_storage_id = { .id = -1 };
static SCFlowStorageId flow_storage_id = { .id = -1 };
static int ndpi_protocol_keyword_id = -1;
static int ndpi_risk_keyword_id = -1;
static struct ndpi_global_context *ndpi_g_ctx;
static enum ndpi_license_type ndpi_license_type = NDPI_LICENSE_NOT_FOR_PROFIT_LGPL;

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

/**
 * Safe helper to get nDPI thread context. Returns NULL if storage
 * is not available (e.g. thread storage not yet initialized).
 */
static inline struct NdpiThreadContext *NdpiGetThreadContext(ThreadVars *tv)
{
    if (unlikely(tv == NULL || thread_storage_id.id < 0))
        return NULL;
    return SCThreadGetStorageById(tv, thread_storage_id);
}

/**
 * Safe helper to get nDPI flow context. Returns NULL if the flow
 * context is not available.
 */
static inline struct NdpiFlowContext *NdpiGetFlowContext(const Flow *f)
{
    if (unlikely(f == NULL || flow_storage_id.id < 0))
        return NULL;
    return SCFlowGetStorageById(f, flow_storage_id);
}

/**
 * Since nDPI 6.0 the caller has to declare under which license the library is
 * used. Dual-licensed dissectors (DHCP, DNS, QUIC and TLS) are not loaded when
 * NDPI_LICENSE_FOR_PROFIT_LGPL is selected, so the not-for-profit case is the
 * default and the choice is left to the user through "ndpi.license".
 *
 * Resolved once at plugin init, while Suricata is still single threaded.
 */
static enum ndpi_license_type NdpiResolveLicenseType(void)
{
    const char *license = NULL;

    if (SCConfGet("ndpi.license", &license) != 1 || license == NULL)
        return NDPI_LICENSE_NOT_FOR_PROFIT_LGPL;

    if (strcmp(license, "not-for-profit") == 0)
        return NDPI_LICENSE_NOT_FOR_PROFIT_LGPL;

    if (strcmp(license, "for-profit") == 0) {
        SCLogWarning("nDPI license set to \"for-profit\": the DHCP, DNS, QUIC and TLS "
                     "dissectors are dual-licensed and will not be loaded");
        return NDPI_LICENSE_FOR_PROFIT_LGPL;
    }

    if (strcmp(license, "for-profit-dual") == 0)
        return NDPI_LICENSE_FOR_PROFIT_DUAL_LICENSE;

    SCLogWarning("unknown nDPI license \"%s\", using \"not-for-profit\"", license);
    return NDPI_LICENSE_NOT_FOR_PROFIT_LGPL;
}

/* nDPI keeps its cross-flow correlations in LRU caches that are private to a
 * detection module unless they are made global, and it only accepts these
 * settings when a global context is in use. Suricata spreads the flows of a
 * single host over all its workers, so without sharing them the DNS, STUN and
 * TLS correlations never leave the thread that saw the first flow. */
static const char *ndpi_shared_lru_caches[] = {
    "lru.ookla.scope",
    "lru.bittorrent.scope",
    "lru.stun.scope",
    "lru.tls_cert.scope",
    "lru.mining.scope",
    "lru.msteams.scope",
    "lru.fpc_dns.scope",
    "lru.signal.scope",
};

/**
 * Allocate and finalize a detection module. Worker modules attach to the
 * global context to share their caches; the throwaway modules used while
 * parsing rules do not, as they only resolve names.
 */
static struct ndpi_detection_module_struct *NdpiModuleNew(bool shared_caches)
{
    struct ndpi_detection_module_struct *ndpi =
            ndpi_init_detection_module(shared_caches ? ndpi_g_ctx : NULL, ndpi_license_type);
    if (ndpi == NULL)
        return NULL;

    if (shared_caches && ndpi_g_ctx != NULL) {
        for (size_t i = 0; i < sizeof(ndpi_shared_lru_caches) / sizeof(ndpi_shared_lru_caches[0]);
                i++) {
            if (ndpi_set_config(ndpi, NULL, ndpi_shared_lru_caches[i], "1") != NDPI_CFG_OK) {
                SCLogWarning("Failed to share the nDPI \"%s\" cache between threads",
                        ndpi_shared_lru_caches[i]);
            }
        }
    }

    ndpi_finalize_initialization(ndpi);
    return ndpi;
}

static void ThreadStorageFree(void *ptr)
{
    SCLogDebug("Free'ing nDPI thread storage");
    struct NdpiThreadContext *context = ptr;
    if (context == NULL)
        return;
    if (context->ndpi != NULL)
        ndpi_exit_detection_module(context->ndpi);
    SCFree(context);
}

static void FlowStorageFree(void *ptr)
{
    struct NdpiFlowContext *ctx = ptr;
    if (ctx == NULL)
        return;
    /* ndpi_flow_free() is the counterpart of ndpi_flow_malloc() and frees the
     * flow internals as well */
    if (ctx->ndpi_flow != NULL)
        ndpi_flow_free(ctx->ndpi_flow);
    SCFree(ctx);
}

static void OnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *_data)
{
    if (unlikely(f == NULL))
        return;

    struct NdpiFlowContext *flowctx = SCCalloc(1, sizeof(*flowctx));
    if (flowctx == NULL) {
        SCLogDebug("Failed to allocate nDPI flow context");
        return;
    }

    flowctx->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flowctx->ndpi_flow == NULL) {
        SCLogDebug("Failed to allocate nDPI flow");
        SCFree(flowctx);
        return;
    }

    memset(flowctx->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    flowctx->detection_completed = false;
    if (SCFlowSetStorageById(f, flow_storage_id, flowctx) != 0) {
        SCLogDebug("Failed to set nDPI flow storage");
        FlowStorageFree(flowctx);
    }
}

static void OnFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *_data)
{
    const uint8_t flow_proto = SCFlowGetIPProtocol(f);

    /* Ignore packets that have a different protocol than the
     * flow. This can happen with ICMP unreachable packets. */
    if (p->proto != flow_proto) {
        return;
    }

    uint16_t ip_len = 0;
    void *ip_ptr = NULL;
    struct NdpiThreadContext *threadctx = NdpiGetThreadContext(tv);
    struct NdpiFlowContext *flowctx = NdpiGetFlowContext(f);

    if (threadctx == NULL || threadctx->ndpi == NULL)
        return;
    if (flowctx == NULL || flowctx->ndpi_flow == NULL)
        return;

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
        struct ndpi_flow_input_info input_info;

        SCLogDebug("Performing nDPI detection...");

        /* Suricata already knows the direction of the packet, so telling nDPI
         * spares it from guessing, which matters on asymmetric and midstream
         * traffic. The beginning of the flow is reported as unknown: the flow
         * accessors expose no reliable "handshake was seen" flag. */
        memset(&input_info, 0, sizeof(input_info));
        input_info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
        if (PKT_IS_TOSERVER(p))
            input_info.in_pkt_dir = NDPI_IN_PKT_DIR_C_TO_S;
        else if (PKT_IS_TOCLIENT(p))
            input_info.in_pkt_dir = NDPI_IN_PKT_DIR_S_TO_C;
        else
            input_info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;

        flowctx->detected_l7_protocol = ndpi_detection_process_packet(
                threadctx->ndpi, flowctx->ndpi_flow, ip_ptr, ip_len, time_ms, &input_info);

        const uint16_t max_num_pkts = (flow_proto == IPPROTO_UDP) ? 8 : 24;
        const bool enough_packets =
                (SCFlowGetToServerPacketCount(f) + SCFlowGetToClientPacketCount(f)) > max_num_pkts;

        /* NDPI_STATE_CLASSIFIED only means the library has enough information
         * to report a protocol, not that it is done with the flow: several
         * dissectors keep extra_packets_func set to observe more packets after
         * that point. Stopping earlier would silently cut those heuristics off,
         * so we stop once the library itself is done or the packet cap fires. */
        if ((flowctx->detected_l7_protocol.state == NDPI_STATE_CLASSIFIED &&
                    flowctx->ndpi_flow->extra_packets_func == NULL) ||
                enough_packets) {
            flowctx->detection_completed = true;

            if (flowctx->detected_l7_protocol.state != NDPI_STATE_CLASSIFIED) {
                flowctx->detected_l7_protocol =
                        ndpi_detection_giveup(threadctx->ndpi, flowctx->ndpi_flow);
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
    context->ndpi = NdpiModuleNew(true);
    if (context->ndpi == NULL) {
        FatalError("Failed to initialize nDPI detection module");
    }
    SCThreadSetStorageById(tv, thread_storage_id, context);
}

static int DetectnDPIProtocolPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    const Flow *f = p->flow;
    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    struct NdpiFlowContext *flowctx = NdpiGetFlowContext(f);
    if (flowctx == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flowctx", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    const DetectnDPIProtocolData *data = (const DetectnDPIProtocolData *)ctx;

    /* if the sig is PD-only we only match when PD packet flags are set */
    /*
    if (s->type == SIG_TYPE_PDONLY &&
            (p->flags & (PKT_PROTO_DETECT_TS_DONE | PKT_PROTO_DETECT_TC_DONE)) == 0) {
        SCLogDebug("packet %"PRIu64": flags not set", PcapPacketCntGet(p));
        SCReturnInt(0);
    }
    */

    if (!flowctx->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi protocol not yet detected", PcapPacketCntGet(p));
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

    /* convert protocol name (string) to ID */
    ndpi_struct = NdpiModuleNew(false);
    if (unlikely(ndpi_struct == NULL))
        return NULL;

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
    SCEnter();

    const Flow *f = p->flow;
    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    struct NdpiFlowContext *flowctx = NdpiGetFlowContext(f);
    if (flowctx == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flowctx", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    const DetectnDPIRiskData *data = (const DetectnDPIRiskData *)ctx;

    if (!flowctx->detection_completed) {
        SCLogDebug("packet %" PRIu64 ": ndpi risks not yet detected", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    if (flowctx->ndpi_flow == NULL) {
        SCLogDebug("packet %" PRIu64 ": ndpi_flow is NULL", PcapPacketCntGet(p));
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
    ndpi_risk risk_mask;

    /* convert list of risk names (string) to mask: ndpi_code2risk() needs no
     * detection module, so none is created here */
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
                    SCFree(dup);
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

    struct NdpiThreadContext *threadctx = NdpiGetThreadContext(tv);
    if (threadctx == NULL || threadctx->ndpi == NULL) {
        return;
    }

    struct NdpiFlowContext *flowctx = NdpiGetFlowContext(f);
    if (flowctx == NULL || flowctx->ndpi_flow == NULL) {
        return;
    }

    ndpi_serializer serializer;
    char *buffer;
    uint32_t buffer_len;

    SCLogDebug("EveCallback: tv=%p, p=%p, f=%p", tv, p, f);

    if (ndpi_init_serializer(&serializer, ndpi_serialization_format_inner_json) != 0) {
        SCLogDebug("Failed to initialize nDPI serializer");
        return;
    }

    /* Use ndpi_dpi2json to get a JSON with nDPI metadata */
    ndpi_dpi2json(threadctx->ndpi, flowctx->ndpi_flow, flowctx->detected_l7_protocol, &serializer);

    buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

    if (buffer != NULL && buffer_len > 0) {
        /* Inject the nDPI JSON to the JsonBuilder */
        SCJbSetFormatted(jb, buffer);
    }

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

    ndpi_license_type = NdpiResolveLicenseType();

    /* The global context is what lets the per-thread detection modules share
     * their LRU caches; nDPI rejects the "lru.*.scope" settings without it.
     * SCPlugin has no deinit hook, so it lives until the process exits. */
    ndpi_g_ctx = ndpi_global_init();
    if (ndpi_g_ctx == NULL) {
        SCLogWarning("Failed to initialize the nDPI global context: "
                     "per-thread caches will not be shared");
    }

    /* Register thread storage. */
    thread_storage_id = SCThreadStorageRegister("ndpi", ThreadStorageFree);
    if (thread_storage_id.id < 0) {
        FatalError("Failed to register nDPI thread storage");
    }

    /* Register flow storage. */
    flow_storage_id = SCFlowStorageRegister("ndpi", FlowStorageFree);
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
