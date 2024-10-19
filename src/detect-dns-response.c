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
 * Detect keyword for DNS response: dns.response
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-dns-response.h"
#include "util-profiling.h"
#include "rust.h"

#ifdef UNITTESTS
static void DetectDnsResponseRegisterTests(void);
#endif

static int detect_buffer_id = 0;
typedef struct PrefilterMpm {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpm;

typedef enum DnsResponseSection_ {
    DNS_RESPONSE_QUERY = 0,
    DNS_RESPONSE_ANSWER,
    DNS_RESPONSE_AUTHORITY,
    DNS_RESPONSE_ADDITIONAL,

    /* always last */
    DNS_RESPONSE_MAX,
} DnsResponseSection;

struct DnsResponseGetDataArgs {
    DnsResponseSection response_section; /**< query, answer, authority, additional */
    uint32_t response_id;                /**< index into response resource records */
    uint32_t local_id;                   /**< used as index into thread inspect array */
};

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, detect_buffer_id) < 0) {
        return -1;
    }
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0) {
        return -1;
    }

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx, uint8_t flags,
        const DetectEngineTransforms *transforms, void *txv, struct DnsResponseGetDataArgs *cbdata,
        int list_id, bool get_rdata)
{
    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL) {
        return NULL;
    }
    if (buffer->initialized) {
        return buffer;
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (get_rdata) {
        /* getting rdata value from resource record */
        switch (cbdata->response_section) {
            case DNS_RESPONSE_ANSWER:
                if (!SCDnsTxGetAnswerRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_AUTHORITY:
                if (!SCDnsTxGetAuthorityRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ADDITIONAL:
                if (!SCDnsTxGetAdditionalRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            default:
                InspectionBufferSetupMultiEmpty(buffer);
                return NULL;
        }
    } else {
        /* getting name value from resource record */
        switch (cbdata->response_section) {
            case DNS_RESPONSE_QUERY:
                if (!SCDnsTxGetQueryName(txv, true, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ANSWER:
                if (!SCDnsTxGetAnswerName(txv, true, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_AUTHORITY:
                if (!SCDnsTxGetAuthorityName(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ADDITIONAL:
                if (!SCDnsTxGetAdditionalName(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            default:
                InspectionBufferSetupMultiEmpty(buffer);
                return NULL;
        }
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

static uint8_t DetectEngineInspectCb(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    uint32_t local_id = 0;
    /* loop through each possible DNS response section */
    for (uint8_t section = DNS_RESPONSE_QUERY; section < DNS_RESPONSE_MAX; section++) {
        uint32_t response_id = 0;
        /* loop through each record in section inspecting "name" and "rdata" */
        while (1) {
            struct DnsResponseGetDataArgs cbdata = { section, response_id, local_id };

            /* do inspection for resource record "name" */
            InspectionBuffer *buffer =
                    GetBuffer(det_ctx, flags, transforms, txv, &cbdata, engine->sm_list, false);
            if (buffer == NULL || buffer->inspect == NULL) {
                local_id++;
                break;
            }

            bool match = DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd, NULL,
                    f, buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
            if (match) {
                return DETECT_ENGINE_INSPECT_SIG_MATCH;
            }

            local_id++;
            if (section == DNS_RESPONSE_QUERY) {
                /* no rdata to inspect for query section, move on to next record */
                response_id++;
                continue;
            }

            /* do inspection for resource record "rdata" */
            cbdata.local_id = local_id;
            buffer = GetBuffer(det_ctx, flags, transforms, txv, &cbdata, engine->sm_list, true);
            if (buffer == NULL || buffer->inspect == NULL) {
                local_id++;
                response_id++;
                continue;
            }

            match = DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd, NULL, f,
                    buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
            if (match) {
                return DETECT_ENGINE_INSPECT_SIG_MATCH;
            }
            local_id++;
            response_id++;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static void PrefilterTx(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f,
        void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpm *ctx = (const PrefilterMpm *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    /* loop through each possible DNS response section */
    for (uint8_t section = DNS_RESPONSE_QUERY; section < DNS_RESPONSE_MAX; section++) {
        uint32_t response_id = 0;
        /* loop through each record in section inspecting "name" and "rdata" */
        while (1) {
            struct DnsResponseGetDataArgs cbdata = { section, response_id, local_id };

            /* extract resource record "name" */
            InspectionBuffer *buffer =
                    GetBuffer(det_ctx, flags, ctx->transforms, txv, &cbdata, list_id, false);
            if (buffer == NULL) {
                local_id++;
                break;
            }

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtc, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
                PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
            }

            local_id++;
            if (section == DNS_RESPONSE_QUERY) {
                /* no rdata to inspect for query section, move on to next name entry */
                response_id++;
                continue;
            }

            /* extract resource record "rdata" */
            cbdata.local_id = local_id;
            buffer = GetBuffer(det_ctx, flags, ctx->transforms, txv, &cbdata, list_id, true);
            if (buffer == NULL) {
                local_id++;
                response_id++;
                continue;
            }

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, &det_ctx->mtc, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
                PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
            }
            local_id++;
            response_id++;
        }
    }
}

static void PrefilterMpmFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpm *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL) {
        return -1;
    }
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTx, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmFree, mpm_reg->pname);
}

void DetectDnsResponseRegister(void)
{
    static const char *keyword = "dns.response";
    sigmatch_table[DETECT_AL_DNS_RESPONSE].name = keyword;
    sigmatch_table[DETECT_AL_DNS_RESPONSE].desc = "DNS response sticky buffer";
    sigmatch_table[DETECT_AL_DNS_RESPONSE].url = "/rules/dns-keywords.html#dns-response";
    sigmatch_table[DETECT_AL_DNS_RESPONSE].Setup = DetectSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DNS_RESPONSE].RegisterTests = DetectDnsResponseRegisterTests;
#endif
    sigmatch_table[DETECT_AL_DNS_RESPONSE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_RESPONSE].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register in the TO_CLIENT direction. */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1, DetectEngineInspectCb, NULL);
    DetectAppLayerMpmRegister(
            keyword, SIG_FLAG_TOCLIENT, 2, PrefilterMpmRegister, NULL, ALPROTO_DNS, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "dns response");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);
}

#ifdef UNITTESTS

#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/** \test google.com match query name field in response */
static int DetectDnsResponseTest01(void)
{
    uint8_t buf[] = {   
        0x10, 0x31, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* questions: 1 */
        0x00, 0x00, /* answer_rrs: 0 */ 
        0x00, 0x00, /* authority_rrs: 0 */
        0x00, 0x00, /* additional_rr: 0 */
        /* Query */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,  
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01,
    };

    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response query name match\"; "
                                      "dns.response; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test google.com match answer name field in response */
static int DetectDnsResponseTest02(void)
{
    uint8_t buf[] = {  
        0x11, 0x32, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x00, /* questions: 0 */
        0x00, 0x01, /* answer_rrs: 1 */ 
        0x00, 0x00, /* authority_rrs: 0 */
        0x00, 0x00, /* additional_rr: 0 */
        /* Answer */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,  
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 
        0x01, 0x2c, 0x00, 0x04, 0x7f, 0x00, 
        0x00, 0x01, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response answer name match\"; "
                                      "dns.response; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test google.com match authority name field in response */
static int DetectDnsResponseTest03(void)
{
    uint8_t buf[] = {   
        0x12, 0x33, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x00, /* questions: 0 */
        0x00, 0x00, /* answer_rrs: 0 */ 
        0x00, 0x01, /* authority_rrs: 1 */
        0x00, 0x00, /* additional_rr: 0 */
        /* Authority */
        /* name = google.com*/
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,  
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x06, /* type: SOA */
        0x00, 0x01, /* Class: IN*/
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x37, /* Data length: 55 */
        /* primary name server: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0x06, 0x67, 
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 
        0x63, 0x6f, 0x6d, 0x00, 0x06, 0x61, 
        0x6e, 0x64, 0x72, 0x65, 0x69, 0x06, 
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 
        0xff, 0xb4, 0x5f, 0x00, 0x00, 0x0e, 
        0x10, 0x00, 0x00, 0x2a, 0x30, 0x00, 
        0x01, 0x51, 0x80, 0x00, 0x00, 0x0e, 
        0x10, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response authority name match\"; "
                                      "dns.response; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test ns1.google.com match additional name field in response */
static int DetectDnsResponseTest04(void)
{
    uint8_t buf[] = {   
        0x13, 0x34, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* questions: 1 */
        0x00, 0x01, /* answer_rrs: 1 */ 
        0x00, 0x00, /* authority_rrs: 0 */
        0x00, 0x01, /* additional_rr: 1 */
        /* Query name = google.com */ 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01,
        /* Answer name = google.com (0xc00c pointer to query) */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01,
        /* Additional: name = ns1.google.com (0xc00c pointer to query) */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 
        0x00 ,0x01 ,0x00, 0x01 ,0x00 ,0x00,
        0x01, 0x2c, 0x00, 0x04, 0x7f, 0x00,
        0x00, 0x01, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response additional name match\"; "
                                      "dns.response; content:\"ns1.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test mail.google.com match answer data field in response (MX type) */
static int DetectDnsResponseTest05(void)
{
    uint8_t buf[] = {   
        0xb7, 0xf6, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num query */
        0x00, 0x01, /* num answer */
        0x00, 0x01, /* num authority */
        0x00, 0x01, /* num additional */
        /* Query */ 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* google.com */
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x0f, 0x00, 0x01, 
        /* Answer */
        0xc0, 0x0c, /* reference to Query name google.com bytes*/
        0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 
        0x01, 0x2c, 0x00, 0x09, 0x00, 0x0a, 
        /* MX record: mail.google.com */
        0x04, 0x6d, 0x61, 0x69, 0x6c,
        0xc0, 0x0c, /* google.com reference to Query name bytes */
        /* Authority */ 
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00, 
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10,
        /* Additional */
        0xc0, 0x3d, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response answer data match\"; "
                                      "dns.response; content:\"mail.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** 
 * \test ns2.google.com match 2nd answer data field in response.
 * This verifies multiple records of one type are parsed.
 */
static int DetectDnsResponseTest06(void)
{
    uint8_t buf[] = {   
        0x53, 0x19, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x02, /* num answers */
        0x00, 0x00, /* num authority */
        0x00, 0x00, /* num additional */
        /* Query */ 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* google.com */
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        /* Answer  1/2 */
        0xc0, 0x0c, /* Name: google.com (pointer to query bytes) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN*/
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x06, /* Data length: 6 */
        /* ns1.google.com (google.com pointer to query bytes)*/
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
        /* Answer 2/2 */
        0xc0, 0x0c, /* Name: google.com (pointer to query bytes) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x06, /* Data length: 6 */
        /* ns2.google.com (google.com pointer to query bytes)*/
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response 2nd answer data match\"; "
                                      "dns.response; content:\"ns2.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test ns1.google.com match authority data field in response (SOA) */
static int DetectDnsResponseTest07(void)
{
    uint8_t buf[] = {   
        0x61, 0xb7, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x00, /* num answers */
        0x00, 0x01, /* num authority */
        0x00, 0x00, /* num additional */
        /* Query, name: www.google.com */
        0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 
        0x00, 0x01,
        /* Authority */
        0xc0, 0x10, /* Name: google.com (pointer to query bytes) */
        0x00, 0x06, /* Type: SOA */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x23, /* Data length: 35 */
        /* Primary name server: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x10, /* 0xc010 pointer to query */
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x10, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00, 
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response authority data match\"; "
                                      "dns.response; content:\"ns1.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test ns2.google.com match second additional data field in response (NS) */
static int DetectDnsResponseTest08(void)
{
    uint8_t buf[] = {   
        0x50, 0x42, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x01, /* num answers */
        0x00, 0x01, /* num authority */
        0x00, 0x02, /* num additional */
        /* Query, name: google.com */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, /* Type: A, Class: IN */
        /* Answer */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01,
        /* Authority */ 
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        /* NS: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00,
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
        /* Additional 1/2 */
        0xc0, 0x0c, /* name: google.com (pointer to query) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x02, /* Data length: 2 */
        0xc0, 0x38, /* Pointer to ns1.google.com in Authority */
        /* Additional 2/2 */
        0xc0, 0x0c, /* name: google.com (pointer to query) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x06, /* Data length: 6 */
        /* ns2.google.com (google.com pointer to query) */
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response additional data match\"; "
                                      "dns.response; content:\"ns2.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/** \test google.com match query name field in response (TCP) */
static int DetectDnsResponseTest09(void)
{
    uint8_t buf[] = {   
        0x00, 28,   /* tcp len */
        0x10, 0x31, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* questions: 1 */
        0x00, 0x00, /* answer_rrs: 0 */ 
        0x00, 0x00, /* authority_rrs: 0 */
        0x00, 0x00, /* additional_rr: 0 */
        /* Query */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,  
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOCLIENT | FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response query name match tcp\"; "
                                      "dns.response; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}
/** \test multi tx (mail,ns2).google.com response matching */
static int DetectDnsResponseTest10(void)
{
    /* Query 1/2 */
    uint8_t buf1[] = {  
        0xa1, 0xc4, 0x01, 0x20, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* google.com */
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x0f, 0x00, 0x01, /* Type: MX, Class: IN */ 
    };
    /* Response 1/2 */
    uint8_t buf2[] = {  
        0xa1, 0xc4, 0x85, 0x80, 0x00, 0x01, 
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        /* Query */ 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x0f, 0x00, 0x01, 
        /* Answer data: mail.google.com  */
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x09, 
        0x00, 0x0a, 0x04, 0x6d, 0x61, 0x69,
        0x6c, 0xc0, 0x0c, 0xc0, 0x0c, 
    };
    /* Query 2/2 */
    uint8_t buf3[] = {  
        0xc1, 0xc5, 0x01, 0x20, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* google.com */
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, /* Type: A, Class: IN */ 
    };
    /* Response 2/2 */
    uint8_t buf4[] = {  
        0xc1, 0xc5, 0x85, 0x80, 0x00, 0x01, 
        0x00, 0x01, 0x00, 0x01, 0x00, 0x02,
        /* Query */ 
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* google.com */
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, 
        /* Answer */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0x7f, 0x00, 0x00, 0x01, 
        /* Authority */
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, /* ns1.google.com */
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00, 
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
        /* Additional 1/2 */
        0xc0, 0x0c, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 
        0x02, 0xc0, 0x38, /* ns1.google.com */
        /* Additional 2/2 */
        0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, 
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, /* ns2.google.com */ 
    };

    Flow f;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    /* Query 1/2 to server */
    p1 = UTHBuildPacketReal(
            buf1, sizeof(buf1), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);
    /* Response 1/2 to client */
    p2 = UTHBuildPacketReal(
            buf2, sizeof(buf2), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);
    /* Query 2/2 to server */
    p3 = UTHBuildPacketReal(
            buf3, sizeof(buf3), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);
    /* Response 2/2 to client */
    p4 = UTHBuildPacketReal(
            buf4, sizeof(buf4), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_DNS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->pcap_cnt = 1;

    p3->flow = &f;
    p3->flags |= PKT_HAS_FLOW;
    p3->flowflags |= FLOW_PKT_TOSERVER;
    p3->pcap_cnt = 1;

    p4->flow = &f;
    p4->flags |= PKT_HAS_FLOW;
    p4->flowflags |= FLOW_PKT_TOCLIENT;
    p4->pcap_cnt = 1;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response multi tx answer match\"; "
                                      "dns.response; content:\"mail.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response multi tx additional match\"; "
                                      "dns.response; content:\"ns2.google.com\"; nocase; sid:2;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response multi tx additional match\"; "
                                      "dns.query; content:\"google.com\"; nocase; sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf1, sizeof(buf1));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    /* should not match */
    FAIL_IF(PacketAlertCheck(p1, 1));
    /* should not match */
    FAIL_IF(PacketAlertCheck(p1, 2));
    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p1, 3));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf2, sizeof(buf2));
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));
    /* should not match */
    FAIL_IF(PacketAlertCheck(p2, 2));
    /* should not match */
    FAIL_IF(PacketAlertCheck(p2, 3));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf3, sizeof(buf3));
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    /* should not match */
    FAIL_IF(PacketAlertCheck(p3, 1));
    /* should not match */
    FAIL_IF(PacketAlertCheck(p3, 2));
    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p3, 3));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf4, sizeof(buf4));
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p4);

    /* should not match */
    FAIL_IF(PacketAlertCheck(p4, 1));
    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p4, 2));
    /* should not match */
    FAIL_IF(PacketAlertCheck(p4, 3));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);

    PASS;
}

/** \test google.com and ns2.google.com response matching, pcre */
static int DetectDnsResponseTest11(void)
{
    uint8_t buf[] = {   
        0x50, 0x42, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x01, /* num answers */
        0x00, 0x01, /* num authority */
        0x00, 0x02, /* num additional */
        /* Query, name: google.com */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, /* Type: A, Class: IN */
        /* Answer */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01,
        /* Authority */ 
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        /* NS: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00,
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
        /* Additional 1/2 */
        0xc0, 0x0c, /* name: google.com (pointer to query) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x02, /* Data length: 2 */
        0xc0, 0x38, /* Pointer to ns1.google.com in Authority */
        /* Additional 2/2 */
        0xc0, 0x0c, /* name: google.com (pointer to query) */
        0x00, 0x02, /* Type: NS */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x06, /* Data length: 6 */
        /* ns2.google.com (google.com pointer to query) */
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response pcre match\"; "
                                      "dns.response; content:\"google\"; nocase; "
                                      "pcre:\"/ns2\\.google\\.com$/i\"; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response pcre match\"; "
                                      "dns.response; content:\"google\"; nocase; "
                                      "pcre:\"/^\\.[a-z]{2,3}$/iR\"; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 2));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test ns2.google.com response matching 2nd additional section
 * with type: A records
 */
static int DetectDnsResponseTest12(void)
{
    uint8_t buf[] = {   
        0x7a, 0x11, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x01, /* num answers */
        0x00, 0x01, /* num authority */
        0x00, 0x02, /* num additional */
        /* Query, name: google.com */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, /* Type: A, Class: IN */
        /* Answer */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01, 
        /* Authority */
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        /* NS: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00,
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
        /* Additional 1/2 */
        0xc0, 0x38, /* name: ns1.google.com (pointer to authority) */
        0x00, 0x01, /* Type: A */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x04, /* Data length: 4 */
        0x7f, 0x00, 0x00, 0x01, /* 127.0.0.1 */
        /* Additional 2/2 */ 
        /* name: ns2.google.com (ns2 + pointer to query) */
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, 
        0x00, 0x01, /* Type: A */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x04, /* Data length: 4 */
        0x7f, 0x00, 0x00, 0x01, /* 127.0.0.1 */ 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns response additional name match\"; "
                                      "dns.response; content:\"ns2.google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test Verify transform applies to dns.response sticky buffer.
 * Test using "to_uppercase". ns2.google.com response matching
 * 2nd additional section name field.
 */
static int DetectDnsResponseTest13(void)
{
    uint8_t buf[] = {   
        0x7a, 0x11, /* ID */
        0x85, 0x80, /* Flags */
        0x00, 0x01, /* num queries */
        0x00, 0x01, /* num answers */
        0x00, 0x01, /* num authority */
        0x00, 0x02, /* num additional */
        /* Query, name: google.com */
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01, /* Type: A, Class: IN */
        /* Answer */
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 
        0x7f, 0x00, 0x00, 0x01, 
        /* Authority */
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 
        /* NS: ns1.google.com */
        0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c,
        0x06, 0x61, 0x6e, 0x64, 0x72, 0x65, 
        0x69, 0xc0, 0x0c, 0x0b, 0xff, 0xb4, 
        0x5f, 0x00, 0x00, 0x0e, 0x10, 0x00,
        0x00, 0x2a, 0x30, 0x00, 0x01, 0x51, 
        0x80, 0x00, 0x00, 0x0e, 0x10, 
        /* Additional 1/2 */
        0xc0, 0x38, /* name: ns1.google.com (pointer to authority) */
        0x00, 0x01, /* Type: A */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x04, /* Data length: 4 */
        0x7f, 0x00, 0x00, 0x01, /* 127.0.0.1 */
        /* Additional 2/2 */
        /* name: ns2.google.com (ns2 + pointer to query) */
        0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c, 
        0x00, 0x01, /* Type: A */
        0x00, 0x01, /* Class: IN */
        0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
        0x00, 0x04, /* Data length: 4 */
        0x7f, 0x00, 0x00, 0x01, /* 127.0.0.1 */ 
    };

    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.1", "192.168.1.5", 53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    /* content with upper case chars after "to_uppercase" transform should match */
    s = DetectEngineAppendSig(de_ctx,
            "alert dns any any -> any any "
            "(msg:\"Test dns response additional name match with transform\"; "
            "dns.response; to_uppercase; content:\"NS2.GOOGLE.COM\"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* should match */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static void DetectDnsResponseRegisterTests(void)
{
    UtRegisterTest("DetectDnsResponseTest01", DetectDnsResponseTest01);
    UtRegisterTest("DetectDnsResponseTest02", DetectDnsResponseTest02);
    UtRegisterTest("DetectDnsResponseTest03", DetectDnsResponseTest03);
    UtRegisterTest("DetectDnsResponseTest04", DetectDnsResponseTest04);
    UtRegisterTest("DetectDnsResponseTest05", DetectDnsResponseTest05);
    UtRegisterTest("DetectDnsResponseTest06", DetectDnsResponseTest06);
    UtRegisterTest("DetectDnsResponseTest07", DetectDnsResponseTest07);
    UtRegisterTest("DetectDnsResponseTest08", DetectDnsResponseTest08);
    UtRegisterTest("DetectDnsResponseTest09", DetectDnsResponseTest09);
    UtRegisterTest("DetectDnsResponseTest10", DetectDnsResponseTest10);
    UtRegisterTest("DetectDnsResponseTest11", DetectDnsResponseTest11);
    UtRegisterTest("DetectDnsResponseTest12", DetectDnsResponseTest12);
    UtRegisterTest("DetectDnsResponseTest13", DetectDnsResponseTest13);
}

#endif