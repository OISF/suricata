/* Copyright (C) 2013-2018 Open Information Security Foundation
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
 * \ingroup dnslayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-dns-query.h"

#include "util-unittest-helper.h"
#include "rust.h"

static int DetectDnsQuerySetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectDnsQueryRegisterTests(void);
#endif
static int g_dns_query_buffer_id = 0;

struct DnsQueryGetDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

static InspectionBuffer *DnsQueryGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, struct DnsQueryGetDataArgs *cbdata, int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_dns_tx_get_query_name(cbdata->txv, cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectDnsQuery(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while(1) {
        struct DnsQueryGetDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = DnsQueryGetData(det_ctx,
            transforms, f, &cbdata, engine->sm_list, false);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmDnsQuery {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmDnsQuery;

/** \brief DnsQuery DnsQuery Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxDnsQuery(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmDnsQuery *ctx = (const PrefilterMpmDnsQuery *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    while(1) {
        // loop until we get a NULL

        struct DnsQueryGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = DnsQueryGetData(det_ctx, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmDnsQueryFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmDnsQueryRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmDnsQuery *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxDnsQuery,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmDnsQueryFree, mpm_reg->pname);
}

/**
 * \brief Registration function for keyword: dns_query
 */
void DetectDnsQueryRegister (void)
{
    sigmatch_table[DETECT_AL_DNS_QUERY].name = "dns.query";
    sigmatch_table[DETECT_AL_DNS_QUERY].alias = "dns_query";
    sigmatch_table[DETECT_AL_DNS_QUERY].desc = "sticky buffer to match DNS query-buffer";
    sigmatch_table[DETECT_AL_DNS_QUERY].url = "/rules/dns-keywords.html#dns-query";
    sigmatch_table[DETECT_AL_DNS_QUERY].Setup = DetectDnsQuerySetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DNS_QUERY].RegisterTests = DetectDnsQueryRegisterTests;
#endif
    sigmatch_table[DETECT_AL_DNS_QUERY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_QUERY].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2("dns_query", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmDnsQueryRegister, NULL,
            ALPROTO_DNS, 1);

    DetectAppLayerInspectEngineRegister2("dns_query",
            ALPROTO_DNS, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectDnsQuery, NULL);

    DetectBufferTypeSetDescriptionByName("dns_query",
            "dns request query");

    g_dns_query_buffer_id = DetectBufferTypeGetByName("dns_query");

#ifdef HAVE_LUA
    /* register these generic engines from here for now */
    DetectAppLayerInspectEngineRegister2(
            "dns_request", ALPROTO_DNS, SIG_FLAG_TOSERVER, 1, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2("dns_response", ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectGenericList, NULL);

    DetectBufferTypeSetDescriptionByName("dns_request",
            "dns requests");
    DetectBufferTypeSetDescriptionByName("dns_response",
            "dns responses");
#endif
}


/**
 * \brief setup the dns_query sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectDnsQuerySetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_dns_query_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0)
        return -1;
    return 0;
}

#ifdef UNITTESTS
#include "detect-isdataat.h"

/** \test simple google.com query matching */
static int DetectDnsQueryTest01(void)
{
    /* google.com */
    uint8_t buf[] = {   0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test multi tx google.(com|net) query matching */
static int DetectDnsQueryTest02(void)
{
    /* google.com */
    uint8_t buf1[] = {  0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x01, 0x00, 0x01, };

    uint8_t buf2[] = {  0x10, 0x32,                             /* tx id */
                        0x81, 0x80,                             /* flags: resp, recursion desired, recursion available */
                        0x00, 0x01,                             /* 1 query */
                        0x00, 0x01,                             /* 1 answer */
                        0x00, 0x00, 0x00, 0x00,                 /* no auth rr, additional rr */
                        /* query record */
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,     /* name */
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,     /* name cont */
                        0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
                        /* answer */
                        0xc0, 0x0c,                             /* ref to name in query above */
                        0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
                        0x00, 0x01, 0x40, 0xef,                 /* ttl */
                        0x00, 0x04,                             /* data len */
                        0x01, 0x02, 0x03, 0x04 };               /* addr */

    /* google.net */
    uint8_t buf3[] = {  0x11, 0x33, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x6E, 0x65, 0x74, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    Flow f;
    void *dns_state = NULL;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p1 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);
    p2 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);
    p3 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);

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
    p2->pcap_cnt = 2;

    p3->flow = &f;
    p3->flags |= PKT_HAS_FLOW;
    p3->flowflags |= FLOW_PKT_TOSERVER;
    p3->pcap_cnt = 3;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.net\"; nocase; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("(p1) sig 1 didn't alert, but it should have: ");
        FAIL;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT,
                            buf2, sizeof(buf2));
    if (r != 0) {
        printf("toserver client 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("(p2) sig 1 alerted, but it should not have: ");
        FAIL;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 alerted, but it should not have: ");
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER,
                            buf3, sizeof(buf3));
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    if (PacketAlertCheck(p3, 1)) {
        printf("(p3) sig 1 alerted, but it should not have: ");
        FAIL;
    }
    if (!(PacketAlertCheck(p3, 2))) {
        printf("(p3) sig 2 didn't alert, but it should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    PASS;
}

/** \test simple google.com query matching (TCP) */
static int DetectDnsQueryTest03(void)
{
    /* google.com */
    uint8_t buf[] = {   0x00, 28,
                        0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_DNS;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}


/** \test simple google.com query matching, pcre */
static int DetectDnsQueryTest04(void)
{
    /* google.com */
    uint8_t buf[] = {   0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; "
                              "pcre:\"/google\\.com$/i\"; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns_query option\"; "
                                      "dns_query; content:\"google\"; nocase; "
                                      "pcre:\"/^\\.[a-z]{2,3}$/iR\"; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        FAIL;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert, but it should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test multi tx google.(com|net) query matching +
 *        app layer event */
static int DetectDnsQueryTest05(void)
{
    /* google.com */
    uint8_t buf1[] = {  0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x01, 0x00, 0x01, };

    uint8_t buf2[] = {  0x10, 0x32,                             /* tx id */
                        0x81, 0x80|0x40,                        /* flags: resp, recursion desired, recursion available */
                        0x00, 0x01,                             /* 1 query */
                        0x00, 0x01,                             /* 1 answer */
                        0x00, 0x00, 0x00, 0x00,                 /* no auth rr, additional rr */
                        /* query record */
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,     /* name */
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,     /* name cont */
                        0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
                        /* answer */
                        0xc0, 0x0c,                             /* ref to name in query above */
                        0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
                        0x00, 0x01, 0x40, 0xef,                 /* ttl */
                        0x00, 0x04,                             /* data len */
                        0x01, 0x02, 0x03, 0x04 };               /* addr */

    /* google.net */
    uint8_t buf3[] = {  0x11, 0x33, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x6E, 0x65, 0x74, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    Flow f;
    void *dns_state = NULL;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p1 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_UDP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);
    p2 = UTHBuildPacketReal(buf2, sizeof(buf2), IPPROTO_UDP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);
    p3 = UTHBuildPacketReal(buf3, sizeof(buf3), IPPROTO_UDP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);

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
    p2->pcap_cnt = 2;

    p3->flow = &f;
    p3->flags |= PKT_HAS_FLOW;
    p3->flowflags |= FLOW_PKT_TOSERVER;
    p3->pcap_cnt = 3;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test dns_query option\"; "
                                   "dns_query; content:\"google.com\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test dns_query option\"; "
                                   "dns_query; content:\"google.net\"; nocase; sid:2;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test Z flag event\"; "
                                   "app-layer-event:dns.z_flag_set; sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("(p1) sig 1 didn't alert, but it should have: ");
        FAIL;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT,
                            buf2, sizeof(buf2));
    if (r != 0) {
        printf("toserver client 1 returned %" PRId32 ", expected 0\n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("(p2) sig 1 alerted, but it should not have: ");
        FAIL;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 alerted, but it should not have: ");
        FAIL;
    }
    if (!(PacketAlertCheck(p2, 3))) {
        printf("(p2) sig 3 didn't alert, but it should have: ");
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER,
                            buf3, sizeof(buf3));
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    if (PacketAlertCheck(p3, 1)) {
        printf("(p3) sig 1 alerted, but it should not have: ");
        FAIL;
    }
    if (!(PacketAlertCheck(p3, 2))) {
        printf("(p3) sig 2 didn't alert, but it should have: ");
        FAIL;
    }
    /** \todo should not alert, bug #839
    if (PacketAlertCheck(p3, 3)) {
        printf("(p3) sig 3 did alert, but it should not have: ");
        goto end;
    }
    */

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    PASS;
}

static int DetectDnsQueryIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert dns any any -> any any ("
            "dns_query; content:\"one\"; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_dns_query_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectDnsQueryRegisterTests(void)
{
    UtRegisterTest("DetectDnsQueryTest01", DetectDnsQueryTest01);
    UtRegisterTest("DetectDnsQueryTest02", DetectDnsQueryTest02);
    UtRegisterTest("DetectDnsQueryTest03 -- tcp", DetectDnsQueryTest03);
    UtRegisterTest("DetectDnsQueryTest04 -- pcre", DetectDnsQueryTest04);
    UtRegisterTest("DetectDnsQueryTest05 -- app layer event",
                   DetectDnsQueryTest05);

    UtRegisterTest("DetectDnsQueryIsdataatParseTest",
            DetectDnsQueryIsdataatParseTest);
}
#endif
