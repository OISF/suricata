/* Copyright (C) 2013 Open Information Security Foundation
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
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
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
#include "app-layer-dns-common.h"
#include "detect-dns-query.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectDnsQuerySetup (DetectEngineCtx *, Signature *, char *);
static void DetectDnsQueryRegisterTests(void);

/**
 * \brief Registration function for keyword: http_uri
 */
void DetectDnsQueryRegister (void)
{
    sigmatch_table[DETECT_AL_DNS_QUERY].name = "dns_query";
    sigmatch_table[DETECT_AL_DNS_QUERY].desc = "content modifier to match specifically and only on the DNS query-buffer";
    sigmatch_table[DETECT_AL_DNS_QUERY].Match = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].alproto = ALPROTO_DNS;
    sigmatch_table[DETECT_AL_DNS_QUERY].Setup = DetectDnsQuerySetup;
    sigmatch_table[DETECT_AL_DNS_QUERY].Free  = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].RegisterTests = DetectDnsQueryRegisterTests;

    sigmatch_table[DETECT_AL_DNS_QUERY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_QUERY].flags |= SIGMATCH_PAYLOAD;
}


/**
 * \brief this function setups the dns_query modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectDnsQuerySetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    s->list = DETECT_SM_LIST_DNSQUERYNAME_MATCH;
    s->alproto = ALPROTO_DNS;
    return 0;
}

/**
 *  \brief Run the pattern matcher against the queries
 *
 *  \param f locked flow
 *  \param dns_state initialized dns state
 *
 *  \warning Make sure the flow/state is locked
 *  \todo what should we return? Just the fact that we matched?
 */
uint32_t DetectDnsQueryInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                  DNSState *dns_state, uint8_t flags, void *txv,
                                  uint64_t tx_id)
{
    SCEnter();

    DNSTransaction *tx = (DNSTransaction *)txv;
    DNSQueryEntry *query = NULL;
    uint8_t *buffer;
    uint16_t buffer_len;
    uint32_t cnt = 0;

    TAILQ_FOREACH(query, &tx->query_list, next) {
        SCLogDebug("tx %p query %p", tx, query);

        buffer = (uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry));
        buffer_len = query->len;

        cnt += DnsQueryPatternSearch(det_ctx,
                buffer, buffer_len,
                flags);
    }

    SCReturnUInt(cnt);
}

#ifdef UNITTESTS
/** \test simple google.com query matching */
static int DetectDnsQueryTest01(void)
{
    /* google.com */
    uint8_t buf[] = {   0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
    return result;
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
                        0x81, 0x80,                             /* flags: resp, recursion desired, recusion available */
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
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.com\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.net\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("(p1) sig 1 didn't alert, but it should have: ");
        goto end;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf2, sizeof(buf2));
    if (r != 0) {
        printf("toserver client 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("(p2) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 alerted, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf3, sizeof(buf3));
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    if (PacketAlertCheck(p3, 1)) {
        printf("(p3) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p3, 2))) {
        printf("(p3) sig 2 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
    return result;
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
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
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

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "content:\"google\"; nocase; dns_query; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test simple google.com query matching (TCP splicing) */
static int DetectDnsQueryTest04(void)
{
    /* google.com */
    uint8_t buf1[] = {  0x00, 28,
                        0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
    uint8_t buf2[] = {  0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
    Packet *p1 = NULL, *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);
    p2 = UTHBuildPacketReal(buf2, sizeof(buf2), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_DNS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p1->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sig 1 alerted, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf2, sizeof(buf2));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    return result;
}

/** \test simple google.com query matching (TCP splicing) */
static int DetectDnsQueryTest05(void)
{
    /* google.com in 2 chunks (buf1 and buf2) */
    uint8_t buf1[] = {  0x00, 28,                               /* len 28 */
                        0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

    uint8_t buf2[] = {  0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };

    uint8_t buf3[] = {  0x00, 44,                               /* len 44 */
                        0x10, 0x32,                             /* tx id */
                        0x81, 0x80,                             /* flags: resp, recursion desired, recusion available */
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
    uint8_t buf4[] = {  0x00, 28,                               /* len 28 */
                        0x11, 0x33, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x6E, 0x65, 0x74, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacketReal(buf1, sizeof(buf1), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);
    p2 = UTHBuildPacketReal(buf2, sizeof(buf2), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);
    p3 = UTHBuildPacketReal(buf3, sizeof(buf3), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);
    p4 = UTHBuildPacketReal(buf4, sizeof(buf4), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1",
                            41424, 53);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_DNS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p1->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;

    p3->flow = &f;
    p3->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p3->flowflags |= FLOW_PKT_TOCLIENT|FLOW_PKT_ESTABLISHED;

    p4->flow = &f;
    p4->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p4->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.com\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.net\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("(p1) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf2, sizeof(buf2));
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf3, sizeof(buf3));
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    if (PacketAlertCheck(p3, 1)) {
        printf("sig 1 did alert, but it should not have: ");
        goto end;
    }
    if (PacketAlertCheck(p3, 2)) {
        printf("(p3) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf4, sizeof(buf4));
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p4);

    if (PacketAlertCheck(p4, 1)) {
        printf("(p4) sig 1 did alert, but it should not have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p4, 2))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    return result;
}

/** \test simple google.com query matching, pcre */
static int DetectDnsQueryTest06(void)
{
    /* google.com */
    uint8_t buf[] = {   0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x10, 0x00, 0x01, };
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google\"; nocase; "
                              "pcre:\"/google\\.com$/i\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                      "(msg:\"Test dns_query option\"; "
                                      "dns_query; content:\"google\"; nocase; "
                                      "pcre:\"/^\\.[a-z]{2,3}$/iR\"; sid:2;)");
    if (s == NULL) {
        goto end;
    }


    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
    return result;
}

/** \test multi tx google.(com|net) query matching +
 *        app layer event */
static int DetectDnsQueryTest07(void)
{
    /* google.com */
    uint8_t buf1[] = {  0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
                        0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x01, 0x00, 0x01, };

    uint8_t buf2[] = {  0x10, 0x32,                             /* tx id */
                        0x81, 0x80|0x40,                        /* flags: resp, recursion desired, recusion available */
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
    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test dns_query option\"; "
                                   "dns_query; content:\"google.com\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test dns_query option\"; "
                                   "dns_query; content:\"google.net\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                                   "(msg:\"Test Z flag event\"; "
                                   "app-layer-event:dns.z_flag_set; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf1, sizeof(buf1));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("(p1) sig 1 didn't alert, but it should have: ");
        goto end;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, buf2, sizeof(buf2));
    if (r != -1) {
        printf("toserver client 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("(p2) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 alerted, but it should not have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p2, 3))) {
        printf("(p2) sig 3 didn't alert, but it should have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf3, sizeof(buf3));
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p3);

    if (PacketAlertCheck(p3, 1)) {
        printf("(p3) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p3, 2))) {
        printf("(p3) sig 2 didn't alert, but it should have: ");
        goto end;
    }
    /** \todo should not alert, bug #839
    if (PacketAlertCheck(p3, 3)) {
        printf("(p3) sig 3 did alert, but it should not have: ");
        goto end;
    }
    */
    result = 1;

end:
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
    return result;
}

#endif

static void DetectDnsQueryRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDnsQueryTest01", DetectDnsQueryTest01, 1);
    UtRegisterTest("DetectDnsQueryTest02", DetectDnsQueryTest02, 1);
    UtRegisterTest("DetectDnsQueryTest03 -- tcp", DetectDnsQueryTest03, 1);
    UtRegisterTest("DetectDnsQueryTest04 -- tcp splicing", DetectDnsQueryTest04, 1);
    UtRegisterTest("DetectDnsQueryTest05 -- tcp splicing/multi tx", DetectDnsQueryTest05, 1);
    UtRegisterTest("DetectDnsQueryTest06 -- pcre", DetectDnsQueryTest06, 1);
    UtRegisterTest("DetectDnsQueryTest07 -- app layer event", DetectDnsQueryTest07, 1);
#endif
}
