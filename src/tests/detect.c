/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifdef UNITTESTS

#include "../app-layer-htp.h"
#include "../conf-yaml-loader.h"
#include "../detect-parse.h"
#include "../detect-engine-content-inspection.h"
#include "../pkt-var.h"
#include "../flow-util.h"
#include "../stream-tcp-reassemble.h"
#include "../util-unittest.h"
#include "../util-unittest-helper.h"

static const char *dummy_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/suricata\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "  output:\n"
    "\n"
    "  - interface: console\n"
    "    log-level: info\n"
    "\n"
    "  - interface: file\n"
    "    filename: /var/log/suricata.log\n"
    "\n"
    "  - interface: syslog\n"
    "    facility: local5\n"
    "    format: \"%l\"\n"
    "\n"
    "pfring:\n"
    "\n"
    "  interface: eth0\n"
    "\n"
    "  clusterid: 99\n"
    "\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[192.168.0.0/16,10.8.0.0/16,127.0.0.1,2001:888:"
    "13c5:5AFE::/64,2001:888:13c5:CAFE::/64]\"\n"
    "\n"
    "    EXTERNAL_NET: \"[!192.168.0.0/16,2000::/3]\"\n"
    "\n"
    "    HTTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SMTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SQL_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    DNS_SERVERS: any\n"
    "\n"
    "    TELNET_SERVERS: any\n"
    "\n"
    "    AIM_SERVERS: any\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n"
    "    SHELLCODE_PORTS: 80\n"
    "\n"
    "    ORACLE_PORTS: 1521\n"
    "\n"
    "    SSH_PORTS: 22\n"
    "\n";

static int SigTest01 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }
#if 0
    //printf("URI0 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[0], p.http_uri.raw_size[0]);
    //printf("URI1 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[1], p.http_uri.raw_size[1]);

    if (p->http_uri.raw_size[0] == 5 &&
        memcmp(p->http_uri.raw[0], "/one/", 5) == 0 &&
        p->http_uri.raw_size[1] == 5 &&
        memcmp(p->http_uri.raw[1], "/two/", 5) == 0)
    {
        result = 1;
    }

#endif
    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int SigTest02 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    char sig[] = "alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:41; sid:1;)";
    int ret = UTHPacketMatchSigMpm(p, sig, MPM_AC);
    UTHFreePacket(p);
    return ret;
}

static int SigTest03 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:39; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTest04 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n" /* 20*/
                    "Host: one.example.org\r\n" /* 23, post "Host:" 18 */
                    "\r\n\r\n" /* 4 */
                    "GET /two/ HTTP/1.1\r\n" /* 20 */
                    "Host: two.example.org\r\n" /* 23 */
                    "\r\n\r\n"; /* 4 */
    uint16_t buflen = strlen((char *)buf);

    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:42; within:47; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTest05 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:48; within:52; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)) {
        result = 1;
    } else {
        printf("sig matched but shouldn't have: ");
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTest06 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    FAIL_IF(r != 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 2));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

static int SigTest07 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"three\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FlowCleanupAppLayer(&f);
    FLOW_DESTROY(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int SigTest08 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(Flow));
    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"one\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;
    else
        printf("sid:1 %s, sid:2 %s: ",
            PacketAlertCheck(p, 1) ? "OK" : "FAIL",
            PacketAlertCheck(p, 2) ? "OK" : "FAIL");

end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest09 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;
    else
        result = 0;

end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest10 (void)
{
    uint8_t *buf = (uint8_t *)
                    "ABC";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (1)\"; content:\"ABCD\"; depth:4; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (2)\"; content:\"VWXYZ\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

 end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest11 (void)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (content:\"VWXYZabcde\"; content:\"5678\"; content:\"89\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;

 end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest12 (void)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        result = 0;

    if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
end:
    UTHFreePackets(&p, 1);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest13 (void)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest14 (void)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTest15 (void)
{
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 80;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 2008284))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}

static int SigTest16 (void)
{
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));

    p = UTHBuildPacketSrcDstPorts((uint8_t *)buf, buflen, IPPROTO_TCP, 12345, 1234);

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 2008284))
        result = 1;
    else
        printf("sid:2008284 %s: ", PacketAlertCheck(p, 2008284) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTest17 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketSrcDstPorts((uint8_t *)buf, buflen, IPPROTO_TCP, 12345, 80);
    FAIL_IF_NULL(p);

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; content:\"Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    uint32_t capid = VarNameStoreLookupByName("http_host", VAR_TYPE_PKT_VAR);

    PktVar *pv_hn = PktVarGet(p, capid);
    FAIL_IF_NULL(pv_hn);

    FAIL_IF(pv_hn->value_len != 15);
    FAIL_IF_NOT(memcmp(pv_hn->value, "one.example.org", pv_hn->value_len) == 0);

    PktVarFree(pv_hn);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ConfDeInit();
    ConfRestoreContextBackup();
    UTHFreePackets(&p, 1);

    PASS;
}

static int SigTest18 (void)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any !21:902 -> any any (msg:\"ET MALWARE Suspicious 220 Banner on Local Port\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:2003055; rev:4;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 2003055))
        result = 1;
    else
        printf("signature shouldn't match, but did: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p);
    return result;
}

static int SigTest19 (void)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> 1.2.3.4 any (msg:\"IP-ONLY test (1)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}

static int SigTest20 (void)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> [99.99.99.99,1.2.3.0/24,1.1.1.1,3.0.0.0/8] any (msg:\"IP-ONLY test (2)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}

static int SigTest21 (void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;
    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sid 2 didn't alert, but should have: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        if (det_ctx != NULL) {
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        }
    }
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest22 (void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.abc; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2)))
        result = 1;
    else
        printf("sid 2 alerted, but shouldn't: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest23 (void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:toggle,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result = 1;
    else
        printf("sid 2 didn't alert, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest24IPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x06};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    PACKET_RESET_CHECKSUMS(p1);
    PACKET_RESET_CHECKSUMS(p2);

    p1->ip4h = (IPV4Hdr *)valid_raw_ipv4;

    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    p2->ip4h = (IPV4Hdr *)invalid_raw_ipv4;

    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
            "alert ip any any -> any any "
            "(content:\"/one/\"; ipv4-csum:valid; "
            "msg:\"ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig 1 parse: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
            "alert ip any any -> any any "
            "(content:\"/one/\"; ipv4-csum:invalid; "
            "msg:\"ipv4-csum keyword check(1)\"; "
            "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        printf("sig 2 parse: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("signature 1 didn't match, but should have: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!((PacketAlertCheck(p2, 2)))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest25NegativeIPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x06};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    PACKET_RESET_CHECKSUMS(p1);
    PACKET_RESET_CHECKSUMS(p2);

    p1->ip4h = (IPV4Hdr *)valid_raw_ipv4;

    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    p2->ip4h = (IPV4Hdr *)invalid_raw_ipv4;

    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"/one/\"; ipv4-csum:invalid; "
                               "msg:\"ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"/one/\"; ipv4-csum:valid; "
                                     "msg:\"ipv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest26TCPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0x4A, 0x04, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(ThreadVars));

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                               "msg:\"tcpv4-csum keyword check(1)\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; "
                                     "msg:\"tcpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(!(PacketAlertCheck(p1, 1)));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(!(PacketAlertCheck(p2, 2)));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    PASS;
}

/* Test SigTest26TCPV4Keyword but also check for invalid IPV4 checksum */
static int SigTest26TCPV4AndNegativeIPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0x4A, 0x04, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                               "ipv4-csum:invalid; "
                               "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; "
                                     "ipv4-csum:invalid; "
                                     "msg:\"tcpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sig 1 didn't match: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sig 2 didn't match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

/* Similar to SigTest26, but with different packet */
static int SigTest26TCPV4AndIPV4Keyword(void)
{
    /* IPV4: src:192.168.176.67 dst: 192.168.176.116
     * TTL: 64 Flags: Don't Fragment
     */
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x40, 0x9b, 0xa4, 0x40, 0x00,
        0x40, 0x06, 0xbd, 0x0a, 0xc0, 0xa8, 0xb0, 0x43,
        0xc0, 0xa8, 0xb0, 0x74};

    /* TCP: sport: 49517 dport: 445 Flags: SYN
     * Window size: 65535, checksum: 0x2009,
     * MTU: 1460, Window scale: 4, TSACK permitted,
     * 24 bytes of options, no payload.
     */
    uint8_t valid_raw_tcp[] = {
        0xc1, 0x6d, 0x01, 0xbd, 0x03, 0x10, 0xd3, 0xc9,
        0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff,
        0x20, 0x09, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x04, 0x01, 0x01, 0x08, 0x0a,
        0x19, 0x69, 0x81, 0x7e, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00};

    uint8_t invalid_raw_tcp[] = {
        0xc1, 0x6d, 0x01, 0xbd, 0x03, 0x10, 0xd3, 0xc9,
        0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff,
        0x20, 0x09, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x04, 0x01, 0x01, 0x08, 0x0a,
        0x19, 0x69, 0x81, 0x7e, 0xFF, 0xAA, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20 + 24;
    p1->payload_len = 0;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20 + 24;
    p2->payload_len = 0;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(tcpv4-csum:valid; "
                               "ipv4-csum:valid; "
                               "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(tcpv4-csum:invalid; "
                                     "ipv4-csum:valid; "
                                     "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sig 1 didn't match: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sig 2 didn't match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest27NegativeTCPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; dsize:20; "
            "msg:\"tcpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                                     "msg:\"tcpv4-csum keyword check(2)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!PacketAlertCheck(p1, 1)) {
        printf("sig 1 didn't match on p1: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2)) {
        printf("sig 2 matched on p2: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest28TCPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xf2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x27};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xc2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x28};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->tcph = (TCPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = valid_raw_ipv6 + 54 + 20;
    p1->payload_len = 12;
    p1->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p1) != 20) {
        BUG_ON(1);
    }

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->tcph = (TCPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = invalid_raw_ipv6 + 54 + 20;;
    p2->payload_len = 12;
    p2->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p2) != 20) {
        BUG_ON(1);
    }

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"|00 01 69|\"; tcpv6-csum:valid; dsize:12; "
                               "msg:\"tcpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|00 01 69|\"; tcpv6-csum:invalid; dsize:12; "
                                     "msg:\"tcpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sid 2 didn't match on p2: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest29NegativeTCPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xf2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x27};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xc2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x28};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->tcph = (TCPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = valid_raw_ipv6 + 54 + 20;
    p1->payload_len = 12;
    p1->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p1) != 20) {
        BUG_ON(1);
    }

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->tcph = (TCPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = invalid_raw_ipv6 + 54 + 20;;
    p2->payload_len = 12;
    p2->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p2) != 20) {
        BUG_ON(1);
    }

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"|00 01 69|\"; tcpv6-csum:invalid; dsize:12; "
                               "msg:\"tcpv6-csum keyword check(1)\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|00 01 69|\"; tcpv6-csum:valid; dsize:12; "
                                     "msg:\"tcpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        goto end;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        goto end;

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest30UDPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x11, 0x00, 0x00, 0xd0, 0x43, 0xdc, 0xdc,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    uint8_t invalid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    Packet *p1 = PacketGetFromAlloc();
    FAIL_IF_NULL(p1);
    Packet *p2 = PacketGetFromAlloc();
    FAIL_IF_NULL(p2);

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0yyyyyyyyyyyyyyyy\r\n"
                    "\r\n\r\nyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->udph = (UDPHdr *)valid_raw_udp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = sizeof(valid_raw_udp) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)raw_ipv4;
    p2->udph = (UDPHdr *)invalid_raw_udp;
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = sizeof(invalid_raw_udp) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv4-csum:valid; "
                               "msg:\"udpv4-csum keyword check(1)\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv4-csum:invalid; "
                                     "msg:\"udpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 2));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    PASS;
}

static int SigTest31NegativeUDPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd0, 0x43, 0xdc, 0xdc,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    uint8_t invalid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0yyyyyyyyyyyyyyyy\r\n"
                    "\r\n\r\nyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->udph = (UDPHdr *)valid_raw_udp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = sizeof(valid_raw_udp) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)raw_ipv4;
    p2->udph = (UDPHdr *)invalid_raw_udp;
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = sizeof(invalid_raw_udp) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv4-csum:invalid; "
                               "msg:\"udpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv4-csum:valid; "
                                     "msg:\"udpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2)) {
        result &= 0;
    }
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}


static int SigTest32UDPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    Packet *p1 = PacketGetFromAlloc();
    FAIL_IF_NULL(p1);
    Packet *p2 = PacketGetFromAlloc();
    FAIL_IF_NULL(p2);

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP\r\n"
                    "\r\n\r\n";

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->udph = (UDPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = IPV6_GET_PLEN((p1)) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->udph = (UDPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = IPV6_GET_PLEN((p2)) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv6-csum:valid; "
                               "msg:\"udpv6-csum keyword check(1)\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv6-csum:invalid; "
                                     "msg:\"udpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 2));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    SCFree(p1);
    SCFree(p2);
    PASS;
}

static int SigTest33NegativeUDPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP\r\n"
                    "\r\n\r\n";

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->udph = (UDPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = IPV6_GET_PLEN((p1)) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->udph = (UDPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = IPV6_GET_PLEN((p2)) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv6-csum:invalid; "
                               "msg:\"udpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv6-csum:valid; "
                                     "msg:\"udpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest34ICMPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x38};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)(valid_raw_ipv4);
    p1->ip4h->ip_verhl = 69;
    p1->icmpv4h = (ICMPV4Hdr *) (valid_raw_ipv4 + IPV4_GET_RAW_HLEN(p1->ip4h) * 4);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)(invalid_raw_ipv4);
    p2->ip4h->ip_verhl = 69;
    p2->icmpv4h = (ICMPV4Hdr *) (invalid_raw_ipv4 + IPV4_GET_RAW_HLEN(p2->ip4h) * 4);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmp any any -> any any "
                               "(content:\"/one/\"; icmpv4-csum:valid; "
                               "msg:\"icmpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmp any any -> any any "
                                     "(content:\"/one/\"; icmpv4-csum:invalid; "
                                     "msg:\"icmpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 1;
    else
        result &= 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 1;
    else
        result &= 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest35NegativeICMPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x38};

    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)(valid_raw_ipv4);
    p1->ip4h->ip_verhl = 69;
    p1->icmpv4h = (ICMPV4Hdr *) (valid_raw_ipv4 + IPV4_GET_RAW_HLEN(p1->ip4h) * 4);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)(invalid_raw_ipv4);
    p2->ip4h->ip_verhl = 69;
    p2->icmpv4h = (ICMPV4Hdr *) (invalid_raw_ipv4 + IPV4_GET_RAW_HLEN(p2->ip4h) * 4);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmp any any -> any any "
                               "(content:\"/one/\"; icmpv4-csum:invalid; "
                               "msg:\"icmpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmp any any -> any any "
                                     "(content:\"/one/\"; icmpv4-csum:valid; "
                                     "msg:\"icmpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else {
        result &= 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest38(void)
{
    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;
    uint8_t raw_eth[] = {
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00
    };
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x7d, 0xd8, 0xf3, 0x40, 0x00,
        0x40, 0x06, 0x63, 0x85, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    uint8_t raw_tcp[] = {
        0xad, 0x22, 0x04, 0x00, 0x16, 0x39, 0x72,
        0xe2, 0x16, 0x1f, 0x79, 0x84, 0x80, 0x18,
        0x01, 0x01, 0xfe, 0x71, 0x00, 0x00, 0x01,
        0x01, 0x08, 0x0a, 0x00, 0x22, 0xaa, 0x10,
        0x00, 0x22, 0xaa, 0x10
    };
    uint8_t buf[] = {
        0x00, 0x00, 0x00, 0x08, 0x62, 0x6f, 0x6f, 0x65,
        0x65, 0x6b, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x31,
        0x20, 0x38, 0x0d, 0x0a, 0x66, 0x6f, 0x30, 0x30, /* LEN1|20| ends at 17 */
        0x30, 0x38, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x32, /* "0008" at offset 5 */
        0x20, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x0d, 0x0a, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d,
        0x0a
    };
    uint16_t ethlen = sizeof(raw_eth);
    uint16_t ipv4len = sizeof(raw_ipv4);
    uint16_t tcplen = sizeof(raw_tcp);
    uint16_t buflen = sizeof(buf);

    memset(&th_v, 0, sizeof(ThreadVars));

    /* Copy raw data into packet */
    if (PacketCopyData(p1, raw_eth, ethlen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen, raw_ipv4, ipv4len) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len, raw_tcp, tcplen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len + tcplen, buf, buflen) == -1) {
        SCFree(p1);
        return 1;
    }
    SET_PKT_LEN(p1, ethlen + ipv4len + tcplen + buflen);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ethh = (EthernetHdr *)raw_eth;
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->tcph = (TCPHdr *)raw_tcp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = GET_PKT_DATA(p1) + ethlen + ipv4len + tcplen;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,0; "
                               "msg:\"byte_test keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,5,relative,string,dec; "
                               "msg:\"byte_test keyword check(2)\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 1 didn't alert, but should have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p1, 2)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 2 didn't alert, but should have: ");
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p1);
    return result;
}

static int SigTest39(void)
{
    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;
    uint8_t raw_eth[] = {
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00
    };
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x7d, 0xd8, 0xf3, 0x40, 0x00,
        0x40, 0x06, 0x63, 0x85, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    uint8_t raw_tcp[] = {
        0xad, 0x22, 0x04, 0x00, 0x16, 0x39, 0x72,
        0xe2, 0x16, 0x1f, 0x79, 0x84, 0x80, 0x18,
        0x01, 0x01, 0xfe, 0x71, 0x00, 0x00, 0x01,
        0x01, 0x08, 0x0a, 0x00, 0x22, 0xaa, 0x10,
        0x00, 0x22, 0xaa, 0x10
    };
    uint8_t buf[] = {
        0x00, 0x00, 0x00, 0x08, 0x62, 0x6f, 0x6f, 0x65,
        0x65, 0x6b, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x31,
        0x20, 0x38, 0x0d, 0x0a, 0x66, 0x30, 0x30, 0x30,
        0x38, 0x72, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x32,
        0x20, 0x39, 0x39, 0x4c, 0x45, 0x4e, 0x32, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x0d, 0x0a, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d,
        0x0a
    };
    uint16_t ethlen = sizeof(raw_eth);
    uint16_t ipv4len = sizeof(raw_ipv4);
    uint16_t tcplen = sizeof(raw_tcp);
    uint16_t buflen = sizeof(buf);

    memset(&th_v, 0, sizeof(ThreadVars));

    /* Copy raw data into packet */
    if (PacketCopyData(p1, raw_eth, ethlen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen, raw_ipv4, ipv4len) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len, raw_tcp, tcplen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len + tcplen, buf, buflen) == -1) {
        SCFree(p1);
        return 1;
    }
    SET_PKT_LEN(p1, ethlen + ipv4len + tcplen + buflen);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ethh = (EthernetHdr *)raw_eth;
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->tcph = (TCPHdr *)raw_tcp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = GET_PKT_DATA(p1) + ethlen + ipv4len + tcplen;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,0; "
                               "byte_jump:4,0; "
                               "byte_test:6,=,0x4c454e312038,0,relative; "
                               "msg:\"byte_jump keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }
    // XXX TODO
    de_ctx->sig_list->next = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,4,relative,string,dec; "
                               "byte_jump:4,4,relative,string,dec,post_offset 2; "
                               "byte_test:4,=,0x4c454e32,0,relative; "
                               "msg:\"byte_jump keyword check(2)\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 1 didn't alert, but should have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p1, 2)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 2 didn't alert, but should have: ");
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p1);
    return result;
}

/**
 * \test SigTest36ContentAndIsdataatKeywords01 is a test to check window with constructed packets,
 * \brief expecting to match a size
 */

static int SigTest36ContentAndIsdataatKeywords01 (void)
{
    int result = 0;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
     0x00,0x25,0x00,0x9e,0xfa,0xfe,0x00,0x02,0xcf,0x74,0xfe,0xe1,0x08,0x00,0x45,0x00
	,0x01,0xcc,0xcb,0x91,0x00,0x00,0x34,0x06,0xdf,0xa8,0xd1,0x55,0xe3,0x67,0xc0,0xa8
	,0x64,0x8c,0x00,0x50,0xc0,0xb7,0xd1,0x11,0xed,0x63,0x81,0xa9,0x9a,0x05,0x80,0x18
	,0x00,0x75,0x0a,0xdd,0x00,0x00,0x01,0x01,0x08,0x0a,0x09,0x8a,0x06,0xd0,0x12,0x21
	,0x2a,0x3b,0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46
	,0x6f,0x75,0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20
	,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c
	,0x65,0x2e,0x65,0x73,0x2f,0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e
	,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43
	,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78
	,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d
	,0x55,0x54,0x46,0x2d,0x38,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a,0x20,0x4d,0x6f,0x6e
	,0x2c,0x20,0x31,0x34,0x20,0x53,0x65,0x70,0x20,0x32,0x30,0x30,0x39,0x20,0x30,0x38
	,0x3a,0x34,0x38,0x3a,0x33,0x31,0x20,0x47,0x4d,0x54,0x0d,0x0a,0x53,0x65,0x72,0x76
	,0x65,0x72,0x3a,0x20,0x67,0x77,0x73,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74
	,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x32,0x31,0x38,0x0d,0x0a,0x0d,0x0a
	,0x3c,0x48,0x54,0x4d,0x4c,0x3e,0x3c,0x48,0x45,0x41,0x44,0x3e,0x3c,0x6d,0x65,0x74
	,0x61,0x20,0x68,0x74,0x74,0x70,0x2d,0x65,0x71,0x75,0x69,0x76,0x3d,0x22,0x63,0x6f
	,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x74,0x79,0x70,0x65,0x22,0x20,0x63,0x6f,0x6e,0x74
	,0x65,0x6e,0x74,0x3d,0x22,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x63
	,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x22,0x3e,0x0a,0x3c
	,0x54,0x49,0x54,0x4c,0x45,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76,0x65,0x64,0x3c
	,0x2f,0x54,0x49,0x54,0x4c,0x45,0x3e,0x3c,0x2f,0x48,0x45,0x41,0x44,0x3e,0x3c,0x42
	,0x4f,0x44,0x59,0x3e,0x0a,0x3c,0x48,0x31,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76
	,0x65,0x64,0x3c,0x2f,0x48,0x31,0x3e,0x0a,0x54,0x68,0x65,0x20,0x64,0x6f,0x63,0x75
	,0x6d,0x65,0x6e,0x74,0x20,0x68,0x61,0x73,0x20,0x6d,0x6f,0x76,0x65,0x64,0x0a,0x3c
	,0x41,0x20,0x48,0x52,0x45,0x46,0x3d,0x22,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77
	,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x65,0x73,0x2f,0x22,0x3e,0x68
	,0x65,0x72,0x65,0x3c,0x2f,0x41,0x3e,0x2e,0x0d,0x0a,0x3c,0x2f,0x42,0x4f,0x44,0x59
	,0x3e,0x3c,0x2f,0x48,0x54,0x4d,0x4c,0x3e,0x0d,0x0a };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);


    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest36ContentAndIsdataatKeywords01 \"; content:\"HTTP\"; isdataat:404, relative; sid:101;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 101) == 0) {
        result = 0;
        goto end;
    } else {
        result=1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if(de_ctx)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if(det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    //PatternMatchDestroy(mpm_ctx);

    if(de_ctx)
             DetectEngineCtxFree(de_ctx);

    if (p != NULL)
        PACKET_RECYCLE(p);

    FlowShutdown();

    SCFree(p);
    return result;
}


/**
 * \test SigTest37ContentAndIsdataatKeywords02 is a test to check window with constructed packets,
 *  \brief not expecting to match a size
 */

static int SigTest37ContentAndIsdataatKeywords02 (void)
{
    int result = 0;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
   0x00,0x25,0x00,0x9e,0xfa,0xfe,0x00,0x02,0xcf,0x74,0xfe,0xe1,0x08,0x00,0x45,0x00
	,0x01,0xcc,0xcb,0x91,0x00,0x00,0x34,0x06,0xdf,0xa8,0xd1,0x55,0xe3,0x67,0xc0,0xa8
	,0x64,0x8c,0x00,0x50,0xc0,0xb7,0xd1,0x11,0xed,0x63,0x81,0xa9,0x9a,0x05,0x80,0x18
	,0x00,0x75,0x0a,0xdd,0x00,0x00,0x01,0x01,0x08,0x0a,0x09,0x8a,0x06,0xd0,0x12,0x21
	,0x2a,0x3b,0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46
	,0x6f,0x75,0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20
	,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c
	,0x65,0x2e,0x65,0x73,0x2f,0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e
	,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43
	,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78
	,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d
	,0x55,0x54,0x46,0x2d,0x38,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a,0x20,0x4d,0x6f,0x6e
	,0x2c,0x20,0x31,0x34,0x20,0x53,0x65,0x70,0x20,0x32,0x30,0x30,0x39,0x20,0x30,0x38
	,0x3a,0x34,0x38,0x3a,0x33,0x31,0x20,0x47,0x4d,0x54,0x0d,0x0a,0x53,0x65,0x72,0x76
	,0x65,0x72,0x3a,0x20,0x67,0x77,0x73,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74
	,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x32,0x31,0x38,0x0d,0x0a,0x0d,0x0a
	,0x3c,0x48,0x54,0x4d,0x4c,0x3e,0x3c,0x48,0x45,0x41,0x44,0x3e,0x3c,0x6d,0x65,0x74
	,0x61,0x20,0x68,0x74,0x74,0x70,0x2d,0x65,0x71,0x75,0x69,0x76,0x3d,0x22,0x63,0x6f
	,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x74,0x79,0x70,0x65,0x22,0x20,0x63,0x6f,0x6e,0x74
	,0x65,0x6e,0x74,0x3d,0x22,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x63
	,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x22,0x3e,0x0a,0x3c
	,0x54,0x49,0x54,0x4c,0x45,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76,0x65,0x64,0x3c
	,0x2f,0x54,0x49,0x54,0x4c,0x45,0x3e,0x3c,0x2f,0x48,0x45,0x41,0x44,0x3e,0x3c,0x42
	,0x4f,0x44,0x59,0x3e,0x0a,0x3c,0x48,0x31,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76
	,0x65,0x64,0x3c,0x2f,0x48,0x31,0x3e,0x0a,0x54,0x68,0x65,0x20,0x64,0x6f,0x63,0x75
	,0x6d,0x65,0x6e,0x74,0x20,0x68,0x61,0x73,0x20,0x6d,0x6f,0x76,0x65,0x64,0x0a,0x3c
	,0x41,0x20,0x48,0x52,0x45,0x46,0x3d,0x22,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77
	,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x65,0x73,0x2f,0x22,0x3e,0x68
	,0x65,0x72,0x65,0x3c,0x2f,0x41,0x3e,0x2e,0x0d,0x0a,0x3c,0x2f,0x42,0x4f,0x44,0x59
	,0x3e,0x3c,0x2f,0x48,0x54,0x4d,0x4c,0x3e,0x0d,0x0a };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);


    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    Signature *s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest37ContentAndIsdataatKeywords01 \"; content:\"HTTP\"; isdataat:500, relative; sid:101;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        result = 0;
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT) {
        printf("type not content: ");
        goto end;
    }
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 101) == 0) {
        result = 1;
        goto end;
    } else {
        printf("sig matched, but should not have: ");
        result=0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if(de_ctx)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if(det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if(de_ctx)
        DetectEngineCtxFree(de_ctx);

    if (p != NULL)
        PACKET_RECYCLE(p);

    FlowShutdown();

    SCFree(p);
    return result;
}

/**
 * \test SigTest41NoPacketInspection is a test to check that when PKT_NOPACKET_INSPECTION
 *  flag is set, we don't need to inspect the packet protocol header or its contents.
 */

static int SigTest40NoPacketInspection01(void)
{

    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    TCPHdr tcphdr;
    if (unlikely(p == NULL))
    return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    PacketQueue pq;
    Flow f;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&pq, 0, sizeof(pq));
    memset(&f, 0, sizeof(f));
    memset(&tcphdr, 0, sizeof(tcphdr));

    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flags |= PKT_NOPACKET_INSPECTION;
    p->tcph = &tcphdr;
    p->flow = &f;

    FLOW_INITIALIZE(&f);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> 1.2.3.4 any (msg:\"No Packet Inspection Test\"; flow:to_server; sid:2; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    det_ctx->de_ctx = de_ctx;

    Detect(&th_v, p, det_ctx, &pq, NULL);
    if (PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p);
    return result;
}

/**
 * \test SigTest42NoPayloadInspection is a test to check that when PKT_NOPAYLOAD_INSPECTION
 *  flasg is set, we don't need to inspect the packet contents.
 */

static int SigTest40NoPayloadInspection02(void)
{

    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_NOPAYLOAD_INSPECTION;

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"No Payload TEST\"; content:\"220 (vsFTPd 2.0.5)\"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p);
    PASS;
}

static int SigTestMemory01 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    SCFree(p);
    return result;
}

static int SigTestMemory02 (void)
{
    ThreadVars th_v;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 456 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any 1:1000 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);

    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    return result;
}

static int SigTestMemory03 (void)
{
    ThreadVars th_v;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> 1.2.3.4 456 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> 1.2.3.3-1.2.3.6 1:1000 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert tcp any any -> !1.2.3.5 1:990 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);

    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    return result;
}

static int SigTestContent01 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTestContent02 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 31\"; content:\"0123456789012345678901234567890\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        if (PacketAlertCheck(p, 2)) {
            result = 1;
        } else
            printf("sig 2 didn't match: ");
    }
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTestContent03 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTestContent04 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

/** \test sigs with patterns at the limit of the pm's size limit */
static int SigTestContent05 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901PADabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        printf("de_ctx == NULL: ");
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig1 parse failed: ");
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:1; within:32; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't: ");
        goto end;
    }

    if (PacketAlertCheck(p, 2)) {
        printf("sig 2 matched but shouldn't: ");
        goto end;
    }

    result = 1;
end:
    UTHFreePackets(&p, 1);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return result;
}

static int SigTestContent06 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Test 32 sig1\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Test 32 sig2\"; content:\"01234567890123456789012345678901\"; content:\"abcdefg\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)){
        //printf("sig 1 matched :");
    }else{
        printf("sig 1 didn't match: ");
        goto end;
    }

    if (PacketAlertCheck(p, 2)){
        result = 1;
    }else{
        printf("sig 2 didn't match: ");
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTestWithin01 (void)
{
    DecodeThreadVars dtv;
    ThreadVars th_v;
    int result = 0;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Packet *p3 = NULL;
    Packet *p4 = NULL;

    uint8_t rawpkt1[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x95,0x50,0x00,0x00,0x40,0x06,
        0x2d,0x45,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcc,0x03,0x09,0x18,0x72,
        0xd0,0xe3,0x1a,0xab,0x7c,0x98,0x50,0x00,
        0x02,0x00,0x46,0xa0,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt1 */

    uint8_t rawpkt2[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x30,0x87,0x00,0x00,0x40,0x06,
        0x92,0x0e,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcd,0x03,0x09,0x73,0xec,
        0xd5,0x35,0x14,0x7d,0x7c,0x12,0x50,0x00,
        0x02,0x00,0xed,0x86,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt2 */

    uint8_t rawpkt3[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x57,0xd8,0x00,0x00,0x40,0x06,
        0x6a,0xbd,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xce,0x03,0x09,0x06,0x3d,
        0x02,0x22,0x2f,0x9b,0x6f,0x8f,0x50,0x00,
        0x02,0x00,0x1f,0xae,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt3 */

    uint8_t rawpkt4[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0xa7,0x2e,0x00,0x00,0x40,0x06,
        0x1b,0x67,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcf,0x03,0x09,0x00,0x0e,
        0xdf,0x72,0x3d,0xc2,0x21,0xce,0x50,0x00,
        0x02,0x00,0x88,0x25,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt4 */

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;

    FlowInitConfig(FLOW_QUIET);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"within test\"; content:\"Hi, this is a big test to check \"; content:\"content matches\"; distance:0; within:15; sid:556;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* packet 1 */
    p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    DecodeEthernet(&th_v, &dtv, p1, rawpkt1, sizeof(rawpkt1), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 556))) {
        printf("failed to match on packet 1: ");
        goto end;
    }

    /* packet 2 */
    p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL))
        return 0;
    DecodeEthernet(&th_v, &dtv, p2, rawpkt2, sizeof(rawpkt2), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 556))) {
        printf("failed to match on packet 2: ");
        goto end;
    }

    /* packet 3 */
    p3 = PacketGetFromAlloc();
    if (unlikely(p3 == NULL))
        return 0;
    DecodeEthernet(&th_v, &dtv, p3, rawpkt3, sizeof(rawpkt3), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    if (!(PacketAlertCheck(p3, 556))) {
        printf("failed to match on packet 3: ");
        goto end;
    }

    /* packet 4 */
    p4 = PacketGetFromAlloc();
    if (unlikely(p4 == NULL))
        return 0;
    DecodeEthernet(&th_v, &dtv, p4, rawpkt4, sizeof(rawpkt4), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p4);
    if (!(PacketAlertCheck(p4, 556))) {
        printf("failed to match on packet 4: ");
        goto end;
    }

    /* packet 5 */
    uint8_t *p5buf = (uint8_t *)"Hi, this is a big test to check content matches";
    uint16_t p5buflen = strlen((char *)p5buf);
    Packet *p5 = UTHBuildPacket(p5buf, p5buflen, IPPROTO_TCP);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p5);
    if (!(PacketAlertCheck(p5, 556))) {
        printf("failed to match on packet 5: ");
        goto end;
    }
    UTHFreePackets(&p5, 1);

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    if (p1 != NULL) {
        PACKET_RECYCLE(p1);
        SCFree(p1);
    }
    if (p2 != NULL) {
        PACKET_RECYCLE(p2);
        SCFree(p2);
    }
    if (p3 != NULL) {
        PACKET_RECYCLE(p3);
        SCFree(p3);
    }
    if (p4 != NULL) {
        PACKET_RECYCLE(p4);
        SCFree(p4);
    }
    FlowShutdown();
    return result;
}

static int SigTestDepthOffset01 (void)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"depth offset\"; content:\"456\"; offset:4; depth:3; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int SigTestDetectAlertCounter(void)
{
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&tv, 0, sizeof(tv));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"Test counter\"; "
                               "content:\"boo\"; sid:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    SigGroupBuild(de_ctx);
    strlcpy(tv.name, "detect_test", sizeof(tv.name));
    DetectEngineThreadCtxInit(&tv, de_ctx, (void *)&det_ctx);
    /* init counters */
    StatsSetupPrivate(&tv);

    p = UTHBuildPacket((uint8_t *)"boo", strlen("boo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 1);

    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"roo", strlen("roo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"laboosa", strlen("laboosa"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 3);
    UTHFreePackets(&p, 1);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode */
static int SigTestDropFlow01(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop http any any -> any any "
                                   "(msg:\"Test proto match\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    if ( !(p->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Ok, now we know that the flag is set for proto http */

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

    UTHFreePackets(&p, 1);
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode */
static int SigTestDropFlow02(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    if ( !(p->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Ok, now we know that the flag is set for app layer sigs
     * (ex: inspecting uricontent) */

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

    UTHFreePackets(&p, 1);
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode, and it doesn't inspect
 *        any other packet of the stream */
static int SigTestDropFlow03(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;

    uint8_t http_buf2[] = "POST /two HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf1) - 1;

    /* Set the engine mode to IPS */
    EngineModeSetIPS();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    /* the no inspection flag should be set after the first sig gets triggered,
     * so the second packet should not match the next sig (because of no inspection) */
    s = de_ctx->sig_list->next = SigInit(de_ctx, "alert tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"two\";"
                                   "sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!PacketAlertCheck(p1, 1)) {
        printf("sig 1 didn't alert on p1, but it should: ");
        goto end;
    }

    if ( !(p1->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Second part.. Let's feed with another packet */
    if (StreamTcpCheckFlowDrops(p2) == 1) {
        SCLogDebug("This flow/stream triggered a drop rule");
        FlowSetNoPacketInspectionFlag(p2->flow);
        DecodeSetNoPacketInspectionFlag(p2);
        StreamTcpDisableAppLayer(p2->flow);
        p2->action |= ACTION_DROP;
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p2);
    }


    if ( !(p2->flags & PKT_NOPACKET_INSPECTION)) {
        printf("The packet was not flagged with no-inspection: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sig 1 alerted, but it should not since the no pkt inspection should be set: ");
        goto end;
    }

    if (PacketAlertCheck(p2, 2)) {
        printf("sig 2 alerted, but it should not since the no pkt inspection should be set: ");
        goto end;
    }

    if ( !(PACKET_TEST_ACTION(p2, ACTION_DROP))) {
        printf("A \"drop\" action should be set from the flow to the packet: ");
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

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);

    /* Restore mode to IDS */
    EngineModeSetIDS();
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IDS mode, but continue the inspection
 *        as usual (instead of on IPS mode) */
static int SigTestDropFlow04(void)
{
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;

    uint8_t http_buf2[] = "POST /two HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf1) - 1;

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "drop tcp any any -> any 80 "
                                      "(msg:\"Test proto match\"; uricontent:\"one\";"
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    /* the no inspection flag should be set after the first sig gets triggered,
     * so the second packet should not match the next sig (because of no inspection) */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any 80 "
                                      "(msg:\"Test proto match\"; uricontent:\"two\";"
                                      "sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    FAIL_IF_NOT(r == 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    FAIL_IF_NOT(PacketAlertCheck(p1, 1));
    FAIL_IF(PacketAlertCheck(p1, 2));

    FAIL_IF_NOT(p1->flow->flags & FLOW_ACTION_DROP);
    FAIL_IF_NOT(PACKET_TEST_ACTION(p1, ACTION_DROP));

    FAIL_IF(p2->flags & PKT_NOPACKET_INSPECTION);

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    FAIL_IF(PacketAlertCheck(p2, 1));
    FAIL_IF(PacketAlertCheck(p2, 2));
    FAIL_IF_NOT(PACKET_TEST_ACTION(p2, ACTION_DROP));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);

    PASS;
}

/** \test ICMP packet shouldn't be matching port based sig
 *        Bug #611 */
static int SigTestPorts01(void)
{
    int result = 0;
    Packet *p1 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    uint8_t payload[] = "AAAAAAAAAAAAAAAAAA";

    memset(&tv, 0, sizeof(ThreadVars));

    p1 = UTHBuildPacket(payload, sizeof(payload), IPPROTO_ICMP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ip any any -> any 80 "
                                   "(content:\"AAA\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sig 1 alerted on p1, but it should not: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    return result;
}

/** \test almost identical patterns */
static int SigTestBug01(void)
{
    int result = 0;
    Packet *p1 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    uint8_t payload[] = "!mymy";

    memset(&tv, 0, sizeof(ThreadVars));

    p1 = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                   "(content:\"Omymy\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                   "(content:\"!mymy\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sig 1 alerted on p1, but it should not: ");
        goto end;
    }
    if (!(PacketAlertCheck(p1, 2))) {
        printf("sig 2 did not p1, but it should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    return result;
}

static const char *dummy_conf_string2 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24, !10.10.10.247]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing01 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string2, strlen(dummy_conf_string2));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string3 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24, !10.10.10.247/32]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing02 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string3, strlen(dummy_conf_string3));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string4 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24,       !10.10.10.247/32]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing03 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string4, strlen(dummy_conf_string4));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string5 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.196.0.0/24, !10.196.0.15]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

/** \test bug #815 */
static int DetectAddressYamlParsing04 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string5, strlen(dummy_conf_string5));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

void SigRegisterTests(void)
{
    SigParseRegisterTests();
    IPOnlyRegisterTests();

    UtRegisterTest("SigTest01", SigTest01);
    UtRegisterTest("SigTest02 -- Offset/Depth match", SigTest02);
    UtRegisterTest("SigTest03 -- offset/depth mismatch", SigTest03);
    UtRegisterTest("SigTest04 -- distance/within match", SigTest04);
    UtRegisterTest("SigTest05 -- distance/within mismatch", SigTest05);
    UtRegisterTest("SigTest06 -- uricontent HTTP/1.1 match test", SigTest06);
    UtRegisterTest("SigTest07 -- uricontent HTTP/1.1 mismatch test",
                   SigTest07);
    UtRegisterTest("SigTest08 -- uricontent HTTP/1.0 match test", SigTest08);
    UtRegisterTest("SigTest09 -- uricontent HTTP/1.0 mismatch test",
                   SigTest09);
    UtRegisterTest("SigTest10 -- long content match, longer than pkt",
                   SigTest10);
    UtRegisterTest("SigTest11 -- mpm searching", SigTest11);
    UtRegisterTest("SigTest12 -- content order matching, normal", SigTest12);
    UtRegisterTest("SigTest13 -- content order matching, diff order",
                   SigTest13);
    UtRegisterTest("SigTest14 -- content order matching, distance 0",
                   SigTest14);
    UtRegisterTest("SigTest15 -- port negation sig (no match)", SigTest15);
    UtRegisterTest("SigTest16 -- port negation sig (match)", SigTest16);
    UtRegisterTest("SigTest17 -- HTTP Host Pkt var capture", SigTest17);
    UtRegisterTest("SigTest18 -- Ftp negation sig test", SigTest18);
    UtRegisterTest("SigTest19 -- IP-ONLY test (1)", SigTest19);
    UtRegisterTest("SigTest20 -- IP-ONLY test (2)", SigTest20);
    UtRegisterTest("SigTest21 -- FLOWBIT test (1)", SigTest21);
    UtRegisterTest("SigTest22 -- FLOWBIT test (2)", SigTest22);
    UtRegisterTest("SigTest23 -- FLOWBIT test (3)", SigTest23);

    UtRegisterTest("SigTest24IPV4Keyword", SigTest24IPV4Keyword);
    UtRegisterTest("SigTest25NegativeIPV4Keyword",
                   SigTest25NegativeIPV4Keyword);

    UtRegisterTest("SigTest26TCPV4Keyword", SigTest26TCPV4Keyword);
    UtRegisterTest("SigTest26TCPV4AndNegativeIPV4Keyword",
                   SigTest26TCPV4AndNegativeIPV4Keyword);
    UtRegisterTest("SigTest26TCPV4AndIPV4Keyword",
                   SigTest26TCPV4AndIPV4Keyword);
    UtRegisterTest("SigTest27NegativeTCPV4Keyword",
                   SigTest27NegativeTCPV4Keyword);

    UtRegisterTest("SigTest28TCPV6Keyword", SigTest28TCPV6Keyword);
    UtRegisterTest("SigTest29NegativeTCPV6Keyword",
                   SigTest29NegativeTCPV6Keyword);

    UtRegisterTest("SigTest30UDPV4Keyword", SigTest30UDPV4Keyword);
    UtRegisterTest("SigTest31NegativeUDPV4Keyword",
                   SigTest31NegativeUDPV4Keyword);

    UtRegisterTest("SigTest32UDPV6Keyword", SigTest32UDPV6Keyword);
    UtRegisterTest("SigTest33NegativeUDPV6Keyword",
                   SigTest33NegativeUDPV6Keyword);

    UtRegisterTest("SigTest34ICMPV4Keyword", SigTest34ICMPV4Keyword);
    UtRegisterTest("SigTest35NegativeICMPV4Keyword",
                   SigTest35NegativeICMPV4Keyword);
    UtRegisterTest("SigTest36ContentAndIsdataatKeywords01",
                   SigTest36ContentAndIsdataatKeywords01);
    UtRegisterTest("SigTest37ContentAndIsdataatKeywords02",
                   SigTest37ContentAndIsdataatKeywords02);

    UtRegisterTest("SigTest38 -- byte_test test (1)", SigTest38);

    UtRegisterTest("SigTest39 -- byte_jump test (2)", SigTest39);

    UtRegisterTest("SigTest40NoPacketInspection01",
                   SigTest40NoPacketInspection01);
    UtRegisterTest("SigTest40NoPayloadInspection02",
                   SigTest40NoPayloadInspection02);

    UtRegisterTest("SigTestMemory01", SigTestMemory01);
    UtRegisterTest("SigTestMemory02", SigTestMemory02);
    UtRegisterTest("SigTestMemory03", SigTestMemory03);

    UtRegisterTest("SigTestContent01 -- 32 byte pattern", SigTestContent01);
    UtRegisterTest("SigTestContent02 -- 32+31 byte pattern", SigTestContent02);
    UtRegisterTest("SigTestContent03 -- 32 byte pattern, x2 + distance",
                   SigTestContent03);
    UtRegisterTest("SigTestContent04 -- 32 byte pattern, x2 + distance/within",
                   SigTestContent04);
    UtRegisterTest("SigTestContent05 -- distance/within", SigTestContent05);
    UtRegisterTest("SigTestContent06 -- distance/within ip only",
                   SigTestContent06);

    UtRegisterTest("SigTestWithinReal01", SigTestWithin01);
    UtRegisterTest("SigTestDepthOffset01", SigTestDepthOffset01);

    UtRegisterTest("SigTestDetectAlertCounter", SigTestDetectAlertCounter);

    UtRegisterTest("SigTestDropFlow01", SigTestDropFlow01);
    UtRegisterTest("SigTestDropFlow02", SigTestDropFlow02);
    UtRegisterTest("SigTestDropFlow03", SigTestDropFlow03);
    UtRegisterTest("SigTestDropFlow04", SigTestDropFlow04);

    UtRegisterTest("DetectAddressYamlParsing01", DetectAddressYamlParsing01);
    UtRegisterTest("DetectAddressYamlParsing02", DetectAddressYamlParsing02);
    UtRegisterTest("DetectAddressYamlParsing03", DetectAddressYamlParsing03);
    UtRegisterTest("DetectAddressYamlParsing04", DetectAddressYamlParsing04);

    UtRegisterTest("SigTestPorts01", SigTestPorts01);
    UtRegisterTest("SigTestBug01", SigTestBug01);

    DetectEngineContentInspectionRegisterTests();
}
#endif /* UNITTESTS */
