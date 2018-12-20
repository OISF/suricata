/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-sigorder.h"
#include "detect-bypass.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "stream-tcp.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-device.h"

static int DetectBypassMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectBypassSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectBypassRegisterTests(void);

/**
 * \brief Registration function for keyword: bypass
 */
void DetectBypassRegister(void)
{
    sigmatch_table[DETECT_BYPASS].name = "bypass";
    sigmatch_table[DETECT_BYPASS].desc = "call the bypass callback when the match of a sig is complete";
    sigmatch_table[DETECT_BYPASS].url = DOC_URL DOC_VERSION "/rules/bypass-keyword.html";
    sigmatch_table[DETECT_BYPASS].Match = DetectBypassMatch;
    sigmatch_table[DETECT_BYPASS].Setup = DetectBypassSetup;
    sigmatch_table[DETECT_BYPASS].Free  = NULL;
    sigmatch_table[DETECT_BYPASS].RegisterTests = DetectBypassRegisterTests;
    sigmatch_table[DETECT_BYPASS].flags = SIGMATCH_NOOPT;
}

static int DetectBypassSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SigMatch *sm = NULL;

    if (s->flags & SIG_FLAG_FILESTORE) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                   "bypass can't work with filestore keyword");
        return -1;
    }
    s->flags |= SIG_FLAG_BYPASS;

    sm = SigMatchAlloc();
    if (sm == NULL)
        return -1;

    sm->type = DETECT_BYPASS;
    sm->ctx = NULL;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);

    return 0;
}

static int DetectBypassMatch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    PacketBypassCallback(p);

    return 1;
}

#ifdef UNITTESTS
#include "app-layer-htp.h"

static int callback_var = 0;

static int BypassCallback(Packet *p)
{
    callback_var = 1;
    return 1;
}

static void ResetCallbackVar(void)
{
    callback_var = 0;
}

static int DetectBypassTestSig01(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: This is dummy message body\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    LiveDevice *livedev = SCMalloc(sizeof(LiveDevice));
    FAIL_IF(livedev == NULL);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF(p1 == NULL);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF(p2 == NULL);

    p1->BypassPacketsFlow = BypassCallback;
    p2->BypassPacketsFlow = BypassCallback;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p1->livedev = livedev;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->livedev = livedev;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    const char *sigs[3];
    sigs[0] = "alert tcp any any -> any any (bypass; content:\"GET \"; sid:1;)";
    sigs[1] = "alert http any any -> any any "
              "(bypass; content:\"message\"; http_server_body; "
              "sid:2;)";
    sigs[2] = "alert http any any -> any any "
              "(bypass; content:\"message\"; http_host; "
              "sid:3;)";
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 3) == 0);

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    FAIL_IF(http_state == NULL);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT,
                            http_buf2, http_len2);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 2)));
    FAIL_IF(!(PacketAlertCheck(p1, 3)));

    FAIL_IF(callback_var == 0);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    ResetCallbackVar();
    SCFree(livedev);
    PASS;
}
#endif /* UNITTESTS */

static void DetectBypassRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectBypassTestSig01", DetectBypassTestSig01);
#endif /* UNITTESTS */
}
