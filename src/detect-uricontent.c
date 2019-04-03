/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author  Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Simple uricontent match part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "threads.h"

#include "stream-tcp.h"
#include "stream.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "conf.h"

/* prototypes */
static int DetectUricontentSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectUricontentRegisterTests(void);
static void DetectUricontentFree(void *);

static int g_http_uri_buffer_id = 0;

/**
 * \brief Registration function for uricontent: keyword
 */
void DetectUricontentRegister (void)
{
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].Match = NULL;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free  = DetectUricontentFree;
    sigmatch_table[DETECT_URICONTENT].RegisterTests = DetectUricontentRegisterTests;
    sigmatch_table[DETECT_URICONTENT].flags = (SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION);
    sigmatch_table[DETECT_URICONTENT].alternative = DETECT_HTTP_URI;

    g_http_uri_buffer_id = DetectBufferTypeRegister("http_uri");
}

/**
 * \brief this function will Free memory associated with DetectContentData
 *
 * \param cd pointer to DetectUricotentData
 */
void DetectUricontentFree(void *ptr)
{
    SCEnter();
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        SCReturn;

    SpmDestroyCtx(cd->spm_ctx);
    SCFree(cd);

    SCReturn;
}

/**
 * \brief Creates a SigMatch for the uricontent keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param contentstr  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
int DetectUricontentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *contentstr)
{
    SCEnter();

    const char *legacy = NULL;
    if (ConfGet("legacy.uricontent", &legacy) == 1) {
        if (strcasecmp("disabled", legacy) == 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "uriconent deprecated.  To "
                       "use a rule with \"uricontent\", either set the "
                       "option - \"legacy.uricontent\" in the conf to "
                       "\"enabled\" OR replace uricontent with "
                       "\'content:%s; http_uri;\'.", contentstr);
            goto error;
        } else if (strcasecmp("enabled", legacy) == 0) {
            ;
        } else {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid value found "
                       "for legacy.uriconent - \"%s\".  Valid values are "
                       "\"enabled\" OR \"disabled\".", legacy);
            goto error;
        }
    }

    if (DetectContentSetup(de_ctx, s, contentstr) < 0)
        goto error;

    if (DetectHttpUriSetup(de_ctx, s, NULL) < 0)
        goto error;

    SCReturnInt(0);
error:
    SCReturnInt(-1);
}

/*
 * UNITTTESTS
 */

#ifdef UNITTESTS

#include "detect-isdataat.h"
#include "stream-tcp-reassemble.h"

/**
 * \brief Helper function to print a DetectContentData
 */
static void DetectUricontentPrint(DetectContentData *cd)
{
    int i = 0;
    if (cd == NULL) {
        SCLogDebug("Detect UricontentData \"cd\" is NULL");
        return;
    }
    char *tmpstr = SCMalloc(sizeof(char) * cd->content_len + 1);
    if (unlikely(tmpstr == NULL))
        return;

    if (tmpstr != NULL) {
        for (i = 0; i < cd->content_len; i++) {
            if (isprint(cd->content[i]))
                tmpstr[i] = cd->content[i];
            else
                tmpstr[i] = '.';
        }
        tmpstr[i] = '\0';
        SCLogDebug("Uricontent: \"%s\"", tmpstr);
        SCFree(tmpstr);
    } else {
        SCLogDebug("Uricontent: ");
        for (i = 0; i < cd->content_len; i++)
            SCLogDebug("%c", cd->content[i]);
    }

    SCLogDebug("Uricontent_id: %"PRIu32, cd->id);
    SCLogDebug("Uricontent_len: %"PRIu16, cd->content_len);
    SCLogDebug("Depth: %"PRIu16, cd->depth);
    SCLogDebug("Offset: %"PRIu16, cd->offset);
    SCLogDebug("Within: %"PRIi32, cd->within);
    SCLogDebug("Distance: %"PRIi32, cd->distance);
    SCLogDebug("flags: %u ", cd->flags);
    SCLogDebug("negated: %s ",
            cd->flags & DETECT_CONTENT_NEGATED ? "true" : "false");
    SCLogDebug("relative match next: %s ",
            cd->flags & DETECT_CONTENT_RELATIVE_NEXT ? "true" : "false");
    SCLogDebug("-----------");
}

/** \test Test case where path traversal has been sent as a path string in the
 *        HTTP URL and normalized path string is checked */
static int HTTPUriTest01(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "GET /../../images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP;
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                            httpbuf1,
                            httplen1);
    if (r != 0) {
        printf("AppLayerParse failed: r(%d) != 0: ", r);
        goto end;
    }

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);

    if (tx->request_method_number != HTP_M_GET ||
        tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        goto end;
    }

    if ((tx->request_hostname == NULL) ||
            (bstr_cmp_c(tx->request_hostname, "www.example.com") != 0))
    {
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmp_c(tx->parsed_uri->path, "/images.gif") != 0))
    {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Test case where path traversal has been sent in special characters in
 *        HEX encoding in the HTTP URL and normalized path string is checked */
static int HTTPUriTest02(void)
{
    int result = 0;
    Flow f;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "GET /%2e%2e/images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP;
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                            httpbuf1,
                            httplen1);
    if (r != 0) {
        printf("AppLayerParse failed: r(%d) != 0: ", r);
        goto end;
    }

    htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);

    if (tx->request_method_number != HTP_M_GET ||
        tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        goto end;
    }

    if ((tx->request_hostname == NULL) ||
            (bstr_cmp_c(tx->request_hostname, "www.example.com") != 0))
    {
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmp_c(tx->parsed_uri->path, "/images.gif") != 0))
    {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Test case where NULL character has been sent in HEX encoding in the
 *        HTTP URL and normalized path string is checked */
static int HTTPUriTest03(void)
{
    int result = 0;
    Flow f;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "GET%00 /images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP;
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                            httpbuf1,
                            httplen1);
    if (r != 0) {
        printf("AppLayerParse failed: r(%d) != 0: ", r);
        goto end;
    }

    htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);

    if (tx->request_method_number != HTP_M_UNKNOWN ||
        tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        goto end;
    }

    if ((tx->request_hostname == NULL) ||
            (bstr_cmp_c(tx->request_hostname, "www.example.com") != 0))
    {
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmp_c(tx->parsed_uri->path, "/images.gif") != 0))
    {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    FLOW_DESTROY(&f);
    return result;
}


/** \test Test case where self referencing directories request has been sent
 *        in the HTTP URL and normalized path string is checked */
static int HTTPUriTest04(void)
{
    int result = 0;
    Flow f;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "GET /./././images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_HTTP;
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                            httpbuf1,
                            httplen1);
    if (r != 0) {
        printf("AppLayerParse failed: r(%d) != 0: ", r);
        goto end;
    }

    htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);

    if (tx->request_method_number != HTP_M_GET ||
        tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        goto end;
    }

    if ((tx->request_hostname == NULL) ||
            (bstr_cmp_c(tx->request_hostname, "www.example.com") != 0))
    {
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
           (bstr_cmp_c(tx->parsed_uri->path, "/images.gif") != 0))
    {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Checks if a uricontent is registered in a Signature
 */
static int DetectUriSigTest01(void)
{
    ThreadVars th_v;
    Signature *s = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert http any any -> any any (msg:"
            "\" Test uricontent\"; content:\"me\"; uricontent:\"me\"; sid:1;)");
    FAIL_IF_NULL(s);

    BUG_ON(s->sm_lists[g_http_uri_buffer_id] == NULL);
    FAIL_IF_NOT(de_ctx->sig_list->sm_lists[g_http_uri_buffer_id]->type == DETECT_CONTENT);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check the signature working to alert when http_cookie is matched . */
static int DetectUriSigTest02(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST /one HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);

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

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"oisf\"; sid:3;)");
    if (s == NULL) {
        goto end;
    }


    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
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
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ((PacketAlertCheck(p, 1))) {
        printf("sig: 1 alerted, but it should not\n");
        goto end;
    } else if (!PacketAlertCheck(p, 2)) {
        printf("sig: 2 did not alerted, but it should\n");
        goto end;
    }  else if ((PacketAlertCheck(p, 3))) {
        printf("sig: 3 alerted, but it should not\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    //if (http_state != NULL) HTPStateFree(http_state);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (det_ctx != NULL) DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the working of search once per packet only in applayer
 *        match */
static int DetectUriSigTest03(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "POST /oneself HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);

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

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

   s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"self\"; sid:3;)");
    if (s == NULL) {
        goto end;
    }


    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    } else if (!PacketAlertCheck(p, 2)) {
        printf("sig 2 did not alert, but it should: ");
        goto end;
    } else if ((PacketAlertCheck(p, 3))) {
        printf("sig 3 alerted, but it should not: ");
        goto end;
    }


    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf2, httplen2);
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
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted, but it should not (chunk 2): ");
        goto end;
    } else if (!PacketAlertCheck(p, 2)) {
        printf("sig 2 alerted, but it should not (chunk 2): ");
        goto end;
    } else if (!(PacketAlertCheck(p, 3))) {
        printf("sig 3 did not alert, but it should (chunk 2): ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (det_ctx != NULL) DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Check that modifiers of content apply only to content keywords
 *       and the same for uricontent modifiers
 */
static int DetectUriSigTest04(void)
{
    int result = 0;
    Signature *s = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; sid:1;)");
    if (s == NULL ||
        s->sm_lists[g_http_uri_buffer_id] == NULL ||
        s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 1 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";sid:1;)");
    if (s == NULL ||
        s->sm_lists[g_http_uri_buffer_id] == NULL ||
        s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 2 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; sid:1;)");
    if (s == NULL ||
        s->sm_lists[g_http_uri_buffer_id] == NULL ||
        s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        ((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
        ((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
        s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 3 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "content:\"foo\"; uricontent:\"bar\";"
                                   " depth:10; offset: 5; sid:1;)");
    if (s == NULL ||
        s->sm_lists[g_http_uri_buffer_id] == NULL ||
        s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        ((DetectContentData *)s->sm_lists[g_http_uri_buffer_id]->ctx)->depth != 15 ||
        ((DetectContentData *)s->sm_lists[g_http_uri_buffer_id]->ctx)->offset != 5 ||
        s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 4 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; within:3; sid:1;)");
    if (s != NULL) {
        printf("sig 5 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; distance:3; sid:1;)");
    if (s != NULL) {
        printf("sig 6 failed to parse: ");
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; content:"
                                   "\"two_contents\"; within:30; sid:1;)");
    if (s == NULL) {
        goto end;
    } else if (s->sm_lists[g_http_uri_buffer_id] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->within != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 7 failed to parse: ");
        DetectContentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx);
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; uricontent:"
                                   "\"two_uricontents\"; within:30; sid:1;)");
    if (s == NULL) {
        goto end;
    } else if (s->sm_lists[g_http_uri_buffer_id] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->within != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 8 failed to parse: ");
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx);
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; content:"
                                   "\"two_contents\"; distance:30; sid:1;)");
    if (s == NULL) {
        goto end;
    } else if (
            s->sm_lists[g_http_uri_buffer_id] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->distance != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 9 failed to parse: ");
        DetectContentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx);
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; uricontent:"
                                   "\"two_uricontents\"; distance:30; sid:1;)");
    if (s == NULL) {
        goto end;
    } else if (
            s->sm_lists[g_http_uri_buffer_id] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->distance != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 10 failed to parse: ");
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx);
        goto end;
    }

    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent and content\"; "
                                   "uricontent:\"foo\"; content:\"bar\";"
                                   " depth:10; offset: 5; uricontent:"
                                   "\"two_uricontents\"; distance:30; "
                                   "within:60; content:\"two_contents\";"
                                   " within:70; distance:45; sid:1;)");
    if (s == NULL) {
        printf("sig 10 failed to parse: ");
        goto end;
    }

    if (s->sm_lists[g_http_uri_buffer_id] == NULL || s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("umatch %p or pmatch %p: ", s->sm_lists[g_http_uri_buffer_id], s->sm_lists[DETECT_SM_LIST_PMATCH]);
        goto end;
    }

    if (    ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->distance != 30 ||
            ((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->within != 60 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->distance != 45 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->within != 70 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        printf("sig 10 failed to parse, content not setup properly: ");
        DetectContentPrint((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx);
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[g_http_uri_buffer_id]->ctx);
        DetectContentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check the modifiers for uricontent and content
 *        match
 */
static int DetectUriSigTest05(void)
{
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    StreamTcpInitConfig(TRUE);

    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->tcph->th_seq = htonl(1000);
    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_TCP;

    UTHAddSessionToFlow(f, 1000, 1000);
    UTHAddStreamToFlow(f, 0, httpbuf1, httplen1);

    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"foo\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"one\"; content:\"two\"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"one\"; offset:1; depth:10; "
            "uricontent:\"two\"; distance:1; within: 4; uricontent:\"three\"; "
            "distance:1; within: 6; sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF((PacketAlertCheck(p, 1)));
    FAIL_IF(!PacketAlertCheck(p, 2));
    FAIL_IF(!(PacketAlertCheck(p, 3)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHRemoveSessionFromFlow(f);
    UTHFreeFlow(f);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    PASS;
}

/** \test Check the modifiers for uricontent and content
 *        match
 */
static int DetectUriSigTest06(void)
{
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    StreamTcpInitConfig(TRUE);

    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->tcph->th_seq = htonl(1000);
    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_TCP;

    UTHAddSessionToFlow(f, 1000, 1000);
    UTHAddStreamToFlow(f, 0, httpbuf1, httplen1);

    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; content:\"bar\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "content:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "content:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "content:\"/three\"; distance:0; within: 7; "
                                   "sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF((PacketAlertCheck(p, 1)));
    FAIL_IF(!PacketAlertCheck(p, 2));
    FAIL_IF(!(PacketAlertCheck(p, 3)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHRemoveSessionFromFlow(f);
    UTHFreeFlow(f);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    PASS;
}

/** \test Check the modifiers for uricontent and content
 *        match
 */
static int DetectUriSigTest07(void)
{
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    StreamTcpInitConfig(TRUE);

    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->tcph->th_seq = htonl(1000);
    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_TCP;

    UTHAddSessionToFlow(f, 1000, 1000);
    UTHAddStreamToFlow(f, 0, httpbuf1, httplen1);

    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; content:\"bar\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "content:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:3; within: 4; "
                                   "content:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "content:\"/three\"; distance:0; within: 7; "
                                   "sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"six\"; distance:1; within: 6; "
                                   "sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF((PacketAlertCheck(p, 1)));
    FAIL_IF((PacketAlertCheck(p, 2)));
    FAIL_IF((PacketAlertCheck(p, 3)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHRemoveSessionFromFlow(f);
    UTHFreeFlow(f);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest08(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest09(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest10(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"boo; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:boo\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriSigTest12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectContentData *ud = 0;
    Signature *s = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert udp any any -> any any "
                                   "(msg:\"test\"; uricontent:    !\"boo\"; sid:238012;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL: ");
        goto end;
    }

    if (s->sm_lists_tail[g_http_uri_buffer_id] == NULL || s->sm_lists_tail[g_http_uri_buffer_id]->ctx == NULL) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    ud = (DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    result = (strncmp("boo", (char *)ud->content, ud->content_len) == 0);

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}


/**
 * \test Parsing test
 */
static int DetectUriContentParseTest13(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest15(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"af|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest16(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest17(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"aast|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest18(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"aast|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest19(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"aast|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest20(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af|asdf\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest21(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af|af|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af|af|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; uricontent:\"|af|af|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; uricontent:\"\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectUricontentIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "uricontent:\"one\"; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_http_uri_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

static void DetectUricontentRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HTTPUriTest01", HTTPUriTest01);
    UtRegisterTest("HTTPUriTest02", HTTPUriTest02);
    UtRegisterTest("HTTPUriTest03", HTTPUriTest03);
    UtRegisterTest("HTTPUriTest04", HTTPUriTest04);

    UtRegisterTest("DetectUriSigTest01", DetectUriSigTest01);
    UtRegisterTest("DetectUriSigTest02", DetectUriSigTest02);
    UtRegisterTest("DetectUriSigTest03", DetectUriSigTest03);
    UtRegisterTest("DetectUriSigTest04 - Modifiers", DetectUriSigTest04);
    UtRegisterTest("DetectUriSigTest05 - Inspection", DetectUriSigTest05);
    UtRegisterTest("DetectUriSigTest06 - Inspection", DetectUriSigTest06);
    UtRegisterTest("DetectUriSigTest07 - Inspection", DetectUriSigTest07);
    UtRegisterTest("DetectUriSigTest08", DetectUriSigTest08);
    UtRegisterTest("DetectUriSigTest09", DetectUriSigTest09);
    UtRegisterTest("DetectUriSigTest10", DetectUriSigTest10);
    UtRegisterTest("DetectUriSigTest11", DetectUriSigTest11);
    UtRegisterTest("DetectUriSigTest12", DetectUriSigTest12);

    UtRegisterTest("DetectUriContentParseTest13", DetectUriContentParseTest13);
    UtRegisterTest("DetectUriContentParseTest14", DetectUriContentParseTest14);
    UtRegisterTest("DetectUriContentParseTest15", DetectUriContentParseTest15);
    UtRegisterTest("DetectUriContentParseTest16", DetectUriContentParseTest16);
    UtRegisterTest("DetectUriContentParseTest17", DetectUriContentParseTest17);
    UtRegisterTest("DetectUriContentParseTest18", DetectUriContentParseTest18);
    UtRegisterTest("DetectUriContentParseTest19", DetectUriContentParseTest19);
    UtRegisterTest("DetectUriContentParseTest20", DetectUriContentParseTest20);
    UtRegisterTest("DetectUriContentParseTest21", DetectUriContentParseTest21);
    UtRegisterTest("DetectUriContentParseTest22", DetectUriContentParseTest22);
    UtRegisterTest("DetectUriContentParseTest23", DetectUriContentParseTest23);
    UtRegisterTest("DetectUriContentParseTest24", DetectUriContentParseTest24);

    UtRegisterTest("DetectUricontentIsdataatParseTest",
            DetectUricontentIsdataatParseTest);
#endif /* UNITTESTS */
}
