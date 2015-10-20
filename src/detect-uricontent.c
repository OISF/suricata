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
#include "util-binsearch.h"
#include "util-spm.h"
#include "util-spm-bm.h"
#include "conf.h"

/* prototypes */
static int DetectUricontentSetup (DetectEngineCtx *, Signature *, char *);
void HttpUriRegisterTests(void);

int DetectAppLayerUricontentMatch (ThreadVars *, DetectEngineThreadCtx *,
                                   Flow *, uint8_t , void *,
                                   Signature *, SigMatch *);
void DetectUricontentFree(void *);

/**
 * \brief Registration function for uricontent: keyword
 */
void DetectUricontentRegister (void)
{
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].AppLayerMatch = NULL;
    sigmatch_table[DETECT_URICONTENT].Match = NULL;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free  = DetectUricontentFree;
    sigmatch_table[DETECT_URICONTENT].RegisterTests = HttpUriRegisterTests;
    sigmatch_table[DETECT_URICONTENT].alproto = ALPROTO_HTTP;

    sigmatch_table[DETECT_URICONTENT].flags |= SIGMATCH_PAYLOAD;
}

/**
 * \brief   pass on the uricontent_max_id
 * \param   de_ctx  pointer to the detect egine context whose max id is asked
 */
uint32_t DetectUricontentMaxId(DetectEngineCtx *de_ctx)
{
    return MpmPatternIdStoreGetMaxId(de_ctx->mpm_pattern_id_store);
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

    BoyerMooreCtxDeInit(cd->bm_ctx);
    SCFree(cd);

    SCReturn;
}

/**
 * \brief Helper function to print a DetectContentData
 */
void DetectUricontentPrint(DetectContentData *cd)
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
int DetectUricontentSetup(DetectEngineCtx *de_ctx, Signature *s, char *contentstr)
{
    SCEnter();

    char *legacy = NULL;
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

/**
 * \brief   Checks if the content sent as the argument, has a uricontent which
 *          has been provided in the rule. This match function matches the
 *          normalized http uri against the given rule using multi pattern
 *          search algorithms.
 *
 * \param det_ctx       Pointer to the detection engine thread context
 * \param content       Pointer to the uri content currently being matched
 * \param content_len   Content_len of the received uri content
 *
 * \retval 1 if the uri contents match; 0 no match
 */
static inline int DoDetectAppLayerUricontentMatch (DetectEngineThreadCtx *det_ctx,
                                                   uint8_t *uri, uint16_t uri_len, uint8_t flags)
{
    int ret = 0;
    /* run the pattern matcher against the uri */
    if (det_ctx->sgh->mpm_uricontent_minlen > uri_len) {
        SCLogDebug("not searching as uri len is smaller than the "
                   "shortest uricontent length we need to match");
    } else {
        SCLogDebug("search: (%p, minlen %" PRIu32 ", sgh->sig_cnt "
                "%" PRIu32 ")", det_ctx->sgh,
                det_ctx->sgh->mpm_uricontent_minlen, det_ctx->sgh->sig_cnt);

        ret += UriPatternSearch(det_ctx, uri, uri_len, flags);

        SCLogDebug("post search: cnt %" PRIu32, ret);
    }
    return ret;
}

/**
 *  \brief Run the pattern matcher against the uri(s)
 *
 *  We run against _all_ uri(s) we have as the pattern matcher will
 *  flag each sig that has a match. We need to do this for all uri(s)
 *  to not miss possible events.
 *
 *  \param f locked flow
 *  \param htp_state initialized htp state
 *
 *  \warning Make sure the flow/state is locked
 *  \todo what should we return? Just the fact that we matched?
 */
uint32_t DetectUricontentInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                    HtpState *htp_state, uint8_t flags,
                                    void *txv, uint64_t idx)
{
    SCEnter();

    htp_tx_t *tx = (htp_tx_t *)txv;
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    uint32_t cnt = 0;

    if (tx_ud == NULL || tx_ud->request_uri_normalized == NULL)
        goto end;
    cnt = DoDetectAppLayerUricontentMatch(det_ctx, (uint8_t *)
                                          bstr_ptr(tx_ud->request_uri_normalized),
                                          bstr_len(tx_ud->request_uri_normalized),
                                          flags);

end:
    SCReturnUInt(cnt);
}

/*
 * UNITTTESTS
 */

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

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
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                            STREAM_EOF, httpbuf1, httplen1);
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
    SCMutexUnlock(&f.m);
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
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                            STREAM_EOF, httpbuf1, httplen1);
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
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    SCMutexUnlock(&f.m);
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
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                            STREAM_EOF, httpbuf1, httplen1);
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
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    SCMutexUnlock(&f.m);
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
    f.flags |= FLOW_IPV4;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                            STREAM_EOF, httpbuf1, httplen1);
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
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    SCMutexUnlock(&f.m);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Checks if a uricontent is registered in a Signature
 */
int DetectUriSigTest01(void)
{
    SigMatch *sm = NULL;
    int result = 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *s = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "content:\"me\"; uricontent:\"me\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    BUG_ON(de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL);

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH];
    if (sm->type == DETECT_CONTENT) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (det_ctx != NULL) DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
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
    de_ctx->mpm_matcher = MPM_B2G;
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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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
    de_ctx->mpm_matcher = MPM_B2G;
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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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


    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
    SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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
        s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
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
        s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
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
        s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
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
        s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        ((DetectContentData *)s->sm_lists[DETECT_SM_LIST_UMATCH]->ctx)->depth != 15 ||
        ((DetectContentData *)s->sm_lists[DETECT_SM_LIST_UMATCH]->ctx)->offset != 5 ||
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
    } else if (s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
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
    } else if (s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx)->within != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 8 failed to parse: ");
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx);
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
            s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
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
            s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
            s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx)->distance != 30 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL)
    {
        printf("sig 10 failed to parse: ");
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx);
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

    if (s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL || s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("umatch %p or pmatch %p: ", s->sm_lists[DETECT_SM_LIST_UMATCH], s->sm_lists[DETECT_SM_LIST_PMATCH]);
        goto end;
    }

    if (    ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth != 15 ||
            ((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset != 5 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx)->distance != 30 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx)->within != 60 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->distance != 45 ||
            ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->within != 70 ||
            s->sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        printf("sig 10 failed to parse, content not setup properly: ");
        DetectContentPrint((DetectContentData*) s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx);
        DetectUricontentPrint((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx);
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
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
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
    p->tcph->th_seq = htonl(1000);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;
    f.proto = p->proto;

    StreamTcpInitConfig(TRUE);

    StreamMsg *stream_msg = StreamMsgGetFromPool();
    if (stream_msg == NULL) {
        printf("no stream_msg: ");
        goto end;
    }

    memcpy(stream_msg->data, httpbuf1, httplen1);
    stream_msg->data_len = httplen1;

    ssn.toserver_smsg_head = stream_msg;
    ssn.toserver_smsg_tail = stream_msg;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"foo\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"one\"; content:\"two\"; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
            "\" Test uricontent\"; uricontent:\"one\"; offset:1; depth:10; "
            "uricontent:\"two\"; distance:1; within: 4; uricontent:\"three\"; "
            "distance:1; within: 6; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if ((PacketAlertCheck(p, 1))) {
        printf("sig: 1 alerted, but it should not: ");
        goto end;
    } else if (! PacketAlertCheck(p, 2)) {
        printf("sig: 2 did not alert, but it should: ");
        goto end;
    } else if (! (PacketAlertCheck(p, 3))) {
        printf("sig: 3 did not alert, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (det_ctx != NULL) DetectEngineThreadCtxDeinit(&th_v, det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the modifiers for uricontent and content
 *        match
 */
static int DetectUriSigTest06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    TCPHdr tcp_hdr;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&tcp_hdr, 0, sizeof(tcp_hdr));


    p = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    p->tcph->th_seq = htonl(1000);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;
    f.proto = p->proto;

    StreamTcpInitConfig(TRUE);

    StreamMsg *stream_msg = StreamMsgGetFromPool();
    if (stream_msg == NULL) {
        printf("no stream_msg: ");
        goto end;
    }

    memcpy(stream_msg->data, httpbuf1, httplen1);
    stream_msg->data_len = httplen1;

    ssn.toserver_smsg_head = stream_msg;
    ssn.toserver_smsg_tail = stream_msg;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; content:\"bar\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "content:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "content:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "content:\"/three\"; distance:0; within: 7; "
                                   "sid:2;)");

    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "sid:3;)");

    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

   /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if ((PacketAlertCheck(p, 1))) {
        printf("sig: 1 alerted, but it should not:");
        goto end;
    } else if (! PacketAlertCheck(p, 2)) {
        printf("sig: 2 did not alert, but it should:");
        goto end;
    } else if (! (PacketAlertCheck(p, 3))) {
        printf("sig: 3 did not alert, but it should:");
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

/** \test Check the modifiers for uricontent and content
 *        match
 */
static int DetectUriSigTest07(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST /one/two/three HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
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
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"foo\"; content:\"bar\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "content:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:3; within: 4; "
                                   "content:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"three\"; distance:1; within: 6; "
                                   "content:\"/three\"; distance:0; within: 7; "
                                   "sid:2;)");

    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                   "uricontent:\"one\"; offset:1; depth:10; "
                                   "uricontent:\"two\"; distance:1; within: 4; "
                                   "uricontent:\"six\"; distance:1; within: 6; "
                                   "sid:3;)");

    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (PacketAlertCheck(p, 1)) {
        printf("sig: 1 alerted, but it should not:");
        goto end;
    } else if (PacketAlertCheck(p, 2)) {
        printf("sig: 2 alerted, but it should not:");
        goto end;
    } else if (PacketAlertCheck(p, 3)) {
        printf("sig: 3 alerted, but it should not:");
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
 * \test Test content for dce sig.
 */
int DetectUriSigTest08(void)
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
int DetectUriSigTest09(void)
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
int DetectUriSigTest10(void)
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
int DetectUriSigTest11(void)
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
int DetectUriSigTest12(void)
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

    if (s->sm_lists_tail[DETECT_SM_LIST_UMATCH] == NULL || s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx == NULL) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    ud = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
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
int DetectUriContentParseTest13(void)
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
int DetectUriContentParseTest14(void)
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
int DetectUriContentParseTest15(void)
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
int DetectUriContentParseTest16(void)
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
int DetectUriContentParseTest17(void)
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
int DetectUriContentParseTest18(void)
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
int DetectUriContentParseTest19(void)
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
int DetectUriContentParseTest20(void)
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
int DetectUriContentParseTest21(void)
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
int DetectUriContentParseTest22(void)
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
int DetectUriContentParseTest23(void)
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
int DetectUriContentParseTest24(void)
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

#endif /* UNITTESTS */

void HttpUriRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HTTPUriTest01", HTTPUriTest01, 1);
    UtRegisterTest("HTTPUriTest02", HTTPUriTest02, 1);
    UtRegisterTest("HTTPUriTest03", HTTPUriTest03, 1);
    UtRegisterTest("HTTPUriTest04", HTTPUriTest04, 1);

    UtRegisterTest("DetectUriSigTest01", DetectUriSigTest01, 1);
    UtRegisterTest("DetectUriSigTest02", DetectUriSigTest02, 1);
    UtRegisterTest("DetectUriSigTest03", DetectUriSigTest03, 1);
    UtRegisterTest("DetectUriSigTest04 - Modifiers", DetectUriSigTest04, 1);
    UtRegisterTest("DetectUriSigTest05 - Inspection", DetectUriSigTest05, 1);
    UtRegisterTest("DetectUriSigTest06 - Inspection", DetectUriSigTest06, 1);
    UtRegisterTest("DetectUriSigTest07 - Inspection", DetectUriSigTest07, 1);
    UtRegisterTest("DetectUriSigTest08", DetectUriSigTest08, 1);
    UtRegisterTest("DetectUriSigTest09", DetectUriSigTest09, 1);
    UtRegisterTest("DetectUriSigTest10", DetectUriSigTest10, 1);
    UtRegisterTest("DetectUriSigTest11", DetectUriSigTest11, 1);
    UtRegisterTest("DetectUriSigTest12", DetectUriSigTest12, 1);

    UtRegisterTest("DetectUriContentParseTest13", DetectUriContentParseTest13, 1);
    UtRegisterTest("DetectUriContentParseTest14", DetectUriContentParseTest14, 1);
    UtRegisterTest("DetectUriContentParseTest15", DetectUriContentParseTest15, 1);
    UtRegisterTest("DetectUriContentParseTest16", DetectUriContentParseTest16, 1);
    UtRegisterTest("DetectUriContentParseTest17", DetectUriContentParseTest17, 1);
    UtRegisterTest("DetectUriContentParseTest18", DetectUriContentParseTest18, 1);
    UtRegisterTest("DetectUriContentParseTest19", DetectUriContentParseTest19, 1);
    UtRegisterTest("DetectUriContentParseTest20", DetectUriContentParseTest20, 1);
    UtRegisterTest("DetectUriContentParseTest21", DetectUriContentParseTest21, 1);
    UtRegisterTest("DetectUriContentParseTest22", DetectUriContentParseTest22, 1);
    UtRegisterTest("DetectUriContentParseTest23", DetectUriContentParseTest23, 1);
    UtRegisterTest("DetectUriContentParseTest24", DetectUriContentParseTest24, 1);
#endif /* UNITTESTS */
}
