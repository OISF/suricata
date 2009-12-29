/**Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
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

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-binsearch.h"
#include "util-print.h"

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-cookie.h"


int DetectHttpCookieMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *m);
int DetectHttpCookieSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectHttpCookieRegisterTests(void);

/**
 * \brief Registration function for keyword: http_cookie
 */
void DetectHttpCookieRegister (void) {
    sigmatch_table[DETECT_AL_HTTP_COOKIE].name = "http_cookie";
    sigmatch_table[DETECT_AL_HTTP_COOKIE].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].AppLayerMatch = DetectHttpCookieMatch;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].Setup = DetectHttpCookieSetup;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].Free  = NULL;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].RegisterTests = DetectHttpCookieRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_COOKIE].flags |= SIGMATCH_PAYLOAD;
}

/**
 * \brief match the specified content in the signature with the received http
 *        cookie header in the http request.
 *
 * \param t         pointer to thread vars
 * \param det_ctx   pointer to the pattern matcher thread
 * \param f         pointer to the current flow
 * \param flags     flags to indicate the direction of the received packet
 * \param state     pointer the app layer state, which will cast into HtpState
 * \param s         pointer to the current signature
 * \param m         pointer to the sigmatch that we will cast into DetectContentData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectHttpCookieMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *m)
{
    SCEnter();

    int ret = 0;

    SCMutexLock(&f->m);
    SCLogDebug("got lock %p", &f->m);

    DetectHttpCookieData *co = (DetectHttpCookieData *)m->ctx;

    HtpState *htp_state = (HtpState *)state;
    if (htp_state == NULL) {
        SCLogDebug("no HTTP layer state has been received, so no match");
        goto end;
    }

    if (!(htp_state->flags & HTP_FLAG_STATE_OPEN)) {
        SCLogDebug("HTP state not yet properly setup, so no match");
        goto end;
    }

    SCLogDebug("htp_state %p, flow %p", htp_state, f);
    SCLogDebug("htp_state->connp %p", htp_state->connp);
    SCLogDebug("htp_state->connp->conn %p", htp_state->connp->conn);

    if (htp_state->connp == NULL || htp_state->connp->conn == NULL) {
        SCLogDebug("HTTP connection structure is NULL");
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        SCLogDebug("No HTTP transaction has received on the connection");
        goto end;
    }

    htp_header_t *h = NULL;
    h = (htp_header_t *)table_getc(tx->request_headers, "Cookie");
    if (h == NULL) {
        SCLogDebug("no HTTP Cookie header in the received request");
        goto end;
    }

    SCLogDebug("we have a cookie header");

    if (BinSearch((const uint8_t *)bstr_ptr(h->value), bstr_size(h->value), co->data,
            co->data_len) != NULL)
    {
        SCLogDebug("match has been found in received request and given http_"
                "cookie rule");
        ret = 1;
    }

end:
    SCMutexUnlock(&f->m);
    SCLogDebug("released lock %p", &f->m);
    SCReturnInt(ret);
}

/**
 * \brief this function setups the http_cookie modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param m        Pointer to the SigMatch
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

int DetectHttpCookieSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                           char *str)
{
    DetectHttpCookieData *hd = NULL;
    SigMatch *sm = NULL;

    if (str != NULL && strcmp(str, "") != 0) {
        SCLogError(SC_INVALID_ARGUMENT, "http_cookie shouldn't be supplied with"
                                        " an argument");
        return -1;
    }

    if (m == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie found inside the "
                     "rule, without any preceding content keywords");
        return -1;
    }

    if (m->type != DETECT_CONTENT) {
        m = SigMatchGetLastSM(s, DETECT_CONTENT);
        if (m == NULL) {
            SCLogWarning(SC_ERR_INVALID_SIGNATURE, "fast_pattern found inside "
                         "the rule, without a content context.  Please use a "
                         "content keyword before using http_cookie");
            return -1;
        }
    }

    /* http_cookie should not be used with the fast_pattern rule */
    if (((DetectContentData *) m->ctx)->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie rule can not "
                "be used with the fast_pattern rule keyword");

        return -1;
    /* http_cookie should not be used with the rawbytes rule */
    } else if (((DetectContentData *) m->ctx)->flags & DETECT_CONTENT_RAWBYTES) {

        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie rule can not "
                "be used with the rawbytes rule keyword");
        return -1;
    }

    /* Setup the HttpCookie data from Content data structure */
    hd = malloc(sizeof(DetectHttpCookieData));
    if (hd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }
    memset(hd, 0, sizeof(DetectHttpCookieData));

    hd->data_len = ((DetectContentData *)m->ctx)->content_len;
    hd->data = malloc(hd->data_len);
    if (hd->data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }
    memcpy(hd->data, ((DetectContentData *)m->ctx)->content, hd->data_len);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_HTTP_COOKIE;
    sm->ctx = (void *)hd;

    /* Okay we need to replace the type to HTTP_COOKIE from CONTENT */
    SigMatchReplace(s, m, sm);

    /* Flagged the signature as to scan the app layer data */
    s->flags |=SIG_FLAG_APPLAYER;

    return 0;
error:
    if (hd != NULL) {
        if (hd->data != NULL)
            free(hd->data);
        free(hd);
    }
    if(sm !=NULL) free(sm);
    return -1;
}

/******************************** UNITESTS **********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Checks if a http_cookie is registered in a Signature, if content is not
 *       specified in the signature
 */
int DetectHttpCookieTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(msg:\"Testing http_cookie\"; http_cookie;sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_cookie is registered in a Signature, if some parameter
 *       is specified with http_cookie in the signature
 */
int DetectHttpCookieTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(msg:\"Testing http_cookie\"; content:\"me\"; "
                               "http_cookie:woo; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_cookie is registered in a Signature
 */
int DetectHttpCookieTest03(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(msg:\"Testing http_cookie\"; content:\"one\"; "
                               "http_cookie; content:\"two\"; http_cookie; "
                               "content:\"two\"; http_cookie; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->match;
    while (sm != NULL) {
        if (sm->type == DETECT_AL_HTTP_COOKIE) {
                result = 1;
        } else {
            result = 0;
            break;
        }
        sm = sm->next;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_cookie is registered in a Signature, when fast_pattern
 *       is also specified in the signature
 */
int DetectHttpCookieTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(msg:\"Testing http_cookie\"; content:\"one\"; "
                               "fast_pattern; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_cookie is registered in a Signature, when rawbytes is
 *       also specified in the signature
 */
int DetectHttpCookieTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(msg:\"Testing http_cookie\"; content:\"one\"; "
                               "rawbytes; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check the signature working to alert when http_cookie is matched . */
static int DetectHttpCookieSigTest01(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatchme\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:\"me\"; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\"HTTP "
                          "cookie\"; content:\"go\"; http_cookie; sid:2;)");
    if (s->next == NULL) {
        goto end;
    }


    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1,
                          FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!(PacketAlertCheck(&p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }
    if (PacketAlertCheck(&p, 2)) {
        printf("sid 2 matched but shouldn't: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest02(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:\"me\"; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1,
                          FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if ((PacketAlertCheck(&p, 1))) {
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    return result;
}
#endif /* UNITTESTS */

/**
 * \brief   Register the UNITTESTS for the http_cookie keyword
 */
void DetectHttpCookieRegisterTests (void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectHttpCookieTest01", DetectHttpCookieTest01, 1);
    UtRegisterTest("DetectHttpCookieTest02", DetectHttpCookieTest02, 1);
    UtRegisterTest("DetectHttpCookieTest03", DetectHttpCookieTest03, 1);
    UtRegisterTest("DetectHttpCookieTest04", DetectHttpCookieTest04, 1);
    UtRegisterTest("DetectHttpCookieTest05", DetectHttpCookieTest05, 1);
    UtRegisterTest("DetectHttpCookieSigTest01", DetectHttpCookieSigTest01, 1);
    UtRegisterTest("DetectHttpCookieSigTest02", DetectHttpCookieSigTest02, 1);
#endif /* UNITTESTS */

}
