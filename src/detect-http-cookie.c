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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Implements the http_cookie keyword
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
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-cookie.h"
#include "stream-tcp.h"

int DetectHttpCookieMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *m);
static int DetectHttpCookieSetup (DetectEngineCtx *, Signature *, char *);
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
 * \param sm        pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectHttpCookieMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *sm)
{
    SCEnter();

    int ret = 0;
    size_t idx;

    SCMutexLock(&f->m);
    SCLogDebug("got lock %p", &f->m);

    DetectHttpCookieData *co = (DetectHttpCookieData *)sm->ctx;

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

    htp_tx_t *tx = NULL;

    for (idx = htp_state->new_in_tx_index;
         idx < list_size(htp_state->connp->conn->transactions); idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL)
            continue;

        htp_header_t *h = NULL;
        h = (htp_header_t *) table_getc(tx->request_headers, "Cookie");
        if (h == NULL) {
            SCLogDebug("no HTTP Cookie header in the received request");
            goto end;
        }

        SCLogDebug("we have a cookie header");

        /* call the case insensitive version if nocase has been specified in the sig */
        if (co->flags & DETECT_AL_HTTP_COOKIE_NOCASE) {
            if (SpmNocaseSearch((uint8_t *) bstr_ptr(h->value), bstr_size(h->value),
                          co->data, co->data_len) != NULL) {
                SCLogDebug("match has been found in received request and given http_"
                           "cookie rule");
                ret = 1;
            }
        } else {
            if (SpmSearch((uint8_t *) bstr_ptr(h->value), bstr_size(h->value),
                                co->data, co->data_len) != NULL) {
                SCLogDebug("match has been found in received request and given http_"
                           "cookie rule");
                ret = 1;
            }
        }
    }

    SCMutexUnlock(&f->m);
    return ret ^ ((co->flags & DETECT_AL_HTTP_COOKIE_NEGATED) ? 1 : 0);

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
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpCookieSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectHttpCookieData *hd = NULL;
    SigMatch *sm = NULL;

    /** new sig match to replace previous content */
    SigMatch *nm = NULL;

    if (str != NULL && strcmp(str, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "http_cookie shouldn't be supplied with"
                                        " an argument");
        return -1;
    }

    if (s->pmatch_tail == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie found inside the "
                     "rule, without any preceding content keywords");
        return -1;
    }

    SigMatch *pm = DetectContentGetLastPattern(s->pmatch_tail);
    if (pm == NULL) {
        SCLogWarning(SC_ERR_INVALID_SIGNATURE, "fast_pattern found inside "
                "the rule, without a content context.  Please use a "
                "content keyword before using http_cookie");
        return -1;
    }

    /* http_cookie should not be used with the fast_pattern rule */
    if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie rule can not "
                "be used with the fast_pattern rule keyword");

        return -1;
    /* http_cookie should not be used with the rawbytes rule */
    } else if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_RAWBYTES) {

        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_cookie rule can not "
                "be used with the rawbytes rule keyword");
        return -1;
    }

    nm = SigMatchAlloc();
    if (nm == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SigMatchAlloc failed");
        goto error;
    }

    /* Setup the HttpCookie data from Content data structure */
    hd = SCMalloc(sizeof(DetectHttpCookieData));
    if (hd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed");
        goto error;
    }
    memset(hd, 0, sizeof(DetectHttpCookieData));

    hd->data_len = ((DetectContentData *)pm->ctx)->content_len;
    hd->data = ((DetectContentData *)pm->ctx)->content;
    hd->flags |= (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_NOCASE) ?
        DETECT_AL_HTTP_COOKIE_NOCASE : 0;
    hd->flags |= (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_NEGATED) ?
        DETECT_AL_HTTP_COOKIE_NEGATED : 0;
    nm->type = DETECT_AL_HTTP_COOKIE;
    nm->ctx = (void *)hd;

    /* pull the previous content from the pmatch list, append
     * the new match to the match list */
    SigMatchReplaceContent(s, pm, nm);

    /* free the old content sigmatch, the content pattern memory
     * is taken over by the new sigmatch */
    SCFree(pm->ctx);
    SCFree(pm);

    /* Flagged the signature as to inspect the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    s->alproto = ALPROTO_HTTP;
    return 0;
error:
    if (hd != NULL) {
        if (hd->data != NULL)
            SCFree(hd->data);
        SCFree(hd);
    }
    if(sm !=NULL) SCFree(sm);
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
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
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    result = 0;
    sm = de_ctx->sig_list->match;
    if (sm == NULL) {
        printf("no sigmatch(es): ");
        goto end;
    }

    while (sm != NULL) {
        if (sm->type == DETECT_AL_HTTP_COOKIE) {
            result = 1;
        } else {
            printf("expected DETECT_AL_HTTP_COOKIE, got %d: ", sm->type);
            goto end;
        }
        sm = sm->next;
    }

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
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

/**
 * \test Checks if a http_cookie is registered in a Signature, when rawbytes is
 *       also specified in the signature
 */
int DetectHttpCookieTest06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_cookie\"; content:\"one\"; "
                               "http_cookie; uricontent:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    Signature *s = de_ctx->sig_list;

    BUG_ON(s->match == NULL);

    if (s->match->type != DETECT_AL_HTTP_COOKIE)
        goto end;

    if (s->umatch == NULL) {
        printf("expected another SigMatch, got NULL: ");
        goto end;
    }

    if (s->umatch->type != DETECT_URICONTENT) {
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
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
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
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
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
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
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest03(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:boo; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
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
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest04(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:!boo; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1)) {
        goto end;
    }

    result = 1;
end:
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest05(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: DuMmY\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:dummy; nocase; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1)) {
        goto end;
    }

    result = 1;
end:
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest06(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: DuMmY\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:dummy; "
                                   "http_cookie; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1)) {
        goto end;
    }

    result = 1;
end:
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest07(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; content:!dummy; "
                                   "http_cookie; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (PacketAlertCheck(&p, 1)) {
        goto end;
    }

    result = 1;
end:
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    UtRegisterTest("DetectHttpCookieTest06", DetectHttpCookieTest06, 1);
    UtRegisterTest("DetectHttpCookieSigTest01", DetectHttpCookieSigTest01, 1);
    UtRegisterTest("DetectHttpCookieSigTest02", DetectHttpCookieSigTest02, 1);
    UtRegisterTest("DetectHttpCookieSigTest03", DetectHttpCookieSigTest03, 1);
    UtRegisterTest("DetectHttpCookieSigTest04", DetectHttpCookieSigTest04, 1);
    UtRegisterTest("DetectHttpCookieSigTest05", DetectHttpCookieSigTest05, 1);
    UtRegisterTest("DetectHttpCookieSigTest06", DetectHttpCookieSigTest06, 1);
    UtRegisterTest("DetectHttpCookieSigTest07", DetectHttpCookieSigTest07, 1);
#endif /* UNITTESTS */

}
