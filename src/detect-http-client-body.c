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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * Implements support for the http_client_body keyword
 */

#include "suricata-common.h"
#include "threads.h"
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

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-client-body.h"
#include "stream-tcp.h"

int DetectHttpClientBodyMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                              Flow *f, uint8_t flags, void *state, Signature *s,
                              SigMatch *m);
int DetectHttpClientBodySetup(DetectEngineCtx *, Signature *, char *);
void DetectHttpClientBodyRegisterTests(void);

/**
 * \brief Registers the keyword handlers for the "http_client_body" keyword.
 */
void DetectHttpClientBodyRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].name = "http_client_body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].AppLayerMatch = DetectHttpClientBodyMatch;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Setup = DetectHttpClientBodySetup;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Free  = NULL;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].RegisterTests = DetectHttpClientBodyRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].flags |= SIGMATCH_PAYLOAD ;
}

/**
 * \brief App layer match function for the "http_client_body" keyword.
 *
 * \param t       Pointer to the ThreadVars instance.
 * \param det_ctx Pointer to the DetectEngineThreadCtx.
 * \param f       Pointer to the flow.
 * \param flags   Pointer to the flags indicating the flow direction.
 * \param state   Pointer to the app layer state data.
 * \param s       Pointer to the Signature instance.
 * \param m       Pointer to the SigMatch.
 *
 * \retval 1 On Match.
 * \retval 0 On no match.
 */
int DetectHttpClientBodyMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                              Flow *f, uint8_t flags, void *state, Signature *s,
                              SigMatch *m)
{
    int result = 0;
    DetectHttpClientBodyData *hcbd = (DetectHttpClientBodyData *)m->ctx;
    HtpState *htp_state = (HtpState *)state;

    SCMutexLock(&f->m);

    if (htp_state == NULL) {
        SCLogDebug("No htp state, no match at http body data");
        goto end;
    }

    if (htp_state->body.nchunks == 0) {
        SCLogDebug("No http chunks to inspect");
        goto end;
    } else {
        HtpBodyChunk *cur = htp_state->body.first;
        /* no chunks?!! get out of here */
        if (cur == NULL) {
            SCLogDebug("No http chunks to inspect");
            goto end;
        }

        /* this applies only for the client request body like the keyword name says */
        if (htp_state->body.operation != HTP_BODY_REQUEST) {
            SCLogDebug("htp chunk not a request chunk");
            goto end;
        }

        /* this is not how we do it now.  We can rather hold the PM state from
         * the previous chunk that was matched, and continue right from where
         * we left off.  We need to devise a scheme to do that, not just for
         * this keyword, but other keywords need it as well */
        uint8_t *chunks_buffer = NULL;
        uint32_t total_chunks_len = 0;
        /* club all the chunks into one whole buffer and call the SPM on the buffer */
        while (cur != NULL) {
            total_chunks_len += cur->len;
            if ( (chunks_buffer = SCRealloc(chunks_buffer, total_chunks_len)) == NULL) {
                return 0;
            }
            memcpy(chunks_buffer + total_chunks_len - cur->len, cur->data, cur->len);
            cur = cur->next;
        }
        /* call the case insensitive version if nocase has been specified in the sig */
        if (hcbd->flags & DETECT_AL_HTTP_CLIENT_BODY_NOCASE) {
            result = (BoyerMooreNocase(hcbd->content, hcbd->content_len, chunks_buffer,
                                       total_chunks_len, hcbd->bm_ctx->bmGs,
                                       hcbd->bm_ctx->bmBc) != NULL);
        /* call the case sensitive version if nocase has been specified in the sig */
        } else {
            result = (BoyerMoore(hcbd->content, hcbd->content_len, chunks_buffer,
                                       total_chunks_len, hcbd->bm_ctx->bmGs,
                                       hcbd->bm_ctx->bmBc) != NULL);
        }
        SCFree(chunks_buffer);
    }

    SCMutexUnlock(&f->m);
    return result ^ ((hcbd->flags & DETECT_AL_HTTP_CLIENT_BODY_NEGATED) ? 1 : 0);

 end:
    SCMutexUnlock(&f->m);
    return result;
}

/**
 * \brief The setup function for the http_client_body keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int DetectHttpClientBodySetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    /* http_client_body_data (hcbd) */
    DetectHttpClientBodyData *hcbd = NULL;
    SigMatch *nm = NULL;
    SigMatch *sm = NULL;

    if (arg != NULL && strcmp(arg, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "http_client_body supplied with no "
                   "args");
        return -1;
    }

    if (s->pmatch_tail == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_client_body found inside the "
                   "rule, without any preceding content keywords");
        return -1;
    }

    sm = DetectContentGetLastPattern(s->pmatch_tail);
    /* if still we are unable to find any content previous keywords, it is an
     * invalid rule */
    if (sm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"http_client_body\" keyword "
                   "found inside the rule without a content context.  "
                   "Please use a \"content\" keyword before using the "
                   "\"http_client_body\" keyword");
        return -1;
    }

    /* http_client_body should not be used with the rawbytes rule */
    if ( ((DetectContentData *)sm->ctx)->flags & DETECT_CONTENT_RAWBYTES) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_client_body rule can not "
                   "be used with the rawbytes rule keyword");
        return -1;
    }

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords");
        goto error;
    }

    /* setup the HttpClientBodyData's data from content data structure's data */
    hcbd = SCMalloc(sizeof(DetectHttpClientBodyData));
    if (hcbd == NULL)
        goto error;
    memset(hcbd, 0, sizeof(DetectHttpClientBodyData));

    /* transfer the pattern details from the content struct to the clientbody struct */
    hcbd->content = ((DetectContentData *)sm->ctx)->content;
    hcbd->content_len = ((DetectContentData *)sm->ctx)->content_len;
    hcbd->flags |= (((DetectContentData *)sm->ctx)->flags & DETECT_CONTENT_NOCASE) ?
        DETECT_AL_HTTP_CLIENT_BODY_NOCASE : 0;
    hcbd->flags |= (((DetectContentData *)sm->ctx)->flags & DETECT_CONTENT_NEGATED) ?
        DETECT_AL_HTTP_CLIENT_BODY_NEGATED : 0;
    hcbd->bm_ctx = ((DetectContentData *)sm->ctx)->bm_ctx;

    nm = SigMatchAlloc();
    if (nm == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        goto error;
    }
    nm->type = DETECT_AL_HTTP_CLIENT_BODY;
    nm->ctx = (void *)hcbd;

    /* pull the previous content from the pmatch list, append
     * the new match to the match list */
    SigMatchReplaceContent(s, sm, nm);

    /* free the old content sigmatch, the content pattern memory
     * is taken over by the new sigmatch */
    SCFree(sm->ctx);
    SCFree(sm);

    /* flag the signature to indicate that we scan the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_HTTP;
    /* enable http request body callback in the http app layer parser */
    AppLayerHtpEnableRequestBodyCallback();

    return 0;

error:
    if (hcbd != NULL) {
        if (hcbd->content != NULL)
            SCFree(hcbd->content);
        SCFree(hcbd);
    }
    if(nm != NULL)
        SCFree(sm);

    return -1;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Test that a signature containting a http_client_body is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpClientBodyTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    SigMatch *sm = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:one; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        goto end;
    }

    sm = de_ctx->sig_list->match;
    if (sm != NULL) {
        result &= (sm->type == DETECT_AL_HTTP_CLIENT_BODY);
        result &= (sm->next == NULL);
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_client_body entry is
 *       parsed.
 */
static int DetectHttpClientBodyTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:one; http_client_body:; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a http_client_body
 *       is invalidated.
 */
static int DetectHttpClientBodyTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:one; rawbytes; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:one; http_client_body; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest06(void)
{
    TcpSession ssn;
    Packet p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(Packet));
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

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:message; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!(PacketAlertCheck(&p, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest07(void)
{
    TcpSession ssn;
    Packet p1;
    Packet p2;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 67\r\n"
        "\r\n"
        "This is dummy message body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p1, 0, sizeof(Packet));
    memset(&p2, 0, sizeof(Packet));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = NULL;
    p1.payload_len = 0;
    p1.proto = IPPROTO_TCP;

    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = NULL;
    p2.payload_len = 0;
    p2.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p1.flow = &f;
    p1.flowflags |= FLOW_PKT_TOSERVER;
    p2.flow = &f;
    p2.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);

    if (!(PacketAlertCheck(&p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);
/* VJ right now we won't inspect the body another time if it
   already matched once. Later we will take care of that.
    if (!(PacketAlertCheck(&p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }
*/
    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest08(void)
{
    TcpSession ssn;
    Packet p1;
    Packet p2;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 67\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p1, 0, sizeof(Packet));
    memset(&p2, 0, sizeof(Packet));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = NULL;
    p1.payload_len = 0;
    p1.proto = IPPROTO_TCP;

    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = NULL;
    p2.payload_len = 0;
    p2.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p1.flow = &f;
    p1.flowflags |= FLOW_PKT_TOSERVER;
    p2.flow = &f;
    p2.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:message; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
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
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);

    if ((PacketAlertCheck(&p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);

    if (!(PacketAlertCheck(&p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpClientBodyTest09(void)
{
    TcpSession ssn;
    Packet p1;
    Packet p2;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 67\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p1, 0, sizeof(Packet));
    memset(&p2, 0, sizeof(Packet));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = NULL;
    p1.payload_len = 0;
    p1.proto = IPPROTO_TCP;

    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = NULL;
    p2.payload_len = 0;
    p2.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p1.flow = &f;
    p1.flowflags |= FLOW_PKT_TOSERVER;
    p2.flow = &f;
    p2.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:body1This; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
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
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);

    if ((PacketAlertCheck(&p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);

    if (!(PacketAlertCheck(&p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpClientBodyTest10(void)
{
    TcpSession ssn;
    Packet p1;
    Packet p2;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 67\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p1, 0, sizeof(Packet));
    memset(&p2, 0, sizeof(Packet));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = NULL;
    p1.payload_len = 0;
    p1.proto = IPPROTO_TCP;

    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = NULL;
    p2.payload_len = 0;
    p2.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p1.flow = &f;
    p1.flowflags |= FLOW_PKT_TOSERVER;
    p2.flow = &f;
    p2.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:body1This; http_client_body; nocase;"
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);

    if ((PacketAlertCheck(&p1, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);

    if (!(PacketAlertCheck(&p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the negated http_client_body content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpClientBodyTest11(void)
{
    TcpSession ssn;
    Packet p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(Packet));
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

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!message1; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
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
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Negative test that the negated http_client_body content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpClientBodyTest12(void)
{
    TcpSession ssn;
    Packet p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(Packet));
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

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!message; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
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
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest13(void)
{
    TcpSession ssn;
    Packet p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;


    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(Packet));
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

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:abcdefghijklmnopqrstuvwxyz0123456789; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
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
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif /* UNITTESTS */

void DetectHttpClientBodyRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectHttpClientBodyTest01", DetectHttpClientBodyTest01, 1);
    UtRegisterTest("DetectHttpClientBodyTest02", DetectHttpClientBodyTest02, 1);
    UtRegisterTest("DetectHttpClientBodyTest03", DetectHttpClientBodyTest03, 1);
    UtRegisterTest("DetectHttpClientBodyTest04", DetectHttpClientBodyTest04, 1);
    UtRegisterTest("DetectHttpClientBodyTest05", DetectHttpClientBodyTest05, 1);
    UtRegisterTest("DetectHttpClientBodyTest06", DetectHttpClientBodyTest06, 1);
    UtRegisterTest("DetectHttpClientBodyTest07", DetectHttpClientBodyTest07, 1);
    UtRegisterTest("DetectHttpClientBodyTest08", DetectHttpClientBodyTest08, 1);
    UtRegisterTest("DetectHttpClientBodyTest09", DetectHttpClientBodyTest09, 1);
    UtRegisterTest("DetectHttpClientBodyTest10", DetectHttpClientBodyTest10, 1);
    UtRegisterTest("DetectHttpClientBodyTest11", DetectHttpClientBodyTest11, 1);
    UtRegisterTest("DetectHttpClientBodyTest12", DetectHttpClientBodyTest12, 1);
    UtRegisterTest("DetectHttpClientBodyTest13", DetectHttpClientBodyTest13, 1);
#endif /* UNITTESTS */

    return;
}
