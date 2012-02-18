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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the http_stat_msg keyword
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-engine-mpm.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-stat-msg.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"

int DetectHttpStatMsgMatch (ThreadVars *, DetectEngineThreadCtx *,
                           Flow *, uint8_t , void *, Signature *,
                           SigMatch *);
static int DetectHttpStatMsgSetup (DetectEngineCtx *, Signature *, char *);
void DetectHttpStatMsgRegisterTests(void);
void DetectHttpStatMsgFree(void *);

/**
 * \brief Registration function for keyword: http_stat_msg
 */
void DetectHttpStatMsgRegister (void) {
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].name = "http_stat_msg";
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].Setup = DetectHttpStatMsgSetup;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].Free  = DetectHttpStatMsgFree;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].RegisterTests = DetectHttpStatMsgRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].flags |= SIGMATCH_PAYLOAD;
}

/**
 * \brief match the specified content in the signature with the received http
 *        status message header in the http response.
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
int DetectHttpStatMsgMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *sm)
{
    SCEnter();

    int ret = 0;
    int idx;

    SCMutexLock(&f->m);
    SCLogDebug("got lock %p", &f->m);

    DetectContentData *co = (DetectContentData *)sm->ctx;

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

    idx = AppLayerTransactionGetInspectId(f);
    if (idx == -1) {
        goto end;
    }

    int size = (int)list_size(htp_state->connp->conn->transactions);
    for (; idx < size; idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL)
            continue;

        if (tx->response_message == NULL)
            continue;

        SCLogDebug("we have a response message");

        /* call the case insensitive version if nocase has been specified in the sig */
        if (co->flags & DETECT_CONTENT_NOCASE) {
            if (SpmNocaseSearch((uint8_t *) bstr_ptr(tx->response_message),
                    bstr_len(tx->response_message), co->content, co->content_len) != NULL)
            {
                SCLogDebug("match has been found in received request and given http_"
                           "stat_msg rule");
                ret = 1;
            }
        } else {
            if (SpmSearch((uint8_t *) bstr_ptr(tx->response_message),
                    bstr_len(tx->response_message), co->content, co->content_len) != NULL)
            {
                SCLogDebug("match has been found in received request and given http_"
                           "stat_msg rule");
                ret = 1;
            }
        }
    }

    SCMutexUnlock(&f->m);
    SCReturnInt(ret ^ ((co->flags & DETECT_CONTENT_NEGATED) ? 1 : 0));

end:
    SCMutexUnlock(&f->m);
    SCLogDebug("released lock %p", &f->m);
    SCReturnInt(ret);
}

/**
 * \brief this function clears the memory of http_stat_msg modifier keyword
 *
 * \param ptr   Pointer to the Detection Stat Message data
 */
void DetectHttpStatMsgFree(void *ptr)
{
    DetectContentData *hsmd = (DetectContentData *)ptr;
    if (hsmd == NULL)
        return;
    if (hsmd->content != NULL)
        SCFree(hsmd->content);
    SCFree(hsmd);
}

/**
 * \brief this function setups the http_stat_msg modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpStatMsgSetup (DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;

    if (arg != NULL && strcmp(arg, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "http_stat_msg supplied with args");
        return -1;
    }

    sm =  SigMatchGetLastSMFromLists(s, 2,
                                     DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
    /* if still we are unable to find any content previous keywords, it is an
     * invalid rule */
    if (sm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"http_stat_msg\" keyword "
                   "found inside the rule without a content context.  "
                   "Please use a \"content\" keyword before using the "
                   "\"http_stat_msg\" keyword");
        return -1;
    }

    cd = (DetectContentData *)sm->ctx;

    /* http_stat_msg should not be used with the rawbytes rule */
    if (cd->flags & DETECT_CONTENT_RAWBYTES) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_stat_msg rule can not "
                   "be used with the rawbytes rule keyword");
        return -1;
    }

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains a non http "
                   "alproto set");
        goto error;
    }

    if (cd->flags & DETECT_CONTENT_WITHIN || cd->flags & DETECT_CONTENT_DISTANCE) {
        SigMatch *pm =  SigMatchGetLastSMFromLists(s, 4,
                                                   DETECT_CONTENT, sm->prev,
                                                   DETECT_PCRE, sm->prev);
        /* pm can be NULL now.  To accomodate parsing sigs like -
         * content:one; http_modifier; content:two; distance:0; http_modifier */
        if (pm != NULL) {
            if (pm->type == DETECT_CONTENT) {
                DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
                tmp_cd->flags &= ~DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags &= ~ DETECT_PCRE_RELATIVE_NEXT;
            }

        } /* if (pm != NULL) */

        /* reassigning pm */
        pm = SigMatchGetLastSMFromLists(s, 4,
                                        DETECT_AL_HTTP_STAT_MSG, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
                                        DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH]);
        if (pm == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "http_stat_msg seen with a "
                       "distance or within without a previous http_stat_msg "
                       "content.  Invalidating signature.");
            goto error;
        }
        if (pm->type == DETECT_PCRE) {
            DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
            tmp_pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
        } else {
            DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
            tmp_cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
        }
    }
    cd->id = DetectPatternGetId(de_ctx->mpm_pattern_id_store, cd, DETECT_SM_LIST_HSMDMATCH);
    sm->type = DETECT_AL_HTTP_STAT_MSG;

    /* transfer the sm from the pmatch list to hcbdmatch list */
    SigMatchTransferSigMatchAcrossLists(sm,
                                        &s->sm_lists[DETECT_SM_LIST_PMATCH],
                                        &s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                        &s->sm_lists[DETECT_SM_LIST_HSMDMATCH],
                                        &s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH]);

    /* flag the signature to indicate that we scan the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_HTTP;

    return 0;

error:

    return -1;
}

#ifdef UNITTESTS

/**
 * \test Checks if a http_stat_msg is registered in a Signature, if content is not
 *       specified in the signature or rawbyes is specified or fast_pattern is
 *       provided in the signature.
 */
int DetectHttpStatMsgTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_stat_msg\"; http_stat_msg;sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_stat_msg\"; content:\"|FF F1|\";"
                                " rawbytes; http_stat_msg;sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_stat_msg\"; content:\"one\";"
            "fast_pattern; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    if (!(((DetectContentData *)de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->ctx)->flags &
        DETECT_CONTENT_FAST_PATTERN))
    {
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_stat_msg is registered in a Signature and also checks
 *       the nocase
 */
int DetectHttpStatMsgTest02(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_stat_msg\"; content:\"one\"; "
                               "http_stat_msg; content:\"two\"; http_stat_msg; "
                               "content:\"two\"; nocase; http_stat_msg; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH];
    if (sm == NULL) {
        printf("no sigmatch(es): ");
        goto end;
    }

    SigMatch *prev = NULL;
    while (sm != NULL) {
        if (sm->type == DETECT_AL_HTTP_STAT_MSG) {
            result = 1;
        } else {
            printf("expected DETECT_AL_HTTP_STAT_MSG, got %d: ", sm->type);
            goto end;
        }
        prev = sm;
        sm = sm->next;
    }

    if (! (((DetectContentData *)prev->ctx)->flags &
            DETECT_CONTENT_NOCASE))
    {
        result = 0;
    }
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check the signature working to alert when http_stat_msg is matched . */
static int DetectHttpStatMsgSigTest01(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"OK\"; "
                                   "http_stat_msg; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\"HTTP "
                      "Status message nocase\"; content:\"ok\"; nocase; "
                      "http_stat_msg; sid:2;)");
    if (s->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when http_stat_msg is not matched . */
static int DetectHttpStatMsgSigTest02(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"no\"; "
                                   "http_stat_msg; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when http_stat_msg is used with
 *        negated content . */
static int DetectHttpStatMsgSigTest03(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"ok\"; "
                                   "nocase; http_stat_msg; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\"HTTP "
                        "Status message nocase\"; content:!\"Not\"; "
                        "http_stat_msg; sid:2;)");
    if (s->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (! PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't matched but should have: ");
        goto end;
    }
    if (! PacketAlertCheck(p, 2)) {
        printf("sid 2 didn't matched but should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief   Register the UNITTESTS for the http_stat_msg keyword
 */
void DetectHttpStatMsgRegisterTests (void)
{
#ifdef UNITTESTS /* UNITTESTS */

    UtRegisterTest("DetectHttpStatMsgTest01", DetectHttpStatMsgTest01, 1);
    UtRegisterTest("DetectHttpStatMsgTest02", DetectHttpStatMsgTest02, 1);
    UtRegisterTest("DetectHttpStatMsgSigTest01", DetectHttpStatMsgSigTest01, 1);
    UtRegisterTest("DetectHttpStatMsgSigTest02", DetectHttpStatMsgSigTest02, 1);
    UtRegisterTest("DetectHttpStatMsgSigTest03", DetectHttpStatMsgSigTest03, 1);

#endif /* UNITTESTS */
}
/**
 * @}
 */
