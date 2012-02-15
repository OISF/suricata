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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-hsmd.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"

#include "flow-util.h"
#include "util-spm.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "threads.h"
#include "flow-alert-sid.h"

#include "stream-tcp.h"
#include "stream.h"
#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

/**
 * \brief Run the actual payload match function for http stat msg.
 *
 *        For accounting the last match in relative matching the
 *        det_ctx->payload_offset var is used.
 *
 * \param de_ctx      Detection engine context.
 * \param det_ctx     Detection engine thread context.
 * \param s           Signature to inspect.
 * \param sm          SigMatch to inspect.
 * \param payload     Ptr to the http stat msg to inspect.
 * \param payload_len Length of the http stat msg.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DoInspectHttpStatMsg(DetectEngineCtx *de_ctx,
                               DetectEngineThreadCtx *det_ctx,
                               Signature *s, SigMatch *sm,
                               uint8_t *payload, uint32_t payload_len)
{
    SCEnter();

    det_ctx->inspection_recursion_counter++;

    if (det_ctx->inspection_recursion_counter == de_ctx->inspection_recursion_limit) {
        det_ctx->discontinue_matching = 1;
        SCReturnInt(0);
    }

    if (sm == NULL) {
        SCReturnInt(0);
    }

    if (sm->type == DETECT_AL_HTTP_STAT_MSG) {
        if (payload_len == 0) {
            SCReturnInt(0);
        }

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        /* disabled to avoid the FP from inspecting multiple transactions */
        //if (cd->flags & DETECT_CONTENT_HRUD_MPM && !(cd->flags & DETECT_CONTENT_NEGATED))
        //    goto match;

        /* rule parsers should take care of this */
#ifdef DEBUG
        BUG_ON(cd->depth != 0 && cd->depth <= cd->offset);
#endif

        /* search for our pattern, checking the matches recursively.
         * if we match we look for the next SigMatch as well */
        uint8_t *found = NULL;
        uint32_t offset = 0;
        uint32_t depth = payload_len;
        uint32_t prev_offset = 0; /**< used in recursive searching */
        uint32_t prev_payload_offset = det_ctx->payload_offset;

        do {
            if (cd->flags & DETECT_CONTENT_DISTANCE ||
                cd->flags & DETECT_CONTENT_WITHIN) {
                SCLogDebug("prev_payload_offset %"PRIu32, prev_payload_offset);

                offset = prev_payload_offset;
                depth = payload_len;

                if (cd->flags & DETECT_CONTENT_DISTANCE) {
                    if (cd->distance < 0 && (uint32_t)(abs(cd->distance)) > offset)
                        offset = 0;
                    else
                        offset += cd->distance;
                }

                if (cd->flags & DETECT_CONTENT_WITHIN) {
                    if ((int32_t)depth > (int32_t)(prev_payload_offset + cd->within + cd->distance)) {
                        depth = prev_payload_offset + cd->within + cd->distance;
                    }
                }

                if (cd->depth != 0) {
                    if ((cd->depth + prev_payload_offset) < depth) {
                        depth = prev_payload_offset + cd->depth;
                    }
                }

                if (cd->offset > offset) {
                    offset = cd->offset;
                }
            } else { /* implied no relative matches */
                /* set depth */
                if (cd->depth != 0) {
                    depth = cd->depth;
                }

                /* set offset */
                offset = cd->offset;
                prev_payload_offset = 0;
            }

            /* update offset with prev_offset if we're searching for
             * matches after the first occurence. */
            if (prev_offset != 0)
                offset = prev_offset;

            if (depth > payload_len)
                depth = payload_len;

            /* if offset is bigger than depth we can never match on a pattern.
             * We can however, "match" on a negated pattern. */
            if (offset > depth || depth == 0) {
                if (cd->flags & DETECT_CONTENT_NEGATED) {
                    goto match;
                } else {
                    SCReturnInt(0);
                }
            }

            uint8_t *spayload = payload + offset;
            uint32_t spayload_len = depth - offset;
            uint32_t match_offset = 0;
#ifdef DEBUG
            BUG_ON(spayload_len > payload_len);
#endif

            /* do the actual search with boyer moore precooked ctx */
            if (cd->flags & DETECT_CONTENT_NOCASE) {
                found = BoyerMooreNocase(cd->content, cd->content_len,
                                         spayload, spayload_len,
                                         cd->bm_ctx->bmGs, cd->bm_ctx->bmBc);
            } else {
                found = BoyerMoore(cd->content, cd->content_len,
                                   spayload, spayload_len,
                                   cd->bm_ctx->bmGs, cd->bm_ctx->bmBc);
            }

            /* next we evaluate the result in combination with the
             * negation flag. */
            if (found == NULL && !(cd->flags & DETECT_CONTENT_NEGATED)) {
                SCReturnInt(0);
            } else if (found == NULL && cd->flags & DETECT_CONTENT_NEGATED) {
                goto match;
            } else if (found != NULL && cd->flags & DETECT_CONTENT_NEGATED) {
                det_ctx->discontinue_matching = 1;
                SCReturnInt(0);
            } else {
                match_offset = (uint32_t)((found - payload) + cd->content_len);
                det_ctx->payload_offset = match_offset;

                if (!(cd->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
                    SCLogDebug("no relative match coming up, so this is a match");
                    goto match;
                }

                /* bail out if we have no next match. Technically this is an
                 * error, as the current cd has the DETECT_CONTENT_RELATIVE_NEXT
                 * flag set. */
                if (sm->next == NULL) {
                    SCReturnInt(0);
                }

                /* see if the next payload keywords match. If not, we will
                 * search for another occurence of this http header content and
                 * see if the others match then until we run out of matches */
                int r = DoInspectHttpStatMsg(de_ctx, det_ctx, s, sm->next,
                                             payload, payload_len);
                if (r == 1) {
                    SCReturnInt(1);
                }

                if (det_ctx->discontinue_matching)
                    SCReturnInt(0);

                /* set the previous match offset to the start of this match + 1 */
                prev_offset = (match_offset - (cd->content_len - 1));
                SCLogDebug("trying to see if there is another match after "
                           "prev_offset %"PRIu32, prev_offset);
            }

        } while(1);

    } else if (sm->type == DETECT_PCRE) {
        SCLogDebug("inspecting pcre");
        DetectPcreData *pe = (DetectPcreData *)sm->ctx;
        uint32_t prev_payload_offset = det_ctx->payload_offset;
        uint32_t prev_offset = 0;
        int r = 0;

        det_ctx->pcre_match_start_offset = 0;
        do {
            r = DetectPcrePayloadMatch(det_ctx, s, sm, NULL, NULL,
                                       payload, payload_len);

            if (r == 0) {
                det_ctx->discontinue_matching = 1;
                SCReturnInt(0);
            }

            if (!(pe->flags & DETECT_PCRE_RELATIVE_NEXT)) {
                SCLogDebug("no relative match coming up, so this is a match");
                goto match;
            }

            /* save it, in case we need to do a pcre match once again */
            prev_offset = det_ctx->pcre_match_start_offset;

            /* see if the next payload keywords match. If not, we will
             * search for another occurence of this pcre and see
             * if the others match, until we run out of matches */
            int r = DoInspectHttpStatMsg(de_ctx, det_ctx, s, sm->next,
                                         payload, payload_len);
            if (r == 1) {
                SCReturnInt(1);
            }

            if (det_ctx->discontinue_matching)
                SCReturnInt(0);

            det_ctx->payload_offset = prev_payload_offset;
            det_ctx->pcre_match_start_offset = prev_offset;
        } while (1);

    } else if (sm->type == DETECT_ISDATAAT) {
        SCLogDebug("inspecting isdataat");

        DetectIsdataatData *id = (DetectIsdataatData *)sm->ctx;
        if (id->flags & ISDATAAT_RELATIVE) {
            if (det_ctx->payload_offset + id->dataat > payload_len) {
                SCLogDebug("det_ctx->payload_offset + id->dataat %"PRIu32" > %"PRIu32, det_ctx->payload_offset + id->dataat, payload_len);
                if (id->flags & ISDATAAT_NEGATED)
                    goto match;
                SCReturnInt(0);
            } else {
                SCLogDebug("relative isdataat match");
                if (id->flags & ISDATAAT_NEGATED)
                    SCReturnInt(0);
                goto match;
            }
        } else {
            if (id->dataat < payload_len) {
                SCLogDebug("absolute isdataat match");
                if (id->flags & ISDATAAT_NEGATED)
                    SCReturnInt(0);
                goto match;
            } else {
                SCLogDebug("absolute isdataat mismatch, id->isdataat %"PRIu32", payload_len %"PRIu32"", id->dataat,payload_len);
                if (id->flags & ISDATAAT_NEGATED)
                    goto match;
                SCReturnInt(0);
            }
        }
    } else {
        /* we should never get here, but bail out just in case */
        SCLogDebug("sm->type %u", sm->type);
#ifdef DEBUG
        BUG_ON(1);
#endif
    }

    SCReturnInt(0);

match:
    /* this sigmatch matched, inspect the next one. If it was the last,
     * the payload portion of the signature matched. */
    if (sm->next != NULL) {
        int r = DoInspectHttpStatMsg(de_ctx, det_ctx, s, sm->next, payload,
                                     payload_len);
        SCReturnInt(r);
    } else {
        SCReturnInt(1);
    }
}

/**
 * \brief Run the mpm against http stat msg.
 *
 * \retval cnt Number of matches reported by the mpm algo.
 */
int DetectEngineRunHttpStatMsgMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                  HtpState *htp_state, uint8_t flags)
{
    SCEnter();

    uint32_t cnt = 0;

    if (htp_state == NULL) {
        SCLogDebug("no HTTP state");
        SCReturnInt(0);
    }

    /* locking the flow, we will inspect the htp state */
    SCMutexLock(&f->m);

    if (htp_state->connp == NULL || htp_state->connp->conn == NULL) {
        SCLogDebug("HTP state has no conn(p)");
        goto end;
    }

    int idx = AppLayerTransactionGetInspectId(f);
    if (idx == -1) {
        goto end;
    }
    htp_tx_t *tx = NULL;

    int size = (int)list_size(htp_state->connp->conn->transactions);
    for ( ; idx < size; idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL || tx->response_message == NULL)
            continue;

        cnt += HttpStatMsgPatternSearch(det_ctx,
                                        (uint8_t *)bstr_ptr(tx->response_message),
                                        bstr_len(tx->response_message), flags);
    }

end:
    SCMutexUnlock(&f->m);
    SCReturnInt(cnt);
}

/**
 * \brief Do the http_stat_msg content inspection for a signature.
 *
 * \param de_ctx  Detection engine context.
 * \param det_ctx Detection engine thread context.
 * \param s       Signature to inspect.
 * \param f       Flow.
 * \param flags   App layer flags.
 * \param state   App layer state.
 *
 * \retval 0 No match.
 * \retval 1 Match.
 */
int DetectEngineInspectHttpStatMsg(DetectEngineCtx *de_ctx,
                                  DetectEngineThreadCtx *det_ctx,
                                  Signature *s, Flow *f, uint8_t flags,
                                  void *alstate)
{
    SCEnter();

    int r = 0;

    HtpState *htp_state = (HtpState *)alstate;
    if (htp_state == NULL) {
        SCLogDebug("no HTTP state");
        SCReturnInt(0);
    }

    /* locking the flow, we will inspect the htp state */
    SCMutexLock(&f->m);

    if (htp_state->connp == NULL || htp_state->connp->conn == NULL) {
        SCLogDebug("HTP state has no conn(p)");
        goto end;
    }

#ifdef DEBUG
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_HSMDMATCH];
    DetectContentData *co = (DetectContentData *)sm->ctx;
    SCLogDebug("co->id %"PRIu32, co->id);
#endif

    int idx = AppLayerTransactionGetInspectId(f);
    if (idx == -1) {
        goto end;
    }

    htp_tx_t *tx = NULL;

    int size = (int)list_size(htp_state->connp->conn->transactions);
    for ( ; idx < size; idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL || tx->response_message == NULL)
            continue;

        det_ctx->discontinue_matching = 0;
        det_ctx->payload_offset = 0;
        det_ctx->inspection_recursion_counter = 0;

        r = DoInspectHttpStatMsg(de_ctx, det_ctx, s,
                                 s->sm_lists[DETECT_SM_LIST_HSMDMATCH],
                                 (uint8_t *)bstr_ptr(tx->response_message),
                                 bstr_len(tx->response_message));
        if (r == 1) {
            goto end;
        }
    }

end:
    SCMutexUnlock(&f->m);
    SCReturnInt(r);
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS

static int DetectEngineHttpStatMsgTest01(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 message\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"message\"; http_stat_msg; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest02(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 xxxxABC\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "xxxxABC";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ABC\"; http_stat_msg; offset:4; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest03(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    int result = 0;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "8901234ABC\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "12345678901234ABC";
    uint32_t http_len3 = sizeof(http_buf3) - 1;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ABC\"; http_stat_msg; offset:14; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest04(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"abc\"; http_stat_msg; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest05(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest06(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"def\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest07(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"def\"; http_stat_msg; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest08(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"abc\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest09(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:\"def\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest10(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:!\"xyz\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest11(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:\"xyz\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 did match but should not have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest12(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ab\"; http_stat_msg; depth:2; "
                               "content:\"ef\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest13(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ab\"; http_stat_msg; depth:3; "
                               "content:!\"yz\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest14(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "pcre:/ab/Y; "
                               "content:\"ef\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpStatMsgTest15(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "pcre:/abc/Y; "
                               "content:!\"xyz\"; http_stat_msg; distance:0; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

#endif /* UNITTESTS */

void DetectEngineHttpStatMsgRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("DetectEngineHttpStatMsgTest01",
                   DetectEngineHttpStatMsgTest01, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest02",
                   DetectEngineHttpStatMsgTest02, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest03",
                   DetectEngineHttpStatMsgTest03, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest04",
                   DetectEngineHttpStatMsgTest04, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest05",
                   DetectEngineHttpStatMsgTest05, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest06",
                   DetectEngineHttpStatMsgTest06, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest07",
                   DetectEngineHttpStatMsgTest07, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest08",
                   DetectEngineHttpStatMsgTest08, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest09",
                   DetectEngineHttpStatMsgTest09, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest10",
                   DetectEngineHttpStatMsgTest10, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest11",
                   DetectEngineHttpStatMsgTest11, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest12",
                   DetectEngineHttpStatMsgTest12, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest13",
                   DetectEngineHttpStatMsgTest13, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest14",
                   DetectEngineHttpStatMsgTest14, 1);
    UtRegisterTest("DetectEngineHttpStatMsgTest15",
                   DetectEngineHttpStatMsgTest15, 1);
#endif /* UNITTESTS */

    return;
}

/**
 * @}
 */
