/* Copyright (C) 2008 by Victor Julien <victor@inliniac.net>
 * Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file   Simple uricontent match part of the detection engine.
 *
 * \author  Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "threads.h"
#include "flow-alert-sid.h"

#include "stream.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-binsearch.h"

/* prototypes */
int DetectUricontentMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
                           Signature *, SigMatch *);
int DetectUricontentSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void HttpUriRegisterTests(void);

int DetectAppLayerUricontentMatch (ThreadVars *, DetectEngineThreadCtx *,
                                   Flow *, uint8_t , void *,
                                   Signature *, SigMatch *);

/**
 * \brief Registration function for uricontent: keyword
 */
void DetectUricontentRegister (void)
{
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].AppLayerMatch = DetectAppLayerUricontentMatch;
    sigmatch_table[DETECT_URICONTENT].Match = DetectUricontentMatch;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free  = NULL;
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
    return de_ctx->uricontent_max_id;
}

/**
 * \brief   Free the stored http_uri in the given packet
 * \param   p   pointer to the given packet whose uri has to be freed
 */
void PktHttpUriFree(Packet *p)
{
    int i;

    for (i = 0; i < p->http_uri.cnt; i++) {
        free(p->http_uri.raw[i]);
        p->http_uri.raw[i] = NULL;
    }
    p->http_uri.cnt = 0;
}

static inline int TestOffsetDepth(MpmMatch *m, DetectUricontentData *co)
{
    if (co->offset == 0 ||
        (co->offset && ((m->offset+1) - co->uricontent_len) >= co->offset))
    {
        if (co->depth == 0 ||
            (co->depth && (m->offset+1) <= co->depth))
        {
            return 1;
        }
    }

    return 0;
}

/* This function is called recursively (if necessary) to be able
 * to determite whether or not a chain of content matches connected
 * with 'within' and 'distance' options fully matches. The reason it
 * was done like this is to make sure we can handle partial matches
 * that turn out to fail being followed by full matches later in the
 * packet. This adds some runtime complexity however. */
static inline int TestWithinDistanceOffsetDepth(ThreadVars *t,
                                                DetectEngineThreadCtx *det_ctx,
                                                MpmMatch *m, SigMatch *nsm)
{
    //printf("test_nextsigmatch m:%p, nsm:%p\n", m,nsm);
    if (nsm == NULL)
        return 1;

    DetectUricontentData *co = (DetectUricontentData *)nsm->ctx;
    MpmMatch *nm = det_ctx->mtcu.match[co->id].top;

    for (; nm; nm = nm->next) {
        SCLogDebug("(nm->offset+1) %" PRIu32 ", (m->offset+1) %" PRIu32 "",
                    (nm->offset+1), (m->offset+1));

        if ((co->within == 0 || (co->within &&
           ((nm->offset+1) > (m->offset+1)) &&
           ((nm->offset+1) - (m->offset+1) <= co->within))))
        {
             SCLogDebug("WITHIN (nm->offset+1) %" PRIu32 ", (m->offset+1) "
                        "%" PRIu32 "", (nm->offset+1), (m->offset+1));

            if (co->distance == 0 || (co->distance &&
               ((nm->offset+1) > (m->offset+1)) &&
               ((nm->offset+1) - (m->offset+1) >= co->distance)))
            {
                if (TestOffsetDepth(nm, co) == 1) {
                      SCLogDebug("DISTANCE (nm->offset+1) %" PRIu32 ", "
                                 "(m->offset+1) %" PRIu32 "", (nm->offset+1),
                                 (m->offset+1));
                    return TestWithinDistanceOffsetDepth(t, det_ctx, nm,
                                                         nsm->next);
                }
            }
        }
    }
    return 0;
}

static inline int DoDetectUricontent(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                     Packet *p, SigMatch *sm,
                                     DetectUricontentData *co)
{
    int ret = 0;
    char match = 0;

    /* Get the top match, we already know we have one. */
    MpmMatch *m = det_ctx->mtcu.match[co->id].top;

    /*  if we have within or distance coming up next, check this match
     *  for distance and/or within and check the rest of this match
     *  chain as well. */
    if ((co->flags & DETECT_URICONTENT_WITHIN_NEXT ||
         co->flags & DETECT_URICONTENT_DISTANCE_NEXT) &&
         det_ctx->de_checking_distancewithin == 0)
    {
        /* indicate to the detection engine the next sigmatch(es)
         * are part of this match chain */
        det_ctx->de_checking_distancewithin = 1;

        for (; m != NULL; m = m->next) {
            /* first check our match for offset and depth */
            if (TestOffsetDepth(m, co) == 1) {
                ret = TestWithinDistanceOffsetDepth(t, det_ctx, m, sm->next);
                if (ret == 1) {
                    /* update pkt ptrs, content doesn't use this,
                     * but pcre does */
                    det_ctx->pkt_ptr = p->payload + m->offset;
                    det_ctx->pkt_off = m->offset;
                    match = 1;
                    break;
                }
            }
        }
    /* Okay, this is complicated... on the first match of a match chain,
     * we do the whole match of that chain (a chain here means a number
     * of consecutive content matches that relate to each other with
     * 'within and/or 'distance options'). But we still get to the next
     * sigmatches. We have already inspected this sigmatch, even for
     * offset and depth. Since the fact that we get there means we have
     * had a match, we return match here too.
     */
    } else if (co->flags & DETECT_URICONTENT_WITHIN ||
               co->flags & DETECT_URICONTENT_DISTANCE)
    {
        det_ctx->de_checking_distancewithin = 0;
        match = 1;
    /* Getting here means we are not in checking an within/distance chain.
     * This means we can just inspect this content match on it's own. So
     * Let's see if at least one of the matches within the offset and depth
     * settings. If so, return a match.
     */
    } else {
        for (; m != NULL; m = m->next) {
            ret = TestOffsetDepth(m,co);
            if (ret == 1) {
                /* update pkt ptrs, content doesn't use this,
                 * but pcre does */
                det_ctx->pkt_ptr = p->payload + m->offset;
                det_ctx->pkt_off = m->offset;
                match = 1;
                break;
            }
        }
    }
    return match;
}


/**
 * \brief   Checks if the packet sent as the argument, has a uricontent which
 *          has been provided in the signature
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match; 0 no match
 */
int DetectUricontentMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Packet *p, Signature *s, SigMatch *m)
{
    SCEnter();
    uint32_t len = 0;

    DetectUricontentData *co = (DetectUricontentData *)m->ctx;

    /* see if we had a match */
    len = det_ctx->mtcu.match[co->id].len;
    if (len == 0) {
        SCLogDebug("We don't have match");
        SCReturnInt(0);
    }

#if 0
    if (SCLogDebugEnabled()) {
        printf("uricontent \'");
        PrintRawUriFp(stdout, co->uricontent, co->uricontent_len);
        printf("\' matched %" PRIu32 " time(s) at offsets: ", len);

        MpmMatch *tmpm = NULL;
        for (tmpm = det_ctx->mtcu.match[co->id].top; tmpm != NULL;
                    tmpm = tmpm->next)
        {
            printf("%" PRIu32 " ", tmpm->offset);
        }
        printf("\n");
    }
#endif

    SCReturnInt(DoDetectUricontent(t, det_ctx, p, m, co));
}

/**
 * \brief   Setup the detecturicontent keyword data from the string defined in
 *          the rule set.
 * \param   contentstr  Pointer to the string which has been defined in the rule
 */
DetectUricontentData *DoDetectUricontentSetup (char * contentstr)
{
    DetectUricontentData *cd = NULL;
    char *temp = NULL;
    char *str = NULL;
    uint16_t len = 0;
    uint16_t pos = 0;
    uint16_t slen = 0;

    if ((temp = strdup(contentstr)) == NULL)
        goto error;

    if (strlen(temp) == 0) {
        free(temp);
        return NULL;
    }

    cd = malloc(sizeof(DetectUricontentData));
    if (cd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }
    memset(cd,0,sizeof(DetectUricontentData));

    /* skip the first spaces */
    slen = strlen(temp);
    while (pos < slen && isspace(temp[pos])) {
        pos++;
    };

    if (temp[pos] == '!') {
        SCLogError(SC_ERR_NO_URICONTENT_NEGATION, "uricontent negation is not "
                                        "supported at this time. See bug #31.");
        goto error;
    }

    if (temp[pos] == '\"' && temp[strlen(temp)-1] == '\"') {
        if ((str = strdup(temp + pos + 1)) == NULL)
            goto error;
        str[strlen(temp) - pos - 2] = '\0';
    } else {
        if ((str = strdup(temp + pos)) == NULL)
            goto error;
    }

    free(temp);
    temp = NULL;
    len = strlen(str);

    SCLogDebug("\"%s\", len %" PRIu32 "", str, len);
    char converted = 0;

    {
        uint16_t i, x;
        uint8_t bin = 0, binstr[3] = "", binpos = 0;
        for (i = 0, x = 0; i < len; i++) {
            SCLogDebug("str[%02u]: %c", i, str[i]);
            if (str[i] == '|') {
                if (bin) {
                    bin = 0;
                } else {
                    bin = 1;
                }
            } else {
                if (bin) {
                    if (isdigit(str[i]) ||
                        str[i] == 'A' || str[i] == 'a' ||
                        str[i] == 'B' || str[i] == 'b' ||
                        str[i] == 'C' || str[i] == 'c' ||
                        str[i] == 'D' || str[i] == 'd' ||
                        str[i] == 'E' || str[i] == 'e' ||
                        str[i] == 'F' || str[i] == 'f') {
                        SCLogDebug("part of binary: %c", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            uint8_t c = strtol((char *)binstr, (char **) NULL,
                                                16) & 0xFF;
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        SCLogDebug("space as part of binary string");
                    }
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }
#ifdef DEBUG
        if (SCLogDebugEnabled()) {
            for (i = 0; i < x; i++) {
                if (isprint(str[i])) printf("%c", str[i]);
                else                 printf("\\x%02u", str[i]);
            }
            printf("\n");
        }
#endif

        if (converted)
            len = x;
    }

    SCLogDebug("len %" PRIu32 "", len);

    cd->uricontent = malloc(len);
    if (cd->uricontent == NULL) {
        free(cd);
        free(str);
        return NULL;;
    }

    memcpy(cd->uricontent, str, len);
    cd->uricontent_len = len;
    cd->depth = 0;
    cd->offset = 0;
    cd->within = 0;
    cd->distance = 0;
    cd->flags = 0;

    free(str);
    return cd;

error:
    free(str);
    if (cd) free(cd);
    return NULL;
}

/**
 * \brief Creates a SigMatch for the uricontent keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param m         Pointer to the head of the SigMatchs for the current rule
*                  being parsed
 * \param contentstr  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
int DetectUricontentSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                           char *contentstr)
{
    SigMatch *sm = NULL;
    DetectUricontentData *cd = DoDetectUricontentSetup(contentstr);
    if (cd == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_URICONTENT;
    sm->ctx = (void *)cd;

    SigMatchAppend(s,m,sm);

    cd->id = de_ctx->uricontent_max_id;
    de_ctx->uricontent_max_id++;

    /* Flagged the signature as to scan the app layer data */
    s->flags |=SIG_FLAG_APPLAYER;

    return 0;

error:
    if (cd) free(cd);
    return -1;
}

/**
 * \brief   Checks if the content sent as the argument, has a uricontent which
 *          has been provided in the rule. This match function matches the
 *          normalized http uri against the given rule using multi pattern
 *          scan/search algorithms.
 *
 * \param t             Pointer to the tv for this detection module instance
 * \param det_ctx       Pointer to the detection engine thread context
 * \param content       Pointer to the uri content currently being matched
 * \param content_len   Content_len of the received uri content
 *
 * \retval 1 if the uri contents match; 0 no match
 */
int DoDetectAppLayerUricontentMatch (ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
                                     uint8_t *content, uint16_t content_len)
{
    int ret = 0;
    /* run the pattern matcher against the uri */
    if (det_ctx->sgh->mpm_uricontent_maxlen > content_len) {
        SCLogDebug("not scanning as pkt payload is smaller than the "
                "largest uricontent length we need to match");
    } else {
        SCLogDebug("scan: (%p, maxlen %" PRIu32 ", sgh->sig_cnt "
                "%" PRIu32 ")", det_ctx->sgh, det_ctx->sgh->
                mpm_uricontent_maxlen, det_ctx->sgh->sig_cnt);

        det_ctx->uris++;

        if (det_ctx->sgh->mpm_uricontent_maxlen == 1) det_ctx->pkts_uri_scanned1++;
        else if (det_ctx->sgh->mpm_uricontent_maxlen == 2) det_ctx->pkts_uri_scanned2++;
        else if (det_ctx->sgh->mpm_uricontent_maxlen == 3) det_ctx->pkts_uri_scanned3++;
        else if (det_ctx->sgh->mpm_uricontent_maxlen == 4) det_ctx->pkts_uri_scanned4++;
        else det_ctx->pkts_uri_scanned++;

        ret += UriPatternScan(tv, det_ctx, content, content_len);

        SCLogDebug("post scan: cnt %" PRIu32 ", searchable %" PRIu32 "",
                    ret, det_ctx->pmq.searchable);
        if (det_ctx->pmq.searchable > 0) {
            if (det_ctx->sgh->mpm_uricontent_maxlen == 1) det_ctx->pkts_uri_searched1++;
            else if (det_ctx->sgh->mpm_uricontent_maxlen == 2) det_ctx->pkts_uri_searched2++;
            else if (det_ctx->sgh->mpm_uricontent_maxlen == 3) det_ctx->pkts_uri_searched3++;
            else if (det_ctx->sgh->mpm_uricontent_maxlen == 4) det_ctx->pkts_uri_searched4++;
            else det_ctx->pkts_uri_searched++;

            ret += UriPatternMatch(tv, det_ctx, content, content_len);

        }
        det_ctx->pmq.searchable = 0;
    }
    return ret;
}

/**
 * \brief   Checks if the received http request has a uricontent, which matches
 *          with the defined signature
 *
 * \param t         Pointer to the tv for this detection module instance
 * \param det_ctx   Pointer to the detection engine thread context
 * \param f         pointer to the current flow
 * \param flags     flags to indicate the direction of the received packet
 * \param state     pointer the app layer state, which will cast into HtpState
 * \param s         pointer to the current signature
 * \param m         pointer to the sigmatch that we will cast into
 *                  DetectUricontentData
 *
 * \retval 1 if the contents matches; 0 no match
 */
int DetectAppLayerUricontentMatch (ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   Signature *s, SigMatch *sm)
{
    SCEnter();
    int ret = 0;
    int res = 0;
    /* if we don't have a uri, don't bother scanning */
    if (det_ctx->de_have_httpuri == FALSE) {
        SCLogDebug("We don't have uri");
        SCReturnInt(res);
    }

    /* Check if we have scanned the URI already or not */
    if (det_ctx->de_scanned_uri == FALSE) {
        SCMutexLock(&f->m);
        TcpSession *ssn = (TcpSession *) f->protoctx;
        if (ssn == NULL) {
            SCLogDebug("no Tcp Session");
            det_ctx->de_have_httpuri = FALSE;
            goto unlock;
        }

        HtpState *htp_state = ssn->aldata[AlpGetStateIdx(ALPROTO_HTTP)];
        if (htp_state == NULL) {
            SCLogDebug("no HTTP state");
            det_ctx->de_have_httpuri = FALSE;
            goto unlock;
        }

        htp_tx_t *tx = NULL;
        list_iterator_reset(htp_state->recent_in_tx);

        while ((tx = list_iterator_next(htp_state->recent_in_tx)) != NULL) {
            if (tx->request_uri_normalized == NULL)
                continue;

            ret = DoDetectAppLayerUricontentMatch(tv, det_ctx, (uint8_t *)
                    bstr_ptr(tx->request_uri_normalized),
                    bstr_len(tx->request_uri_normalized));
        }
unlock:
        SCMutexUnlock(&f->m);
        det_ctx->de_scanned_uri = TRUE;
        SCReturnInt(ret);
    }

    DetectUricontentData *co = (DetectUricontentData *)sm->ctx;
    if (det_ctx->mtcu.match[co->id].len > 0) {
        SCLogDebug("Match has been found in the received request and "
                        "signature s->id %"PRIu32"", s->id);
        res = 1;
    } else {
        SCLogDebug("We don't have app layer URI match");
        res = 0;
    }

    SCReturnInt(res);
}

/*
 * UNITTTESTS
 */

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/** \test Test case where path traversal has been sent as a path string in the
 *        HTTP URL and normalized path string is checked */
static int HTTPUriTest01(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "GET /../../images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);
    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    if (htp_state->connp == NULL || tx->request_method_number != M_GET ||
            tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->hostname == NULL) ||
            (bstr_cmpc(tx->parsed_uri->hostname, "www.example.com") != 0))
    {
        printf("expected www.example.com as hostname, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->hostname));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmpc(tx->parsed_uri->path, "/images.gif") != 0))
    {
        printf("expected /images.gif as path, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->path));
        result = 0;
        goto end;
    }


end:
    return result;
}

/** \test Test case where path traversal has been sent in special characters in
 *        HEX encoding in the HTTP URL and normalized path string is checked */
static int HTTPUriTest02(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "GET /%2e%2e/images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    if (htp_state->connp == NULL || tx->request_method_number != M_GET ||
            tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->hostname == NULL) ||
            (bstr_cmpc(tx->parsed_uri->hostname, "www.example.com") != 0))
    {
        printf("expected www.example.com as hostname, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->hostname));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmpc(tx->parsed_uri->path, "/images.gif") != 0))
    {
        printf("expected /images.gif as path, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->path));
        result = 0;
        goto end;
    }


end:
    return result;
}

/** \test Test case where NULL character has been sent in HEX encoding in the
 *        HTTP URL and normalized path string is checked */
static int HTTPUriTest03(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "GET%00 /images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    if (htp_state->connp == NULL || tx->request_method_number != M_UNKNOWN ||
            tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

   if ((tx->parsed_uri->hostname == NULL) ||
            (bstr_cmpc(tx->parsed_uri->hostname, "www.example.com") != 0))
    {
        printf("expected www.example.com as hostname, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->hostname));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
            (bstr_cmpc(tx->parsed_uri->path, "/images.gif") != 0))
    {
        printf("expected /images.gif as path, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->path));
        result = 0;
        goto end;
    }

end:
    return result;
}


/** \test Test case where self referencing directories request has been sent
 *        in the HTTP URL and normalized path string is checked */
static int HTTPUriTest04(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "GET /./././images.gif HTTP/1.1\r\nHost: www.ExA"
                         "mPlE.cOM\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    if (htp_state->connp == NULL || tx->request_method_number != M_GET ||
            tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->hostname == NULL) ||
            (bstr_cmpc(tx->parsed_uri->hostname, "www.example.com") != 0))
    {
        printf("expected www.example.com as hostname, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->hostname));
        result = 0;
        goto end;
    }

    if ((tx->parsed_uri->path == NULL) ||
           (bstr_cmpc(tx->parsed_uri->path, "/images.gif") != 0))
    {
        printf("expected /images.gif as path, but got: %s \n",
                bstr_tocstr(tx->parsed_uri->path));
        result = 0;
        goto end;
    }


end:
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
    DetectEngineThreadCtx *det_ctx;
    Signature *s = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\" Test uricontent\"; "
                                  "uricontent:\"me\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    sm = de_ctx->sig_list->match;
    if (sm->type == DETECT_URICONTENT) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check the signature working to alert when http_cookie is matched . */
static int DetectUriSigTest02(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST /one HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
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
    p.payload = httpbuf1;
    p.payload_len = httplen1;
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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if ((PacketAlertCheck(&p, 1))) {
        printf("sig: 1 alerted, but it should not\n");
        goto end;
    } else if (!PacketAlertCheck(&p, 2)) {
        printf("sig: 2 did not alerted, but it should\n");
        goto end;
    }  else if ((PacketAlertCheck(&p, 3))) {
        printf("sig: 3 alerted, but it should not\n");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Check the working of scan/search once per packet only in applayer
 *        match */
static int DetectUriSigTest03(void) {
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST /one HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "POST /oneself HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatch\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
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
    p.payload = httpbuf1;
    p.payload_len = httplen1;
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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

   /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
   if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if ((PacketAlertCheck(&p, 1))) {
        printf("sig: 1 alerted, but it should not\n");
        goto end;
    } else if (! PacketAlertCheck(&p, 2)) {
        printf("sig: 2 did not alerted, but it should\n");
        goto end;
    } else if (! (PacketAlertCheck(&p, 3))) {
        printf("sig: 3 did not alerted, but it should\n");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    return result;
}

#endif /* UNITTESTS */

void HttpUriRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HTTPUriTest01", HTTPUriTest01, 1);
    UtRegisterTest("HTTPUriTest02", HTTPUriTest02, 1);
    UtRegisterTest("HTTPUriTest03", HTTPUriTest03, 1);
    UtRegisterTest("HTTPUriTest04", HTTPUriTest04, 1);
    UtRegisterTest("DetectUriSigTest01", DetectUriSigTest01, 1);
    UtRegisterTest("DetectUriSigTest02", DetectUriSigTest02, 1);
    UtRegisterTest("DetectUriSigTest03", DetectUriSigTest03, 1);
#endif /* UNITTESTS */
}
