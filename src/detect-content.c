/* Simple content match part of the detection engine.
 *
 * Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

/* This is a very important part of the detection engine, and certainly one
 * of the most complex parts. String searching is complex and expensive,
 * and thus worth optimizing. The way that is done here is by only running
 * the pattern matcher once for every packet. In this search, all search words,
 * the 'content' matches, are looked for. All results, of all the search words
 * are stored in a array of lists. The array is an array of MpmMatchBucket's,
 * that can be entered through the DetectContentData id field. There, it finds
 * the bucket containing a list of 0, 1, or more matches of that content match.
 * The list contains MpmMatch items, that contain an offset field. This field
 * is the possition of the last character in the match.
 *
 * 03/22/2008 -- VJ:
 * Recursive capture runs do something special to the depth and offset: the
 * settings are only considered for the initial match. For the next matches,
 * they are not. The reason is that this way we can still anchor the first
 * match to a specific part of the payload, while the rest can be handled
 * by content and pcre matches.
 *
 * 06/11/2009 -- PR:
 * Now Patterns that exceed the max_pattern_length allowed by the current mpm
 * are split into multiple chunk. The modifiers must be set in the first
 * chunk of a group of chunks, and after a modifier is set, the modifiers of the
 * next chunks must be recalculated (propagated). This way, each DETECT_CONTENT
 * installed should be completely independent, as if it were loaded in another
 * content option of the signature.
 *
 * TODO: add a 'recursive depth' to limit the depth to do the recursion on...
 *
 * XXX more later....
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "util-mpm.h"
#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"
#include "threads.h"

int DetectContentMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectContentSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectContentRegisterTests(void);

void DetectContentRegister (void) {
    sigmatch_table[DETECT_CONTENT].name = "content";
    sigmatch_table[DETECT_CONTENT].Match = DetectContentMatch;
    sigmatch_table[DETECT_CONTENT].Setup = DetectContentSetup;
    sigmatch_table[DETECT_CONTENT].Free  = DetectContentFree;
    sigmatch_table[DETECT_CONTENT].RegisterTests = DetectContentRegisterTests;

    sigmatch_table[DETECT_CONTENT].flags |= SIGMATCH_PAYLOAD;
}

/* pass on the content_max_id */
uint32_t DetectContentMaxId(DetectEngineCtx *de_ctx) {
    //SCLogDebug("DetectContentMaxId: %" PRIu32 "", de_ctx->content_max_id);
    return de_ctx->content_max_id;
}

#ifdef DEBUG
static void DetectContentDebugPrint(DetectContentData *co) {
    char buf[2048] = "";
    char tmp[4] = "";
    uint16_t u = 0;

    for (u = 0; u < co->content_len; u++) {
        if (isprint((char)co->content[u])) {
            snprintf(tmp,sizeof(tmp),"%c", (char)co->content[u]);
        } else {
            snprintf(tmp,sizeof(tmp),"\\%02x", co->content[u]);
        }
        strncat(buf,tmp,sizeof(buf));
    }

    SCLogDebug("content \"%s\"",buf);
}

static void DetectContentPrintMatches(DetectEngineThreadCtx *det_ctx, DetectContentData *co) {
    DetectContentDebugPrint(co);
    if (det_ctx->mtc.match[co->id].len == 0)
        SCLogDebug("pattern did not match");
    else
        SCLogDebug("matched %" PRIu32 " time(s) at offsets: ", det_ctx->mtc.match[co->id].len);

    MpmMatch *tmpm = NULL;
    for (tmpm = det_ctx->mtc.match[co->id].top; tmpm != NULL; tmpm = tmpm->next) {
        SCLogDebug("pattern matched at offset %" PRIu32 " ", tmpm->offset);
    }
}
#endif

static inline int
TestOffsetDepth(MpmMatch *m, DetectContentData *co, uint16_t pktoff) {
    SCEnter();

    if (m->offset >= pktoff) {
        if (co->offset == 0 || (m->offset >= co->offset)) {
            if (co->depth == 0 || ((m->offset + co->content_len) <= co->depth)) {
                SCLogDebug("depth %" PRIu32 ", offset %" PRIu32 ", m->offset "
                           "%" PRIu32 ", return 1", co->depth, co->offset,
                           m->offset);

                /* If we reach this point, it means we have obtained a depth and
                 * offset match, which indicates that we have a FAILURE if the
                 * content is negated, and SUCCESS if the content is not negated */
                if (co->negated == 1)
                    SCReturnInt(0);
                else
                    SCReturnInt(1);
            } else {
                /* We have success so far with offset, but a failure with
                 * depth.  We can return a match at the bottom of this function
                 * for negated_content, provided offset is 0.  If offset
                 * isn't 0 for negated_content, we have a failure and we return
                 * a no match here.  If the content is not negated, we have a no
                 * match, which we return at the end of this function. */
                if (co->offset && co->negated == 1)
                    SCReturnInt(0);
            }
        } else {
            /* If offset fails, and if the content is negated, we check if depth
             * succeeds.  If it succeeds, we have a no match for negated content.
             * Else we have a success for negated content.  If the content is
             * not negated, we go down till the end and return a no match. */
            if (co->negated == 1) {
                if (co->offset != 0) {
                    SCReturnInt(1);
                } else if (co->depth && (m->offset+co->content_len) <= co->depth) {
                    SCLogDebug("depth %" PRIu32 ", offset %" PRIu32 ", m->offset %" PRIu32 ", "
                            "return 0", co->depth, co->offset, m->offset);
                    SCReturnInt(0);
                }
            }
        }
    }
    SCLogDebug("depth %" PRIu32 ", offset %" PRIu32 ", m->offset %" PRIu32 ", "
               "return 0 (or 1 if negated)", co->depth, co->offset, m->offset);

    /* If we reach this point, we have a match for negated content and no match
     * otherwise */
    if (co->negated == 1)
        SCReturnInt(1);
    else
        SCReturnInt(0);
}

/**
 * \brief test the within, distance, offset and depth of a match
 *
 *         This function is called recursively (if nescessary) to be able
 *         to determine whether or not a chain of content matches connected
 *         with 'within' and 'distance' options fully matches. The reason it
 *         was done like this is to make sure we can handle partial matches
 *         that turn out to fail being followed by full matches later in the
 *         packet. This adds some runtime complexity however.
 *
 *         WITHIN
 *         The within check, if enabled, works as follows. The check is done
 *         against the current match "m". This is the pattern that we check
 *         the next against. So we will figure out if the next pattern exists
 *         within X bytes of "m".
 *
 *         To do this, we take the next pattern (nsm) and loop through all
 *         matches of it. We then for each of the matches "nm" below, see if
 *         it is in the within limit.
 *
 *         The within limit is checked as follows. It's checked against the
 *         current match "m". "m->offset" indicates the start of that match.
 *         So we need to consider m->offset + co->content_len. This will give
 *         us the end of the match "m". The next match then needs to occur
 *         before that point + the lenght of the pattern we're checking,
 *         nco->content_len.
 *
 * \param t       thread vars
 * \param det_ctx thread local data of the detection engine ctx
 * \param m       match we are inspecting
 * \param nm      current sigmatch to work with
 * \param nsm     next sigmatch to work with
 * \param pktoff  packet offset
 *
 * \retval  1 On success.
 * \retval  0 On failure because of non-negated content.
 * \retval -1 On failure because of negated content.
 */
int TestWithinDistanceOffsetDepth(ThreadVars *t,
                                  DetectEngineThreadCtx *det_ctx,
                                  MpmMatch *m, SigMatch *sm,
                                  SigMatch *nsm, uint16_t pktoff)
{
    int neg_success_flag = 0;

    if (nsm == NULL) {
        SCLogDebug("No next sigmatch, all sigmatches matched.");
        return 1;
    }

    /** content match of current pattern */
    DetectContentData *co = (DetectContentData *)sm->ctx;

    if (!(co->flags & DETECT_CONTENT_DISTANCE_NEXT) && !(co->flags & DETECT_CONTENT_WITHIN_NEXT)) {
        SCLogDebug("Next content does not need distance/within checking.");
        return 1;
    }

    /** content match of next pattern */
    DetectContentData *nco = (DetectContentData *)nsm->ctx;
#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        SCLogDebug("printing matches");
        DetectContentPrintMatches(det_ctx, nco);
    }
#endif
    /** list of matches of the next pattern */
    MpmMatch *nm = det_ctx->mtc.match[nco->id].top;

    /* if we have no matches and the content is negated, we can return a success */
    if (nm == NULL) {
        SCLogDebug("no nm to inspect");

        if (nco->negated == 1)
            return 1;
        else
            return 0;
    }

    /* recursively check if we have a next pattern that matches */
    for ( ; nm != NULL; nm = nm->next) {
        SCLogDebug("nm->offset %" PRIu32 ", m->offset %" PRIu32 ", pktoff "
                   "%" PRIu32 "", nm->offset, m->offset, pktoff);
        SCLogDebug("nm->offset + nco->content_len = %"PRIu32" + %"PRIu32" = "
                   "%"PRIu32"", nm->offset, nco->content_len,
                   nm->offset + nco->content_len);
        SCLogDebug("within (0 if disabled) = %"PRIu32" (nco->within "
                   "%"PRIu32" + co->content_len %"PRIu32")",
                   (nco->flags & DETECT_CONTENT_WITHIN) ?
                   (nco->within + co->content_len) : 0, nco->within,
                   co->content_len);

        if (nm->offset >= pktoff) {
            if ((!(nco->flags & DETECT_CONTENT_WITHIN) ||
                (nco->within > 0 && (nm->offset > m->offset) &&
                (((nm->offset + nco->content_len) - m->offset) <= (nco->within + co->content_len)))))  {
                SCLogDebug("MATCH: %" PRIu32 " <= WITHIN(%" PRIu32 ")",
                           (nm->offset + nco->content_len) - m->offset,
                           nco->within + co->content_len);

                if (!(nco->flags & DETECT_CONTENT_DISTANCE) ||
                    ((nm->offset >= (m->offset + co->content_len)) &&
                    ((nm->offset - (m->offset + co->content_len)) >= nco->distance))) {
                    SCLogDebug("MATCH: %" PRIu32 " >= DISTANCE(%" PRIu32 ")",
                        nm->offset - (m->offset + co->content_len), nco->distance);

                    if (TestOffsetDepth(nm, nco, pktoff) == 0) {
                        /* if the content is not negated, we have to return a 0
                         * under all circumstances, because we can't afford for
                         * the offset and depth match to fail.  If the content
                         * is negated, we have 2 cases.  First case is when we
                         * have a distance or within and TestOffsetDepth() fails.
                         * In this case we have to return a 0, irrespective of
                         * whether we have a depth or offset, because we seem to
                         * be having a match for within or distance.  If we don't
                         * have distance and within, and if the depth/offset
                         * check failed, then we still have a failure because of
                         * the obvious reason that in the absence of within and
                         * distance, offset/depth check has to succeed. */
                        if (nco->negated == 1)
                            return -1;
                        else
                            return 0;
                    } else {
                        /* if the content is negated and we had a within or a
                         * distance, it indicates that we passed through the
                         * within/distance, which is a failure */
                        if (nco->negated == 1 &&
                            ((nco->flags & DETECT_CONTENT_WITHIN) ||
                             (nco->flags & DETECT_CONTENT_DISTANCE))) {
                            return -1;
                        } else {
                            return TestWithinDistanceOffsetDepth(t, det_ctx, nm,
                                    nsm, DetectContentFindNextApplicableSM(nsm->next),
                                    pktoff);
                        }
                    }
                } else {
                    SCLogDebug("NO MATCH: %" PRIu32 " < DISTANCE(%" PRIu32 ")",
                               nm->offset - (m->offset + co->content_len),
                               nco->distance);
                    /* looks like we got through within, but failed at distance.
                     * An obvious failure in case of non-negated content, in which
                     * case we move on to the next match.
                     * In case of negated content, if there was a within
                     * previously, it indicates that we got through the within
                     * and we have a nomatch now with distance.  If we didn't
                     * have within, we made it through, but we check for depth
                     * and offset now.  If depth/offset check succeeds we have a
                     * temporary success and we move on to the next match.  If
                     * it fails, we check if it failed because we didn't have
                     * offset and depth, in which case, it is not a failure and
                     * we on to the nextmatch.  Otherwise it is a failure */
                    if (nco->negated == 1 && (nm->offset >= (m->offset + co->content_len))) {
                        if (nco->flags & DETECT_CONTENT_WITHIN)
                            return -1;

                        if (TestOffsetDepth(nm, nco, pktoff) == 1) {
                            neg_success_flag = 1;
                        } else {
                            if (nco->offset == 0 && nco->depth == 0)
                                neg_success_flag = 1;
                            else
                                return -1;
                        }
                    }
                }
            } else {
                /* We have failed at within.  If the content is not negated we
                 * have an obvious failure and we move on to the next match.  If
                 * the content is negated, we check if distance exists.  If it
                 * does, and if the distance check succeeds, we have a failure
                 * for negated content.  If we don't have a failure or if distance
                 * doesn't exist, we move on to test offset/depth check.  The
                 * offset/depth test is the same as in the previous else. */
                if (nco->negated == 1 && nm->offset > m->offset) {
                    if ((nco->flags & DETECT_CONTENT_DISTANCE) &&
                        ((nm->offset - (m->offset + co->content_len)) >= nco->distance)) {
                            return -1;
                        /* distance check meets non-negated requirements.  Let
                         * us move on and check depth/offset */
                    }

                    if (TestOffsetDepth(nm, nco, pktoff) == 1) {
                        /* offset, depth success for negated content.  A temp
                         * success for us.  Let us set the flag indicating
                         * this and move on to the next match. */
                        neg_success_flag = 1;
                    } else {
                        /* looks like offset/depth failed.  If it failed because
                         * both offset and depth weren't present, then it is not
                         * precisely a failure, because the existance of negated
                         * content is governed by the presence of within/distance.
                         * So we set the flag and move on to the next content.
                         * But if offset and depth do exist, then it indicates
                         * that the negated content doesn't meet the requirements
                         * of offset/depth and we have a failure. */
                        if (nco->offset == 0 && nco->depth == 0)
                            neg_success_flag = 1;
                        else
                            return -1;
                    }
                }
            }
        } else {
            SCLogDebug("pktoff %"PRIu16" > nm->offset %"PRIu32"", pktoff, nm->offset);
        }
    }

    if (neg_success_flag == 1) {
        return 1;
    }

    SCLogDebug("no match found, returning 0");
    return 0;
}

int
DoDetectContent(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *sm, DetectContentData *co)
{
    int ret = 0;
    char match = 0;
    uint16_t pkt_off = det_ctx->pkt_off;
    MpmMatch *temp_m = NULL;

    /* Get the top match, we already know we have one. */
    MpmMatch *m = det_ctx->mtc.match[co->id].top;

    SCLogDebug("det_ctx->mtc.match[co->id].len %"PRIu32"", det_ctx->mtc.match[co->id].len);

    /* reset de_checking_distancewithin */
    if (!(co->flags & DETECT_CONTENT_WITHIN) &&
        !(co->flags & DETECT_CONTENT_DISTANCE))
    {
        det_ctx->de_checking_distancewithin = 0;

        /* only use pkt offset of previous matches
         * on relative matches. */
        pkt_off = 0;
    }

    SCLogDebug("using pkt_off %"PRIu16"", pkt_off);

    /*  if we have within or distance coming up next, check this match
     *  for distance and/or within and check the rest of this match
     *  chain as well. */
    if ((co->flags & DETECT_CONTENT_WITHIN_NEXT ||
         co->flags & DETECT_CONTENT_DISTANCE_NEXT) &&
         det_ctx->de_checking_distancewithin == 0)
    {
        SCLogDebug("DETECT_CONTENT_WITHIN_NEXT is %s",
            co->flags & DETECT_CONTENT_WITHIN_NEXT ? "true":"false");
        SCLogDebug("DETECT_CONTENT_DISTANCE_NEXT is %s",
            co->flags & DETECT_CONTENT_DISTANCE_NEXT ? "true":"false");

        /* indicate to the detection engine the next sigmatch(es)
         * are part of this match chain */
        det_ctx->de_checking_distancewithin = 1;

        for (; m != NULL; m = m->next) {
            /* first check our match for offset and depth */
            if (TestOffsetDepth(m, co, pkt_off) == 1) {
                SCLogDebug("TestOffsetDepth returned 1, for co->id %"PRIu32"", co->id);

                SigMatch *real_sm_next = DetectContentFindNextApplicableSM(sm->next);
                ret = TestWithinDistanceOffsetDepth(t, det_ctx, m, sm, real_sm_next, pkt_off);

                if (ret == 1) {
                    SCLogDebug("TestWithinDistanceOffsetDepth returned 1");
                    det_ctx->pkt_ptr = p->payload + m->offset;
                    /* update both the local and ctx pkt_off */
                    pkt_off = det_ctx->pkt_off = m->offset;
                    match = 1;
                    break;
                } else if (ret == -1) {
                    SCLogDebug("TestWithinDistanceOffsetDepth returned -1");
                    break;
                }
            } else {
                SCLogDebug("TestOffsetDepth returned 0, for co->id %"PRIu32"", co->id);
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
    } else if (co->flags & DETECT_CONTENT_WITHIN ||
               co->flags & DETECT_CONTENT_DISTANCE)
    {
        SCLogDebug("distance/within checking already done, returning 1");

        det_ctx->de_checking_distancewithin = 0;
        match = 1;

    /* Getting here means we are not in checking an within/distance chain.
     * This means we can just inspect this content match on it's own. So
     * Let's see if at least one of the matches within the offset and depth
     * settings. If so, return a match.
     */
    } else {
        SCLogDebug("no distance/within checking");

        /* if we have no matches, we return MATCH if the content is negated, or
         * NOMATCH if the content is not negated */
        if (m == NULL) {
            if (co->negated == 1)
                match = 1;
            else
                match = 0;

            SCLogDebug("returning %d", match);
            return match;
        }

        /* when in recursive capture mode don't check depth and offset
         * after the first match */
        if (s->flags & SIG_FLAG_RECURSIVE && det_ctx->pkt_cnt) {
            for (; m != NULL; m = m->next) {
                if (m->offset >= det_ctx->pkt_off) {
                    /* update pkt ptrs, content doesn't use this,
                     * but pcre does */
                    det_ctx->pkt_ptr = p->payload + m->offset;
                    det_ctx->pkt_off = m->offset;
                    match = 1;
                    break;
                }
            }
        } else {
            temp_m = m;
            for (; m != NULL; m = m->next) {
                /* no offset as we inspect each match on it's own */
                ret = TestOffsetDepth(m, co, 0);

                /* If ret is 0 and content is negated, we have a failure and we
                 * break.  If ret is 0 and content is not negated, we have a
                 * failure for this match, so we will continue in this loop
                 * testing other matches.  If ret is 1, and the content is
                 * negated we have a success and we will continue along the loop
                 * to check that other matches also return 1 for TestOffsetDepth()
                 * with the negated content.  But if ret is 1, and the content
                 * is not negated, we have a match, which is sufficient for us to
                 * return with a break, with match = 1. */
                if (ret == 0) {
                    if (co->negated == 1) {
                        match = 0;
                        break;
                    }
                } else {
                    if (co->negated == 0) {
                        /* update pkt ptrs, this content run doesn't
                         * use this, but pcre does */
                        det_ctx->pkt_ptr = p->payload + m->offset;
                        det_ctx->pkt_off = m->offset;
                        match = 1;
                        break;
                    }
                }
            }
            /* If there were matches, with the content being negated, and all of
             * them passed TestOffsetDepth(), we have a match.  This is the
             * reason why we continue in the else part if ret == 1, if the
             * content is negated */
            if (temp_m != NULL && ret == 1 && co->negated == 1) {
                SCLogDebug("setting match to true");
                match = 1;
            }
        }
    }

    /* If it has matched, check if it's set a "isdataat" option and process it */
    /* If it has matched, check if it's set a "isdataat" option and process it */
    if (match == 1 && (co->flags & DETECT_CONTENT_ISDATAAT_RELATIVE) &&
        co->negated == 0) {
        /* if the rest of the payload (from the last match) is less than
          the "isdataat" there is no data where the rule expected
          so match=0
        */

        SCLogDebug("isdataat: payload_len: %u, used %u, rest %u, isdataat? %u", p->payload_len, (m->offset + co->content_len),p->payload_len - (m->offset + co->content_len), co->isdataat);

        if ( ((p->payload_len - (m->offset + co->content_len)) < co->isdataat) )
            match = 0;

        if (match) {
            SCLogDebug("still matching after isdataat check");
        }
    }

    SCLogDebug("returning %d", match);
    return match;
}


/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectContentMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    if (p->payload_len == 0)
        return 0;

    DetectContentData *co = (DetectContentData *)m->ctx;

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        SCLogDebug("printing matches");
        DetectContentPrintMatches(det_ctx, co);
    }
#endif

    return DoDetectContent(t, det_ctx, p, s, m, co);
}

DetectContentData *DetectContentParse (char *contentstr)
{
    DetectContentData *cd = NULL;
    char *str = NULL;
    char *temp = NULL;
    uint16_t len;
    uint16_t pos = 0;
    uint16_t slen = 0;

    if ((temp = strdup(contentstr)) == NULL)
        goto error;

    if (strlen(temp) == 0) {
        if (temp) free(temp);
        return NULL;
    }

    cd = malloc(sizeof(DetectContentData));
    if (cd == NULL) {
        printf("DetectContentParse malloc failed\n");
        goto error;
    }
    memset(cd, 0, sizeof(DetectContentData));

    /* skip the first spaces */
    slen = strlen(temp);
    while (pos < slen && isspace(temp[pos])) {
        pos++;
    };

    if (temp[pos] == '!') {
        free(temp);
        if ((temp = strdup(contentstr + pos + 1)) == NULL)
            goto error;
        cd->negated = 1;
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

    if (str[0] == '!') {
        if (cd->negated == 1) {
            SCLogDebug("Invalid negated content. \"!\" located twice at the "
                       "start of the contet string: %s", contentstr);
            goto error;
        } else {
            temp = str;
            if ( (str = strdup(temp + 1)) == NULL)
                goto error;
            cd->negated = 1;
            free(temp);
        }
    }

    len = strlen(str);
    if (len == 0)
        goto error;

    //SCLogDebug("DetectContentParse: \"%s\", len %" PRIu32 "", str, len);
    char converted = 0;

    {
        uint16_t i, x;
        uint8_t bin = 0;
        uint8_t escape = 0;
        uint8_t binstr[3] = "";
        uint8_t binpos = 0;

        for (i = 0, x = 0; i < len; i++) {
            // SCLogDebug("str[%02u]: %c", i, str[i]);
            if (str[i] == '|') {
                if (bin) {
                    bin = 0;
                } else {
                    bin = 1;
                }
            } else if(!escape && str[i] == '\\') {
                escape = 1;
            } else {
                if (bin) {
                    if (isdigit(str[i]) ||
                            str[i] == 'A' || str[i] == 'a' ||
                            str[i] == 'B' || str[i] == 'b' ||
                            str[i] == 'C' || str[i] == 'c' ||
                            str[i] == 'D' || str[i] == 'd' ||
                            str[i] == 'E' || str[i] == 'e' ||
                            str[i] == 'F' || str[i] == 'f')
                    {
                        // SCLogDebug("part of binary: %c", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            uint8_t c = strtol((char *)binstr, (char **) NULL, 16) & 0xFF;
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        // SCLogDebug("space as part of binary string");
                    }
                } else if (escape) {
                    if (str[i] == ':' ||
                        str[i] == ';' ||
                        str[i] == '\\' ||
                        str[i] == '\"')
                    {
                        str[x] = str[i];
                        x++;
                    } else {
                        //SCLogDebug("Can't escape %c", str[i]);
                        goto error;
                    }
                    escape = 0;
                    converted = 1;
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }
#if 0//def DEBUG
        if (SCLogDebugEnabled()) {
            for (i = 0; i < x; i++) {
                if (isprint(str[i])) SCLogDebug("%c", str[i]);
                else                 SCLogDebug("\\x%02u", str[i]);
            }
            SCLogDebug("");
        }
#endif

        if (converted) {
            len = x;
        }
    }

    cd->content = malloc(len);
    if (cd->content == NULL)
        goto error;

    memcpy(cd->content, str, len);
    cd->content_len = len;
    cd->depth = 0;
    cd->offset = 0;
    cd->within = 0;
    cd->distance = 0;
    cd->flags = 0;

    free(str);
    return cd;

error:
    free(str);
    if (cd != NULL) {
        if (cd->content != NULL)
            free(cd->content);
        free(cd);
    }
    return NULL;
}

/**
 * \brief Helper function to print a DetectContentData
 */
void DetectContentPrint(DetectContentData *cd)
{
    int i = 0;
    if (cd == NULL) {
        SCLogDebug("DetectContentData \"cd\" is NULL");
        return;
    }
    char *tmpstr=malloc(sizeof(char) * cd->content_len + 1);

    if (tmpstr != NULL) {
        for (i = 0; i < cd->content_len; i++) {
            if (isprint(cd->content[i]))
                tmpstr[i] = cd->content[i];
            else
                tmpstr[i] = '.';
        }
        tmpstr[i] = '\0';
        SCLogDebug("Content: \"%s\"", tmpstr);
        free(tmpstr);
    } else {
        SCLogDebug("Content: ");
        for (i = 0; i < cd->content_len; i++)
            SCLogDebug("%c", cd->content[i]);
    }

    SCLogDebug("Content_id: %u ", cd->id);
    SCLogDebug("Content_len: %u ", cd->content_len);
    SCLogDebug("Depth: %u ", cd->depth);
    SCLogDebug("Offset: %u ", cd->offset);
    SCLogDebug("Within: %u ", cd->within);
    SCLogDebug("Distance: %u ", cd->distance);
    SCLogDebug("Isdataat: %u ", cd->isdataat);
    SCLogDebug("flags: %u ", cd->flags);
    SCLogDebug("negated %u ", cd->negated);

    /** If it's a chunk, print the data related */
    if (cd->flags & DETECT_CONTENT_IS_CHUNK) {
        SCLogDebug("* Is_Chunk: is set");
        SCLogDebug("chunk_group_id: %u ", cd->chunk_group_id);
        SCLogDebug("chunk_id: %u ", cd->chunk_id);
    } else {
        SCLogDebug("Is_Chunk: is not set");
    }
    SCLogDebug("-----------");
}

/**
 * \brief Function that return chunks of a original DetectContentData
 *        that need to be split
 * \param origcd pointer to the real DetectContentData
 * \param remaining_content_length to the real DetectContentData
 *
 * \retval NULL if something goes wrong
 * \retval DetectContentData pointer to the new chunk
 */
DetectContentData *DetectContentSplitChunk(DetectContentData *origcd,
                                           uint8_t remaining_content_len,
                                           uint8_t index, int32_t mpl)
{
    DetectContentData *cd = malloc(sizeof(DetectContentData));
    if (cd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "DetectContentData malloc failed");
        goto error;
    }
    memset(cd,0,sizeof(DetectContentData));

    /* Get the length for this chunk */
    if (remaining_content_len < mpl)
        cd->content_len = remaining_content_len;
    else
        cd->content_len = mpl;

    if (cd->content_len <= 0)
        goto error;

    cd->content = (uint8_t*) malloc(sizeof(uint8_t) * cd->content_len);
    if (cd->content == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "string for content malloc failed");
        goto error;
    }

    memcpy(cd->content, origcd->content + index * sizeof(uint8_t), cd->content_len);

    return cd;

error:
    if (cd != NULL) {
        if (cd->content != NULL)
            free(cd->content);
        free(cd);
    }
    return NULL;
}

/**
 * \brief Search the next applicable DETECT_CONTENT SigMatch
          (includes the current sm)
 *
 * \param sm pointer to the current SigMatch of a parsing process
 *
 * \retval null if no applicable DetectContent was found
 * \retval pointer to the SigMatch next DETECT_CONTENT SigMatch
 */
SigMatch *DetectContentFindNextApplicableSM(SigMatch *sm)
{
    if (sm == NULL)
        return NULL;
    while ( sm != NULL && sm->type != DETECT_CONTENT)
        sm = sm->next;

    return sm;
}

/**
 * \brief Helper function to determine if there are patterns before this one,
 *        this is used before installing a new within or distance modifier
 *        because if this return NULL, it will never match!
 *
 * \param sm pointer to the current SigMatch of a parsing process
 *
 * \retval null if no applicable SigMatch pattern was found
 * \retval pointer to the SigMatch that has the previous SigMatch
 *                 of type DetectContent, (and is the first chunk if
 *                 the pattern was splitted)
 *
 * \todo: should we add here DETECT_PCRE, DETECT_URI_CONTENT, etc?
 */
SigMatch *DetectContentHasPrevSMPattern(SigMatch *sm)
{
    if (sm == NULL)
        return NULL;

    /* the current SM doesn't apply */
    sm = sm->prev;
    while (sm != NULL && sm->type != DETECT_CONTENT)
        sm = sm->prev;
    return sm;
}

/**
 * \brief Search the first DETECT_CONTENT chunk of the last group in the
 *        previous SigMatches or the first DETECT_CONTENT not chunked
 * \retval pointer to the SigMatch holding the DetectContent
 * \param sm pointer to the current SigMatch of a parsing process
 * \retval null if no applicable DetectContent was found
 * \retval pointer to the SigMatch that has the previous SigMatch
 *                 of type DetectContent, (and is the first chunk if
 *                 the pattern was splitted)
 */
SigMatch *DetectContentFindPrevApplicableSM(SigMatch *sm)
{
    if (sm == NULL)
        return NULL;
    while (sm != NULL && sm->type != DETECT_CONTENT)
        sm = sm->prev;

    if (sm == NULL)
        return NULL;

    DetectContentData *cd = (DetectContentData*) sm->ctx;
    if (cd == NULL)
        return NULL;

    /** It's not a chunk, so its the only DetectContent for this pattern */
    if (!(cd->flags & DETECT_CONTENT_IS_CHUNK))
        return sm;

    /** Else search for the first chunk in this group of chunks */
    uint8_t chunk_group_id = cd->chunk_group_id;
    while (sm != NULL && sm->type == DETECT_CONTENT)
    {
        cd = (DetectContentData*) sm->ctx;
        if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK))
            return NULL;

        /** Weird case, this means that the chunk are not consecutive
         * or not likned correctly */
        if (cd->chunk_group_id != chunk_group_id)
            return NULL;

        /** If we get the first one, return the SimMatch */
        if (cd->chunk_id == 0)
            return sm;

        sm = sm->prev;
    }
    /* We should not be here */
    return NULL;
}

/**
 * \brief Count the number of chunks of a specified chunk group
 * \param sm pointer to a SigMatch that belong to this chunk group
 * \param chunk_group_id id of the group of chunks (to ensure)
 * \retval -1 if something fail
 * \retval count of the chunks of this group
 */
int DetectContentCountChunksInGroup(SigMatch *sm, uint8_t chunk_group_id)
{
    int count = 0;
    if (sm == NULL || sm->type != DETECT_CONTENT)
        return -1;

    DetectContentData *cd = NULL;
    SigMatch *first_sm = DetectContentFindPrevApplicableSM(sm);
    for (; first_sm != NULL &&
           first_sm->type == DETECT_CONTENT &&
           first_sm->ctx != NULL &&
           (cd = (DetectContentData*) first_sm->ctx) &&
           (cd->flags & DETECT_CONTENT_IS_CHUNK) &&
           cd->chunk_group_id == chunk_group_id
         ; first_sm = first_sm->next, count++);

    return count;
}

/**
 * \brief Get the remaining legth of a splitted pattern
 *        (current content not included!)
 * \param first_sm pointer to a SigMatch that belong to this chunk group
 * \retval pointer to the SigMatch holding the DetectContent
 * \retval -1 if fail
 * \retval length if every thing was ok
 */
int DetectContentChunksGetRemainingLength(SigMatch *first_sm)
{
    int length = 0;
    if (first_sm == NULL)
        return -1;

    if (first_sm->type != DETECT_CONTENT || first_sm->ctx == NULL)
        return -1;

    DetectContentData *cd = (DetectContentData*) first_sm->ctx;
    uint8_t chunk_group_id = cd->chunk_group_id;

    /** Skip the current content (not included) */
    first_sm = first_sm->next;

    /** sum the content_len's */
    for (; first_sm != NULL &&
           first_sm->type == DETECT_CONTENT &&
           first_sm->ctx != NULL &&
           (cd = (DetectContentData*) first_sm->ctx) &&
           (cd->flags & DETECT_CONTENT_IS_CHUNK) &&
           cd->chunk_group_id == chunk_group_id
         ; first_sm = first_sm->next, length += cd->content_len);

    return length;
}


/**
 * \brief Get the previous legth of a splitted pattern (current content not included!)
 * \param first_sm pointer to a SigMatch that belong to this chunk group
 * \retval pointer to the SigMatch holding the DetectContent
 * \retval length if every thing was ok
 * \retval -1 if fail
 */
int DetectContentChunksGetPreviousLength(SigMatch *sm)
{
    int length = 0;
    if (sm == NULL)
        return -1;

    if (sm->type != DETECT_CONTENT || sm->ctx == NULL)
        return -1;

    DetectContentData *cd = (DetectContentData*) sm->ctx;
    uint8_t chunk_group_id = cd->chunk_group_id;
    uint8_t chunk_id = cd->chunk_id;

    SigMatch *first_sm = DetectContentFindPrevApplicableSM(sm);

    for (; first_sm != NULL &&
           first_sm->type == DETECT_CONTENT &&
           first_sm->ctx != NULL &&
           (cd = (DetectContentData*) first_sm->ctx) &&
           (cd->flags & DETECT_CONTENT_IS_CHUNK) &&
           cd->chunk_group_id == chunk_group_id &&
           cd->chunk_id != chunk_id
         ; first_sm = first_sm->next, length += cd->content_len);

    if (cd != NULL && cd->chunk_id == chunk_id)
        return length;

    return 0;
}

/**
 * \brief Get the total legth of a splitted pattern
 * \param first_sm pointer to a SigMatch that belong to this chunk group
 * \retval pointer to the SigMatch holding the DetectContent
 * \retval length if every thing was ok
 * \retval -1 if fail
 */
int DetectContentChunksGetTotalLength(SigMatch *sm)
{
    int length = 0;
    if (sm == NULL)
        return -1;

    if (sm->type != DETECT_CONTENT || sm->ctx == NULL)
        return -1;

    DetectContentData *cd = (DetectContentData*) sm->ctx;
    uint8_t chunk_group_id = cd->chunk_group_id;

    /** Go to the first SigMatch of this Chunk group */
    SigMatch *first_sm = DetectContentFindPrevApplicableSM(sm);

    for (; first_sm != NULL &&
           first_sm->type == DETECT_CONTENT &&
           first_sm->ctx != NULL &&
           (cd = (DetectContentData*) first_sm->ctx) &&
           (cd->flags & DETECT_CONTENT_IS_CHUNK) &&
           cd->chunk_group_id == chunk_group_id
         ; first_sm = first_sm->next, length += cd->content_len);

    return length;
}

/**
 * \brief Print list of DETECT_CONTENT SigMatch's allocated in a
 * SigMatch list, from the current sm to the end
 * \param sm pointer to the current SigMatch to start printing from
 */
void DetectContentPrintAll(SigMatch *sm)
{
#ifdef DEBUG
    int i = 0;

    if (SCLogDebugEnabled()) {
        if (sm == NULL)
            return;

        /** Go to the first SigMatch of this Chunk group */
        SigMatch *first_sm = sm;

       /* Print all of them */
        for (; first_sm != NULL; first_sm = first_sm->next) {
            if (first_sm->type == DETECT_CONTENT) {
                SCLogDebug("Printing SigMatch DETECT_CONTENT %d", ++i);
                DetectContentPrint(first_sm->ctx);
            }
        }
    }
#endif /* DEBUG */
}

/**
 * \brief Function to update modifiers of a chunk group after setting depth
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateDepth(SigMatch *first_sm)
{
    int res = -1;
    DetectContentData *cd = first_sm->ctx;
    if (first_sm == NULL || first_sm->ctx == NULL)
        return -1;

    if (cd->chunk_flags & CHUNK_UPDATED_DEPTH)
    {
        SCLogDebug("Depth already set for this pattern!!");
        return res;
    }

    res = DetectContentPropagateModifiers(first_sm);
    if (res == 1) {
        cd->chunk_flags |= CHUNK_UPDATED_DEPTH;
    }
    return res;
}

/**
 * \brief Function to update modifiers of a chunk group after setting isdataat
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateIsdataat(SigMatch *first_sm)
{
    int res = -1;
    DetectContentData *cd = first_sm->ctx;

    if (first_sm == NULL || first_sm->ctx == NULL)
        return -1;

    if (cd->chunk_flags & CHUNK_UPDATED_ISDATAAT)
    {
        SCLogDebug("Depth already set for this pattern!!");
        return res;
    }

    res = DetectContentPropagateModifiers(first_sm);
    if (res == 1) {
        cd->chunk_flags |= CHUNK_UPDATED_ISDATAAT;
    }
    return res;
}

/**
 * \brief Function to update modifiers of a chunk group after setting within
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateWithin(SigMatch *first_sm)
{
    int res = -1;
    DetectContentData *cd = first_sm->ctx;
    if (first_sm == NULL || first_sm->ctx == NULL)
        return -1;

    if (cd->chunk_flags & CHUNK_UPDATED_WITHIN)
    {
        SCLogDebug("Depth already set for this pattern!!");
        return res;
    }

    res = DetectContentPropagateModifiers(first_sm);
    if (res == 1) {
        cd->chunk_flags |= CHUNK_UPDATED_WITHIN;
    }
    return res;
}

/**
 * \brief Function to update modifiers of a chunk group after setting distance
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateDistance(SigMatch *first_sm)
{
    int res = -1;
    DetectContentData *cd = first_sm->ctx;
    if (first_sm == NULL || first_sm->ctx == NULL)
        return -1;

    if (cd->chunk_flags & CHUNK_UPDATED_DISTANCE)
    {
        SCLogDebug("Depth already set for this pattern!!");
        return res;
    }

    res = DetectContentPropagateModifiers(first_sm);
    if (res == 1) {
        cd->chunk_flags |= CHUNK_UPDATED_DISTANCE;
    }
    return res;
}

/**
 * \brief Function to update modifiers of a chunk group after setting Offset
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateOffset(SigMatch *first_sm)
{
    int res = -1;
    DetectContentData *cd = first_sm->ctx;
    if (first_sm == NULL || first_sm->ctx == NULL)
        return -1;

    if (cd->chunk_flags & CHUNK_UPDATED_OFFSET)
    {
        SCLogDebug("Depth already set for this pattern!!");
        return res;
    }

    res = DetectContentPropagateModifiers(first_sm);
    if (res == 1) {
        cd->chunk_flags |= CHUNK_UPDATED_OFFSET;
    }
    return res;
}

/**
 * \brief Function to update modifiers of a chunk group after setting a modifier
 *   This function should not be called directly from outside detect-content.c !
 *
 * \param first_sm pointer to the head of this group of chunks to update
 * \retval -1 if error
 * \retval 1 if all was ok
 */
int DetectContentPropagateModifiers(SigMatch *first_sm)
{
    if (first_sm == NULL)
        return -1;

    /** Rewind the pointer to the start of the chunk if we have a chunk group */
    first_sm = DetectContentFindPrevApplicableSM(first_sm);

    if (first_sm->ctx == NULL)
        return -1;

    DetectContentData *first_chunk = (DetectContentData*)first_sm->ctx;
    if (first_chunk == NULL)
        return -1;

    if ( !(first_chunk->flags & DETECT_CONTENT_IS_CHUNK))
        /** No modifiers to update */
        return 1;

    uint8_t chunk_group_id = first_chunk->chunk_group_id;
    uint8_t num_chunks = DetectContentCountChunksInGroup(first_sm, chunk_group_id);
    int16_t total_len = DetectContentChunksGetTotalLength(first_sm);

    if (num_chunks < 1 || total_len < 1)
        return -1;

    DetectContentData *cur_chunk = NULL;
    DetectContentData *last_chunk = first_chunk;
    SigMatch *cur_sm = NULL;

    /** The first chunk has the real modifiers that we want to propagate */
    for (cur_sm = first_sm;
         cur_sm != NULL &&
         cur_sm->type == DETECT_CONTENT &&
         (cur_chunk = (DetectContentData*) cur_sm->ctx) != NULL &&
         cur_chunk->chunk_group_id == chunk_group_id ;
         cur_sm = cur_sm->next) {

        //SCLogDebug("Cur: %u %s Last: %u %s", cur_chunk->offset, cur_chunk->content, last_chunk->offset, last_chunk->content);

        int16_t remaining_len = DetectContentChunksGetRemainingLength(cur_sm);
        int16_t previous_len = DetectContentChunksGetRemainingLength(cur_sm);
        if (previous_len < 0 || remaining_len < 0)
            return -1;


        /** If we are in the first chunk */
        if (cur_chunk->chunk_id == 0) {
            /** Reset the first depth removing the length of the remaining chunks
            */
            SCLogDebug("CUR depth = %u remain_len %d ", cur_chunk->depth, remaining_len);

            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_DEPTH) && cur_chunk->depth > 0)
                cur_chunk->depth -= remaining_len;

            /** Reset the first within removing the length of the remaining chunks
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_WITHIN) && cur_chunk->within > 0)
                cur_chunk->within -= remaining_len;

            /** Reset the first isdataat adding the length of the remaining chunks
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_ISDATAAT) && cur_chunk->isdataat > 0)
                cur_chunk->isdataat += remaining_len;
            /**
            * The offseth for the first chunk is the real offset,
            * so no need to update it here
            * The same is applicable here to offset and distance
            */

        /** If it's not the first chunk we need to propagate the changes */
        } else {

            /** Propagate the flags */
            cur_chunk->flags = last_chunk->flags;

            /** Update the depth adding the content_len of the current chunk
            * to the previous chunk depth
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_DEPTH) && last_chunk->depth > 0)
                cur_chunk->depth = last_chunk->depth + cur_chunk->content_len;

            /** Update the offset adding the content_len of the last chunk
            * to the previous chunk offset
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_OFFSET) && last_chunk->offset > 0)
                cur_chunk->offset = last_chunk->offset + last_chunk->content_len;

            /** We are iterating in the chunks after the first one, so within is
            * relative to the previous chunks and should be exactly the size of
            * its content_len since they are consecutive
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_WITHIN)) {
                /** Even if they don't specify a within option,
                 * we set the flag, since they are relative to the chunks
                 * of the same pattern
                 */
                cur_chunk->flags |= DETECT_CONTENT_WITHIN;
                cur_chunk->within = cur_chunk->content_len;

                /* set the within next flag on the previous chunk */
                if (last_chunk != NULL)
                    last_chunk->flags |= DETECT_CONTENT_WITHIN_NEXT;
            }

            /** We are iterating in the chunks after the first one, so distance
            * must be 0 between the chunks, since they are consecutive
            * splitted chunks
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_DISTANCE)) {
                /** Even if they don't specify a within option,
                 * we set the flag, since they are relative to the chunks
                 * of the same pattern
                 */
                cur_chunk->flags |= DETECT_CONTENT_DISTANCE;
                cur_chunk->distance = 0;

                /* set the distance next flag on the previous chunk */
                if (last_chunk != NULL)
                    last_chunk->flags |= DETECT_CONTENT_DISTANCE_NEXT;
            }

            /** The isdataat (relative) is updated to the
            * last_chunk isdataat - the content_len  of the current
            * chunk content_len
            */
            if ( !(cur_chunk->chunk_flags & CHUNK_UPDATED_ISDATAAT) && last_chunk->isdataat > 0)
                cur_chunk->isdataat = last_chunk->isdataat - cur_chunk->content_len;
        }

        last_chunk = cur_chunk;
    }

    return 1;
}

/**
 * \brief Function to setup a content pattern. Patterns that doesn't fit the
 * current max_pattern_length, are splitted into multiple chunks in independent
 * DetectContentData structures with it's own modifiers. Each modifier must be
 * recalculated for each chunk from the modifiers of the head of the chunk
 * group, and will act as independent patterns
 *
 * \param de_ctx pointer to the current detection_engine
 * \param s pointer to the current Signature
 * \param m pointer to the last parsed SigMatch
 * \param contentstr pointer to the current keyword content string
 * \retval -1 if error
 * \retval 0 if all was ok
 */
int DetectContentSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *contentstr)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;
    /* max_pattern_length */
    int32_t mpltmp = -1;
    uint8_t mpl = 0;
    uint8_t index = 0;

    cd = DetectContentParse(contentstr);
    if (cd == NULL) goto error;

    mpltmp = MpmMatcherGetMaxPatternLength(de_ctx->mpm_matcher);
    if (mpltmp < 0)
    {
        SCLogDebug("Unknown Matcher type. Exiting...");
        exit(EXIT_FAILURE);
    }
    mpl = mpltmp;

    SCLogDebug("Matcher type: %"PRIu16" max_pattern_length: %"PRIu32"", de_ctx->mpm_matcher, mpl);

    /** We are going to assign a chunk group to all the DetectContents, even
      * if it's not splitted. This will give us the number of loaded patterns
      * in this signature */
    if (s != NULL) {
        s->nchunk_groups++;
    }

    /** Check if we need to split the content into chunks */
    if (mpl > 0 && cd->content_len > mpl) {
        DetectContentData *aux = NULL;
        SigMatch *first = NULL;
        uint8_t chunk_id = 0;


        /** Split it from DetectContentSplitChunk() */
        for (index = 0; index < cd->content_len; index += mpl)
        {
            aux = DetectContentSplitChunk(cd, (uint8_t)(cd->content_len - index), index, mpl);
            if ( aux == NULL) {
                SCLogDebug("Couldn't split pattern chunks. Exiting...");
                exit(EXIT_FAILURE);
            }

            aux->flags |= DETECT_CONTENT_IS_CHUNK;

            /** If we load a signature, assing the internal
              * chunk_group_id of the sig
              */
            if (s != NULL)
            {
                /** each group of chunks has it's own internal id in the sig */
                aux->chunk_group_id = s->nchunk_groups;
                /**
                  * The first chunk will have id = 0
                  * we need to search for applying the content modifiers
                  */
                aux->chunk_id = chunk_id++;
            }

            /** Allocate it as a normal SigMatch */
            sm = SigMatchAlloc();
            if (sm == NULL)
                goto error;

            sm->type = DETECT_CONTENT;
            sm->ctx = (void *)aux;
            SigMatchAppend(s,m,sm);
            m = sm;

            aux->id = de_ctx->content_max_id;
            de_ctx->content_max_id++;

            s->flags |= SIG_FLAG_MPM;

            /** We need to setup the modifiers for the chunks respect
              * the last chunk installed inmediatelly before
              * so do the propagation from the first one
              * The function DetectContentPropagate*Modifier*() should
              * be called when a new content modifier is
              * parsed/installed
              */
            if (aux->chunk_id == 0)
                first = sm;
            DetectContentPropagateModifiers(first);
            DetectContentPrint(aux);
        }

        /** Free the original pattern */
        DetectContentFree(cd);
    /**
     * If we dont need to split it is because the matcher has no length limit
     * or the payload fit in the current max pattern length, so no chunks here
     */
    } else {

        sm = SigMatchAlloc();
        if (sm == NULL)
            goto error;

        sm->type = DETECT_CONTENT;
        sm->ctx = (void *)cd;
        SigMatchAppend(s,m,sm);

        if (s != NULL) {
            /** each group of chunks has it's own internal id in the sig,
              * if the content is not splitted we will assign a chunk group id
              * anyway, so we know the real number of detect_content
              * patterns loaded */
            cd->chunk_group_id = s->nchunk_groups;
        }

        cd->id = de_ctx->content_max_id;
        de_ctx->content_max_id++;

        s->flags |= SIG_FLAG_MPM;
        if (cd->negated == 1)
            s->flags |= SIG_FLAG_MPM_NEGCONTENT;

        DetectContentPrint(cd);
    }

    return 0;

error:
    if (cd != NULL) DetectContentFree(cd);
    if (sm != NULL) free(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectContentData
 *
 * \param cd pointer to DetectCotentData
 */
void DetectContentFree(void *ptr) {
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        return;

    if (cd->content != NULL)
        free(cd->content);

    free(cd);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectCotentParseTest01 this is a test to make sure we can deal with escaped colons
 */
int DetectContentParseTest01 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\:def\"";
    char *teststringparsed = "abc:def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest02 this is a test to make sure we can deal with escaped semi-colons
 */
int DetectContentParseTest02 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\;def\"";
    char *teststringparsed = "abc;def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest03 this is a test to make sure we can deal with escaped double-quotes
 */
int DetectContentParseTest03 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\\"def\"";
    char *teststringparsed = "abc\"def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest04 this is a test to make sure we can deal with escaped backslashes
 */
int DetectContentParseTest04 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\\\def\"";
    char *teststringparsed = "abc\\def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest05 test illegal escape
 */
int DetectContentParseTest05 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\def\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got ");
        PrintRawUriFp(stdout,cd->content,cd->content_len);
        SCLogDebug(": ");
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test DetectCotentParseTest06 test a binary content
 */
int DetectContentParseTest06 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"a|42|c|44|e|46|\"";
    char *teststringparsed = "abcdef";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest07 test an empty content
 */
int DetectContentParseTest07 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test DetectCotentParseTest08 test an empty content
 */
int DetectContentParseTest08 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test DetectCotentParseChunksTest01B2G test split process
 */
int DetectContentChunkTestB2G01 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /** MPM_B2G is currently 32 bytes word, so the number of chunks
      * created should be 0, since the pattern is 32 bytes and fit in a word */
    de_ctx->mpm_matcher = MPM_B2G;
    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly"
                   "32 bytes lentgh\"; content:\"12345678901234567890123456789012\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK) && m->next == NULL)
        result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectCotentParseChunksTest01B3G test split process
 */
int DetectContentChunkTestB3G01 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /** MPM_B3G is currently 32 bytes word, so the number of chunks
      * created should be 0, since the pattern is 32 bytes and fit in a word */
    de_ctx->mpm_matcher = MPM_B3G;

    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly"
                   "32 bytes lentgh\"; content:\"12345678901234567890123456789012\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK) && m->next == NULL)
        result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectCotentParseChunksTestB2G02 test split process
 */
int DetectContentChunkTestB2G02 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /** MPM_B2G is currently 33 bytes word, so the number of chunks
      * created should be 2, since the pattern is 33 bytes and
      * wont fit in a word */
    de_ctx->mpm_matcher = MPM_B2G;

    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly 33 bytes length, so it should be splitted\"; content:\"123456789012345678901234567890123\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL && cd->content_len == 32 && cd->chunk_id == 0))
        goto end;

    m = m->next;
    if (m != NULL && m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;

    if ( cd->flags & DETECT_CONTENT_IS_CHUNK && m->next == NULL && cd->content_len == 1 && cd->chunk_id == 1)
        result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectCotentParseChunksTestB3G02 test split proccess
 */
int DetectContentChunkTestB3G02 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /** MPM_B3G is currently 33 bytes word, so the number of chunks
      * created should be 2, since the pattern is 33 bytes and
      * wont fit in a word */
    de_ctx->mpm_matcher = MPM_B3G;

    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly 33 bytes length, so it should be splitted\"; content:\"123456789012345678901234567890123\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL && cd->content_len == 32 && cd->chunk_id == 0))
        goto end;

    m = m->next;
    if (m != NULL && m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;

    if ( cd->flags & DETECT_CONTENT_IS_CHUNK && m->next == NULL && cd->content_len == 1 && cd->chunk_id == 1)
        result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectCotentParseChunksTestB2G03 test split proccess
 */
int DetectContentChunkTestB2G03 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->mpm_matcher = MPM_B2G;

    /** content_len = 100, so 3 chunks of 32 and the last chunk length == 4 */
    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly 100 bytes length, so it should be splitted\"; content:\"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;

    uint8_t chunk_id = 0;
    do {
        if (m->type == DETECT_CONTENT && m->ctx != NULL)
            cd = m->ctx;
        else
            goto end;

        if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL && cd->content_len == 32 && cd->chunk_id == chunk_id++))
            goto end;

    } while ((m = m->next) && m != NULL && m->next != NULL);

    /** Now let's see if the last Chunk hast the content_len of 4 */
    if (m == NULL || m->next != NULL)
        goto end;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;
    if (cd->content_len != 4 || cd->chunk_id != chunk_id)
        goto end;
    result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectCotentParseChunksTestB3G03 test split proccess
 */
int DetectContentChunkTestB3G03 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->mpm_matcher = MPM_B3G;

    /** content_len = 100, so 3 chunks of 32 and the last chunk length == 4 */
    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly 100 bytes length, so it should be splitted\"; content:\"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\"; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;

    uint8_t chunk_id = 0;
    do {
        if (m->type == DETECT_CONTENT && m->ctx != NULL)
            cd = m->ctx;
        else
            goto end;

        if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL && cd->content_len == 32 && cd->chunk_id == chunk_id++))
            goto end;

    } while ((m = m->next) && m != NULL && m->next != NULL);

    /** Now let's see if the last Chunk hast the content_len of 4 */
    if (m == NULL || m->next != NULL)
        goto end;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;
    if (cd->content_len != 4 || cd->chunk_id != chunk_id)
        goto end;
    result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectContentChunkTestModifiers01 test modifiers propagation
 * given a signature with just one pattern
 */
int DetectContentChunkModifiersTest01 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->mpm_matcher = MPM_B2G;

    /** content_len = 43, so 1 chunk of length 32 and another chunk of length == 11 */
    char *sigstr = "alert tcp any any -> any any (msg:\"This content is exactly 43 bytes length, so it should be splitted\"; content:\"1234567890123456789012345678901234567890123\"; depth:50; offset:10; isdataat:10, relative; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    SCLogDebug("---DetectContentChunkModifiersTest01---");
    DetectContentPrintAll(m);

    uint8_t chunk_id = 0;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL &&
        cd->content_len == 32 && cd->chunk_id == chunk_id++))
        goto end;

    /** Check modifiers for the first chunk */
    if (cd->offset != 10 || cd->depth != 42 || cd->isdataat != 21 ||
        cd->within != 0 || cd->distance != 0) {
        SCLogDebug("First Chunk has bad modifiers");
        goto end;
    }

    /** Check specified flags (offset and depth have no flags) */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check not specified flags (should not be set
      * automatically set for the first chunk) */
    if ( (cd->flags & DETECT_CONTENT_WITHIN) ||
         (cd->flags & DETECT_CONTENT_DISTANCE))
        goto end;

    /** Now let's see if the last Chunk of this first group has
      * the content_len of 11 and the modifiers correctly set */
    m = m->next;

    if (m == NULL)
        goto end;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if (!(cd->flags & DETECT_CONTENT_IS_CHUNK))
        goto end;

    if (cd->content_len != 11 || cd->chunk_id != chunk_id)
        goto end;

    /** Check modifiers for the second chunk */
    if (cd->offset != 42 || cd->depth != 53 || cd->isdataat != 10 ||
        cd->within != 11 || cd->distance != 0) {
        SCLogDebug("Second Chunk has bad modifiers");
        goto end;
    }

    /** Check specified flags */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check flags, the second chunk should have a distance and depth
      * relative to the first chunk, so flags should be automatically set */
    if ( !(cd->flags & DETECT_CONTENT_DISTANCE) ||
         !(cd->flags & DETECT_CONTENT_WITHIN))
        goto end;

    /* Great! */
    result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectContentChunkTestModifiers01 test modifiers propagation
 * mixing splitted patterns with non splitted
 */
int DetectContentChunkModifiersTest02 (void) {
    int result = 0;
    DetectContentData *cd = NULL;
    Signature *s = NULL;
    SigMatch *m = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->mpm_matcher = MPM_B2G;

    /** content 1: content_len = 3, so not splitted
    * content 2: content_len = 43, so 1 chunk of length 32 and another chunk of length == 11
    * content 3: content_len = 4, so not splitted
    * content 4: content_len = 43, so 1 chunk of length 32 and another chunk of length == 11
    */
    char *sigstr = "alert tcp any any -> any any (msg:\"Lot of contents\"; content:\"GET\"; depth:3; offset:0; isdataat:43,relative ; content:\"1234567890123456789012345678901234567890123\"; distance: 1; within: 50; depth:50; offset:10; isdataat:10, relative; content:\"HTTP\"; distance:10; within:20; content:\"1234567890123456789012345678901234567890123\"; distance: 10; within: 50; depth:1000; offset:50; isdataat:20, relative; sid:1;)";

    s = de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (s == NULL)
        goto end;

    if (de_ctx->sig_list->match == NULL)
        goto end;

    m = de_ctx->sig_list->match;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    SCLogDebug("---DetectContentChunkModifiersTest02---");
    DetectContentPrintAll(m);
    //uint8_t num_chunks = DetectContentCountChunksInGroup(first_sm, chunk_group_id);

    /** The first DetectContent should not be splitted */
    if ( (cd->flags & DETECT_CONTENT_IS_CHUNK) || m->next == NULL ||
        cd->depth != 3 || cd->isdataat != 43 || cd->offset!= 0 ||
        cd->within != 0 || cd->distance != 0 || cd->content_len != 3)
        goto end;

    /** First detect content ok, now let's see the first group of chunks */
    m = m->next;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !(cd->flags & DETECT_CONTENT_IS_CHUNK && m->next != NULL &&
        cd->content_len == 32 && cd->chunk_id == 0))
        goto end;

    /** Check modifiers for the first chunk */
    if (cd->offset != 10 || cd->depth != 42 || cd->isdataat != 21 ||
        cd->within != 39 || cd->distance != 1) {
        SCLogDebug("First Chunk has bad modifiers");
        goto end;
    }

    /** Check specified flags (offset and depth have no flags) */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check specified flags relative to the previous DetectContent
      * are correctly set for the first chunk) */
    if ( !(cd->flags & DETECT_CONTENT_WITHIN) ||
         !(cd->flags & DETECT_CONTENT_DISTANCE))
        goto end;

    /** Now let's see if the last Chunk of this first group has
      * the content_len of 11 and the modifiers correctly set */
    m = m->next;

    if (m == NULL)
        goto end;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if (!(cd->flags & DETECT_CONTENT_IS_CHUNK))
        goto end;

    if (cd->content_len != 11 || cd->chunk_id != 1)
        goto end;

    /** Check modifiers for the second chunk */
    if (cd->offset != 42 || cd->depth != 53 || cd->isdataat != 10 ||
        cd->within != 11 || cd->distance != 0) {
        SCLogDebug("Second Chunk has bad modifiers");
        goto end;
    }

    /** Check specified flags */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check flags, the second chunk should have a distance and depth
      * relative to the first chunk, so flags should be automatically set */
    if ( !(cd->flags & DETECT_CONTENT_DISTANCE) ||
         !(cd->flags & DETECT_CONTENT_WITHIN))
        goto end;

    /** The next DetectContent should not be splitted (pattern "HTTP") */
    m = m->next;

    if (m == NULL)
        goto end;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    /** Should not be a chunk */
    if (cd->flags & DETECT_CONTENT_IS_CHUNK)
        goto end;

    if (cd->content_len != 4)
        goto end;

    /** Check modifiers for the second chunk */
    if (cd->offset != 0 || cd->depth != 0 || cd->isdataat != 0 ||
        cd->within != 20 || cd->distance != 10) {
        SCLogDebug("Second Chunk has bad modifiers");
        goto end;
    }

    /** Check not specified flags */
    if ( cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE)
        goto end;

    /** Check specified flags */
    if ( !(cd->flags & DETECT_CONTENT_DISTANCE) ||
         !(cd->flags & DETECT_CONTENT_WITHIN))
        goto end;

    /** Ok, now the last group of chunks */
    m = m->next;
    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if ( !((cd->flags & DETECT_CONTENT_IS_CHUNK) && m->next != NULL &&
        cd->content_len == 32 && cd->chunk_id == 0 &&
        cd->chunk_group_id == 4))
        goto end;

    /** Check modifiers for the first chunk */
    if (cd->offset != 50 || cd->depth != 989 || cd->isdataat != 31 ||
        cd->within != 39 || cd->distance != 10) {
        SCLogDebug("First Chunk of last group has bad modifiers");
        goto end;
    }

    /** Check specified flags (offset and depth have no flags) */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check specified flags relative to the previous DetectContent
      * are correctly set for the first chunk) */
    if ( !(cd->flags & DETECT_CONTENT_WITHIN) ||
         !(cd->flags & DETECT_CONTENT_DISTANCE))
        goto end;

    /** Now let's see if the last Chunk of this last group has
      * the content_len of 11 and the modifiers correctly set */
    m = m->next;

    if (m == NULL)
        goto end;

    if (m->type == DETECT_CONTENT && m->ctx != NULL)
        cd = m->ctx;
    else
        goto end;

    if (!(cd->flags & DETECT_CONTENT_IS_CHUNK))
        goto end;

    if (cd->content_len != 11 || cd->chunk_id != 1 || cd->chunk_group_id != 4)
        goto end;

    /** Check modifiers for the second chunk */
    if (cd->offset != 82 || cd->depth != 1000 || cd->isdataat != 20 ||
        cd->within != 11 || cd->distance != 0) {
        SCLogDebug("Second Chunk of last group has bad modifiers");
        goto end;
    }

    /** Check specified flags */
    if ( !(cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE))
        goto end;

    /** Check flags, the second chunk should have a distance and depth
      * relative to the first chunk, so flags should be automatically set */
    if ( !(cd->flags & DETECT_CONTENT_DISTANCE) ||
         !(cd->flags & DETECT_CONTENT_WITHIN))
        goto end;

    /** Great!!! */
    result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Test packet Matches
 * \param raw_eth_pkt pointer to the ethernet packet
 * \param pktsize size of the packet
 * \param sig pointer to the signature to test
 * \param sid sid number of the signature
 * \retval return 1 if match
 * \retval return 0 if not
 */
int DetectContentChunkMatchTest(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
                      uint32_t sid)
{
    int result = 1;

    Packet p;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, &p, raw_eth_pkt, pktsize, NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result=0;
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig);
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = NULL;

    SCLogDebug("---DetectContentChunkMatchTest---");
    DetectContentPrintAll(de_ctx->sig_list->match);

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, sid) != 1) {
        result = 0;
        goto end;
    }

end:
    if (de_ctx != NULL)
    {
        //PatternMatchDestroy(mpm_ctx);
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    FlowShutdown();

    return result;
}

/**
 * \brief Wrapper for DetectContentChunkMatchTest
 */
int DetectContentChunkMatchTestWrp(char *sig, uint32_t sid) {
    /** Real packet with the following tcp data:
     * "Hi, this is a big test to check content matches of splitted"
     * "patterns between multiple chunks!"
     * (without quotes! :) )
     */
    uint8_t raw_eth_pkt[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,
        0x00,0x00,0x00,0x00,0x08,0x00,0x45,0x00,
        0x00,0x85,0x00,0x01,0x00,0x00,0x40,0x06,
        0x7c,0x70,0x7f,0x00,0x00,0x01,0x7f,0x00,
        0x00,0x01,0x00,0x14,0x00,0x50,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x02,
        0x20,0x00,0xc9,0xad,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x20,0x6f,0x66,
        0x20,0x73,0x70,0x6c,0x69,0x74,0x74,0x65,
        0x64,0x20,0x70,0x61,0x74,0x74,0x65,0x72,
        0x6e,0x73,0x20,0x62,0x65,0x74,0x77,0x65,
        0x65,0x6e,0x20,0x6d,0x75,0x6c,0x74,0x69,
        0x70,0x6c,0x65,0x20,0x63,0x68,0x75,0x6e,
        0x6b,0x73,0x21 }; /* end raw_eth_pkt */

    return DetectContentChunkMatchTest(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt),
                             sig, sid);
}

/**
 * \test Check if we match a normal pattern (not splitted)
 */
int DetectContentChunkMatchTest01()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test\"; sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match a splitted pattern
 */
int DetectContentChunkMatchTest02()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple chunks!\"; sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check that we don't match the signature if one of the splitted
 * chunks doesn't match the packet
 */
int DetectContentChunkMatchTest03()
{
    /** The last chunk of the content should not match */
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple splitted chunks!\"; sid:1;)";
    return (DetectContentChunkMatchTestWrp(sig, 1) == 0) ? 1: 0;
}

/**
 * \test Check if we match multiple content (not splitted)
 */
int DetectContentChunkMatchTest04()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is\"; depth:15 ;content:\"a big test\"; "
                " within:15; content:\"to check content matches of\"; "
                " within:30; content:\"splitted patterns\"; distance:1; "
                " within:30; depth:400;"
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check that we match packets with multiple chunks and not chunks
 * Here we should specify only contents that fit in 32 bytes
 * Each of them with their modifier values
 */
int DetectContentChunkMatchTest05()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big\"; depth:17; "
                " isdataat:30, relative; "
                " content:\"test\"; within: 5; distance:1; depth:22; "
                " isdataat:15, relative; offset:18; "
                " content:\"of splitted\"; within:37; distance:15; "
                " depth:60; isdataat:20,relative; offset: 48; "
                " content:\"patterns\"; within:9; distance:1; depth:69; "
                " isdataat:10, relative; offset:60; "
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check that we match packets with multiple chunks and not chunks
 * Here we should specify contents that fit and contents that must be splitted
 * Each of them with their modifier values
 */
int DetectContentChunkMatchTest06()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big test to check cont\"; depth:36;"
                " content:\"ent matches\"; within:11; distance:0; "
                " content:\"of splitted patterns between multiple\"; "
                " within:38; distance:1; offset:47; depth:85; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " depth:94; offset: 50; "
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentChunkMatchTest07()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"chunks!\"; "
                " content:\"content matches\"; offset:32; depth:47; "
                " content:\"of splitted patterns between multiple\"; "
                " content:\"Hi, this is a big\"; offset:0; depth:17; "
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentChunkMatchTest08()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"ent matches\"; "
                " content:\"of splitted patterns between multiple\"; "
                " within:38; distance:1; offset:47; depth:85; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " depth:94; offset: 50; "
                " content:\"Hi, this is a big test to check cont\"; depth:36;"
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentChunkMatchTest09()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"ent matches\"; "
                " content:\"of splitted patterns between multiple\"; "
                " within:38; distance:1; offset:47; depth:85; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " depth:94; offset: 50; "
                " content:\"Hi, this is a big test to chec\"; depth:36;"
                " content:\"k cont\"; distance:0; within:6;"
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match two consecutive simple contents
 */
int DetectContentChunkMatchTest10()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big test to check \"; "
                " content:\"con\"; "
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match two contents of length 1
 */
int DetectContentChunkMatchTest11()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"H\"; "
                " content:\"i\"; "
                " sid:1;)";
    return DetectContentChunkMatchTestWrp(sig, 1);
}

int DetectContentParseTest09(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "!boo";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 1);
        DetectContentFree(cd);
    }

    return result;
}

int DetectContentParseTest10(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "!\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 1);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest11(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "boo";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 0);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest12(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 0);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest13(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "\"!boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 1);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest14(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  \"!boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 1);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest15(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  !boo";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->negated == 1);
        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest16(void) {
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  boo";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->content_len == 3 && memcmp(cd->content,"boo",3) == 0);
        DetectContentFree(cd);
    }
    return result;
}

static int SigTestPositiveTestContent(char *rule, uint8_t *buf)
{
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) == 1) {
        result = 1;
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int SigTestNegativeTestContent(char *rule, uint8_t *buf)
{
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) == 0) {
        result = 1;
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test A positive test that checks that the content string doesn't contain
 *       the negated content
 */
static int SigTest41TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!GES; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A positive test that checks that the content string doesn't contain
 *       the negated content within the specified depth
 */
static int SigTest42TestNegatedContent(void)
{                                                                                                                                                        // 01   5    10   15   20  24
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!twentythree; depth:22; offset:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks that the content string doesn't contain
 *       the negated content within the specified depth, and also after the
 *       specified offset.  If it is present in the depth we get a failure
 *       anyways, and we don't do a check on the offset
 */
static int SigTest43TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!twentythree; depth:15; offset:22; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks that the content string doesn't contain
 *       the negated content after the specified offset and within the specified
 *       depth.
 */
static int SigTest44TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!twentythree; offset:40; depth:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that uses a combination of content string with negated
 *       content string
 */
static int SigTest45TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:5; content:!twentythree; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that uses a combination of content string with negated
 *       content string, with we receiving a failure for 'onee' itself.
 */
static int SigTest46TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:onee; content:!twentythree; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that uses a combination of content string with negated
 *       content string, with we receiving a failure of first content's offset
 *       condition
 */
static int SigTest47TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; offset:5; content:!twentythree; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks that we don't have a negated content within
 *       the specified length from the previous content match.
 */
static int SigTest48TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:GET; content:!GES; within:26; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *        content with the use of within
 */
static int SigTest49TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:GET; content:!Host; within:26; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *        content with the use of distance
 */
static int SigTest50TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:GET; content:!GES; distance:25; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content with the use of distance
 */
static int SigTest51TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:GET; content:!Host; distance:18; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, with the content not being present
 */
static int SigTest52TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:GES; content:!BOO; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest53TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest54TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:20; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the use of negated content along with
 *       the presence of depth
 */
static int SigTest55TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!one; depth:5; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of 2 contents in the
 *       presence of within
 */
static int SigTest56TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:fourty; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest57TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *       content, in the presence of distance
 */
static int SigTest58TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; distance:57; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of distance
 */
static int SigTest59TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; distance:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest60TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!one; content:fourty; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest61TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest62TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:30; depth:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest63TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest64TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:30; depth:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest65TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:30; offset:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest66TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!fourty; within:30; offset:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest67TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:!four; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest68TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:nine; offset:8; content:!fourty; within:28; content:fiftysix; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest69TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:10; content:nine; offset:8; content:!fourty; within:48; content:fiftysix; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest70TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:52; distance:45 sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest71TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:40; distance:43; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest72TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; content:!fourty; within:52; distance:47; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest73TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:one; depth:5; content:!twentythree; depth:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest74TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"USER\"; content:!\"PASS\"; sid:1;)",  (uint8_t *)"USER apple");
}

static int SigTest75TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"USER\"; content:\"!PASS\"; sid:1;)",  (uint8_t *)"USER apple");
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectContent
 */
void DetectContentRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectContentParseTest01", DetectContentParseTest01, 1);
    UtRegisterTest("DetectContentParseTest02", DetectContentParseTest02, 1);
    UtRegisterTest("DetectContentParseTest03", DetectContentParseTest03, 1);
    UtRegisterTest("DetectContentParseTest04", DetectContentParseTest04, 1);
    UtRegisterTest("DetectContentParseTest05", DetectContentParseTest05, 1);
    UtRegisterTest("DetectContentParseTest06", DetectContentParseTest06, 1);
    UtRegisterTest("DetectContentParseTest07", DetectContentParseTest07, 1);
    UtRegisterTest("DetectContentParseTest08", DetectContentParseTest08, 1);
    UtRegisterTest("DetectContentParseTest09", DetectContentParseTest09, 1);
    UtRegisterTest("DetectContentParseTest10", DetectContentParseTest10, 1);
    UtRegisterTest("DetectContentParseTest11", DetectContentParseNegTest11, 1);
    UtRegisterTest("DetectContentParseTest12", DetectContentParseNegTest12, 1);
    UtRegisterTest("DetectContentParseTest13", DetectContentParseNegTest13, 1);
    UtRegisterTest("DetectContentParseTest14", DetectContentParseNegTest14, 1);
    UtRegisterTest("DetectContentParseTest15", DetectContentParseNegTest15, 1);
    UtRegisterTest("DetectContentParseTest16", DetectContentParseNegTest16, 1);

    UtRegisterTest("DetectContentChunkTestB2G01 l=32", DetectContentChunkTestB2G01, 1);
    UtRegisterTest("DetectContentChunkTestB3G01 l=32", DetectContentChunkTestB3G01, 1);
    UtRegisterTest("DetectContentChunkTestB2G02 l=33", DetectContentChunkTestB2G02, 1);
    UtRegisterTest("DetectContentChunkTestB3G02 l=33", DetectContentChunkTestB3G02, 1);
    UtRegisterTest("DetectContentChunkTestB2G03 l=100", DetectContentChunkTestB2G03, 1);
    UtRegisterTest("DetectContentChunkTestB3G03 l=100", DetectContentChunkTestB3G03, 1);
    UtRegisterTest("DetectContentChunkModifiersTest01", DetectContentChunkModifiersTest01, 1);
    UtRegisterTest("DetectContentChunkModifiersTest02", DetectContentChunkModifiersTest02, 1);

    /* The reals */
    UtRegisterTest("DetectContentChunkMatchTest01", DetectContentChunkMatchTest01, 1);
    UtRegisterTest("DetectContentChunkMatchTest02", DetectContentChunkMatchTest02, 1);
    UtRegisterTest("DetectContentChunkMatchTest03", DetectContentChunkMatchTest03, 1);
    UtRegisterTest("DetectContentChunkMatchTest04", DetectContentChunkMatchTest04, 1);
    UtRegisterTest("DetectContentChunkMatchTest05", DetectContentChunkMatchTest05, 1);
    UtRegisterTest("DetectContentChunkMatchTest06", DetectContentChunkMatchTest06, 1);
    UtRegisterTest("DetectContentChunkMatchTest07", DetectContentChunkMatchTest07, 1);
    UtRegisterTest("DetectContentChunkMatchTest08", DetectContentChunkMatchTest08, 1);
    UtRegisterTest("DetectContentChunkMatchTest09", DetectContentChunkMatchTest09, 1);
    UtRegisterTest("DetectContentChunkMatchTest10", DetectContentChunkMatchTest10, 1);
    UtRegisterTest("DetectContentChunkMatchTest11", DetectContentChunkMatchTest11, 1);

    /* Negated content tests */
    UtRegisterTest("SigTest41TestNegatedContent", SigTest41TestNegatedContent, 1);
    UtRegisterTest("SigTest42TestNegatedContent", SigTest42TestNegatedContent, 1);
    UtRegisterTest("SigTest43TestNegatedContent", SigTest43TestNegatedContent, 1);
    UtRegisterTest("SigTest44TestNegatedContent", SigTest44TestNegatedContent, 1);
    UtRegisterTest("SigTest45TestNegatedContent", SigTest45TestNegatedContent, 1);
    UtRegisterTest("SigTest46TestNegatedContent", SigTest46TestNegatedContent, 1);
    UtRegisterTest("SigTest47TestNegatedContent", SigTest47TestNegatedContent, 1);
    UtRegisterTest("SigTest48TestNegatedContent", SigTest48TestNegatedContent, 1);
    UtRegisterTest("SigTest49TestNegatedContent", SigTest49TestNegatedContent, 1);
    UtRegisterTest("SigTest50TestNegatedContent", SigTest50TestNegatedContent, 1);
    UtRegisterTest("SigTest51TestNegatedContent", SigTest51TestNegatedContent, 1);
    UtRegisterTest("SigTest52TestNegatedContent", SigTest52TestNegatedContent, 1);
    UtRegisterTest("SigTest53TestNegatedContent", SigTest53TestNegatedContent, 1);
    UtRegisterTest("SigTest54TestNegatedContent", SigTest54TestNegatedContent, 1);
    UtRegisterTest("SigTest55TestNegatedContent", SigTest55TestNegatedContent, 1);
    UtRegisterTest("SigTest56TestNegatedContent", SigTest56TestNegatedContent, 1);
    UtRegisterTest("SigTest57TestNegatedContent", SigTest57TestNegatedContent, 1);
    UtRegisterTest("SigTest58TestNegatedContent", SigTest58TestNegatedContent, 1);
    UtRegisterTest("SigTest59TestNegatedContent", SigTest59TestNegatedContent, 1);
    UtRegisterTest("SigTest60TestNegatedContent", SigTest60TestNegatedContent, 1);
    UtRegisterTest("SigTest61TestNegatedContent", SigTest61TestNegatedContent, 1);
    UtRegisterTest("SigTest62TestNegatedContent", SigTest62TestNegatedContent, 1);
    UtRegisterTest("SigTest63TestNegatedContent", SigTest63TestNegatedContent, 1);
    UtRegisterTest("SigTest64TestNegatedContent", SigTest64TestNegatedContent, 1);
    UtRegisterTest("SigTest65TestNegatedContent", SigTest65TestNegatedContent, 1);
    UtRegisterTest("SigTest66TestNegatedContent", SigTest66TestNegatedContent, 1);
    UtRegisterTest("SigTest67TestNegatedContent", SigTest67TestNegatedContent, 1);
    UtRegisterTest("SigTest68TestNegatedContent", SigTest68TestNegatedContent, 1);
    UtRegisterTest("SigTest69TestNegatedContent", SigTest69TestNegatedContent, 1);
    UtRegisterTest("SigTest70TestNegatedContent", SigTest70TestNegatedContent, 1);
    UtRegisterTest("SigTest71TestNegatedContent", SigTest71TestNegatedContent, 1);
    UtRegisterTest("SigTest72TestNegatedContent", SigTest72TestNegatedContent, 1);
    UtRegisterTest("SigTest73TestNegatedContent", SigTest73TestNegatedContent, 1);
    UtRegisterTest("SigTest74TestNegatedContent", SigTest74TestNegatedContent, 1);
    UtRegisterTest("SigTest75TestNegatedContent", SigTest75TestNegatedContent, 1);

#endif /* UNITTESTS */
}
