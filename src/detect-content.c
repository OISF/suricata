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
 * TODO: add a 'recursive depth' to limit the depth to do the recursion on...
 *
 * XXX more later....
 *
 */

#include <ctype.h>
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "detect-engine-mpm.h"
#include "util-mpm.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "util-unittest.h"

#include "threads.h"

int DetectContentMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectContentSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectContentRegisterTests(void);
void DetectContentFree(DetectContentData *);

u_int8_t nocasetable[256];
#define _nc(c) nocasetable[(c)]

void DetectContentRegister (void) {
    sigmatch_table[DETECT_CONTENT].name = "content";
    sigmatch_table[DETECT_CONTENT].Match = DetectContentMatch;
    sigmatch_table[DETECT_CONTENT].Setup = DetectContentSetup;
    sigmatch_table[DETECT_CONTENT].Free  = NULL;
    sigmatch_table[DETECT_CONTENT].RegisterTests = DetectContentRegisterTests;

    /* create table for O(1) case conversion lookup */
    u_int8_t c = 0;
    for ( ; c < 255; c++) {
       if ( c >= 'a' && c <= 'z')
           nocasetable[c] = (c - ('a' - 'A'));
       else if (c >= 'A' && c <= 'Z')
           nocasetable[c] = (c + ('a' - 'A'));
       else
           nocasetable[c] = c;
    }
#ifdef DEBUG
    for (c = 0; c < 255; c++) {
        if (isprint(nocasetable[c]))
            printf("nocasetable[%c]: %c\n", c, nocasetable[c]);
    }
#endif /* DEBUG */
}

/* pass on the content_max_id */
u_int32_t DetectContentMaxId(DetectEngineCtx *de_ctx) {
    //printf("DetectContentMaxId: %u\n", de_ctx->content_max_id);
    return de_ctx->content_max_id;
}

static inline int
TestOffsetDepth(MpmMatch *m, DetectContentData *co, u_int16_t pktoff) {
    if (m->offset >= pktoff) {
        if (co->offset == 0 ||
           (co->offset && m->offset >= co->offset)) {
            if (co->depth == 0 ||
               (co->depth && (m->offset+co->content_len) <= co->depth))
            {
                //printf("TestOffsetDepth: depth %u, offset %u, m->offset %u, return 1\n",
                //    co->depth, co->offset, m->offset);
                return 1;
            }
        }
    }
    //printf("TestOffsetDepth: depth %u, offset %u, m->offset %u, return 0\n",
    //    co->depth, co->offset, m->offset);
    return 0;
}

/* This function is called recursively (if nescessary) to be able
 * to determine whether or not a chain of content matches connected
 * with 'within' and 'distance' options fully matches. The reason it
 * was done like this is to make sure we can handle partial matches
 * that turn out to fail being followed by full matches later in the
 * packet. This adds some runtime complexity however. */
static inline int
TestWithinDistanceOffsetDepth(ThreadVars *t, PatternMatcherThread *pmt, MpmMatch *m, SigMatch *nsm, u_int16_t pktoff)
{
    //printf("test_nextsigmatch m:%p, nsm:%p\n", m,nsm);
    if (nsm == NULL)
        return 1;

    DetectContentData *co = (DetectContentData *)nsm->ctx;
    MpmMatch *nm = pmt->mtc.match[co->id].top;

    for (; nm; nm = nm->next) {
        //printf("TestWithinDistanceOffsetDepth: nm->offset %u, m->offset %u, pktoff %u\n", nm->offset, m->offset, pktoff);
        if (nm->offset >= pktoff) {
            if ((!(co->flags & DETECT_CONTENT_WITHIN) || (co->within > 0 &&
                (nm->offset > m->offset) &&
                ((nm->offset - m->offset + co->content_len) <= co->within))))
            {
                //printf("TestWithinDistanceOffsetDepth: MATCH: %u <= WITHIN(%u), "
                //    "nm->offset %u, m->offset %u\n", nm->offset - m->offset + co->content_len,
                //    co->within, nm->offset, m->offset);

                if (!(co->flags & DETECT_CONTENT_DISTANCE) ||
                    ((nm->offset > m->offset) &&
                    ((nm->offset - m->offset) >= co->distance)))
                {
                    //printf("TestWithinDistanceOffsetDepth: MATCH: %u >= DISTANCE(%u), "
                    //    "nm->offset %u, m->offset %u\n", nm->offset - m->offset,
                    //    co->distance, nm->offset, m->offset);
                    if (TestOffsetDepth(nm, co, pktoff) == 1) {
                        return TestWithinDistanceOffsetDepth(t, pmt, nm, nsm->next, pktoff);
                    }
                } else {
                    //printf("TestWithinDistanceOffsetDepth: NO MATCH: %u >= DISTANCE(%u), "
                    //     "nm->offset %u, m->offset %u\n", nm->offset - m->offset,
                    //     co->distance, nm->offset, m->offset);
                }
            } else {
                //printf("TestWithinDistanceOffsetDepth: NO MATCH: %u <= WITHIN(%u), "
                //    "nm->offset %u, m->offset %u\n", nm->offset - m->offset + co->content_len,
                //    co->within, nm->offset, m->offset);
            }
        }
    }
    return 0;
}

static inline int
DoDetectContent(ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *sm, DetectContentData *co)
{
    int ret = 0;
    char match = 0;

    /* Get the top match, we already know we have one. */
    MpmMatch *m = pmt->mtc.match[co->id].top;

    /*  if we have within or distance coming up next, check this match
     *  for distance and/or within and check the rest of this match
     *  chain as well. */
    if ((co->flags & DETECT_CONTENT_WITHIN_NEXT ||
         co->flags & DETECT_CONTENT_DISTANCE_NEXT) &&
         pmt->de_checking_distancewithin == 0)
    {
        //printf("DoDetectContent: Content \""); PrintRawUriFp(stdout, co->content, co->content_len);
        //printf("\" DETECT_CONTENT_WITHIN_NEXT or DETECT_CONTENT_DISTANCE_NEXT is true\n");

        /* indicate to the detection engine the next sigmatch(es)
         * are part of this match chain */
        pmt->de_checking_distancewithin = 1;

        for (; m != NULL; m = m->next) {
            /* first check our match for offset and depth */
            if (TestOffsetDepth(m, co, pmt->pkt_off) == 1) {
                //printf("DoDetectContent: TestOffsetDepth returned 1\n");
                ret = TestWithinDistanceOffsetDepth(t, pmt, m, sm->next, pmt->pkt_off);
                if (ret == 1) {
                    //printf("DoDetectContent: TestWithinDistanceOffsetDepth returned 1\n");
                    pmt->pkt_ptr = p->payload + m->offset;
                    pmt->pkt_off = m->offset;
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
    } else if (co->flags & DETECT_CONTENT_WITHIN ||
               co->flags & DETECT_CONTENT_DISTANCE)
    {
        pmt->de_checking_distancewithin = 0;
        match = 1;

    /* Getting here means we are not in checking an within/distance chain.
     * This means we can just inspect this content match on it's own. So
     * Let's see if at least one of the matches within the offset and depth
     * settings. If so, return a match.
     */
    } else {
        /* when in recursive capture mode don't check depth and offset
         * after the first match */
        if (s->flags & SIG_FLAG_RECURSIVE && pmt->pkt_cnt) {
            for (; m != NULL; m = m->next) {
                if (m->offset >= pmt->pkt_off) {
                    /* update pkt ptrs, content doesn't use this,
                     * but pcre does */
                    pmt->pkt_ptr = p->payload + m->offset;
                    pmt->pkt_off = m->offset;
                    match = 1;
                    break;
                }
            }
        } else {
            for (; m != NULL; m = m->next) {
                ret = TestOffsetDepth(m,co, 0); /* no offset as we inspect each
                                                 * match on it's own */
                if (ret == 1) {
                    /* update pkt ptrs, this content run doesn't
                     * use this, but pcre does */
                    pmt->pkt_ptr = p->payload + m->offset;
                    pmt->pkt_off = m->offset;
                    match = 1;
                    break;
                }
            }
        }
    }
    return match;
}


/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectContentMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
    u_int32_t len = 0;

    if (p->payload_len == 0)
        return 0;

    DetectContentData *co = (DetectContentData *)m->ctx;

    /* see if we had a match */
    len = pmt->mtc.match[co->id].len;
    if (len == 0)
        return 0;

#ifdef DEBUG
    printf("content \""); PrintRawUriFp(stdout, co->content, co->content_len);
    printf("\" matched %u time(s) at offsets: ", len);

    MpmMatch *tmpm = NULL;
    for (tmpm = pmt->mtc.match[co->id].top; tmpm != NULL; tmpm = tmpm->next) {
        printf("%u ", tmpm->offset);
    }
    printf("\n");
#endif

    return DoDetectContent(t, pmt, p, s, m, co);
}

DetectContentData *DetectContentParse (char *contentstr)
{
    DetectContentData *cd = NULL;
    char *str = contentstr;
    char dubbed = 0;
    u_int16_t len;

    if (contentstr[0] == '\"' && contentstr[strlen(contentstr)-1] == '\"') {
        str = strdup(contentstr+1);
        str[strlen(contentstr)-2] = '\0';
        dubbed = 1;
    }

    len = strlen(str);
    if (len == 0)
        goto error;

    cd = malloc(sizeof(DetectContentData));
    if (cd == NULL) {
        printf("DetectContentParse malloc failed\n");
        goto error;
    }
    memset(cd,0,sizeof(DetectContentData));

    //printf("DetectContentParse: \"%s\", len %u\n", str, len);
    char converted = 0;

    {
        u_int16_t i, x;
        u_int8_t bin = 0, binstr[3] = "", binpos = 0;
        for (i = 0, x = 0; i < len; i++) {
            // printf("str[%02u]: %c\n", i, str[i]);
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
                        // printf("part of binary: %c\n", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            u_int8_t c = strtol((char *)binstr, (char **) NULL, 16) & 0xFF;
#ifdef DEBUG
                            printf("Binstr %X\n", c);
#endif
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        // printf("space as part of binary string\n");
                    }
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }
#ifdef DEBUG
        for (i = 0; i < x; i++) {
            if (isprint(str[i])) printf("%c", str[i]);
            else                 printf("\\x%02u", str[i]);
        }
        printf("\n");
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

    if (dubbed != 0) free(str);
    return cd;

error:
    if (dubbed != 0) free(str);
    if (cd != NULL) free(cd);
    return NULL;
}

int DetectContentSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *contentstr)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;

    cd = DetectContentParse(contentstr);
    if (cd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CONTENT;
    sm->ctx = (void *)cd;

    SigMatchAppend(s,m,sm);

    cd->id = de_ctx->content_max_id;
    de_ctx->content_max_id++;

    s->flags |= SIG_FLAG_MPM;

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
void DetectContentFree(DetectContentData *cd) {
    free(cd);
}

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
        if(memcmp(cd->content, teststringparsed, sizeof(teststringparsed)) != 0){
            printf("expected %s got %s: ", teststringparsed, cd->content);
            result = 0;
            DetectContentFree(cd);
        }
    }else if(cd == NULL){
        printf("expected %s got NULL: ", teststringparsed);
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
        if(memcmp(cd->content, teststringparsed, sizeof(teststringparsed)) != 0){
            printf("expected %s got %s: ", teststringparsed, cd->content);
            result = 0;
            DetectContentFree(cd);
        }
    }else if(cd == NULL){
        printf("expected %s got NULL: ", teststringparsed);
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
        if(memcmp(cd->content, teststringparsed, sizeof(teststringparsed)) != 0){
            printf("expected %s got %s: ", teststringparsed, cd->content);
            result = 0;
            DetectContentFree(cd);
        }
    }else if(cd == NULL){
        printf("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest04 ****BROKEN***** this is a test to make sure we can deal with escaped backslashes
 */
int DetectContentParseTest04 (void) {
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\\\def\"";
    char *teststringparsed = "abc\\def";
    cd = DetectContentParse(teststring);
    if (cd != NULL) {
            printf("expected %s got %s: ", teststringparsed, cd->content);
        if(memcmp(cd->content, teststringparsed, sizeof(teststringparsed)) != 0){
            printf("expected %s got %s: ", teststringparsed, cd->content);
            result = 0;
            DetectContentFree(cd);
        }
    }else if(cd == NULL){
        printf("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \brief this function registers unit tests for DetectFlow
 */
void DetectContentRegisterTests(void) {
    UtRegisterTest("DetectContentParseTest01", DetectContentParseTest01, 1);
    UtRegisterTest("DetectContentParseTest02", DetectContentParseTest02, 1);
    UtRegisterTest("DetectContentParseTest03", DetectContentParseTest03, 1);
    UtRegisterTest("DetectContentParseTest04", DetectContentParseTest04, 1);
}
