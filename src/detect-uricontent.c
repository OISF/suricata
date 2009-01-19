/* Simple uricontent match part of the detection engine.
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
 * XXX more later....
 *
 */

#include <ctype.h>
#include "decode.h"
#include "detect.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "threads.h"
#include "util-mpm.h"

#include "util-unittest.h"

int DetectUricontentMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectUricontentSetup (Signature *, SigMatch *, char *);
void HttpUriRegisterTests(void);

u_int8_t nocasetable[256];
#define _nc(c) nocasetable[(c)]

/* we use a global id for uricontent matches to be able to
 * use just one pattern matcher thread context per thread. */
static u_int32_t uricontent_max_id = 0;

void DetectUricontentRegister (void) {
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].Match = DetectUricontentMatch;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free  = NULL;
    sigmatch_table[DETECT_URICONTENT].RegisterTests = HttpUriRegisterTests;

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

/* pass on the uricontent_max_id */
u_int32_t DetectUricontentMaxId(void) {
    //printf("DetectUricontentMaxId: %u\n", uricontent_max_id);
    return uricontent_max_id;
}

/* Normalize http buffer
 *
 * Returns 0: on ok
 *         1: normalized with events occurred.
 *
 * What we normalize:
 * - ../ becomes
 *   example: /one/../two/ becomes /two/
 * - // becomes /
 *   example: /one//two/ becomes /one/two/
 * - '%20' becomes ' '
 *   example: '/one/%20/two/' becomes '/one/ /two/'
 */
static inline int
HttpUriNormalize(u_int8_t *raw, u_int16_t rawlen, u_int8_t *norm, u_int16_t *normlen) {
    u_int16_t i,x;
    for (i = 0, x = 0; i < rawlen; i++) {
            /* check for ../ */
            /* check for // */

        norm[x] = raw[i];
        x++;
    }
    *normlen = x;

    return 0;
}

static inline int
TestOffsetDepth(MpmMatch *m, DetectUricontentData *co) {
    if (co->offset == 0 ||
        (co->offset && ((m->offset+1) - co->uricontent_len) >= co->offset)) {
        if (co->depth == 0 ||
            (co->depth && (m->offset+1) <= co->depth))
        {
            return 1;
        }
    }

    return 0;
}

/* This function is called recursively (if nescessary) to be able
 * to determite whether or not a chain of content matches connected
 * with 'within' and 'distance' options fully matches. The reason it
 * was done like this is to make sure we can handle partial matches
 * that turn out to fail being followed by full matches later in the
 * packet. This adds some runtime complexity however. */
static inline int
TestWithinDistanceOffsetDepth(ThreadVars *t, PatternMatcherThread *pmt, MpmMatch *m, SigMatch *nsm)
{
    //printf("test_nextsigmatch m:%p, nsm:%p\n", m,nsm);
    if (nsm == NULL)
        return 1;

    DetectUricontentData *co = (DetectUricontentData *)nsm->ctx;
    MpmMatch *nm = pmt->mtcu.match[co->id].top;

    for (; nm; nm = nm->next) {
        //printf("test_nextsigmatch: (nm->offset+1) %u, (m->offset+1) %u\n", (nm->offset+1), (m->offset+1));

        if ((co->within == 0 || (co->within &&
           ((nm->offset+1) > (m->offset+1)) &&
           ((nm->offset+1) - (m->offset+1) <= co->within))))
        {
            //printf("test_nextsigmatch: WITHIN (nm->offset+1) %u, (m->offset+1) %u\n", (nm->offset+1), (m->offset+1));

            if (co->distance == 0 || (co->distance &&
               ((nm->offset+1) > (m->offset+1)) &&
               ((nm->offset+1) - (m->offset+1) >= co->distance)))
            {
                if (TestOffsetDepth(nm, co) == 1) {
                     //printf("test_nextsigmatch: DISTANCE (nm->offset+1) %u, (m->offset+1) %u\n", (nm->offset+1), (m->offset+1));
                    return TestWithinDistanceOffsetDepth(t, pmt, nm, nsm->next);
                }
            }
        }
    }
    return 0;
}

static inline int
DoDetectUricontent(ThreadVars *t, PatternMatcherThread *pmt, Packet *p, SigMatch *sm, DetectUricontentData *co)
{
    int ret = 0;
    char match = 0;

    /* Get the top match, we already know we have one. */
    MpmMatch *m = pmt->mtcu.match[co->id].top;

    /*  if we have within or distance coming up next, check this match
     *  for distance and/or within and check the rest of this match
     *  chain as well. */
    if ((co->flags & DETECT_URICONTENT_WITHIN_NEXT ||
         co->flags & DETECT_URICONTENT_DISTANCE_NEXT) &&
         pmt->de_checking_distancewithin == 0)
    {
        /* indicate to the detection engine the next sigmatch(es)
         * are part of this match chain */
        pmt->de_checking_distancewithin = 1;

        for (; m != NULL; m = m->next) {
            /* first check our match for offset and depth */
            if (TestOffsetDepth(m, co) == 1) {
                ret = TestWithinDistanceOffsetDepth(t, pmt, m, sm->next);
                if (ret == 1) {
                    /* update pkt ptrs, content doesn't use this,
                     * but pcre does */
                    pmt->pkt_ptr = p->tcp_payload + m->offset;
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
    } else if (co->flags & DETECT_URICONTENT_WITHIN ||
               co->flags & DETECT_URICONTENT_DISTANCE)
    {
        pmt->de_checking_distancewithin = 0;
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
                pmt->pkt_ptr = p->tcp_payload + m->offset;
                pmt->pkt_off = m->offset;
                match = 1;
                break;
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

int DetectUricontentMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
    u_int32_t len = 0;
/*
    if (s->id == 2008238) {
        printf("scanning uricontent have %u\n", pmt->de_have_httpuri);
        PrintRawUriFp(stdout,p->http_uri.raw[0],p->http_uri.raw_size[0]);
        printf("\n");
    }
*/
    /* if we don't have a uri, don't bother scanning */
    if (pmt->de_have_httpuri == 0)
        return 0;

    DetectUricontentData *co = (DetectUricontentData *)m->ctx;

    /* see if we had a match */
    len = pmt->mtcu.match[co->id].len;
/*
    if (s->id == 2008238)
        printf("len %u\n", len);
*/
    if (len == 0)
        return 0;

#ifdef DEBUG
    if (s->id == 2008238) {
    printf("uricontent \'");
    PrintRawUriFp(stdout, co->uricontent, co->uricontent_len);    
    printf("\' matched %u time(s) at offsets: ", len);

    MpmMatch *tmpm = NULL;
    for (tmpm = pmt->mtcu.match[co->id].top; tmpm != NULL; tmpm = tmpm->next) {
        printf("%u ", tmpm->offset);
    }
    printf("\n");
    }
#endif

    return DoDetectUricontent(t, pmt, p, m, co);
}

int DetectUricontentSetup (Signature *s, SigMatch *m, char *contentstr)
{
    DetectUricontentData *cd = NULL;
    SigMatch *sm = NULL;
    char *str = contentstr;
    char dubbed = 0;
    u_int16_t len = 0;

    if (contentstr[0] == '\"' && contentstr[strlen(contentstr)-1] == '\"') {
        str = strdup(contentstr+1);
        str[strlen(contentstr)-2] = '\0';
        dubbed = 1;
    }

    len = strlen(str);
    if (len == 0)
        return -1;

    cd = malloc(sizeof(DetectUricontentData));
    if (cd == NULL) {
        printf("DetectContentSetup malloc failed\n");
        goto error;
    }
    memset(cd,0,sizeof(DetectUricontentData));

    //printf("DetectUricontentSetup: \"%s\", len %u\n", str, len);
    char converted = 0;

    {
        u_int16_t i, x;
        u_int8_t bin = 0, binstr[3] = "", binpos = 0;
        for (i = 0, x = 0; i < len; i++) {
            //printf("str[%02u]: %c\n", i, str[i]);
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

        if (converted)
            len = x;
    }

#ifdef DEBUG
    printf("DetectUricontentSetup: len %u\n", len);
#endif

    cd->uricontent = malloc(len);
    if (cd->uricontent == NULL)
        return -1;

    memcpy(cd->uricontent, str, len);
    cd->uricontent_len = len;
    cd->depth = 0;
    cd->offset = 0;
    cd->within = 0;
    cd->distance = 0;
    cd->flags = 0;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_URICONTENT;
    sm->ctx = (void *)cd;

    SigMatchAppend(s,m,sm);

    cd->id = uricontent_max_id;
    uricontent_max_id++;

    if (dubbed) free(str);
    return 0;

error:
    if (dubbed) free(str);
    if (cd) free(cd);
    if (sm) free(sm);
    return -1;
}


/*
 * TESTS
 */

int HttpUriTest01 (void) {
    u_int8_t *raw = (u_int8_t *)"/one/../two/";
    u_int16_t rawlen = strlen((char *)raw);
    u_int8_t *norm = (u_int8_t *)"/two/";
    u_int16_t normlen = strlen((char *)norm);
    int result = 0, r = 0;

    u_int8_t buf[1024];
    u_int16_t buflen = 0;

    r = HttpUriNormalize(raw, rawlen, buf, &buflen);

    if (buflen == normlen && memcmp(norm, buf, normlen) == 0)
        result = 1;

    //printf("HttpUriTest01: buflen %u, %s\n", buflen, buf);

//end:
    return result;
}

void HttpUriRegisterTests(void) {
    UtRegisterTest("HttpUriTest01", HttpUriTest01, 1);
}

