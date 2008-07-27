/* Multi Pattern Matcher 
 *
 * (c) 2008 Victor Julien
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "util-mpm.h"
#include "util-mpm-trie.h"

#include "util-unittest.h"

/*
 * TODO/IDEAS/XXX
 * - we know if we are interested in just the first match (simple content of
 *   also in more matches (within, distance, offset, depth, etc). Act on that.
 * - Do the search on demand.
 *
 */

/* prototypes to be exported */
void TrieInitCtx(MpmCtx *mpm_ctx);
void TrieThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx);
int TrieAddPattern(MpmCtx *mpm_ctx, u_int8_t *key, u_int16_t keylen, u_int32_t id);
int TrieAddPatternNocase(MpmCtx *mpm_ctx, u_int8_t *key, u_int16_t keylen, u_int32_t id);
u_int32_t TrieSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int8_t *buf, u_int16_t buflen);
void TriePrintInfo(MpmCtx *mpm_ctx);
void TriePrintThreadInfo(MpmThreadCtx *mpm_ctx);
void TrieRegisterTests(void);

/* uppercase to lowercase conversion lookup table */
static u_int8_t lowercasetable[256];
/* marco to do the actual lookup */
#define trie_tolower(c) lowercasetable[(c)]

void MpmTrieRegister (void) {
    mpm_table[MPM_TRIE].name = "trie";
    mpm_table[MPM_TRIE].InitCtx = TrieInitCtx;
    mpm_table[MPM_TRIE].InitThreadCtx = TrieThreadInitCtx;
    mpm_table[MPM_TRIE].AddPattern = TrieAddPattern;
    mpm_table[MPM_TRIE].AddPatternNocase = TrieAddPatternNocase;
    mpm_table[MPM_TRIE].Prepare = NULL;
    mpm_table[MPM_TRIE].Search = TrieSearch;
    mpm_table[MPM_TRIE].Cleanup = MpmMatchCleanup;
    mpm_table[MPM_TRIE].PrintCtx = TriePrintInfo;
    mpm_table[MPM_TRIE].PrintThreadCtx = TriePrintThreadInfo;
    mpm_table[MPM_TRIE].RegisterUnittests = TrieRegisterTests;

    /* create table for O(1) lowercase conversion lookup */
    u_int8_t c = 0;
    for ( ; c < 255; c++) {
       if (c >= 'A' && c <= 'Z')
           lowercasetable[c] = (c + ('a' - 'A'));
       else
           lowercasetable[c] = c;
    }
}

/*
 * function implementations
 */


/* append an endmatch to a character node
 *
 * Only used in the initialization phase */
static void TrieEndMatchAppend(MpmCtx *mpm_ctx, TrieCharacter *c, u_int32_t id)
{
    MpmEndMatch *em = MpmAllocEndMatch(mpm_ctx);
    if (em == NULL) {
        printf("ERROR: TrieAllocEndMatch failed\n");
        return;
    }

    em->id = id;

    if (c->em == NULL) {
        c->em = em;
        return;
    }

    MpmEndMatch *m = c->em;
    while (m->next) {
        m = m->next;
    }
    m->next = em;
}

/* allocate a character node
 *
 * Only used in the initialization phase */
static TrieCharacter *TrieAllocCharacter (MpmCtx *mpm_ctx)
{
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;

    TrieCharacter *c = malloc(sizeof(TrieCharacter));
    if (c == NULL)
        return NULL;

    memset(c, 0, sizeof(TrieCharacter));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(TrieCharacter);

    trie_ctx->characters++;
    return c;
}

static void TrieFreeCharacter (MpmCtx *mpm_ctx, TrieCharacter *c) {
    if (c != NULL) {
        int i = 0;
        for (i = 0; i < 256; i++) {
             TrieFreeCharacter(mpm_ctx, c->nc[i]);
        }

        MpmEndMatchFreeAll(mpm_ctx,c->em);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(TrieCharacter);
        free(c);
    }
}

/* add a keyword to the search tree
 *
 * Only used in the initialization phase */
static int DoTrieAddPattern(MpmCtx *mpm_ctx, TrieCharacter *c,
            u_int8_t *key, u_int16_t keylen, u_int32_t id, char nocase)
{
#ifdef DEBUG
    /* DEBUG */
    { u_int16_t i;
    for (i = 0; i < keylen; i++) {
        printf("TrieAddPattern: ");
        if (isprint(key[i])) {
            printf("%c", key[i]);
        } else {
            printf("\\x%02u", key[i]);
        }
    printf(" (id %u)\n", id); }
    }
#endif

    if (keylen > mpm_ctx->maxlen)
        mpm_ctx->maxlen = keylen;
    if (mpm_ctx->minlen == 0)
        mpm_ctx->minlen = keylen;
    if (keylen < mpm_ctx->minlen)
        mpm_ctx->minlen = keylen;

    u_int16_t i;
    u_int8_t ch;
    u_int16_t lenleft = 0;

    /* ADD PATTERN */
    for (i = 0, lenleft = keylen; i < keylen; i++, lenleft--) {

        if (nocase) ch = trie_tolower(key[i]); /* for nocase, add keywords in lowercase */
        else        ch = key[i];

        if (c->nc[ch] == NULL) {
           // printf("TrieAddPattern: Addending new Character for \\x%02u\n", ch);

           c->nc[ch] = TrieAllocCharacter(mpm_ctx);
           if (c->nc[ch] == NULL) {
               printf("ERROR: TrieAllocCharacter failed\n");
               return -1;
           }
           c->nc[ch]->min_matchlen_left = lenleft;
        } else {
           if (lenleft < c->nc[ch]->min_matchlen_left)
               c->nc[ch]->min_matchlen_left = lenleft;

           // printf("TrieAddPattern: Using existing Character for \\x%02u\n", ch);
        }

        /* set the endmatch */
        if (i == keylen - 1) {
            // printf("TrieAddPattern: last char of keyword, now append an EndMatch\n");
            TrieEndMatchAppend(mpm_ctx, c->nc[ch], id);
        }

        c = c->nc[ch];
    }

    if (id > mpm_ctx->max_pattern_id)
        mpm_ctx->max_pattern_id = id;

    return 0;
}

int TrieAddPattern(MpmCtx *mpm_ctx, u_int8_t *key, u_int16_t keylen, u_int32_t id) {
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;

    trie_ctx->keywords++;

    return(DoTrieAddPattern(mpm_ctx, &trie_ctx->root, key, keylen, id, 0 /* no nocase */));
}

int TrieAddPatternNocase(MpmCtx *mpm_ctx, u_int8_t *key, u_int16_t keylen, u_int32_t id) {
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;

    trie_ctx->nocase_keywords++;

    return(DoTrieAddPattern(mpm_ctx, &trie_ctx->nocase_root, key, keylen, id, 1 /* nocase */));
}

static void TrieDoPrint(TrieCharacter *c, int depth)
{
    int d;
    u_int8_t i;
    for (i = 0; i < 255; i++) {
        if (c->nc[i] != NULL) {
            for (d = depth; d; d--) printf(" ");
            if (isprint(i)) printf("%c", i);
            else printf("\\x%02u", i);

            printf("[%u] ", c->nc[i]->min_matchlen_left);

            if (c->nc[i]->em != NULL) {
                MpmEndMatch *em = c->nc[i]->em;
                while (em) {
                    printf("* (%u) ", em->id);
                    em = em->next;
                }
                printf("\n");
            }
            else printf("\n");

            TrieDoPrint(c->nc[i], depth+1);
        }
    }
}

void TriePrintTree(TrieCharacter *root)
{
    TrieDoPrint(root,0);
}

/* allocate a partial match
 *
 * used at search runtime */
static TriePartialMatch *TrieAllocPartialMatch (MpmThreadCtx *trie_thread_ctx)
{
    TriePartialMatch *pm = malloc(sizeof(TriePartialMatch));
    if (pm == NULL) {
        return NULL;
    }

    trie_thread_ctx->memory_cnt++;
    trie_thread_ctx->memory_size += sizeof(TriePartialMatch);

    return pm;
}

/* dequeue from pmlist */
#define MPM_PM_DEQUEUE(pmlist,item) { \
    if ((item)->prev != NULL) (item)->prev->next = (item)->next; \
    if ((item)->next != NULL) (item)->next->prev = (item)->prev; \
    if ((item) == (pmlist)) (pmlist) = (item)->next; \
    (item)->next = NULL; \
    (item)->prev = NULL; \
}

/* enqueue into pmlist */
#define MPM_PM_ENQUEUE(list,item) { \
    if ((list) == NULL) { \
        (list) = (item); \
        (item)->prev = NULL; \
        (item)->next = NULL; \
    } else { \
        (list)->prev = (item); \
        (item)->next = (list); \
        (item)->prev = NULL; \
        (list) = (item); \
    } \
}

/* enqueue in spare list */
#define MPM_SPARE_ENQUEUE(sparelist,item) { \
    if ((sparelist)->top != NULL) { \
        (item)->next = (sparelist)->top; \
        (sparelist)->top->prev = (item); \
        (sparelist)->top = (item); \
    } else { \
        (sparelist)->top = (item); } \
}

/* dequeue from spare list, or allocate a new pm */
static inline TriePartialMatch *
TrieSpareDequeue (MpmThreadCtx *mpm_thread_ctx, TriePartialMatchList *q)
{
    TriePartialMatch *p = q->top;
    if (p == NULL)
        return TrieAllocPartialMatch(mpm_thread_ctx);

    if (q->top->next != NULL) {
        q->top = q->top->next;
        q->top->prev = NULL;
    } else {
        q->top = NULL;
    }

    return p;
}


#define MAX_PREPEEK 5

static inline u_int32_t
TrieSearchCharNocase(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                     TrieThreadCtx *trie_thread_ctx, TrieCharacter *c,
                     TriePartialMatch **qpm, u_int8_t ch)
{
    TriePartialMatch *tmppm, *tpm;

    //printf("TrieSearchChar: ch ");
    //if (isprint(ch)) printf("%c", ch);
    //else printf("%02X", ch);
    //printf("\n");

    #ifdef MPM_DBG_PERF
    trie_thread_ctx->searchchar_nocase_cnt++;
    #endif /* MPM_DBG_PERF */

    /* First see if any of our partial matches is happy with
     * the new character. */
    for (tmppm = *qpm; tmppm != NULL; ) {
        #ifdef MPM_DBG_PERF
        trie_thread_ctx->searchchar_nocase_pmloop_cnt++;
        #endif /* MPM_DBG_PERF */

        if (tmppm->c->nc[ch] != NULL) {
            /* This PM is happy, lets see if it's done */
            MpmEndMatch *em = tmppm->c->nc[ch]->em;
            if (em != NULL) {
                for (; em != NULL; em = em->next) {
                    MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],
                                   trie_thread_ctx->buf - trie_thread_ctx->bufmin);

                    //printf("NOCASE MATCH! id %u, matched at offset %u, char %c\n", em->id,
                    //    trie_thread_ctx->buf - mpm_thread_ctx->bufmin, *mpm_thread_ctx->buf);
                    mpm_thread_ctx->matches++;
                }

                tpm = tmppm->next;
                MPM_PM_DEQUEUE(*qpm,tmppm);
                MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
                tmppm = tpm;
            /* So far so good, but not yet done. */
            } else {
                tmppm->c = tmppm->c->nc[ch];
                tmppm = tmppm->next;
            }
        } else {
            /* No match, so this partial match can be removed
             * as it will never be able to match anymore. */
            tpm = tmppm->next;
            MPM_PM_DEQUEUE(*qpm,tmppm);
            MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
            tmppm = tpm;
        }
    }

    if (c->nc[ch] != NULL) {
        //printf("TrieSearchChar: c->nc[ch] != NULL\n");
        /* Match at root, so we may be at the start of a match
         * 
         * First check if we may be looking for a single char
         * match. In that case we have no need for creating a 
         * partial match. */
        MpmEndMatch *em = c->nc[ch]->em;
        if (em != NULL) {
            #ifdef MPM_DBG_PERF
            trie_thread_ctx->searchchar_nocase_matchroot_cnt++;
            #endif /* MPM_DBG_PERF */

            for (; em != NULL; em = em->next) {
                MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],
                               trie_thread_ctx->buf - trie_thread_ctx->bufmin);
                //printf("NOCASE MATCH @search root! id %u, matched at offset %u, char %c\n", em->id,
                //    trie_thread_ctx->buf - mpm_thread_ctx->bufmin, *mpm_thread_ctx->buf);
                mpm_thread_ctx->matches++;
            }
        /* Setup a partial match, unless we are at the end of
         * the buffer. */
        } else if (trie_thread_ctx->buf != trie_thread_ctx->buflast) {
            /* quick look forward, if the next doesn't match don't
             * create a new patial match */
            TrieCharacter *tc;
            int i = 1; /* start at offset 1 */

            for (tc = c->nc[ch]->nc[trie_tolower(*(trie_thread_ctx->buf+i))];
                 tc != NULL && i < MAX_PREPEEK && trie_thread_ctx->buf+i <= trie_thread_ctx->buflast;
                 i++, tc = tc->nc[trie_tolower(*(trie_thread_ctx->buf+i))])
            {
                #ifdef MPM_DBG_PERF
                trie_thread_ctx->searchchar_nocase_prepeek_cnt++;
                #endif /* MPM_DBG_PERF */

                /* check if we match here already */
                MpmEndMatch *nem = tc->em;
                //printf("TrieSearchChar: i %d, tc %p, nem %p\n", i, tc, nem);
                if (nem != NULL) {
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_nocase_prepeekmatch_cnt++;
                    #endif /* MPM_DBG_PERF */

                    for (; nem != NULL; nem = nem->next) {
                         MpmMatchAppend(mpm_thread_ctx, nem, &mpm_thread_ctx->match[nem->id],
                                        trie_thread_ctx->buf - trie_thread_ctx->bufmin);
                         //printf("MATCH! id %u, matched at offset %u\n", nem->id,
                         //    trie_thread_ctx->buf - mpm_thread_ctx->bufmin);
                         mpm_thread_ctx->matches++;
                    }
                } else if ((trie_thread_ctx->buf+i) == trie_thread_ctx->buflast) {
                    //printf("TrieSearchChar: (trie_thread_ctx->buf+i) == mpm_thread_ctx->buflast: %p+%d == %p\n", mpm_thread_ctx->buf, i, mpm_thread_ctx->buflast);
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_nocase_prepeek_nomatchnobuf_cnt++;
                    #endif /* MPM_DBG_PERF */

                    tc = NULL;
                    break;
                } else if (tc->min_matchlen_left > (trie_thread_ctx->buflast - (trie_thread_ctx->buf+i-1))) {
                    //printf("TrieSearchChar: tc->min_matchlen_left > (trie_thread_ctx->buflast - (mpm_thread_ctx->buf+i-1)): %u > %p - (%p + %d - 1 = %p) = %d\n", tc->min_matchlen_left, mpm_thread_ctx->buflast, mpm_thread_ctx->buf, i, mpm_thread_ctx->buf+i-1, (mpm_thread_ctx->buflast - (mpm_thread_ctx->buf+i-1)));
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_nocase_prepeek_nomatchbuflen_cnt++;
                    #endif /* MPM_DBG_PERF */

                    tc = NULL;
                    break;
                }
            }
            /* if we still have a tc, setup a pm */
            if (tc != NULL) {
                #ifdef MPM_DBG_PERF
                trie_thread_ctx->searchchar_nocase_pmcreate_cnt++;
                #endif /* MPM_DBG_PERF */

                tpm = TrieSpareDequeue(mpm_thread_ctx, &trie_thread_ctx->spare_queue);
                if (tpm != NULL) {
                    tpm->c = c->nc[ch];
                    MPM_PM_ENQUEUE(*qpm,tpm);
                }
            }
        }
    }
    return 0;
}

static inline u_int32_t
TrieSearchChar(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
               TrieThreadCtx *trie_thread_ctx, TrieCharacter *c,
               TriePartialMatch **qpm, u_int8_t ch)
{
    TriePartialMatch *tmppm, *tpm;

    #ifdef MPM_DBG_PERF
    trie_thread_ctx->searchchar_cnt++;
    #endif /* MPM_DBG_PERF */

//    printf("TrieSearchChar: ch ");
//    if (isprint(ch)) printf("%c", ch);
//    else printf("%02X", ch);
//    printf("\n");

    /* First see if any of our partial matches is happy with
     * the new character. */
    for (tmppm = *qpm; tmppm != NULL; ) {
        #ifdef MPM_DBG_PERF
        trie_thread_ctx->searchchar_pmloop_cnt++;
        #endif /* MPM_DBG_PERF */

        if (tmppm->c->nc[ch] != NULL) {
            /* This PM is happy, lets see if it's done */
            MpmEndMatch *em = tmppm->c->nc[ch]->em;
            if (em != NULL) {
                for (; em != NULL; em = em->next) {
                    MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],
                                   trie_thread_ctx->buf - trie_thread_ctx->bufmin);

                    //printf("MATCH! id %u, matched at offset %u, char %c\n", em->id,
                    //    trie_thread_ctx->buf - mpm_thread_ctx->bufmin, *mpm_thread_ctx->buf);
                    mpm_thread_ctx->matches++;
                }

                tpm = tmppm->next;
                MPM_PM_DEQUEUE(*qpm,tmppm);
                MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
                tmppm = tpm;
            /* So far so good, but not yet done. */
            } else {
                tmppm->c = tmppm->c->nc[ch];
                tmppm = tmppm->next;
            }
        } else {
            /* No match, so this partial match can be removed
             * as it will never be able to match anymore. */
            tpm = tmppm->next;
            MPM_PM_DEQUEUE(*qpm,tmppm);
            MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
            tmppm = tpm;
        }
    }

    if (c->nc[ch] != NULL) {
//        printf("TrieSearchChar: c->nc[ch] != NULL\n");
        /* Match at root, so we may be at the start of a match
         * 
         * First check if we may be looking for a single char
         * match. In that case we have no need for creating a 
         * partial match. */
        MpmEndMatch *em = c->nc[ch]->em;
        if (em != NULL) {
            #ifdef MPM_DBG_PERF
            trie_thread_ctx->searchchar_matchroot_cnt++;
            #endif /* DBG_MPM_PERF */

            for (; em != NULL; em = em->next) {
                MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],
                               trie_thread_ctx->buf - trie_thread_ctx->bufmin);
//                printf("MATCH! @search root id %u, matched at offset %u, char %c\n", em->id,
//                    trie_thread_ctx->buf - mpm_thread_ctx->bufmin, *mpm_thread_ctx->buf);
                mpm_thread_ctx->matches++;
            }
        /* Setup a partial match, unless we are at the end of
         * the buffer. */
        } else if (trie_thread_ctx->buf != trie_thread_ctx->buflast) {
            /* quick look forward, if the next doesn't match don't
             * create a new patial match */
            TrieCharacter *tc;
            int i = 1; /* start at offset 1 */

            for (tc = c->nc[ch]->nc[*(trie_thread_ctx->buf+i)];
                 tc != NULL && i < MAX_PREPEEK && trie_thread_ctx->buf+i <= trie_thread_ctx->buflast;
                 i++, tc = tc->nc[*(trie_thread_ctx->buf+i)])
            {
                #ifdef MPM_DBG_PERF
                trie_thread_ctx->searchchar_prepeek_cnt++;
                #endif /* MPM_DBG_PERF */

                /* check if we match here already */
                MpmEndMatch *nem = tc->em;
//                printf("TrieSearchChar: i %d ", i);
//                printf("tc %p ", tc);
//                printf("(left %u) ", tc->min_matchlen_left);
//                printf("*(trie_thread_ctx->buf+i+1) %02X ", *(mpm_thread_ctx->buf+i));
//                printf("tc->nc[*(trie_thread_ctx->buf+i+1)] %p ", tc->nc[*(mpm_thread_ctx->buf+i)]);
//                printf("nem %p\n", nem);
                if (nem != NULL) {
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_prepeekmatch_cnt++;
                    #endif /* MPM_DBG_PERF */

                    for (; nem != NULL; nem = nem->next) {
                         MpmMatchAppend(mpm_thread_ctx, nem, &mpm_thread_ctx->match[nem->id],
                                        trie_thread_ctx->buf - trie_thread_ctx->bufmin);
//                         printf("MATCH! id %u, matched at offset %u\n", nem->id,
//                             trie_thread_ctx->buf - mpm_thread_ctx->bufmin);
                         mpm_thread_ctx->matches++;
                    }
                } else if ((trie_thread_ctx->buf+i) == trie_thread_ctx->buflast) {
//                    printf("TrieSearchChar: (trie_thread_ctx->buf+i) == mpm_thread_ctx->buflast: %p+%d == %p\n", mpm_thread_ctx->buf, i, mpm_thread_ctx->buflast);
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_prepeek_nomatchnobuf_cnt++;
                    #endif /* MPM_DBG_PERF */

                    tc = NULL;
                    break;
                } else if (tc->min_matchlen_left > (trie_thread_ctx->buflast - (trie_thread_ctx->buf+i-1))) {
//                    printf("TrieSearchChar: tc->min_matchlen_left > (trie_thread_ctx->buflast - (mpm_thread_ctx->buf+i-1)): %u > %p - (%p + %d - 1 = %p) = %d\n", tc->min_matchlen_left, mpm_thread_ctx->buflast, mpm_thread_ctx->buf, i, mpm_thread_ctx->buf+i-1, (mpm_thread_ctx->buflast - (mpm_thread_ctx->buf+i-1)));
                    #ifdef MPM_DBG_PERF
                    trie_thread_ctx->searchchar_prepeek_nomatchbuflen_cnt++;
                    #endif /* MPM_DBG_PERF */

                    tc = NULL;
                    break;
                }
            }
            /* if we still have a tc, setup a pm */
            if (tc != NULL) {
                #ifdef MPM_DBG_PERF
                trie_thread_ctx->searchchar_pmcreate_cnt++;
                #endif /* MPM_DBG_PERF */

                tpm = TrieSpareDequeue(mpm_thread_ctx, &trie_thread_ctx->spare_queue);
                if (tpm != NULL) {
                    tpm->c = c->nc[ch];
                    MPM_PM_ENQUEUE(*qpm,tpm);
                }
            }
        }
    }
    return 0;
}

/* TrieSearchOffsetDepth
 *
 * Returns:
 * - number of match occurences in total (including multiple matches
 *   of the same keyword or even duplicate keywords).
 * - 0 if no match at all
 *
 */
u_int32_t
TrieSearchOffsetDepth(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
           u_int8_t *buf, u_int16_t buflen, u_int16_t offset, u_int16_t depth)
{
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;
    TrieThreadCtx *trie_thread_ctx = (TrieThreadCtx *)mpm_thread_ctx->ctx;

    trie_thread_ctx->buf = buf + offset;
    trie_thread_ctx->bufmin = buf + offset;

    if (depth) trie_thread_ctx->bufmax = buf + depth;
    else       trie_thread_ctx->bufmax = buf + buflen;

    trie_thread_ctx->buflast = trie_thread_ctx->bufmax - 1;
    TriePartialMatch *tmppm, *tpm;
    mpm_thread_ctx->matches = 0;

#ifdef MPM_DBG_PERF
    trie_thread_ctx->mpmsearchoffsetdepth++;
#endif /* MPM_DBG_PERF */

    /* go through the buffer in one swell swoop and do our
     * matching magic. Test both case and nocase together
     * to prevent having to go through the buf twice */
    for ( ; trie_thread_ctx->buf != trie_thread_ctx->bufmax;
            trie_thread_ctx->buf++) {
        TrieSearchChar(mpm_ctx, mpm_thread_ctx, trie_thread_ctx,
                   &trie_ctx->root, &trie_thread_ctx->pmqueue,
                   *trie_thread_ctx->buf);
        TrieSearchCharNocase(mpm_ctx, mpm_thread_ctx, trie_thread_ctx,
                   &trie_ctx->nocase_root, &trie_thread_ctx->nocase_pmqueue,
                   trie_tolower(*trie_thread_ctx->buf));
    }

    /* We reached the end of the buffer, clean up leftover
     * partial matches that didn't match. */
    for (tmppm = trie_thread_ctx->pmqueue; tmppm != NULL; ) {
        tpm = tmppm->next;
        MPM_PM_DEQUEUE(trie_thread_ctx->pmqueue,tmppm);
        MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
        tmppm = tpm;
    }
    for (tmppm = trie_thread_ctx->nocase_pmqueue; tmppm != NULL; ) {
        tpm = tmppm->next;
        MPM_PM_DEQUEUE(trie_thread_ctx->nocase_pmqueue,tmppm);
        MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
        tmppm = tpm;
    }

    return mpm_thread_ctx->matches;
}

/* TrieSearch
 *
 * Returns:
 * - number of match occurences in total (including multiple matches
 *   of the same keyword or even duplicate keywords).
 * - 0 if no match at all
 *
 */
u_int32_t
TrieSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
           u_int8_t *buf, u_int16_t buflen)
{
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;
    TrieThreadCtx *trie_thread_ctx = (TrieThreadCtx *)mpm_thread_ctx->ctx;

    trie_thread_ctx->buf = buf;
    trie_thread_ctx->bufmin = buf;
    trie_thread_ctx->bufmax = buf + buflen;
    trie_thread_ctx->buflast = buf + buflen - 1;
    TriePartialMatch *tmppm, *tpm;
    mpm_thread_ctx->matches = 0;

#ifdef MPM_DBG_PERF
    trie_thread_ctx->mpmsearch++;
#endif /* MPM_DBG_PERF */

    /* go through the buffer in one swell swoop and do our
     * matching magic. Test both case and nocase together
     * to prevent having to go through the buf twice */
    for ( ; trie_thread_ctx->buf != trie_thread_ctx->bufmax;
            trie_thread_ctx->buf++) {
        TrieSearchChar(mpm_ctx, mpm_thread_ctx, trie_thread_ctx,
                   &trie_ctx->root, &trie_thread_ctx->pmqueue,
                   *trie_thread_ctx->buf);
        TrieSearchCharNocase(mpm_ctx, mpm_thread_ctx, trie_thread_ctx,
                   &trie_ctx->nocase_root, &trie_thread_ctx->nocase_pmqueue,
                   trie_tolower(*trie_thread_ctx->buf));
    }

    /* We reached the end of the buffer, clean up leftover
     * partial matches that didn't match. */
    for (tmppm = trie_thread_ctx->pmqueue; tmppm != NULL; ) {
        tpm = tmppm->next;
        MPM_PM_DEQUEUE(trie_thread_ctx->pmqueue,tmppm);
        MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
        tmppm = tpm;
    }
    for (tmppm = trie_thread_ctx->nocase_pmqueue; tmppm != NULL; ) {
        tpm = tmppm->next;
        MPM_PM_DEQUEUE(trie_thread_ctx->nocase_pmqueue,tmppm);
        MPM_SPARE_ENQUEUE(&trie_thread_ctx->spare_queue,tmppm);
        tmppm = tpm;
    }

    return mpm_thread_ctx->matches;
}

void TriePrintThreadInfo(MpmThreadCtx *mpm_ctx) {
    printf("\nMPM Trie thread stats:\n");
    printf("Memory blocks:   %u\n", mpm_ctx->memory_cnt);
    printf("Memory size:     %u\n", mpm_ctx->memory_size);
#ifdef MPM_DBG_PERF
    TrieThreadCtx *trie_ctx = (TrieThreadCtx *)mpm_ctx->ctx;

    printf("triesearch                                   %llu\n", mpm_ctx->mpmsearch);
    printf("triesearchoffsetdepth                        %llu\n", mpm_ctx->mpmsearchoffsetdepth);
    printf("searchchar_cnt                              %llu\n", trie_ctx->searchchar_cnt);
    printf("searchchar_pmloop_cnt                       %llu\n", trie_ctx->searchchar_pmloop_cnt);
    printf("searchchar_nocase_cnt                       %llu\n", trie_ctx->searchchar_nocase_cnt);
    printf("searchchar_nocase_pmloop_cnt                %llu\n", trie_ctx->searchchar_nocase_pmloop_cnt);
    printf("searchchar_nocase_prepeek_cnt               %llu\n", trie_ctx->searchchar_nocase_prepeek_cnt);
    printf("searchchar_nocase_prepeekmatch_cnt          %llu\n", trie_ctx->searchchar_nocase_prepeekmatch_cnt);
    printf("searchchar_nocase_prepeek_nomatchnobuf_cnt  %llu\n", trie_ctx->searchchar_nocase_prepeek_nomatchnobuf_cnt);
    printf("searchchar_nocase_prepeek_nomatchbuflen_cnt %llu\n", trie_ctx->searchchar_nocase_prepeek_nomatchbuflen_cnt);
    printf("searchchar_nocase_pmcreate_cnt              %llu\n", trie_ctx->searchchar_nocase_pmcreate_cnt);
    printf("searchchar_matchroot_cnt                    %llu\n", trie_ctx->searchchar_matchroot_cnt);
    printf("searchchar_prepeek_cnt                      %llu\n", trie_ctx->searchchar_prepeek_cnt);
    printf("searchchar_prepeekmatch_cnt                 %llu\n", trie_ctx->searchchar_prepeekmatch_cnt);
    printf("searchchar_prepeek_nomatchnobuf_cnt         %llu\n", trie_ctx->searchchar_prepeek_nomatchnobuf_cnt);
    printf("searchchar_prepeek_nomatchbuflen_cnt        %llu\n", trie_ctx->searchchar_prepeek_nomatchbuflen_cnt);
    printf("searchchar_pmcreate_cnt                     %llu\n", trie_ctx->searchchar_pmcreate_cnt);
#endif /* MPM_DBG_PERF */
    printf("\n");
}

void TriePrintInfo(MpmCtx *mpm_ctx) {
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;

    printf("\nMPM Trie stats:\n");
    printf("Patterns:        %u\n", trie_ctx->keywords);
    printf("Patterns Nocase: %u\n", trie_ctx->nocase_keywords);
    printf(" -shortest len:  %u\n", mpm_ctx->minlen);
    printf(" -longest len:   %u\n", mpm_ctx->maxlen);
    printf("Characters:      %u\n", trie_ctx->characters);
    printf("EndMatches:      %u\n", mpm_ctx->endmatches);
    printf("Memory blocks:   %u\n", mpm_ctx->memory_cnt);
    printf("Memory size:     %u\n", mpm_ctx->memory_size);
}

void TrieInitCtx(MpmCtx *mpm_ctx)
{
    memset(mpm_ctx, 0, sizeof(MpmCtx));

    mpm_ctx->ctx = malloc(sizeof(TrieCtx));
    if (mpm_ctx->ctx == NULL)
        return;

    memset(mpm_ctx->ctx, 0, sizeof(TrieCtx));
}

void TrieDestroyCtx(MpmCtx *mpm_ctx) {
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx->ctx;
    if (trie_ctx != NULL) {
        int i;
        for (i = 0; i < 256; i++) {
            TrieFreeCharacter(mpm_ctx, trie_ctx->root.nc[i]);
            TrieFreeCharacter(mpm_ctx, trie_ctx->nocase_root.nc[i]);
        }

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(TrieCtx);
        free(trie_ctx);
        mpm_ctx->ctx = NULL;
    }
}

void TrieThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx) {
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = malloc(sizeof(TrieThreadCtx));
    if (mpm_thread_ctx->ctx == NULL)
        return;

    memset(mpm_thread_ctx->ctx, 0, sizeof(TrieThreadCtx));

    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(TrieThreadCtx);

    /* alloc an array with the size of _all_ keys in all instances.
     * this is done so the detect engine won't have to care about
     * what instance it's looking up in. The matches all have a
     * unique id and is the array lookup key at the same time */
    u_int32_t keys = mpm_ctx->max_pattern_id + 1;
    if (keys) {
        mpm_thread_ctx->match = malloc(keys * sizeof(MpmMatchBucket));
        if (mpm_thread_ctx->match == NULL) {
            printf("ERROR: could not setup memory for pattern matcher: %s\n", strerror(errno));
            exit(1);
        }
        memset(mpm_thread_ctx->match, 0, keys * sizeof(MpmMatchBucket));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += (keys * sizeof(MpmMatchBucket));
    }
}

void TrieThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx) {
    TrieThreadCtx *trie_ctx = (TrieThreadCtx *)mpm_thread_ctx->ctx;
    if (trie_ctx) {
        if (mpm_thread_ctx->match != NULL) {
            mpm_thread_ctx->memory_cnt--;
            mpm_thread_ctx->memory_size -= ((mpm_ctx->max_pattern_id + 1) * sizeof(MpmMatchBucket));
            free(mpm_thread_ctx->match);
        }

        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(TrieThreadCtx);
        free(mpm_thread_ctx->ctx);
    }

    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->sparelist);
    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->qlist);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */


int TrieTestInitCtx01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    TrieInitCtx(&mpm_ctx);

    if (mpm_ctx.ctx != NULL)
        result = 1;

    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitCtx02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    TrieInitCtx(&mpm_ctx);

    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx; 

    if (trie_ctx->characters == 0)
        result = 1;

    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitCtx03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    if (mpm_ctx.Search == TrieSearch)
        result = 1;

    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestThreadInitCtx01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    if (mpm_thread_ctx.memory_cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestThreadInitCtx02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    TrieThreadCtx *trie_thread_ctx = (TrieThreadCtx *)mpm_thread_ctx.ctx;

    if (trie_thread_ctx->buf == NULL)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    int ret = TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);
    if (ret == 0)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx;

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);

    if (trie_ctx->root.nc['a'] != NULL)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx;

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);

    if (trie_ctx->root.nc['a']->min_matchlen_left == 4)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx;

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);

    if (trie_ctx->nocase_root.nc['a'] != NULL)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx;

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"Abcd", 4, 1234);

    if (trie_ctx->root.nc['A'] != NULL)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern06 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieCtx *trie_ctx = (TrieCtx *)mpm_ctx.ctx;

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);

    if (trie_ctx->root.nc['a'] != NULL &&
        trie_ctx->root.nc['a']->nc['b'] != NULL &&
        trie_ctx->root.nc['a']->nc['b']->nc['c'] != NULL &&
        trie_ctx->root.nc['a']->nc['b']->nc['c']->nc['d'] != NULL)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestInitAddPattern07 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1234);

    if (mpm_ctx.max_pattern_id == 1234)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcd", 4);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abce", 4);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"bcde", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"efgh", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch06 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"eFgH", 4, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdEfGh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch07 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"abcd", 4, 0);
    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"eFgH", 4, 1);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdEfGh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch08 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"abcde", 5, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"bcde",  4, 1);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch09 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"ab", 2, 0);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"ab", 2);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch10 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"bc", 2, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"gh", 2, 1);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch11 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"a", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"d", 1, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"h", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch12 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"A", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"d", 1, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch13 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"a", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"h", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch14 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"A", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    u_int32_t cnt = TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch15 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPattern(&mpm_ctx, (u_int8_t *)"A", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);

    u_int32_t len = mpm_thread_ctx.match[1].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

int TrieTestSearch16 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_TRIE);

    TrieAddPatternNocase(&mpm_ctx, (u_int8_t *)"A", 1, 0);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1);
    TrieAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 2);
    TrieThreadInitCtx(&mpm_ctx, &mpm_thread_ctx);

    TrieSearch(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    TrieThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    TrieDestroyCtx(&mpm_ctx);
    return result;
}

void TrieRegisterTests(void) {
    UtRegisterTest("TrieTestInitCtx01", TrieTestInitCtx01, 1);
    UtRegisterTest("TrieTestInitCtx02", TrieTestInitCtx02, 1);
    UtRegisterTest("TrieTestInitCtx03", TrieTestInitCtx03, 1);

    UtRegisterTest("TrieTestThreadInitCtx01", TrieTestThreadInitCtx01, 1);
    UtRegisterTest("TrieTestThreadInitCtx02", TrieTestThreadInitCtx02, 1);

    UtRegisterTest("TrieTestInitAddPattern01", TrieTestInitAddPattern01, 1);
    UtRegisterTest("TrieTestInitAddPattern02", TrieTestInitAddPattern02, 1);
    UtRegisterTest("TrieTestInitAddPattern03", TrieTestInitAddPattern03, 1);
    UtRegisterTest("TrieTestInitAddPattern04", TrieTestInitAddPattern04, 1);
    UtRegisterTest("TrieTestInitAddPattern05", TrieTestInitAddPattern05, 1);
    UtRegisterTest("TrieTestInitAddPattern06", TrieTestInitAddPattern06, 1);
    UtRegisterTest("TrieTestInitAddPattern07", TrieTestInitAddPattern07, 1);

    UtRegisterTest("TrieTestSearch01", TrieTestSearch01, 1);
    UtRegisterTest("TrieTestSearch02", TrieTestSearch02, 1);
    UtRegisterTest("TrieTestSearch03", TrieTestSearch03, 1);
    UtRegisterTest("TrieTestSearch04", TrieTestSearch04, 1);
    UtRegisterTest("TrieTestSearch05", TrieTestSearch05, 1);
    UtRegisterTest("TrieTestSearch06", TrieTestSearch06, 1);
    UtRegisterTest("TrieTestSearch07", TrieTestSearch07, 1);
    UtRegisterTest("TrieTestSearch08", TrieTestSearch08, 1);
    UtRegisterTest("TrieTestSearch09", TrieTestSearch09, 1);
    UtRegisterTest("TrieTestSearch10", TrieTestSearch10, 1);
    UtRegisterTest("TrieTestSearch11", TrieTestSearch11, 1);
    UtRegisterTest("TrieTestSearch12", TrieTestSearch12, 1);
    UtRegisterTest("TrieTestSearch13", TrieTestSearch13, 1);
    UtRegisterTest("TrieTestSearch14", TrieTestSearch14, 1);
    UtRegisterTest("TrieTestSearch15", TrieTestSearch15, 1);
    UtRegisterTest("TrieTestSearch16", TrieTestSearch16, 1);
}
