#include "suricata-common.h"
#include "util-mpm.h"
#include "util-debug.h"

/* include pattern matchers */
#include "util-mpm-wumanber.h"
#include "util-mpm-b2g.h"
#include "util-mpm-b3g.h"

/** \brief Setup a pmq
  * \param pmq Pattern matcher queue to be initialized
  * \param maxid Max id to be matched on
  * \retval -1 error
  * \retval 0 ok
  */
int PmqSetup(PatternMatcherQueue *pmq, uint32_t maxid) {
    if (pmq == NULL)
        return -1;

    memset(pmq, 0, sizeof(PatternMatcherQueue));

    pmq->sig_id_array = malloc(maxid * sizeof(uint32_t));
    if (pmq->sig_id_array == NULL) {
        printf("ERROR: could not setup memory for pattern matcher: %s\n", strerror(errno));
        return -1;
    }
    memset(pmq->sig_id_array, 0, maxid * sizeof(uint32_t));
    pmq->sig_id_array_cnt = 0;

    /* lookup bitarray */
    pmq->sig_bitarray = malloc(maxid / 8 + 1);
    if (pmq->sig_bitarray == NULL) {
        printf("ERROR: could not setup memory for pattern matcher: %s\n", strerror(errno));
        return -1;
    }
    memset(pmq->sig_bitarray, 0, maxid / 8 + 1);

    return 0;
}

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 */
void PmqReset(PatternMatcherQueue *pmq) {
    int i;
    for (i = 0; i < pmq->sig_id_array_cnt; i++) {
        pmq->sig_bitarray[(pmq->sig_id_array[i] / 8)] &= ~(1<<(pmq->sig_id_array[i] % 8));
    }
    pmq->sig_id_array_cnt = 0;
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    if (pmq->sig_id_array != NULL) {
        free(pmq->sig_id_array);
        pmq->sig_id_array = NULL;
    }

    if (pmq->sig_bitarray != NULL) {
        free(pmq->sig_bitarray);
        pmq->sig_bitarray = NULL;
    }

    pmq->sig_id_array_cnt = 0;
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
    free(pmq);
}

/* cleanup list with all matches
 *
 * used at search runtime (or actually once per search) */
void
MpmMatchCleanup(MpmThreadCtx *thread_ctx) {
    SCLogDebug("mem %" PRIu32 "", thread_ctx->memory_size);

    MpmMatch *nxt;
    MpmMatch *m = thread_ctx->qlist;

    while (m != NULL) {
        nxt = m->qnext;

        /* clear the bucket */
        m->mb->top = NULL;
        m->mb->bot = NULL;
        m->mb->len = 0;

        thread_ctx->qlist = m->qnext;

        /* add to the spare list */
        if (thread_ctx->sparelist == NULL) {
            thread_ctx->sparelist = m;
            m->qnext = NULL;
        } else {
            m->qnext = thread_ctx->sparelist;
            thread_ctx->sparelist = m;
        }

        m = nxt;
    }

}

/** \brief allocate a match
 *
 * used at search runtime */
inline MpmMatch *
MpmMatchAlloc(MpmThreadCtx *thread_ctx) {
    MpmMatch *m = malloc(sizeof(MpmMatch));
    if (m == NULL)
        return NULL;

    thread_ctx->memory_cnt++;
    thread_ctx->memory_size += sizeof(MpmMatch);

    m->offset = 0;
    m->next = NULL;
    m->qnext = NULL;
    m->mb = NULL;
    return m;
}

/** \brief append a match to a bucket
 *
 * used at search runtime */
inline int
MpmMatchAppend(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, MpmEndMatch *em, MpmMatchBucket *mb, uint16_t offset, uint16_t patlen)
{
    /* don't bother looking at sigs that didn't match
     * when we scanned. There's no matching anyway. */
    if (pmq != NULL && pmq->mode == PMQ_MODE_SEARCH) {
        if (!(pmq->sig_bitarray[(em->sig_id / 8)] & (1<<(em->sig_id % 8))))
            return 0;
    }

    /* if our endmatch is set to a single match being enough,
       we're not going to add more if we already have one */
    if (em->flags & MPM_ENDMATCH_SINGLE && mb->len)
        return 0;

    /* check offset */
    if (offset < em->offset)
        return 0;

    /* check depth */
    if (em->depth && (offset+patlen) > em->depth)
        return 0;

    /* ok all checks passed, now append the match */
    MpmMatch *m;
    /* pull a match from the spare list */
    if (thread_ctx->sparelist != NULL) {
        m = thread_ctx->sparelist;
        thread_ctx->sparelist = m->qnext;
    } else {
        m = MpmMatchAlloc(thread_ctx);
        if (m == NULL)
            return 0;
    }

    m->offset = offset;
    m->mb = mb;
    m->next = NULL;
    m->qnext = NULL;

    /* append to the mb list */
    if (mb->bot == NULL) { /* empty list */
        mb->top = m;
        mb->bot = m;
    } else { /* more items in list */
        mb->bot->next = m;
        mb->bot = m;
    }

    mb->len++;

    /* put in the queue list */
    if (thread_ctx->qlist == NULL) { /* empty list */
        thread_ctx->qlist = m;
    } else { /* more items in list */
        m->qnext = thread_ctx->qlist;
        thread_ctx->qlist = m;
    }

    if (pmq != NULL) {
        /* make sure we only append a sig with a matching pattern once,
         * so we won't inspect it more than once. For this we keep a
         * bitarray of sig internal id's and flag each sig that matched */
        if (!(pmq->sig_bitarray[(em->sig_id / 8)] & (1<<(em->sig_id % 8)))) {
            /* flag this sig_id as being added now */
            pmq->sig_bitarray[(em->sig_id / 8)] |= (1<<(em->sig_id % 8));
            /* append the sig_id to the array with matches */
            pmq->sig_id_array[pmq->sig_id_array_cnt] = em->sig_id;
            pmq->sig_id_array_cnt++;
        }

        /* nosearch flag */
        if (pmq->mode == PMQ_MODE_SCAN && !(em->flags & MPM_ENDMATCH_NOSEARCH)) {
            pmq->searchable++;
        }
    }

    SCLogDebug("len %" PRIu32 " (offset %" PRIu32 ")", mb->len, m->offset);
    return 1;
}

void MpmMatchFree(MpmThreadCtx *ctx, MpmMatch *m) {
    ctx->memory_cnt--;
    ctx->memory_size -= sizeof(MpmMatch);
    free(m);
}

void MpmMatchFreeSpares(MpmThreadCtx *mpm_ctx, MpmMatch *m) {
    while(m) {
        MpmMatch *tm = m->qnext;
        MpmMatchFree(mpm_ctx, m);
        m = tm;
    }
}

/* allocate an endmatch
 *
 * Only used in the initialization phase */
MpmEndMatch *MpmAllocEndMatch (MpmCtx *ctx)
{
    MpmEndMatch *e = malloc(sizeof(MpmEndMatch));
    if (e == NULL)
        return NULL;

    memset(e, 0, sizeof(MpmEndMatch));

    ctx->memory_cnt++;
    ctx->memory_size += sizeof(MpmEndMatch);
    ctx->endmatches++;
    return e;
}

/**
 * \brief Return the pattern max length of a registered matcher
 * \retval 0 if it has no limit
 * \retval max_pattern_length of the specified matcher type
 * \retval -1 if the type is not registered return -1
 */
int32_t MpmMatcherGetMaxPatternLength(uint16_t matcher) {
    if (matcher < MPM_TABLE_SIZE && matcher >= 0)
        return mpm_table[matcher].max_pattern_length;
    else
        return -1;
}

void MpmEndMatchFree(MpmCtx *ctx, MpmEndMatch *em) {
    ctx->memory_cnt--;
    ctx->memory_size -= sizeof(MpmEndMatch);
    free(em);
}

void MpmEndMatchFreeAll(MpmCtx *mpm_ctx, MpmEndMatch *em) {
    while(em) {
        MpmEndMatch *tem = em->next;
        MpmEndMatchFree(mpm_ctx, em);
        em = tem;
    }
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher, uint32_t max_id) {
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx, max_id);
}

void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher) {
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx);
}

void MpmTableSetup(void) {
    memset(mpm_table, 0, sizeof(mpm_table));

    MpmWuManberRegister();
    MpmB2gRegister();
    MpmB3gRegister();
}

void MpmRegisterTests(void) {
#ifdef UNITTESTS
    uint16_t i;

    for (i = 0; i < MPM_TABLE_SIZE; i++) {
        if (mpm_table[i].RegisterUnittests != NULL) {
            mpm_table[i].RegisterUnittests();
        } else {
            printf("Warning: mpm %s has no unittest registration function...", mpm_table[i].name);
        }
    }
#endif
}

