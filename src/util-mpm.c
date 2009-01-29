
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "util-mpm.h"

/* include pattern matchers */
#include "util-mpm-trie.h"
#include "util-mpm-wumanber.h"
#include "util-mpm-b2g.h"
#include "util-mpm-b3g.h"

/* cleanup list with all matches
 *
 * used at search runtime (or actually once per search) */
void
MpmMatchCleanup(MpmThreadCtx *thread_ctx) {
#ifdef DEBUG
    printf("MpmMatchCleanup: mem %u\n", thread_ctx->memory_size);
#endif

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

/* allocate a match
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

/* append a match to a bucket
 *
 * used at search runtime */
inline int
MpmMatchAppend(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, MpmEndMatch *em, MpmMatchBucket *mb, u_int16_t offset, u_int16_t patlen)
{
    /* don't bother looking at sigs that didn't match
     * when we scanned. There's not matching anyway. */
    if (pmq != NULL && pmq->mode == PMQ_MODE_SEARCH) {
        if (!(pmq->sig_bitarray[(em->sig_id / 8)] & (1<<(em->sig_id % 8))))
            return 0;
    }

    /* XXX is this correct? */
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
            pmq->sig_bitarray[(em->sig_id / 8)] |= (1<<(em->sig_id % 8));
            pmq->sig_id_array[pmq->sig_id_array_cnt] = em->sig_id;
            pmq->sig_id_array_cnt++;
        }
    }

#ifdef DEBUG
    printf("MpmMatchAppend: len %u (offset %u)\n", mb->len, m->offset);

    MpmMatch *tmp = thread_ctx->qlist;
    while (tmp) {
        printf("tmp %p tmp->next %p\n", tmp, tmp->next);
        tmp = tmp->qnext;
    }
#endif

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

void MpmInitCtx (MpmCtx *mpm_ctx, u_int16_t matcher) {
    mpm_table[matcher].InitCtx(mpm_ctx);

    mpm_ctx->InitCtx              = mpm_table[matcher].InitCtx;
    mpm_ctx->InitThreadCtx        = mpm_table[matcher].InitThreadCtx;
    mpm_ctx->DestroyCtx           = mpm_table[matcher].DestroyCtx;
    mpm_ctx->DestroyThreadCtx     = mpm_table[matcher].DestroyThreadCtx;
    mpm_ctx->AddScanPattern       = mpm_table[matcher].AddScanPattern;
    mpm_ctx->AddScanPatternNocase = mpm_table[matcher].AddScanPatternNocase;
    mpm_ctx->AddPattern           = mpm_table[matcher].AddPattern;
    mpm_ctx->AddPatternNocase     = mpm_table[matcher].AddPatternNocase;
    mpm_ctx->Prepare              = mpm_table[matcher].Prepare;
    mpm_ctx->Scan                 = mpm_table[matcher].Scan;
    mpm_ctx->Search               = mpm_table[matcher].Search;
    mpm_ctx->PrintCtx             = mpm_table[matcher].PrintCtx;
    mpm_ctx->PrintThreadCtx       = mpm_table[matcher].PrintThreadCtx;
    mpm_ctx->Cleanup              = mpm_table[matcher].Cleanup;
}


void MpmTableSetup(void) {
    memset(mpm_table, 0, sizeof(mpm_table));

    //MpmTrieRegister();
    MpmWuManberRegister();
    MpmB2gRegister();
    MpmB3gRegister();
}

void MpmRegisterTests(void) {
    u_int16_t i;

    for (i = 0; i < MPM_TABLE_SIZE; i++) {
        if (mpm_table[i].RegisterUnittests != NULL) {
            mpm_table[i].RegisterUnittests();
        } else {
            printf("Warning: mpm %s has no unittest registration function...", mpm_table[i].name);
        }
    }
}

