/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 *         Implementation of aho-corasick MPM from -
 *
 *         Efficient String Matching: An Aid to Bibliographic Search
 *         Alfred V. Aho and Margaret J. Corasick
 *
 *         - We use the goto-failure table to calculate transitions.
 *         - If we cross 2 ** 16 states, we use 4 bytes in the transition table
 *           to hold each state, otherwise we use 2 bytes.
 *         - To reduce memory consumption, we throw all the failure transitions
 *           out and use binary search to pick out the right transition in
 *           the modified goto table.
 *
 * \todo - Do a proper analyis of our existing MPMs and suggest a good one based
 *         on the pattern distribution and the expected traffic(say http).
 *       - Tried out loop unrolling without any perf increase.  Need to dig deeper.
 *       - Try out holding whether they are any output strings from a particular
 *         state in one of the bytes of a state var.  Will be useful in cuda esp.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-mpm-ac-gfbs.h"

#include "conf.h"
#include "util-memcmp.h"
#include "util-memcpy.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

void SCACGfbsInitCtx(MpmCtx *);
void SCACGfbsInitThreadCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void SCACGfbsDestroyCtx(MpmCtx *);
void SCACGfbsDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCACGfbsAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, SigIntId, uint8_t);
int SCACGfbsAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, SigIntId, uint8_t);
int SCACGfbsPreparePatterns(MpmCtx *mpm_ctx);
uint32_t SCACGfbsSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen);
void SCACGfbsPrintInfo(MpmCtx *mpm_ctx);
void SCACGfbsPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void SCACGfbsRegisterTests(void);

/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_GFBS_FAIL (-1)
/* size of the hash table used to speed up pattern insertions initially */
#define INIT_HASH_SIZE 65536

#define STATE_QUEUE_CONTAINER_SIZE 65536

/**
 * \brief Helper structure used by AC during state table creation
 */
typedef struct StateQueue_ {
    int32_t store[STATE_QUEUE_CONTAINER_SIZE];
    int top;
    int bot;
} StateQueue;

/**
 * \brief Register the goto failure table based aho-corasick mpm.
 */
void MpmACGfbsRegister(void)
{
    mpm_table[MPM_AC_GFBS].name = "ac-gfbs";
    /* don't need this.  isn't that awesome?  no more chopping and blah blah */
    mpm_table[MPM_AC_GFBS].max_pattern_length = 0;

    mpm_table[MPM_AC_GFBS].InitCtx = SCACGfbsInitCtx;
    mpm_table[MPM_AC_GFBS].InitThreadCtx = SCACGfbsInitThreadCtx;
    mpm_table[MPM_AC_GFBS].DestroyCtx = SCACGfbsDestroyCtx;
    mpm_table[MPM_AC_GFBS].DestroyThreadCtx = SCACGfbsDestroyThreadCtx;
    mpm_table[MPM_AC_GFBS].AddPattern = SCACGfbsAddPatternCS;
    mpm_table[MPM_AC_GFBS].AddPatternNocase = SCACGfbsAddPatternCI;
    mpm_table[MPM_AC_GFBS].Prepare = SCACGfbsPreparePatterns;
    mpm_table[MPM_AC_GFBS].Search = SCACGfbsSearch;
    mpm_table[MPM_AC_GFBS].Cleanup = NULL;
    mpm_table[MPM_AC_GFBS].PrintCtx = SCACGfbsPrintInfo;
    mpm_table[MPM_AC_GFBS].PrintThreadCtx = SCACGfbsPrintSearchStats;
    mpm_table[MPM_AC_GFBS].RegisterUnittests = SCACGfbsRegisterTests;

    return;
}

/**
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACGfbsGetConfig()
{
    //ConfNode *ac_conf;
    //const char *hash_val = NULL;

    //ConfNode *pm = ConfGetNode("pattern-matcher");

    return;
}

/**
 * \internal
 * \brief Creates a hash of the pattern.  We use it for the hashing process
 *        during the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline uint32_t SCACGfbsInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

/**
 * \internal
 * \brief Looks up a pattern.  We use it for the hashing process during the
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param ctx    Pointer to the AC ctx.
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline SCACGfbsPattern *SCACGfbsInitHashLookup(SCACGfbsCtx *ctx, uint8_t *pat,
                                                      uint16_t patlen, char flags,
                                                      uint32_t pid)
{
    uint32_t hash = SCACGfbsInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL)
        return NULL;

    SCACGfbsPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (t->id == pid)
            return t;
    }

    return NULL;
}

/**
 * \internal
 * \brief Allocs a new pattern instance.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval p Pointer to the newly created pattern.
 */
static inline SCACGfbsPattern *SCACGfbsAllocPattern(MpmCtx *mpm_ctx)
{
    SCACGfbsPattern *p = SCMalloc(sizeof(SCACGfbsPattern));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(SCACGfbsPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACGfbsPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCACGfbsPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCACGfbsPattern instance to be freed.
 */
static inline void SCACGfbsFreePattern(MpmCtx *mpm_ctx, SCACGfbsPattern *p)
{
    if (p != NULL && p->cs != NULL && p->cs != p->ci) {
        SCFree(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->ci != NULL) {
        SCFree(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->original_pat != NULL) {
        SCFree(p->original_pat);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(SCACGfbsPattern);
    }
    return;
}

static inline uint32_t SCACGfbsInitHash(SCACGfbsPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int SCACGfbsInitHashAdd(SCACGfbsCtx *ctx, SCACGfbsPattern *p)
{
    uint32_t hash = SCACGfbsInitHash(p);

    if (ctx->init_hash == NULL) {
        return 0;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCACGfbsPattern *tt = NULL;
    SCACGfbsPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}

/**
 * \internal
 * \brief Add a pattern to the mpm-ac context.
 *
 * \param mpm_ctx Mpm context.
 * \param pat     Pointer to the pattern.
 * \param patlen  Length of the pattern.
 * \param pid     Pattern id
 * \param sid     Signature id (internal id).
 * \param flags   Pattern's MPM_PATTERN_* flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCACGfbsAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                              uint16_t offset, uint16_t depth, uint32_t pid,
                              SigIntId sid, uint8_t flags)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    SCLogDebug("Adding pattern for ctx %p, patlen %"PRIu16" and pid %" PRIu32,
               ctx, patlen, pid);

    if (patlen == 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCACGfbsPattern *p = SCACGfbsInitHashLookup(ctx, pat, patlen, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCACGfbsAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        p->id = pid;

        p->original_pat = SCMalloc(patlen);
        if (p->original_pat == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->original_pat, pat, patlen);

        p->ci = SCMalloc(patlen);
        if (p->ci == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci, pat, p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL)
                    goto error;
                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;
                memcpy(p->cs, pat, patlen);
            }
        }

        /* put in the pattern hash */
        SCACGfbsInitHashAdd(ctx, p);

        if (mpm_ctx->pattern_cnt == 65535) {
            SCLogError(SC_ERR_AHO_CORASICK, "Max search words reached.  Can't "
                       "insert anymore.  Exiting");
            exit(EXIT_FAILURE);
        }
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0) {
            mpm_ctx->minlen = patlen;
        } else {
            if (mpm_ctx->minlen > patlen)
                mpm_ctx->minlen = patlen;
        }

        /* we need the max pat id */
        if (pid > ctx->max_pat_id)
            ctx->max_pat_id = pid;

        p->sids_size = 1;
        p->sids = SCMalloc(p->sids_size * sizeof(SigIntId));
        BUG_ON(p->sids == NULL);
        p->sids[0] = sid;
    } else {
        /* TODO figure out how we can be called multiple times for the same CTX with the same sid */

        int found = 0;
        uint32_t x = 0;
        for (x = 0; x < p->sids_size; x++) {
            if (p->sids[x] == sid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            SigIntId *sids = SCRealloc(p->sids, (sizeof(SigIntId) * (p->sids_size + 1)));
            BUG_ON(sids == NULL);
            p->sids = sids;
            p->sids[p->sids_size] = sid;
            p->sids_size++;
        }
    }

    return 0;

error:
    SCACGfbsFreePattern(mpm_ctx, p);
    return -1;
}

/**
 * \internal
 * \brief Initialize a new state in the goto and output tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval The state id, of the newly created state.
 */
static inline int SCACGfbsInitNewState(MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int size = 0;

    /* reallocate space in the goto table to include a new state */
    size = (ctx->state_count + 1) * 1024;
    ptmp = SCRealloc(ctx->goto_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->goto_table);
        ctx->goto_table = NULL;
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    ctx->goto_table = ptmp;

    /* set all transitions for the newly assigned state as FAIL transitions */
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        ctx->goto_table[ctx->state_count][ascii_code] = SC_AC_GFBS_FAIL;
    }

    /* reallocate space in the output table for the new state */
    size = (ctx->state_count + 1) * sizeof(SCACGfbsOutputTable);
    ptmp = SCRealloc(ctx->output_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->output_table);
        ctx->output_table = NULL;
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    ctx->output_table = ptmp;

    memset(ctx->output_table + ctx->state_count, 0, sizeof(SCACGfbsOutputTable));

    /* \todo using it temporarily now during dev, since I have restricted
     *       state var in SCACGfbsCtx->state_table to uint16_t. */
    //if (ctx->state_count > 65536) {
    //    printf("state count exceeded\n");
    //    exit(EXIT_FAILURE);
    //}

    return ctx->state_count++;
}

/**
 * \internal
 * \brief Adds a pid to the output table for a state.
 *
 * \param state   The state to whose output table we should add the pid.
 * \param pid     The pattern id to add.
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACGfbsSetOutputState(int32_t state, uint32_t pid, MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    SCACGfbsOutputTable *output_state = &ctx->output_table[state];
    uint32_t i = 0;

    for (i = 0; i < output_state->no_of_entries; i++) {
        if (output_state->pids[i] == pid)
            return;
    }

    output_state->no_of_entries++;
    ptmp = SCRealloc(output_state->pids,
                     output_state->no_of_entries * sizeof(uint32_t));
    if (ptmp == NULL) {
        SCFree(output_state->pids);
        output_state->pids = NULL;
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    output_state->pids = ptmp;

    output_state->pids[output_state->no_of_entries - 1] = pid;

    return;
}

/**
 * \brief Helper function used by SCACGfbsCreateGotoTable.  Adds a pattern to the
 *        goto table.
 *
 * \param pattern     Pointer to the pattern.
 * \param pattern_len Pattern length.
 * \param pid         The pattern id, that corresponds to this pattern.  We
 *                    need it to updated the output table for this pattern.
 * \param mpm_ctx     Pointer to the mpm context.
 */
static inline void SCACGfbsEnter(uint8_t *pattern, uint16_t pattern_len, uint32_t pid,
                                 MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    int32_t state = 0;
    int32_t newstate = 0;
    int i = 0;
    int p = 0;

    /* walk down the trie till we have a match for the pattern prefix */
    state = 0;
    for (i = 0; i < pattern_len; i++) {
        if (ctx->goto_table[state][pattern[i]] != SC_AC_GFBS_FAIL) {
            state = ctx->goto_table[state][pattern[i]];
        } else {
            break;
        }
    }

    /* add the non-matching pattern suffix to the trie, from the last state
     * we left off */
    for (p = i; p < pattern_len; p++) {
        newstate = SCACGfbsInitNewState(mpm_ctx);
        ctx->goto_table[state][pattern[p]] = newstate;
        state = newstate;
    }

    /* add this pattern id, to the output table of the last state, where the
     * pattern ends in the trie */
    SCACGfbsSetOutputState(state, pid, mpm_ctx);

    return;
}

/**
 * \internal
 * \brief Create the goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACGfbsCreateGotoTable(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    uint32_t i = 0;

    /* add each pattern to create the goto table */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        SCACGfbsEnter(ctx->parray[i]->ci, ctx->parray[i]->len,
                      ctx->parray[i]->id, mpm_ctx);
    }

    int ascii_code = 0;
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        if (ctx->goto_table[0][ascii_code] == SC_AC_GFBS_FAIL) {
            ctx->goto_table[0][ascii_code] = 0;
        }
    }

    return;
}

static inline int SCACGfbsStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACGfbsEnqueue(StateQueue *q, int32_t state)
{
    int i = 0;

    /*if we already have this */
    for (i = q->bot; i < q->top; i++) {
        if (q->store[i] == state)
            return;
    }

    q->store[q->top++] = state;

    if (q->top == STATE_QUEUE_CONTAINER_SIZE)
        q->top = 0;

    if (q->top == q->bot) {
        SCLogCritical(SC_ERR_AHO_CORASICK, "Just ran out of space in the queue.  "
                      "Fatal Error.  Exiting.  Please file a bug report on this");
        exit(EXIT_FAILURE);
    }

    return;
}

static inline int32_t SCACGfbsDequeue(StateQueue *q)
{
    if (q->bot == STATE_QUEUE_CONTAINER_SIZE)
        q->bot = 0;

    if (q->bot == q->top) {
        SCLogCritical(SC_ERR_AHO_CORASICK, "StateQueue behaving weirdly.  "
                      "Fatal Error.  Exiting.  Please file a bug report on this");
        exit(EXIT_FAILURE);
    }

    return q->store[q->bot++];
}

/*
#define SCACGfbsStateQueueIsEmpty(q) (((q)->top == (q)->bot) ? 1 : 0)

#define SCACGfbsEnqueue(q, state) do { \
                                  int i = 0; \
                                             \
                                  for (i = (q)->bot; i < (q)->top; i++) { \
                                      if ((q)->store[i] == state)       \
                                      return; \
                                  } \
                                    \
                                  (q)->store[(q)->top++] = state;   \
                                                                \
                                  if ((q)->top == STATE_QUEUE_CONTAINER_SIZE) \
                                      (q)->top = 0;                     \
                                                                        \
                                  if ((q)->top == (q)->bot) {           \
                                  SCLogCritical(SC_ERR_AHO_CORASICK, "Just ran out of space in the queue.  " \
                                                "Fatal Error.  Exiting.  Please file a bug report on this"); \
                                  exit(EXIT_FAILURE);                   \
                                  }                                     \
                              } while (0)

#define SCACGfbsDequeue(q) ( (((q)->bot == STATE_QUEUE_CONTAINER_SIZE)? ((q)->bot = 0): 0), \
                         (((q)->bot == (q)->top) ?                      \
                          (printf("StateQueue behaving "                \
                                         "weirdly.  Fatal Error.  Exiting.  Please " \
                                         "file a bug report on this"), \
                           exit(EXIT_FAILURE)) : 0), \
                         (q)->store[(q)->bot++])     \
*/

/**
 * \internal
 * \brief Club the output data from 2 states and store it in the 1st state.
 *        dst_state_data = {dst_state_data} UNION {src_state_data}
 *
 * \todo Use a better way to find union of 2 sets.
 *
 * \param dst_state First state(also the destination) for the union operation.
 * \param src_state Second state for the union operation.
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACGfbsClubOutputStates(int32_t dst_state, int32_t src_state,
                                            MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    uint32_t i = 0;
    uint32_t j = 0;

    SCACGfbsOutputTable *output_dst_state = &ctx->output_table[dst_state];
    SCACGfbsOutputTable *output_src_state = &ctx->output_table[src_state];

    for (i = 0; i < output_src_state->no_of_entries; i++) {
        for (j = 0; j < output_dst_state->no_of_entries; j++) {
            if (output_src_state->pids[i] == output_dst_state->pids[j]) {
                break;
            }
        }
        if (j == output_dst_state->no_of_entries) {
            output_dst_state->no_of_entries++;

            ptmp = SCRealloc(output_dst_state->pids,
                             (output_dst_state->no_of_entries * sizeof(uint32_t)));
            if (ptmp == NULL) {
                SCFree(output_dst_state->pids);
                output_dst_state->pids = NULL;
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            output_dst_state->pids = ptmp;

            output_dst_state->pids[output_dst_state->no_of_entries - 1] =
                output_src_state->pids[i];
        }
    }

    return;
}

/**
 * \internal
 * \brief Create the failure table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACGfbsCreateFailureTable(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int32_t state = 0;
    int32_t r_state = 0;

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    /* allot space for the failure table.  A failure entry in the table for
     * every state(SCACGfbsCtx->state_count) */
    ctx->failure_table = SCMalloc(ctx->state_count * sizeof(int32_t));
    if (ctx->failure_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->failure_table, 0, ctx->state_count * sizeof(int32_t));

    /* add the failure transitions for the 0th state, and add every non-fail
     * transition from the 0th state to the queue for further processing
     * of failure states */
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        int32_t temp_state = ctx->goto_table[0][ascii_code];
        if (temp_state != 0) {
            SCACGfbsEnqueue(&q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACGfbsStateQueueIsEmpty(&q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACGfbsDequeue(&q);
        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            int32_t temp_state = ctx->goto_table[r_state][ascii_code];
            if (temp_state == SC_AC_GFBS_FAIL)
                continue;
            SCACGfbsEnqueue(&q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][ascii_code] == SC_AC_GFBS_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][ascii_code];
            SCACGfbsClubOutputStates(temp_state, ctx->failure_table[temp_state],
                                     mpm_ctx);
        }
    }

    return;
}

/**
 * \internal
 * \brief Creates a new goto table structure(throw out all the failure
 *        transitions), to hold the existing goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACGfbsCreateModGotoTable(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    if (ctx->state_count < 32767) {
        int size = 0;
        int32_t state = 0;
        for (state = 1; state < ctx->state_count; state++) {
            int k = 0;
            int ascii_code = 0;
            for (; ascii_code < 256; ascii_code++) {
                if (ctx->goto_table[state][ascii_code] == SC_AC_GFBS_FAIL)
                    continue;
                k++;
            }

            if ((k % 2) != 0)
                size += 1;
        }

        /* Let us use uint16_t for all.  That way we don't have to worry about
         * alignment.  Technically 8 bits is all we need to store ascii codes,
         * but by avoiding it, we save a lot of time on handling alignment */
        size += (ctx->state_count * sizeof(SC_AC_GFBS_STATE_TYPE_U16) * 3 +
                 ctx->state_count * sizeof(uint8_t) +
                 256 * sizeof(SC_AC_GFBS_STATE_TYPE_U16) * 1);
        ctx->goto_table_mod = SCMalloc(size);
        if (ctx->goto_table_mod == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->goto_table_mod, 0, size);
        //printf("size- %d\n", size);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        /* buffer to hold pointers in the buffer, so that a state can use it
         * directly to access its state data */
        ctx->goto_table_mod_pointers = SCMalloc(ctx->state_count * sizeof(uint8_t *));
        if (ctx->goto_table_mod_pointers == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->goto_table_mod_pointers, 0,
               ctx->state_count * sizeof(uint8_t *));

        SC_AC_GFBS_STATE_TYPE_U16 temp_states[256];
        uint16_t *curr_loc = (uint16_t *)ctx->goto_table_mod;
        uint16_t *no_of_entries = NULL;
        uint16_t *failure_entry = NULL;
        uint8_t *ascii_codes = NULL;
        uint16_t ascii_code = 0;
        uint16_t k = 0;
        for (state = 0; state < ctx->state_count; state++) {
            /* store the starting location in the buffer for this state */
            ctx->goto_table_mod_pointers[state] = (uint8_t *)curr_loc;
            no_of_entries = curr_loc++;
            failure_entry = curr_loc++;
            ascii_codes = (uint8_t *)curr_loc;
            k = 0;
            /* store all states that have non fail transitions in the temp buffer */
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                if (ctx->goto_table[state][ascii_code] == SC_AC_GFBS_FAIL)
                    continue;
                ascii_codes[k] = ascii_code;
                temp_states[k] = ctx->goto_table[state][ascii_code];
                k++;
            }
            /* if we have any non fail transitions from our previous for search,
             * store the acii codes as well the corresponding states */
            if (k > 0) {
                no_of_entries[0] = k;
                if (state != 0) {
                    int jump = (k + 1) & 0xFFE;
                    curr_loc += jump / 2;
                }
                memcpy(curr_loc, temp_states, k * sizeof(SC_AC_GFBS_STATE_TYPE_U16));
                curr_loc += k;
            }
            failure_entry[0] = ctx->failure_table[state];
        }

        /* > 33766 */
    } else {
        int size = 0;
        int32_t state = 0;
        for (state = 1; state < ctx->state_count; state++) {
            int k = 0;
            int ascii_code = 0;
            for (; ascii_code < 256; ascii_code++) {
                if (ctx->goto_table[state][ascii_code] == SC_AC_GFBS_FAIL)
                    continue;
                k++;
            }

            if ( (k % 4) != 0)
                size += (4 - (k % 4));
        }

        /* Let us use uint32_t for all.  That way we don't have to worry about
         * alignment.  Technically 8 bits is all we need to store ascii codes,
         * but by avoiding it, we save a lot of time on handling alignment */
        size += (ctx->state_count * (sizeof(SC_AC_GFBS_STATE_TYPE_U32) * 3)+
                 ctx->state_count * sizeof(uint8_t) +
                 256 * (sizeof(SC_AC_GFBS_STATE_TYPE_U32) * 1));
        ctx->goto_table_mod = SCMalloc(size);
        if (ctx->goto_table_mod == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->goto_table_mod, 0, size);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        /* buffer to hold pointers in the buffer, so that a state can use it
         * directly to access its state data */
        ctx->goto_table_mod_pointers = SCMalloc(ctx->state_count * sizeof(uint8_t *));
        if (ctx->goto_table_mod_pointers == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->goto_table_mod_pointers, 0,
               ctx->state_count * sizeof(uint8_t *));

        SC_AC_GFBS_STATE_TYPE_U32 temp_states[256];
        uint32_t *curr_loc = (uint32_t *)ctx->goto_table_mod;
        uint32_t *no_of_entries = NULL;
        uint32_t *failure_entry = NULL;
        uint8_t *ascii_codes = NULL;
        uint16_t ascii_code = 0;
        uint16_t k = 0;
        for (state = 0; state < ctx->state_count; state++) {
            /* store the starting location in the buffer for this state */
            ctx->goto_table_mod_pointers[state] = (uint8_t *)curr_loc;
            no_of_entries = curr_loc++;
            failure_entry = curr_loc++;
            ascii_codes = (uint8_t *)curr_loc;
            k = 0;
            /* store all states that have non fail transitions in the temp buffer */
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                if (ctx->goto_table[state][ascii_code] == SC_AC_GFBS_FAIL)
                    continue;
                ascii_codes[k] = ascii_code;
                temp_states[k] = ctx->goto_table[state][ascii_code];
                k++;
            }
            /* if we have any non fail transitions from our previous for search,
             * store the acii codes as well the corresponding states */
            if (k > 0) {
                no_of_entries[0] = k;
                if (state != 0) {
                    int jump = (k + 3) & 0xFFC;
                    curr_loc += jump / 4;
                }
                memcpy(curr_loc, temp_states, k * sizeof(SC_AC_GFBS_STATE_TYPE_U32));
                curr_loc += k;
            }
            failure_entry[0] = ctx->failure_table[state];
        }
    }

    return;
}

static inline void SCACGfbsClubOutputStatePresenceWithModGotoTable(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    int state = 0;
    int no_of_entries;
    int i;

    if (ctx->state_count < 32767) {
        uint16_t *states;
        for (state = 0; state < ctx->state_count; state++) {
            no_of_entries = *((uint16_t *)ctx->goto_table_mod_pointers[state]);
            if (no_of_entries == 0)
                continue;

            //if (*((uint16_t *)ctx->goto_table_mod_pointers[state] + 1) != 0) {
            if (ctx->output_table[((uint16_t *)ctx->goto_table_mod_pointers[state] + 1)[0]].no_of_entries != 0) {
                *((uint16_t *)ctx->goto_table_mod_pointers[state] + 1) |= (1 << 15);
            }

            if (state == 0)
                states = ((uint16_t *)ctx->goto_table_mod_pointers[state] + 2);
            else
                states = ((uint16_t *)ctx->goto_table_mod_pointers[state] + 2 + ((no_of_entries + 1) & 0xFFE) / 2);
            for (i = 0; i < no_of_entries; i++) {
                //if (states[i] == 0)
                if (ctx->output_table[states[i]].no_of_entries == 0)
                    continue;

                states[i] |= (1 << 15);
            }
        }

    } else {
        uint32_t *states;
        for (state = 0; state < ctx->state_count; state++) {
            no_of_entries = *((uint32_t *)ctx->goto_table_mod_pointers[state]);
            if (no_of_entries == 0)
                continue;

            //if (*((uint32_t *)ctx->goto_table_mod_pointers[state] + 1) != 0) {
            if (ctx->output_table[((uint32_t *)ctx->goto_table_mod_pointers[state] + 1)[0]].no_of_entries != 0) {
                *((uint32_t *)ctx->goto_table_mod_pointers[state] + 1) |= (1 << 24);
            }

            if (state == 0)
                states = ((uint32_t *)ctx->goto_table_mod_pointers[state] + 2);
            else
                states = ((uint32_t *)ctx->goto_table_mod_pointers[state] + 2 + ((no_of_entries + 3) & 0xFFC) / 4);
            for (i = 0; i < no_of_entries; i++) {
                //if (states[i] == 0)
                if (ctx->output_table[states[i]].no_of_entries == 0)
                    continue;

                states[i] |= (1 << 24);
            }
        }
    }

    return;
}

static inline void SCACGfbsInsertCaseSensitiveEntriesForPatterns(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    int32_t state = 0;
    uint32_t k = 0;

    for (state = 0; state < ctx->state_count; state++) {
        if (ctx->output_table[state].no_of_entries == 0)
            continue;

        for (k = 0; k < ctx->output_table[state].no_of_entries; k++) {
            if (ctx->pid_pat_list[ctx->output_table[state].pids[k]].cs != NULL) {
                ctx->output_table[state].pids[k] &= 0x0000FFFF;
                ctx->output_table[state].pids[k] |= 1 << 16;
            }
        }
    }

    return;
}

/**
 * \brief Process the patterns and prepare the state table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACGfbsPrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    /* create the 0th state in the goto table and output_table */
    SCACGfbsInitNewState(mpm_ctx);

    /* create the goto table */
    SCACGfbsCreateGotoTable(mpm_ctx);
    /* create the failure table */
    SCACGfbsCreateFailureTable(mpm_ctx);
    /* create the final state(delta) table */
    SCACGfbsCreateModGotoTable(mpm_ctx);
    /* club the output state presence with transition entries */
    SCACGfbsClubOutputStatePresenceWithModGotoTable(mpm_ctx);

    /* club nocase entries */
    SCACGfbsInsertCaseSensitiveEntriesForPatterns(mpm_ctx);

    /* we don't need this anymore */
    SCFree(ctx->goto_table);
    ctx->goto_table = NULL;
    SCFree(ctx->failure_table);
    ctx->failure_table = NULL;

    return;
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCACGfbsPreparePatterns(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0 || ctx->init_hash == NULL) {
        SCLogDebug("No patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (SCACGfbsPattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                               sizeof(SCACGfbsPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(SCACGfbsPattern *));
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(SCACGfbsPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        SCACGfbsPattern *node = ctx->init_hash[i], *nnode = NULL;
        while(node != NULL) {
            nnode = node->next;
            node->next = NULL;
            ctx->parray[p++] = node;
            node = nnode;
        }
    }

    /* we no longer need the hash, so free it's memory */
    SCFree(ctx->init_hash);
    ctx->init_hash = NULL;

    /* the memory consumed by a single state in our goto table */
    //ctx->single_state_size = sizeof(int32_t) * 256;

    /* handle no case patterns */
    ctx->pid_pat_list = SCMalloc((ctx->max_pat_id + 1)* sizeof(SCACGfbsPatternList));
    if (ctx->pid_pat_list == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->pid_pat_list, 0, (ctx->max_pat_id + 1) * sizeof(SCACGfbsPatternList));

    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (!(ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE)) {
            ctx->pid_pat_list[ctx->parray[i]->id].cs = SCMalloc(ctx->parray[i]->len);
            if (ctx->pid_pat_list[ctx->parray[i]->id].cs == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            memcpy(ctx->pid_pat_list[ctx->parray[i]->id].cs,
                   ctx->parray[i]->original_pat, ctx->parray[i]->len);
            ctx->pid_pat_list[ctx->parray[i]->id].patlen = ctx->parray[i]->len;
        }

        /* ACPatternList now owns this memory */
        ctx->pid_pat_list[ctx->parray[i]->id].sids_size = ctx->parray[i]->sids_size;
        ctx->pid_pat_list[ctx->parray[i]->id].sids = ctx->parray[i]->sids;
    }

    /* prepare the state table required by AC */
    SCACGfbsPrepareStateTable(mpm_ctx);

    /* free all the stored patterns.  Should save us a good 100-200 mbs */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i] != NULL) {
            SCACGfbsFreePattern(mpm_ctx, ctx->parray[i]);
        }
    }
    SCFree(ctx->parray);
    ctx->parray = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACGfbsPattern *));

    return 0;

error:
    return -1;
}

/**
 * \brief Init the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param matchsize      We don't need this.
 */
void SCACGfbsInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                           uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = SCMalloc(sizeof(SCACGfbsThreadCtx));
    if (mpm_thread_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_thread_ctx->ctx, 0, sizeof(SCACGfbsThreadCtx));
    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCACGfbsThreadCtx);

    return;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 * \param module_handle Cuda module handle from the cuda handler API.  We don't
 *                      have to worry about this here.
 */
void SCACGfbsInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCMalloc(sizeof(SCACGfbsCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->ctx, 0, sizeof(SCACGfbsCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACGfbsCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCMalloc(sizeof(SCACGfbsPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(ctx->init_hash, 0, sizeof(SCACGfbsPattern *) * INIT_HASH_SIZE);

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACGfbsGetConfig();

    SCReturn;
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACGfbsDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCACGfbsPrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCACGfbsThreadCtx);
    }

    return;
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCACGfbsDestroyCtx(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash != NULL) {
        SCFree(ctx->init_hash);
        ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(SCACGfbsPattern *));
    }

    if (ctx->parray != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                SCACGfbsFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        ctx->parray = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACGfbsPattern *));
    }

    if (ctx->goto_table_mod != NULL) {
        SCFree(ctx->goto_table_mod);
        ctx->goto_table_mod = NULL;

        mpm_ctx->memory_cnt--;
        if (ctx->state_count < 32767) {
            mpm_ctx->memory_size -= (ctx->state_count * sizeof(SC_AC_GFBS_STATE_TYPE_U16) * 3 +
                                     256 * sizeof(SC_AC_GFBS_STATE_TYPE_U16) * 2);
        } else {
            mpm_ctx->memory_size -= (ctx->state_count * sizeof(SC_AC_GFBS_STATE_TYPE_U32) * 3 +
                                     256 * sizeof(SC_AC_GFBS_STATE_TYPE_U32) * 2);
        }
    }

    if (ctx->goto_table_mod_pointers != NULL) {
        SCFree(ctx->goto_table_mod_pointers);
        ctx->goto_table_mod_pointers = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= ctx->state_count * sizeof(uint8_t *);
    }

    if (ctx->output_table != NULL) {
        int32_t state_count;
        for (state_count = 0; state_count < ctx->state_count; state_count++) {
            if (ctx->output_table[state_count].pids != NULL) {
                SCFree(ctx->output_table[state_count].pids);
            }
        }
        SCFree(ctx->output_table);
    }

    if (ctx->pid_pat_list != NULL) {
        int i;
        for (i = 0; i < (ctx->max_pat_id + 1); i++) {
            if (ctx->pid_pat_list[i].cs != NULL)
                SCFree(ctx->pid_pat_list[i].cs);
            if (ctx->pid_pat_list[i].sids != NULL)
                SCFree(ctx->pid_pat_list[i].sids);
        }
        SCFree(ctx->pid_pat_list);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACGfbsCtx);

    return;
}

/**
 * \brief The aho corasick search function.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param pmq            Pointer to the Pattern Matcher Queue to hold
 *                       search matches.
 * \param buf            Buffer to be searched.
 * \param buflen         Buffer length.
 *
 * \retval matches Match count.
 */
uint32_t SCACGfbsSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;
    int matches = 0;
    uint8_t buf_local;

    SCACGfbsPatternList *pid_pat_list = ctx->pid_pat_list;

    uint8_t bitarray[pmq->pattern_id_bitarray_size];
    memset(bitarray, 0, pmq->pattern_id_bitarray_size);

    /* really hate the extra cmp here, but can't help it */
    if (ctx->state_count < 32767) {
        /* \todo Change it for stateful MPM.  Supply the state using mpm_thread_ctx */
        int32_t temp_state;
        uint16_t no_of_entries;
        uint8_t *ascii_codes;
        uint16_t **goto_table_mod_pointers = (uint16_t **)ctx->goto_table_mod_pointers;

        //int32_t *failure_table = ctx->failure_table;
        int i;
        /* \todo tried loop unrolling with register var, with no perf increase.  Need
         * to dig deeper */
        /* with so many var declarations the register declaration here is useless */
        register int32_t state = 0;
        for (i = 0; i < buflen; i++) {
            if (state == 0) {
                state = (goto_table_mod_pointers[0] + 2)[u8_tolower(buf[i])];
            } else {

            /* get the goto state transition */
            no_of_entries = *(goto_table_mod_pointers[state & 0x7FFF]);
            if (no_of_entries == 0) {
                temp_state = SC_AC_GFBS_FAIL;
            } else {
                if (no_of_entries == 1) {
                    ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x7FFF] + 2);
                    buf_local = u8_tolower(buf[i]);
                    if (buf_local == ascii_codes[0])
                        temp_state = ((uint16_t *)(ascii_codes + ((no_of_entries + 1) & 0xFFE)))[0];
                    else
                        temp_state = SC_AC_GFBS_FAIL;
                } else {
                    buf_local = u8_tolower(buf[i]);
                    ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x7FFF] + 2);
                    int low = 0;
                    int high = no_of_entries;
                    int mid;
                    temp_state = SC_AC_GFBS_FAIL;
                    while (low <= high) {
                        mid = (low + high) / 2;
                        if (ascii_codes[mid] == buf_local) {
                            temp_state = ((uint16_t *)(ascii_codes + ((no_of_entries + 1) & 0xFFE)))[mid];
                            break;
                        } else if (ascii_codes[mid] < buf_local) {
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    }
                }
            }
            while (temp_state == SC_AC_GFBS_FAIL) {
                state = *(goto_table_mod_pointers[state & 0x7FFF] + 1);

                /* get the goto state transition */
                no_of_entries = *(goto_table_mod_pointers[state & 0x7FFF]);
                if (no_of_entries == 0) {
                    temp_state = SC_AC_GFBS_FAIL;
                } else {
                    if (no_of_entries == 1) {
                        ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x7FFF] + 2);
                        buf_local = u8_tolower(buf[i]);
                        if (buf_local == ascii_codes[0])
                            temp_state = ((uint16_t *)(ascii_codes + ((no_of_entries + 1) & 0xFFE)))[0];
                        else
                            temp_state = SC_AC_GFBS_FAIL;
                    } else {
                        ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x7FFF] + 2);
                        buf_local = u8_tolower(buf[i]);
                        if (state == 0) {
                            temp_state = ((uint16_t *)ascii_codes)[buf_local];
                        } else {
                            int low = 0;
                            int high = no_of_entries;
                            int mid;
                            temp_state = SC_AC_GFBS_FAIL;
                            while (low <= high) {
                                mid = (low + high) / 2;
                                if (ascii_codes[mid] == buf_local) {
                                    temp_state = ((uint16_t *)(ascii_codes + ((no_of_entries + 1) & 0xFFE)))[mid];
                                    break;
                                } else if (ascii_codes[mid] < buf_local) {
                                    low = mid + 1;
                                } else {
                                    high = mid - 1;
                                }
                            }
                        }
                    }
                } /* else - if (no_of_entries == 0) */
            } /* while (temp_state == SC_AC_GFBS_FAIL) */

            state = temp_state;

            }

            if (state & 0x8000) {
                uint32_t no_of_pid_entries = ctx->output_table[state & 0x7FFF].no_of_entries;
                uint32_t *pids = ctx->output_table[state & 0x7FFF].pids;
                uint32_t k = 0;
                for (k = 0; k < no_of_pid_entries; k++) {
                    if (pids[k] & 0xFFFF0000) {
                        uint32_t lower_pid = pids[k] & 0x0000FFFF;
                        if (SCMemcmp(pid_pat_list[lower_pid].cs,
                                     buf + i - pid_pat_list[lower_pid].patlen + 1,
                                     pid_pat_list[lower_pid].patlen) != 0) {
                            /* inside loop */
                            continue;
                        }

                        if (bitarray[(lower_pid) / 8] & (1 << ((lower_pid) % 8))) {
                            ;
                        } else {
                            bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));
                            pmq->pattern_id_bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));

                            MpmAddPid(pmq, lower_pid);
                            MpmAddSids(pmq, pid_pat_list[lower_pid].sids, pid_pat_list[lower_pid].sids_size);
                        }
                        matches++;
                    } else {
                        if (bitarray[pids[k] / 8] & (1 << (pids[k] % 8))) {
                            ;
                        } else {
                            bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                            pmq->pattern_id_bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));

                            MpmAddPid(pmq, pids[k]);
                            MpmAddSids(pmq, pid_pat_list[pids[k]].sids, pid_pat_list[pids[k]].sids_size);
                        }
                        matches++;
                    }
                }
            } /* if (ctx->output_table[state].no_of_entries != 0) */
        } /* for (i = 0; i < buflen; i++) */

    } else {
        /* \todo Change it for stateful MPM.  Supply the state using mpm_thread_ctx */
        int32_t temp_state = 0;
        uint32_t no_of_entries;
        uint8_t *ascii_codes = NULL;
        uint32_t **goto_table_mod_pointers = (uint32_t **)ctx->goto_table_mod_pointers;
        //int32_t *failure_table = ctx->failure_table;
        int i = 0;
        /* \todo tried loop unrolling with register var, with no perf increase.  Need
         * to dig deeper */
        register int32_t state = 0;
        for (i = 0; i < buflen; i++) {
            if (state == 0) {
                state = (goto_table_mod_pointers[0] + 2)[u8_tolower(buf[i])];
            } else {

            /* get the goto state transition */
            no_of_entries = *(goto_table_mod_pointers[state & 0x00FFFFFF]);
            if (no_of_entries == 0) {
                temp_state = SC_AC_GFBS_FAIL;
            } else {
                if (no_of_entries == 1) {
                    ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x00FFFFFF] + 2);
                    buf_local = u8_tolower(buf[i]);
                    if (buf_local == ascii_codes[0])
                        temp_state = ((uint32_t *)(ascii_codes + ((no_of_entries + 3) & 0xFFC)))[0];
                    else
                        temp_state = SC_AC_GFBS_FAIL;
                } else {
                    buf_local = u8_tolower(buf[i]);
                    ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x00FFFFFF] + 2);
                    int low = 0;
                    int high = no_of_entries;
                    int mid;
                    temp_state = SC_AC_GFBS_FAIL;
                    while (low <= high) {
                        mid = (low + high) / 2;
                        if (ascii_codes[mid] == buf_local) {
                            temp_state = ((uint32_t *)(ascii_codes + ((no_of_entries + 3) & 0xFFC)))[mid];
                            break;
                        } else if (ascii_codes[mid] < buf_local) {
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    }
                }
            }
            while (temp_state == SC_AC_GFBS_FAIL) {
                state = *(goto_table_mod_pointers[state & 0x00FFFFFF] + 1);

                /* get the goto state transition */
                no_of_entries = *(goto_table_mod_pointers[state & 0x00FFFFFF]);
                if (no_of_entries == 0) {
                    temp_state = SC_AC_GFBS_FAIL;
                } else {
                    if (no_of_entries == 1) {
                        ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x00FFFFFF] + 2);
                        buf_local = u8_tolower(buf[i]);
                        if (buf_local == ascii_codes[0])
                            temp_state = ((uint32_t *)(ascii_codes + ((no_of_entries + 3) & 0xFFC)))[0];
                        else
                            temp_state = SC_AC_GFBS_FAIL;
                    } else {
                        ascii_codes = (uint8_t *)(goto_table_mod_pointers[state & 0x00FFFFFF] + 2);
                        buf_local = u8_tolower(buf[i]);
                        if (state == 0) {
                            temp_state = ((uint32_t *)ascii_codes)[buf_local];
                        } else {
                            int low = 0;
                            int high = no_of_entries;
                            int mid;
                            temp_state = SC_AC_GFBS_FAIL;
                            while (low <= high) {
                                mid = (low + high) / 2;
                                if (ascii_codes[mid] == buf_local) {
                                    temp_state = ((uint32_t *)(ascii_codes + ((no_of_entries + 3) & 0xFFC)))[mid];
                                    break;
                                } else if (ascii_codes[mid] < buf_local) {
                                    low = mid + 1;
                                } else {
                                    high = mid - 1;
                                }
                            }
                        }
                    } /* else - if (no_of_entries[0] == 1) */
                } /* else - if (no_of_entries[0] == 0) */
            } /* while (temp_state == SC_AC_GFBS_FAIL) */
            state = temp_state;

            }

            if (state & 0x01000000) {
                uint32_t no_of_pid_entries = ctx->output_table[state & 0x00FFFFFF].no_of_entries;
                uint32_t *pids = ctx->output_table[state & 0x00FFFFFF].pids;
                uint32_t k = 0;
                for (k = 0; k < no_of_pid_entries; k++) {
                    if (pids[k] & 0xFFFF0000) {
                        uint32_t lower_pid = pids[k] & 0x0000FFFF;
                        if (SCMemcmp(pid_pat_list[lower_pid].cs,
                                     buf + i - pid_pat_list[lower_pid].patlen + 1,
                                     pid_pat_list[lower_pid].patlen) != 0) {
                            /* inside loop */
                            continue;
                        }

                        if (bitarray[(lower_pid) / 8] & (1 << ((lower_pid) % 8))) {
                            ;
                        } else {
                            bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));
                            pmq->pattern_id_bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));

                            MpmAddPid(pmq, lower_pid);
                            MpmAddSids(pmq, pid_pat_list[lower_pid].sids, pid_pat_list[lower_pid].sids_size);
                        }
                        matches++;
                    } else {
                        if (bitarray[pids[k] / 8] & (1 << (pids[k] % 8))) {
                            ;
                        } else {
                            bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                            pmq->pattern_id_bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));

                            MpmAddPid(pmq, pids[k]);
                            MpmAddSids(pmq, pid_pat_list[pids[k]].sids, pid_pat_list[pids[k]].sids_size);
                        }
                        matches++;
                    }
                    //loop1:
                    //;
                }
            } /* if (ctx->output_table[state].no_of_entries != 0) */
        } /* for (i = 0; i < buflen; i++) */
    }

    return matches;
}

/**
 * \brief Add a case insensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCACGfbsAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return SCACGfbsAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

/**
 * \brief Add a case sensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCACGfbsAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         SigIntId sid, uint8_t flags)
{
    return SCACGfbsAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCACGfbsPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{

#ifdef SC_AC_COUNTERS
    SCACGfbsThreadCtx *ctx = (SCACGfbsThreadCtx *)mpm_thread_ctx->ctx;
    printf("AC Thread Search stats (ctx %p)\n", ctx);
    printf("Total calls: %" PRIu32 "\n", ctx->total_calls);
    printf("Total matches: %" PRIu64 "\n", ctx->total_matches);
#endif /* SC_AC_COUNTERS */

    return;
}

void SCACGfbsPrintInfo(MpmCtx *mpm_ctx)
{
    SCACGfbsCtx *ctx = (SCACGfbsCtx *)mpm_ctx->ctx;

    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCACGfbsCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(SCACGfbsCtx));
    printf("  SCACGfbsPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(SCACGfbsPattern));
    printf("  SCACGfbsPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(SCACGfbsPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %" PRIu32 "\n", ctx->state_count);
    printf("\n");

    return;
}

/*************************************Unittests********************************/

#ifdef UNITTESTS

static int SCACGfbsTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcd";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* should match 30 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     30, 0, 0, 5, 0, 0);
    /* total matches: 135 */
    PmqSetup(&pmq, 6);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq, 4);

    if (SCACGfbsPreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    char *buf = "he";
    result &= (SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "she";
    result &= (SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);
    buf = "his";
    result &= (SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);

 end:
    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcde""fghij""klmno""pqrst""uvwxy""z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "works";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));
    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "tone";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));
    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_GFBS);
    SCACGfbsInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACGfbsPreparePatterns(&mpm_ctx);

    char *buf = "tONE";
    uint32_t cnt = SCACGfbsSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACGfbsDestroyCtx(&mpm_ctx);
    SCACGfbsDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACGfbsTest29(void)
{
    uint8_t *buf = (uint8_t *)"onetwothreefourfivesixseveneightnine";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->mpm_matcher = MPM_AC_GFBS;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"onetwothreefourfivesixseveneightnine\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    de_ctx->sig_list->next = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"onetwothreefourfivesixseveneightnine\"; fast_pattern:3,3; sid:2;)");
    if (de_ctx->sig_list->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) != 1) {
        printf("if (PacketAlertCheck(p, 1) != 1) failure\n");
        goto end;
    }
    if (PacketAlertCheck(p, 2) != 1) {
        printf("if (PacketAlertCheck(p, 1) != 2) failure\n");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

void SCACGfbsRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCACGfbsTest01", SCACGfbsTest01, 1);
    UtRegisterTest("SCACGfbsTest02", SCACGfbsTest02, 1);
    UtRegisterTest("SCACGfbsTest03", SCACGfbsTest03, 1);
    UtRegisterTest("SCACGfbsTest04", SCACGfbsTest04, 1);
    UtRegisterTest("SCACGfbsTest05", SCACGfbsTest05, 1);
    UtRegisterTest("SCACGfbsTest06", SCACGfbsTest06, 1);
    UtRegisterTest("SCACGfbsTest07", SCACGfbsTest07, 1);
    UtRegisterTest("SCACGfbsTest08", SCACGfbsTest08, 1);
    UtRegisterTest("SCACGfbsTest09", SCACGfbsTest09, 1);
    UtRegisterTest("SCACGfbsTest10", SCACGfbsTest10, 1);
    UtRegisterTest("SCACGfbsTest11", SCACGfbsTest11, 1);
    UtRegisterTest("SCACGfbsTest12", SCACGfbsTest12, 1);
    UtRegisterTest("SCACGfbsTest13", SCACGfbsTest13, 1);
    UtRegisterTest("SCACGfbsTest14", SCACGfbsTest14, 1);
    UtRegisterTest("SCACGfbsTest15", SCACGfbsTest15, 1);
    UtRegisterTest("SCACGfbsTest16", SCACGfbsTest16, 1);
    UtRegisterTest("SCACGfbsTest17", SCACGfbsTest17, 1);
    UtRegisterTest("SCACGfbsTest18", SCACGfbsTest18, 1);
    UtRegisterTest("SCACGfbsTest19", SCACGfbsTest19, 1);
    UtRegisterTest("SCACGfbsTest20", SCACGfbsTest20, 1);
    UtRegisterTest("SCACGfbsTest21", SCACGfbsTest21, 1);
    UtRegisterTest("SCACGfbsTest22", SCACGfbsTest22, 1);
    UtRegisterTest("SCACGfbsTest23", SCACGfbsTest23, 1);
    UtRegisterTest("SCACGfbsTest24", SCACGfbsTest24, 1);
    UtRegisterTest("SCACGfbsTest25", SCACGfbsTest25, 1);
    UtRegisterTest("SCACGfbsTest26", SCACGfbsTest26, 1);
    UtRegisterTest("SCACGfbsTest27", SCACGfbsTest27, 1);
    UtRegisterTest("SCACGfbsTest28", SCACGfbsTest28, 1);
    UtRegisterTest("SCACGfbsTest29", SCACGfbsTest29, 1);
#endif

    return;
}
