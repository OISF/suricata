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
 *         First iteration of aho-corasick MPM from -
 *
 *         Efficient String Matching: An Aid to Bibliographic Search
 *         Alfred V. Aho and Margaret J. Corasick
 *
 *         - Uses the delta table for calculating transitions, instead of having
 *           separate goto and failure transitions.
 *         - If we cross 2 ** 16 states, we use 4 bytes in the transition table
 *           to hold each state, otherwise we use 2 bytes.
 *         - This version of the MPM is heavy on memory, but it performs well.
 *           If you can fit the ruleset with this mpm on your box without hitting
 *           swap, this is the MPM to go for.
 *
 * \todo - Do a proper analyis of our existing MPMs and suggest a good one based
 *         on the pattern distribution and the expected traffic(say http).
 *       - Tried out loop unrolling without any perf increase.  Need to dig deeper.
 *       - Irrespective of whether we cross 2 ** 16 states or not,shift to using
 *         uint32_t for state type, so that we can integrate it's status as a
 *         final state or not in the topmost byte.  We are already doing it if
 *         state_count is > 2 ** 16.
 *       - Test case-senstive patterns if they have any ascii chars.  If they
 *         don't treat them as nocase.
 *       - Carry out other optimizations we are working on.  hashes, compression.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-mpm-ac-bs.h"

#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "util-memcpy.h"

void SCACBSInitCtx(MpmCtx *);
void SCACBSInitThreadCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void SCACBSDestroyCtx(MpmCtx *);
void SCACBSDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCACBSAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                       uint32_t, SigIntId, uint8_t);
int SCACBSAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                       uint32_t, SigIntId, uint8_t);
int SCACBSPreparePatterns(MpmCtx *mpm_ctx);
uint32_t SCACBSSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen);
void SCACBSPrintInfo(MpmCtx *mpm_ctx);
void SCACBSPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void SCACBSRegisterTests(void);

/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_BS_FAIL (-1)
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
 * \brief Register the aho-corasick mpm.
 */
void MpmACBSRegister(void)
{
    mpm_table[MPM_AC_BS].name = "ac-bs";
    /* don't need this.  isn't that awesome?  no more chopping and blah blah */
    mpm_table[MPM_AC_BS].max_pattern_length = 0;

    mpm_table[MPM_AC_BS].InitCtx = SCACBSInitCtx;
    mpm_table[MPM_AC_BS].InitThreadCtx = SCACBSInitThreadCtx;
    mpm_table[MPM_AC_BS].DestroyCtx = SCACBSDestroyCtx;
    mpm_table[MPM_AC_BS].DestroyThreadCtx = SCACBSDestroyThreadCtx;
    mpm_table[MPM_AC_BS].AddPattern = SCACBSAddPatternCS;
    mpm_table[MPM_AC_BS].AddPatternNocase = SCACBSAddPatternCI;
    mpm_table[MPM_AC_BS].Prepare = SCACBSPreparePatterns;
    mpm_table[MPM_AC_BS].Search = SCACBSSearch;
    mpm_table[MPM_AC_BS].Cleanup = NULL;
    mpm_table[MPM_AC_BS].PrintCtx = SCACBSPrintInfo;
    mpm_table[MPM_AC_BS].PrintThreadCtx = SCACBSPrintSearchStats;
    mpm_table[MPM_AC_BS].RegisterUnittests = SCACBSRegisterTests;

    return;
}

/**
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACBSGetConfig()
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
static inline uint32_t SCACBSInitHashRaw(uint8_t *pat, uint16_t patlen)
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
static inline SCACBSPattern *SCACBSInitHashLookup(SCACBSCtx *ctx, uint8_t *pat,
                                                  uint16_t patlen, char flags,
                                                  uint32_t pid)
{
    uint32_t hash = SCACBSInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL) {
        return NULL;
    }

    SCACBSPattern *t = ctx->init_hash[hash];
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
static inline SCACBSPattern *SCACBSAllocPattern(MpmCtx *mpm_ctx)
{
    SCACBSPattern *p = SCMalloc(sizeof(SCACBSPattern));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(SCACBSPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACBSPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCACBSPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCACBSPattern instance to be freed.
 */
static inline void SCACBSFreePattern(MpmCtx *mpm_ctx, SCACBSPattern *p)
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
        mpm_ctx->memory_size -= sizeof(SCACBSPattern);
    }
    return;
}

static inline uint32_t SCACBSInitHash(SCACBSPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int SCACBSInitHashAdd(SCACBSCtx *ctx, SCACBSPattern *p)
{
    uint32_t hash = SCACBSInitHash(p);

    if (ctx->init_hash == NULL) {
        return 0;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCACBSPattern *tt = NULL;
    SCACBSPattern *t = ctx->init_hash[hash];

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
static int SCACBSAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                            uint16_t offset, uint16_t depth, uint32_t pid,
                            SigIntId sid, uint8_t flags)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;

    SCLogDebug("Adding pattern for ctx %p, patlen %"PRIu16" and pid %" PRIu32,
               ctx, patlen, pid);

    if (patlen == 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCACBSPattern *p = SCACBSInitHashLookup(ctx, pat, patlen, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCACBSAllocPattern(mpm_ctx);

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
        SCACBSInitHashAdd(ctx, p);

        //if (mpm_ctx->pattern_cnt == 65535) {
        //    SCLogError(SC_ERR_AHO_CORASICK, "Max search words reached.  Can't "
        //               "insert anymore.  Exiting");
        //    exit(EXIT_FAILURE);
        //}
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
    SCACBSFreePattern(mpm_ctx, p);
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
static inline int SCACBSInitNewState(MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int size = 0;

    /* reallocate space in the goto table to include a new state */
    size = (ctx->state_count + 1) * ctx->single_state_size;
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
        ctx->goto_table[ctx->state_count][ascii_code] = SC_AC_BS_FAIL;
    }

    /* reallocate space in the output table for the new state */
    size = (ctx->state_count + 1) * sizeof(SCACBSOutputTable);
    ptmp = SCRealloc(ctx->output_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->output_table);
        ctx->output_table = NULL;
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    ctx->output_table = ptmp;

    memset(ctx->output_table + ctx->state_count, 0, sizeof(SCACBSOutputTable));

    /* \todo using it temporarily now during dev, since I have restricted
     *       state var in SCACBSCtx->state_table to uint16_t. */
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
static void SCACBSSetOutputState(int32_t state, uint32_t pid, MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    SCACBSOutputTable *output_state = &ctx->output_table[state];
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
 * \brief Helper function used by SCACBSCreateGotoTable.  Adds a pattern to the
 *        goto table.
 *
 * \param pattern     Pointer to the pattern.
 * \param pattern_len Pattern length.
 * \param pid         The pattern id, that corresponds to this pattern.  We
 *                    need it to updated the output table for this pattern.
 * \param mpm_ctx     Pointer to the mpm context.
 */
static inline void SCACBSEnter(uint8_t *pattern, uint16_t pattern_len, uint32_t pid,
                               MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int32_t state = 0;
    int32_t newstate = 0;
    int i = 0;
    int p = 0;

    /* walk down the trie till we have a match for the pattern prefix */
    state = 0;
    for (i = 0; i < pattern_len; i++) {
        if (ctx->goto_table[state][pattern[i]] != SC_AC_BS_FAIL) {
            state = ctx->goto_table[state][pattern[i]];
        } else {
            break;
        }
    }

    /* add the non-matching pattern suffix to the trie, from the last state
     * we left off */
    for (p = i; p < pattern_len; p++) {
        newstate = SCACBSInitNewState(mpm_ctx);
        ctx->goto_table[state][pattern[p]] = newstate;
        state = newstate;
    }

    /* add this pattern id, to the output table of the last state, where the
     * pattern ends in the trie */
    SCACBSSetOutputState(state, pid, mpm_ctx);

    return;
}

/**
 * \internal
 * \brief Create the goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACBSCreateGotoTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    uint32_t i = 0;

    /* add each pattern to create the goto table */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        SCACBSEnter(ctx->parray[i]->ci, ctx->parray[i]->len,
                  ctx->parray[i]->id, mpm_ctx);
    }

    int ascii_code = 0;
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        if (ctx->goto_table[0][ascii_code] == SC_AC_BS_FAIL) {
            ctx->goto_table[0][ascii_code] = 0;
        }
    }

    return;
}

static inline int SCACBSStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACBSEnqueue(StateQueue *q, int32_t state)
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

static inline int32_t SCACBSDequeue(StateQueue *q)
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
#define SCACBSStateQueueIsEmpty(q) (((q)->top == (q)->bot) ? 1 : 0)

#define SCACBSEnqueue(q, state) do { \
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

#define SCACBSDequeue(q) ( (((q)->bot == STATE_QUEUE_CONTAINER_SIZE)? ((q)->bot = 0): 0), \
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
 * \param dst_state First state(also the destination) for the union operation.
 * \param src_state Second state for the union operation.
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACBSClubOutputStates(int32_t dst_state, int32_t src_state,
                                        MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    uint32_t i = 0;
    uint32_t j = 0;

    SCACBSOutputTable *output_dst_state = &ctx->output_table[dst_state];
    SCACBSOutputTable *output_src_state = &ctx->output_table[src_state];

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
            else {
                output_dst_state->pids = ptmp;
            }

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
static inline void SCACBSCreateFailureTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int32_t state = 0;
    int32_t r_state = 0;

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    /* allot space for the failure table.  A failure entry in the table for
     * every state(SCACBSCtx->state_count) */
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
            SCACBSEnqueue(&q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACBSStateQueueIsEmpty(&q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACBSDequeue(&q);
        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            int32_t temp_state = ctx->goto_table[r_state][ascii_code];
            if (temp_state == SC_AC_BS_FAIL)
                continue;
            SCACBSEnqueue(&q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][ascii_code] == SC_AC_BS_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][ascii_code];
            SCACBSClubOutputStates(temp_state, ctx->failure_table[temp_state],
                                 mpm_ctx);
        }
    }

    return;
}

/**
 * \internal
 * \brief Create the delta table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACBSCreateDeltaTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int32_t r_state = 0;

    if (ctx->state_count < 32767) {
        ctx->state_table_u16 = SCMalloc(ctx->state_count *
                                        sizeof(SC_AC_BS_STATE_TYPE_U16) * 256);
        if (ctx->state_table_u16 == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_u16, 0,
               ctx->state_count * sizeof(SC_AC_BS_STATE_TYPE_U16) * 256);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += (ctx->state_count *
                                 sizeof(SC_AC_BS_STATE_TYPE_U16) * 256);

        StateQueue q;
        memset(&q, 0, sizeof(StateQueue));

        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            SC_AC_BS_STATE_TYPE_U16 temp_state = ctx->goto_table[0][ascii_code];
            ctx->state_table_u16[0][ascii_code] = temp_state;
            if (temp_state != 0)
                SCACBSEnqueue(&q, temp_state);
        }

        while (!SCACBSStateQueueIsEmpty(&q)) {
            r_state = SCACBSDequeue(&q);

            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                int32_t temp_state = ctx->goto_table[r_state][ascii_code];
                if (temp_state != SC_AC_BS_FAIL) {
                    SCACBSEnqueue(&q, temp_state);
                    ctx->state_table_u16[r_state][ascii_code] = temp_state;
                } else {
                    ctx->state_table_u16[r_state][ascii_code] =
                        ctx->state_table_u16[ctx->failure_table[r_state]][ascii_code];
                }
            }
        }
    } else {
        /* create space for the state table.  We could have used the existing goto
         * table, but since we have it set to hold 32 bit state values, we will create
         * a new state table here of type SC_AC_BS_STATE_TYPE(current set to uint16_t) */
        ctx->state_table_u32 = SCMalloc(ctx->state_count *
                                        sizeof(SC_AC_BS_STATE_TYPE_U32) * 256);
        if (ctx->state_table_u32 == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_u32, 0,
               ctx->state_count * sizeof(SC_AC_BS_STATE_TYPE_U32) * 256);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += (ctx->state_count *
                                 sizeof(SC_AC_BS_STATE_TYPE_U32) * 256);

        StateQueue q;
        memset(&q, 0, sizeof(StateQueue));

        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            SC_AC_BS_STATE_TYPE_U32 temp_state = ctx->goto_table[0][ascii_code];
            ctx->state_table_u32[0][ascii_code] = temp_state;
            if (temp_state != 0)
                SCACBSEnqueue(&q, temp_state);
        }

        while (!SCACBSStateQueueIsEmpty(&q)) {
            r_state = SCACBSDequeue(&q);

            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                int32_t temp_state = ctx->goto_table[r_state][ascii_code];
                if (temp_state != SC_AC_BS_FAIL) {
                    SCACBSEnqueue(&q, temp_state);
                    ctx->state_table_u32[r_state][ascii_code] = temp_state;
                } else {
                    ctx->state_table_u32[r_state][ascii_code] =
                        ctx->state_table_u32[ctx->failure_table[r_state]][ascii_code];
                }
            }
        }
    }

    return;
}

static inline void SCACBSClubOutputStatePresenceWithDeltaTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    uint32_t state = 0;
    uint32_t temp_state = 0;

    if (ctx->state_count < 32767) {
        for (state = 0; state < ctx->state_count; state++) {
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                temp_state = ctx->state_table_u16[state & 0x7FFF][ascii_code];
                if (ctx->output_table[temp_state & 0x7FFF].no_of_entries != 0)
                    ctx->state_table_u16[state & 0x7FFF][ascii_code] |= (1 << 15);
            }
        }
    } else {
        for (state = 0; state < ctx->state_count; state++) {
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                temp_state = ctx->state_table_u32[state & 0x00FFFFFF][ascii_code];
                if (ctx->output_table[temp_state & 0x00FFFFFF].no_of_entries != 0)
                    ctx->state_table_u32[state & 0x00FFFFFF][ascii_code] |= (1 << 24);
            }
        }
    }

    return;
}

static inline void SCACBSInsertCaseSensitiveEntriesForPatterns(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    uint32_t state = 0;
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

#if 0
static void SCACBSPrintDeltaTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int i = 0, j = 0;

    printf("##############Delta Table##############\n");
    for (i = 0; i < ctx->state_count; i++) {
        printf("%d: \n", i);
        for (j = 0; j < 256; j++) {
            if (SCACBSGetDelta(i, j, mpm_ctx) != 0) {
                printf("  %c -> %d\n", j, SCACBSGetDelta(i, j, mpm_ctx));
            }
        }
    }

    return;
}
#endif

static inline int SCACBSZeroTransitionPresent(SCACBSCtx *ctx, uint32_t state)
{
    if (state == 0)
        return 1;

    if (ctx->state_count < 32767) {
        int ascii;
        for (ascii = 0; ascii < 256; ascii++) {
            if ((ctx->state_table_u16[0][ascii] & 0x7fff) == (state & 0x7fff)) {
                return 1;
            }
        }

        return 0;
    } else {
        int ascii;
        for (ascii = 0; ascii < 256; ascii++) {
            if ((ctx->state_table_u32[0][ascii] & 0x00FFFFFF) ==
                (state & 0x00FFFFFF)) {
                return 1;
            }
        }

        return 0;
    }
}

/**
 * \internal
 * \brief Creates a new goto table structure(throw out all the failure
 *        transitions), to hold the existing goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACBSCreateModDeltaTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;

    if (ctx->state_count < 32767) {
        int size = 0;
        uint32_t state;

        for (state = 1; state < ctx->state_count; state++) {
            int ascii_code;
            int k = 0;
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                uint32_t temp_state = ctx->state_table_u16[state][ascii_code];
                if (SCACBSZeroTransitionPresent(ctx, temp_state))
                    continue;
                k++;
            }
            size += sizeof(uint16_t) * k * 2;
        }

        /* Let us use uint16_t for all.  That way we don//'t have to worry about
         * alignment.  Technically 8 bits is all we need to store ascii codes,
         * but by avoiding it, we save a lot of time on handling alignment */
        size += (ctx->state_count * sizeof(SC_AC_BS_STATE_TYPE_U16) +
                 256 * sizeof(SC_AC_BS_STATE_TYPE_U16) * 1);
        ctx->state_table_mod = SCMalloc(size);
        if (ctx->state_table_mod == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_mod, 0, size);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        /* buffer to hold pointers in the buffer, so that a state can use it
         * directly to access its state data */
        ctx->state_table_mod_pointers = SCMalloc(ctx->state_count * sizeof(uint8_t *));
        if (ctx->state_table_mod_pointers == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_mod_pointers, 0,
               ctx->state_count * sizeof(uint8_t *));

        SC_AC_BS_STATE_TYPE_U16 temp_states[256];
        uint16_t *curr_loc = (uint16_t *)ctx->state_table_mod;
        uint16_t *no_of_entries = NULL;
        uint16_t *ascii_codes = NULL;
        state = 0;
        uint16_t ascii_code = 0;
        uint16_t k = 0;
        for (state = 0; state < ctx->state_count; state++) {
            /* store the starting location in the buffer for this state */
            ctx->state_table_mod_pointers[state] = (uint8_t *)curr_loc;
            no_of_entries = curr_loc++;
            ascii_codes = curr_loc;
            k = 0;
            /* store all states that have non 0 transitions in the temp buffer */
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                uint32_t temp_state = ctx->state_table_u16[state][ascii_code];
                if (state != 0 && SCACBSZeroTransitionPresent(ctx, temp_state))
                    continue;

                ascii_codes[k] = ascii_code;
                temp_states[k] = ctx->state_table_u16[state][ascii_code];
                k++;
            }
            /* if we have any non 0 transitions from our previous for search,
             * store the acii codes as well the corresponding states */
            if (k > 0) {
                no_of_entries[0] = k;
                if (state != 0)
                    curr_loc += k;
                memcpy(curr_loc, temp_states, k * sizeof(SC_AC_BS_STATE_TYPE_U16));
                curr_loc += k;
            }
        }

        /* > 33766 */
    } else {
        int size = 0;
        uint32_t state;
        for (state = 1; state < ctx->state_count; state++) {
            int ascii_code;
            int k = 0;
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                uint32_t temp_state = ctx->state_table_u32[state][ascii_code];
                if (SCACBSZeroTransitionPresent(ctx, temp_state))
                    continue;
                k++;
            }
            size += sizeof(uint32_t) * k * 2;
        }

        /* Let us use uint32_t for all.  That way we don//'t have to worry about
         * alignment.  Technically 8 bits is all we need to store ascii codes,
         * but by avoiding it, we save a lot of time on handling alignment */
        size += (ctx->state_count * sizeof(SC_AC_BS_STATE_TYPE_U32) +
                 256 * sizeof(SC_AC_BS_STATE_TYPE_U32) * 1);
        ctx->state_table_mod = SCMalloc(size);
        if (ctx->state_table_mod == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_mod, 0, size);

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += size;

        /* buffer to hold pointers in the buffer, so that a state can use it
         * directly to access its state data */
        ctx->state_table_mod_pointers = SCMalloc(ctx->state_count * sizeof(uint8_t *));
        if (ctx->state_table_mod_pointers == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(ctx->state_table_mod_pointers, 0,
               ctx->state_count * sizeof(uint8_t *));

        SC_AC_BS_STATE_TYPE_U32 temp_states[256];
        uint32_t *curr_loc = (uint32_t *)ctx->state_table_mod;
        uint32_t *no_of_entries = NULL;
        uint32_t *ascii_codes = NULL;
        state = 0;
        uint32_t ascii_code = 0;
        uint32_t k = 0;
        for (state = 0; state < ctx->state_count; state++) {
            /* store the starting location in the buffer for this state */
            ctx->state_table_mod_pointers[state] = (uint8_t *)curr_loc;
            no_of_entries = curr_loc++;
            ascii_codes = curr_loc;
            k = 0;
            /* store all states that have non 0 transitions in the temp buffer */
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                uint32_t temp_state = ctx->state_table_u32[state][ascii_code];
                if (state != 0 && SCACBSZeroTransitionPresent(ctx, temp_state))
                    continue;

                ascii_codes[k] = ascii_code;
                temp_states[k] = ctx->state_table_u32[state][ascii_code];
                k++;
            }
            /* if we have any non 0 transitions from our previous for search,
             * store the acii codes as well the corresponding states */
            if (k > 0) {
                no_of_entries[0] = k;
                if (state != 0)
                    curr_loc += k;
                memcpy(curr_loc, temp_states, k * sizeof(SC_AC_BS_STATE_TYPE_U32));
                curr_loc += k;
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
static inline void SCACBSPrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;

    /* create the 0th state in the goto table and output_table */
    SCACBSInitNewState(mpm_ctx);

    /* create the goto table */
    SCACBSCreateGotoTable(mpm_ctx);
    /* create the failure table */
    SCACBSCreateFailureTable(mpm_ctx);
    /* create the final state(delta) table */
    SCACBSCreateDeltaTable(mpm_ctx);
    /* club the output state presence with delta transition entries */
    SCACBSClubOutputStatePresenceWithDeltaTable(mpm_ctx);
    /* create the modified table */
    SCACBSCreateModDeltaTable(mpm_ctx);

    /* club nocase entries */
    SCACBSInsertCaseSensitiveEntriesForPatterns(mpm_ctx);

//    int state = 0;
//    for (state = 0; state < ctx->state_count; state++) {
//        int i = 0;
//        for (i = 0; i < 256; i++) {
//            if (ctx->state_table_u16[state][i] != 0) {
//                printf("%d-%d-%d\n", state, i, ctx->state_table_u16[state][i] & 0x7fff) ;
//            }
//        }
//    }

#if 0
    SCACBSPrintDeltaTable(mpm_ctx);
#endif

    /* we don't need these anymore */
    SCFree(ctx->goto_table);
    ctx->goto_table = NULL;
    SCFree(ctx->failure_table);
    ctx->failure_table = NULL;
    SCFree(ctx->state_table_u16);
    ctx->state_table_u16 = NULL;
    SCFree(ctx->state_table_u32);
    ctx->state_table_u32 = NULL;

    return;
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCACBSPreparePatterns(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0 || ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (SCACBSPattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                           sizeof(SCACBSPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(SCACBSPattern *));
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(SCACBSPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        SCACBSPattern *node = ctx->init_hash[i], *nnode = NULL;
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
    ctx->single_state_size = sizeof(int32_t) * 256;

    /* handle no case patterns */
    ctx->pid_pat_list = SCMalloc((ctx->max_pat_id + 1)* sizeof(SCACBSPatternList));
    if (ctx->pid_pat_list == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->pid_pat_list, 0, (ctx->max_pat_id + 1) * sizeof(SCACBSPatternList));

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
    SCACBSPrepareStateTable(mpm_ctx);

    /* free all the stored patterns.  Should save us a good 100-200 mbs */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i] != NULL) {
            SCACBSFreePattern(mpm_ctx, ctx->parray[i]);
        }
    }
    SCFree(ctx->parray);
    ctx->parray = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACBSPattern *));

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
void SCACBSInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = SCMalloc(sizeof(SCACBSThreadCtx));
    if (mpm_thread_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_thread_ctx->ctx, 0, sizeof(SCACBSThreadCtx));
    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCACBSThreadCtx);

    return;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 * \param module_handle Cuda module handle from the cuda handler API.  We don't
 *                      have to worry about this here.
 */
void SCACBSInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCMalloc(sizeof(SCACBSCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->ctx, 0, sizeof(SCACBSCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACBSCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCMalloc(sizeof(SCACBSPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(ctx->init_hash, 0, sizeof(SCACBSPattern *) * INIT_HASH_SIZE);

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACBSGetConfig();

    SCReturn;
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACBSDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCACBSPrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCACBSThreadCtx);
    }

    return;
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCACBSDestroyCtx(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash != NULL) {
        SCFree(ctx->init_hash);
        ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(SCACBSPattern *));
    }

    if (ctx->parray != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                SCACBSFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        ctx->parray = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACBSPattern *));
    }

    if (ctx->state_table_u16 != NULL) {
        SCFree(ctx->state_table_u16);
        ctx->state_table_u16 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_BS_STATE_TYPE_U16) * 256);
    } else if (ctx->state_table_u32 != NULL) {
        SCFree(ctx->state_table_u32);
        ctx->state_table_u32 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_BS_STATE_TYPE_U32) * 256);
    }

    if (ctx->output_table != NULL) {
        uint32_t state_count;
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

    if (ctx->state_table_mod != NULL) {
        SCFree(ctx->state_table_mod);
        ctx->state_table_mod = NULL;
    }

    if (ctx->state_table_mod_pointers != NULL) {
        SCFree(ctx->state_table_mod_pointers);
        ctx->state_table_mod_pointers = NULL;
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACBSCtx);

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
uint32_t SCACBSSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;
    int i = 0;
    int matches = 0;
    uint8_t buf_local;

    /* \todo tried loop unrolling with register var, with no perf increase.  Need
     * to dig deeper */
    /* \todo Change it for stateful MPM.  Supply the state using mpm_thread_ctx */
    SCACBSPatternList *pid_pat_list = ctx->pid_pat_list;

    uint8_t bitarray[pmq->pattern_id_bitarray_size];
    memset(bitarray, 0, pmq->pattern_id_bitarray_size);

    if (ctx->state_count < 32767) {
        register SC_AC_BS_STATE_TYPE_U16 state = 0;
        uint16_t no_of_entries;
        uint16_t *ascii_codes;
        uint16_t **state_table_mod_pointers = (uint16_t **)ctx->state_table_mod_pointers;
        uint16_t *zero_state = state_table_mod_pointers[0] + 1;

        for (i = 0; i < buflen; i++) {
            if (state == 0) {
                state = zero_state[u8_tolower(buf[i])];
            } else {
                no_of_entries = *(state_table_mod_pointers[state & 0x7FFF]);
                if (no_of_entries == 1) {
                    ascii_codes = state_table_mod_pointers[state & 0x7FFF] + 1;
                    buf_local = u8_tolower(buf[i]);
                    if (buf_local == ascii_codes[0]) {
                        state = *(ascii_codes + no_of_entries);;
                    } else {
                        state = zero_state[buf_local];
                    }
                } else {
                    if (no_of_entries == 0) {
                        state = zero_state[u8_tolower(buf[i])];
                        goto match_u16;
                    }
                    buf_local = u8_tolower(buf[i]);
                    ascii_codes = state_table_mod_pointers[state & 0x7FFF] + 1;
                    int low = 0;
                    int high = no_of_entries;
                    int mid;
                    state = 0;
                    while (low <= high) {
                        mid = (low + high) / 2;
                        if (ascii_codes[mid] == buf_local) {
                            state = ((ascii_codes + no_of_entries))[mid];
                            goto match_u16;
                        } else if (ascii_codes[mid] < buf_local) {
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    } /* while */
                    state = zero_state[buf_local];
                } /* else - if (no_of_entires == 1) */
            }

        match_u16:
            if (state & 0x8000) {
                uint32_t no_of_entries = ctx->output_table[state & 0x7FFF].no_of_entries;
                uint32_t *pids = ctx->output_table[state & 0x7FFF].pids;
                uint32_t k;
                for (k = 0; k < no_of_entries; k++) {
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
            }
        } /* for (i = 0; i < buflen; i++) */

    } else {
        register SC_AC_BS_STATE_TYPE_U32 state = 0;
        uint32_t no_of_entries;
        uint32_t *ascii_codes;
        uint32_t **state_table_mod_pointers = (uint32_t **)ctx->state_table_mod_pointers;
        uint32_t *zero_state = state_table_mod_pointers[0] + 1;

        for (i = 0; i < buflen; i++) {
            if (state == 0) {
                state = zero_state[u8_tolower(buf[i])];
            } else {
                no_of_entries = *(state_table_mod_pointers[state & 0x00FFFFFF]);
                if (no_of_entries == 1) {
                    ascii_codes = state_table_mod_pointers[state & 0x00FFFFFF] + 1;
                    buf_local = u8_tolower(buf[i]);
                    if (buf_local == ascii_codes[0]) {
                        state = *(ascii_codes + no_of_entries);;
                    } else {
                        state = zero_state[buf_local];;
                    }
                } else {
                    if (no_of_entries == 0) {
                        state = zero_state[u8_tolower(buf[i])];
                        goto match_u32;
                    }
                    buf_local = u8_tolower(buf[i]);
                    ascii_codes = state_table_mod_pointers[state & 0x00FFFFFF] + 1;
                    int low = 0;
                    int high = no_of_entries;
                    int mid;
                    state = 0;
                    while (low <= high) {
                        mid = (low + high) / 2;
                        if (ascii_codes[mid] == buf_local) {
                            state = ((ascii_codes + no_of_entries))[mid];
                            goto match_u32;
                        } else if (ascii_codes[mid] < buf_local) {
                            low = mid + 1;
                        } else {
                            high = mid - 1;
                        }
                    } /* while */
                    state = zero_state[buf_local];
                } /* else - if (no_of_entires == 1) */
            }

        match_u32:
            if (state & 0xFF000000) {
                uint32_t no_of_entries = ctx->output_table[state & 0x00FFFFFF].no_of_entries;
                uint32_t *pids = ctx->output_table[state & 0x00FFFFFF].pids;
                uint32_t k;
                for (k = 0; k < no_of_entries; k++) {
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
            }
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
int SCACBSAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return SCACBSAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
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
int SCACBSAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    return SCACBSAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCACBSPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{

#ifdef SC_AC_BS_COUNTERS
    SCACBSThreadCtx *ctx = (SCACBSThreadCtx *)mpm_thread_ctx->ctx;
    printf("AC Thread Search stats (ctx %p)\n", ctx);
    printf("Total calls: %" PRIu32 "\n", ctx->total_calls);
    printf("Total matches: %" PRIu64 "\n", ctx->total_matches);
#endif /* SC_AC_BS_COUNTERS */

    return;
}

void SCACBSPrintInfo(MpmCtx *mpm_ctx)
{
    SCACBSCtx *ctx = (SCACBSCtx *)mpm_ctx->ctx;

    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCACBSCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(SCACBSCtx));
    printf("  SCACBSPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(SCACBSPattern));
    printf("  SCACBSPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(SCACBSPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %" PRIu32 "\n", ctx->state_count);
    printf("\n");

    return;
}

/*************************************Unittests********************************/

#ifdef UNITTESTS

static int SCACBSTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcd";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

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
    PmqSetup(&pmq, 6);
    /* total matches: 135 */

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq, 5);

    if (SCACBSPreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    char *buf = "he";
    result &= (SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "she";
    result &= (SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);
    buf = "his";
    result &= (SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);

 end:
    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcde""fghij""klmno""pqrst""uvwxy""z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 3);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 2);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "works";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "tone";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 1);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "tONE";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest29(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_BS);
    SCACBSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdef", 5, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"cdefg", 5, 0, 0, 3, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"defgh", 5, 0, 0, 4, 0, 0);
    PmqSetup(&pmq, 4);

    SCACBSPreparePatterns(&mpm_ctx);

    char *buf = "abcdefgh";
    uint32_t cnt = SCACBSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                (uint8_t *)buf, strlen(buf));

    if (cnt == 4)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACBSDestroyCtx(&mpm_ctx);
    SCACBSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACBSTest30(void)
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
    de_ctx->mpm_matcher = MPM_AC_BS;

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

void SCACBSRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCACBSTest01", SCACBSTest01, 1);
    UtRegisterTest("SCACBSTest02", SCACBSTest02, 1);
    UtRegisterTest("SCACBSTest03", SCACBSTest03, 1);
    UtRegisterTest("SCACBSTest04", SCACBSTest04, 1);
    UtRegisterTest("SCACBSTest05", SCACBSTest05, 1);
    UtRegisterTest("SCACBSTest06", SCACBSTest06, 1);
    UtRegisterTest("SCACBSTest07", SCACBSTest07, 1);
    UtRegisterTest("SCACBSTest08", SCACBSTest08, 1);
    UtRegisterTest("SCACBSTest09", SCACBSTest09, 1);
    UtRegisterTest("SCACBSTest10", SCACBSTest10, 1);
    UtRegisterTest("SCACBSTest11", SCACBSTest11, 1);
    UtRegisterTest("SCACBSTest12", SCACBSTest12, 1);
    UtRegisterTest("SCACBSTest13", SCACBSTest13, 1);
    UtRegisterTest("SCACBSTest14", SCACBSTest14, 1);
    UtRegisterTest("SCACBSTest15", SCACBSTest15, 1);
    UtRegisterTest("SCACBSTest16", SCACBSTest16, 1);
    UtRegisterTest("SCACBSTest17", SCACBSTest17, 1);
    UtRegisterTest("SCACBSTest18", SCACBSTest18, 1);
    UtRegisterTest("SCACBSTest19", SCACBSTest19, 1);
    UtRegisterTest("SCACBSTest20", SCACBSTest20, 1);
    UtRegisterTest("SCACBSTest21", SCACBSTest21, 1);
    UtRegisterTest("SCACBSTest22", SCACBSTest22, 1);
    UtRegisterTest("SCACBSTest23", SCACBSTest23, 1);
    UtRegisterTest("SCACBSTest24", SCACBSTest24, 1);
    UtRegisterTest("SCACBSTest25", SCACBSTest25, 1);
    UtRegisterTest("SCACBSTest26", SCACBSTest26, 1);
    UtRegisterTest("SCACBSTest27", SCACBSTest27, 1);
    UtRegisterTest("SCACBSTest28", SCACBSTest28, 1);
    UtRegisterTest("SCACBSTest29", SCACBSTest29, 1);
    UtRegisterTest("SCACBSTest30", SCACBSTest30, 1);
#endif

    return;
}
