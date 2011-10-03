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
 * \file
 *
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
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
#include "util-mpm-ac.h"

#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-memcmp.h"

void SCACInitCtx(MpmCtx *, int);
void SCACInitThreadCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void SCACDestroyCtx(MpmCtx *);
void SCACDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCACAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, uint32_t, uint8_t);
int SCACAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, uint32_t, uint8_t);
int SCACPreparePatterns(MpmCtx *mpm_ctx);
uint32_t SCACSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen);
void SCACPrintInfo(MpmCtx *mpm_ctx);
void SCACPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void SCACRegisterTests(void);

/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_FAIL (-1)
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
void MpmACRegister(void)
{
    mpm_table[MPM_AC].name = "ac";
    /* don't need this.  isn't that awesome?  no more chopping and blah blah */
    mpm_table[MPM_AC].max_pattern_length = 0;

    mpm_table[MPM_AC].InitCtx = SCACInitCtx;
    mpm_table[MPM_AC].InitThreadCtx = SCACInitThreadCtx;
    mpm_table[MPM_AC].DestroyCtx = SCACDestroyCtx;
    mpm_table[MPM_AC].DestroyThreadCtx = SCACDestroyThreadCtx;
    mpm_table[MPM_AC].AddPattern = SCACAddPatternCS;
    mpm_table[MPM_AC].AddPatternNocase = SCACAddPatternCI;
    mpm_table[MPM_AC].Prepare = SCACPreparePatterns;
    mpm_table[MPM_AC].Search = SCACSearch;
    mpm_table[MPM_AC].Cleanup = NULL;
    mpm_table[MPM_AC].PrintCtx = SCACPrintInfo;
    mpm_table[MPM_AC].PrintThreadCtx = SCACPrintSearchStats;
    mpm_table[MPM_AC].RegisterUnittests = SCACRegisterTests;

    return;
}

/**
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACGetConfig()
{
    //ConfNode *ac_conf;
    //const char *hash_val = NULL;

    //ConfNode *pm = ConfGetNode("pattern-matcher");

    return;
}

/**
 * \internal
 * \brief Compares 2 patterns.  We use it for the hashing process during the
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param p      Pointer to the first pattern(SCACPattern).
 * \param pat    Pointer to the second pattern(raw pattern array).
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline int SCACCmpPattern(SCACPattern *p, uint8_t *pat, uint16_t patlen,
                                 char flags)
{
    if (p->len != patlen)
        return 0;

    if (p->flags != flags)
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
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
static inline uint32_t SCACInitHashRaw(uint8_t *pat, uint16_t patlen)
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
static inline SCACPattern *SCACInitHashLookup(SCACCtx *ctx, uint8_t *pat,
                                              uint16_t patlen, char flags,
                                              uint32_t pid)
{
    uint32_t hash = SCACInitHashRaw(pat, patlen);

    if (ctx->init_hash[hash] == NULL) {
        return NULL;
    }

    SCACPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        //if (SCACCmpPattern(t, pat, patlen, flags) == 1)
        if (t->flags == flags && t->id == pid)
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
static inline SCACPattern *SCACAllocPattern(MpmCtx *mpm_ctx)
{
    SCACPattern *p = SCMalloc(sizeof(SCACPattern));
    if (p == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(SCACPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCACPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCACPattern instance to be freed.
 */
static inline void SCACFreePattern(MpmCtx *mpm_ctx, SCACPattern *p)
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
        mpm_ctx->memory_size -= sizeof(SCACPattern);
    }
    return;
}

/**
 * \internal
 * \brief Does a memcpy of the input string to lowercase.
 *
 * \param d   Pointer to the target area for memcpy.
 * \param s   Pointer to the src string for memcpy.
 * \param len len of the string sent in s.
 */
static inline void memcpy_tolower(uint8_t *d, uint8_t *s, uint16_t len)
{
    uint16_t i;
    for (i = 0; i < len; i++)
        d[i] = u8_tolower(s[i]);

    return;
}

static inline uint32_t SCACInitHash(SCACPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int SCACInitHashAdd(SCACCtx *ctx, SCACPattern *p)
{
    uint32_t hash = SCACInitHash(p);

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCACPattern *tt = NULL;
    SCACPattern *t = ctx->init_hash[hash];

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
static int SCACAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                          uint16_t offset, uint16_t depth, uint32_t pid,
                          uint32_t sid, uint8_t flags)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    SCLogDebug("Adding pattern for ctx %p, patlen %"PRIu16" and pid %" PRIu32,
               ctx, patlen, pid);

    if (patlen == 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCACPattern *p = SCACInitHashLookup(ctx, pat, patlen, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCACAllocPattern(mpm_ctx);

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
        SCACInitHashAdd(ctx, p);

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
    }

    return 0;

error:
    SCACFreePattern(mpm_ctx, p);
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
static inline int SCACInitNewState(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int size = 0;

    /* reallocate space in the goto table to include a new state */
    size = (ctx->state_count + 1) * ctx->single_state_size;
    ctx->goto_table = SCRealloc(ctx->goto_table, size);
    if (ctx->goto_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    /* set all transitions for the newly assigned state as FAIL transitions */
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        ctx->goto_table[ctx->state_count][ascii_code] = SC_AC_FAIL;
    }

    /* reallocate space in the output table for the new state */
    size = (ctx->state_count + 1) * sizeof(SCACOutputTable);
    ctx->output_table = SCRealloc(ctx->output_table, size);
    if (ctx->output_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->output_table + ctx->state_count, 0, sizeof(SCACOutputTable));

    /* \todo using it temporarily now during dev, since I have restricted
     *       state var in SCACCtx->state_table to uint16_t. */
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
static void SCACSetOutputState(int32_t state, uint32_t pid, MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    SCACOutputTable *output_state = &ctx->output_table[state];
    uint32_t i = 0;

    for (i = 0; i < output_state->no_of_entries; i++) {
        if (output_state->pids[i] == pid)
            return;
    }

    output_state->no_of_entries++;
    output_state->pids = SCRealloc(output_state->pids,
                                   output_state->no_of_entries * sizeof(uint32_t));
    if (output_state->pids == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    output_state->pids[output_state->no_of_entries - 1] = pid;

    return;
}

/**
 * \brief Helper function used by SCACCreateGotoTable.  Adds a pattern to the
 *        goto table.
 *
 * \param pattern     Pointer to the pattern.
 * \param pattern_len Pattern length.
 * \param pid         The pattern id, that corresponds to this pattern.  We
 *                    need it to updated the output table for this pattern.
 * \param mpm_ctx     Pointer to the mpm context.
 */
static inline void SCACEnter(uint8_t *pattern, uint16_t pattern_len, uint32_t pid,
                             MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int32_t state = 0;
    int32_t newstate = 0;
    int i = 0;
    int p = 0;

    /* walk down the trie till we have a match for the pattern prefix */
    state = 0;
    for (i = 0; i < pattern_len; i++) {
        if (ctx->goto_table[state][pattern[i]] != SC_AC_FAIL) {
            state = ctx->goto_table[state][pattern[i]];
        } else {
            break;
        }
    }

    /* add the non-matching pattern suffix to the trie, from the last state
     * we left off */
    for (p = i; p < pattern_len; p++) {
        newstate = SCACInitNewState(mpm_ctx);
        ctx->goto_table[state][pattern[p]] = newstate;
        state = newstate;
    }

    /* add this pattern id, to the output table of the last state, where the
     * pattern ends in the trie */
    SCACSetOutputState(state, pid, mpm_ctx);

    return;
}

/**
 * \internal
 * \brief Create the goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACCreateGotoTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    uint32_t i = 0;

    /* add each pattern to create the goto table */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        SCACEnter(ctx->parray[i]->ci, ctx->parray[i]->len,
                  ctx->parray[i]->id, mpm_ctx);
    }

    int ascii_code = 0;
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        if (ctx->goto_table[0][ascii_code] == SC_AC_FAIL) {
            ctx->goto_table[0][ascii_code] = 0;
        }
    }

    return;
}

static inline int SCACStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACEnqueue(StateQueue *q, int32_t state)
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

static inline int32_t SCACDequeue(StateQueue *q)
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
#define SCACStateQueueIsEmpty(q) (((q)->top == (q)->bot) ? 1 : 0)

#define SCACEnqueue(q, state) do { \
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

#define SCACDequeue(q) ( (((q)->bot == STATE_QUEUE_CONTAINER_SIZE)? ((q)->bot = 0): 0), \
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
static inline void SCACClubOutputStates(int32_t dst_state, int32_t src_state,
                                        MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    uint32_t i = 0;
    uint32_t j = 0;

    SCACOutputTable *output_dst_state = &ctx->output_table[dst_state];
    SCACOutputTable *output_src_state = &ctx->output_table[src_state];

    for (i = 0; i < output_src_state->no_of_entries; i++) {
        for (j = 0; j < output_dst_state->no_of_entries; j++) {
            if (output_src_state->pids[i] == output_dst_state->pids[j]) {
                break;
            }
        }
        if (j == output_dst_state->no_of_entries) {
            output_dst_state->no_of_entries++;

            output_dst_state->pids = SCRealloc(output_dst_state->pids,
                                               (output_dst_state->no_of_entries *
                                                sizeof(uint32_t)) );
            if (output_dst_state->pids == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
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
static inline void SCACCreateFailureTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int32_t state = 0;
    int32_t r_state = 0;

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    /* allot space for the failure table.  A failure entry in the table for
     * every state(SCACCtx->state_count) */
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
            SCACEnqueue(&q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACStateQueueIsEmpty(&q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACDequeue(&q);
        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            int32_t temp_state = ctx->goto_table[r_state][ascii_code];
            if (temp_state == SC_AC_FAIL)
                continue;
            SCACEnqueue(&q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][ascii_code] == SC_AC_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][ascii_code];
            SCACClubOutputStates(temp_state, ctx->failure_table[temp_state],
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
static inline void SCACCreateDeltaTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    int32_t r_state = 0;

    /* create space for the state table.  We could have used the existing goto
     * table, but since we have it set to hold 32 bit state values, we will create
     * a new state table here of type SC_AC_STATE_TYPE(current set to uint16_t) */
    ctx->state_table_u32 = SCMalloc(ctx->state_count *
                                    sizeof(SC_AC_STATE_TYPE_U32) * 256);
    if (ctx->state_table_u32 == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->state_table_u32, 0,
           ctx->state_count * sizeof(SC_AC_STATE_TYPE_U32) * 256);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (ctx->state_count *
                             sizeof(SC_AC_STATE_TYPE_U32) * 256);

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        SC_AC_STATE_TYPE_U32 temp_state = ctx->goto_table[0][ascii_code];
        ctx->state_table_u32[0][ascii_code] = temp_state;
        if (temp_state != 0)
            SCACEnqueue(&q, temp_state);
    }

    while (!SCACStateQueueIsEmpty(&q)) {
        r_state = SCACDequeue(&q);

        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            int32_t temp_state = ctx->goto_table[r_state][ascii_code];
            if (temp_state != SC_AC_FAIL) {
                SCACEnqueue(&q, temp_state);
                ctx->state_table_u32[r_state][ascii_code] = temp_state;
            } else {
                ctx->state_table_u32[r_state][ascii_code] =
                    ctx->state_table_u32[ctx->failure_table[r_state]][ascii_code];
            }
        }
    }

    return;
}

static inline void SCACClubOutputStatePresenceWithDeltaTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    uint32_t state = 0;
    uint32_t temp_state = 0;

    for (state = 0; state < ctx->state_count; state++) {
        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            temp_state = ctx->state_table_u32[state & 0x00FFFFFF][ascii_code];
            if (ctx->output_table[temp_state & 0x00FFFFFF].no_of_entries != 0)
                ctx->state_table_u32[state & 0x00FFFFFF][ascii_code] |= (1 << 24);
        }
    }

    return;
}

static inline void SCACInsertCaseSensitiveEntriesForPatterns(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
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
static void SCACPrintDeltaTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int i = 0, j = 0;

    printf("##############Delta Table##############\n");
    for (i = 0; i < ctx->state_count; i++) {
        printf("%d: \n", i);
        for (j = 0; j < 256; j++) {
            if (SCACGetDelta(i, j, mpm_ctx) != 0) {
                printf("  %c -> %d\n", j, SCACGetDelta(i, j, mpm_ctx));
            }
        }
    }

    return;
}
#endif

/**
 * \brief Process the patterns and prepare the state table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACPrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    /* create the 0th state in the goto table and output_table */
    SCACInitNewState(mpm_ctx);

    /* create the goto table */
    SCACCreateGotoTable(mpm_ctx);
    /* create the failure table */
    SCACCreateFailureTable(mpm_ctx);
    /* create the final state(delta) table */
    SCACCreateDeltaTable(mpm_ctx);
    /* club the output state presence with delta transition entries */
    SCACClubOutputStatePresenceWithDeltaTable(mpm_ctx);

    /* club nocase entries */
    SCACInsertCaseSensitiveEntriesForPatterns(mpm_ctx);

#if 0
    SCACPrintDeltaTable(mpm_ctx);
#endif

    /* we don't need these anymore */
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
int SCACPreparePatterns(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (SCACPattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                           sizeof(SCACPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(SCACPattern *));
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(SCACPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        SCACPattern *node = ctx->init_hash[i], *nnode = NULL;
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
    ctx->pid_pat_list = SCMalloc((ctx->max_pat_id + 1)* sizeof(SCACPatternList));
    if (ctx->pid_pat_list == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(ctx->pid_pat_list, 0, (ctx->max_pat_id + 1) * sizeof(SCACPatternList));

    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE) {
            if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 0)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 1;
            else if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 1)
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 1;
            else
                ctx->pid_pat_list[ctx->parray[i]->id].case_state = 3;
        } else {
            //if (memcmp(ctx->parray[i]->original_pat, ctx->parray[i]->ci,
            //           ctx->parray[i]->len) != 0) {
                ctx->pid_pat_list[ctx->parray[i]->id].cs = SCMalloc(ctx->parray[i]->len);
                if (ctx->pid_pat_list[ctx->parray[i]->id].cs == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                memcpy(ctx->pid_pat_list[ctx->parray[i]->id].cs,
                       ctx->parray[i]->original_pat, ctx->parray[i]->len);
                ctx->pid_pat_list[ctx->parray[i]->id].patlen = ctx->parray[i]->len;

                if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 0)
                    ctx->pid_pat_list[ctx->parray[i]->id].case_state = 2;
                else if (ctx->pid_pat_list[ctx->parray[i]->id].case_state == 2)
                    ctx->pid_pat_list[ctx->parray[i]->id].case_state = 2;
                else
                    ctx->pid_pat_list[ctx->parray[i]->id].case_state = 3;
                //}
        }
    }

    /* prepare the state table required by AC */
    SCACPrepareStateTable(mpm_ctx);

    /* free all the stored patterns.  Should save us a good 100-200 mbs */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i] != NULL) {
            SCACFreePattern(mpm_ctx, ctx->parray[i]);
        }
    }
    SCFree(ctx->parray);
    ctx->parray = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACPattern *));

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
void SCACInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = SCMalloc(sizeof(SCACThreadCtx));
    if (mpm_thread_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_thread_ctx->ctx, 0, sizeof(SCACThreadCtx));
    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCACThreadCtx);

    return;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 * \param module_handle Cuda module handle from the cuda handler API.  We don't
 *                      have to worry about this here.
 */
void SCACInitCtx(MpmCtx *mpm_ctx, int module_handle)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCMalloc(sizeof(SCACCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->ctx, 0, sizeof(SCACCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCMalloc(sizeof(SCACPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(ctx->init_hash, 0, sizeof(SCACPattern *) * INIT_HASH_SIZE);

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACGetConfig();

    SCReturn;
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCACPrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCACThreadCtx);
    }

    return;
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCACDestroyCtx(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash != NULL) {
        SCFree(ctx->init_hash);
        ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(SCACPattern *));
    }

    if (ctx->parray != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                SCACFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        ctx->parray = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(SCACPattern *));
    }

    if (ctx->state_table_u32 != NULL) {
        SCFree(ctx->state_table_u32);
        ctx->state_table_u32 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_STATE_TYPE_U32) * 256);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACCtx);

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
uint32_t SCACSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int i = 0;
    int matches = 0;

    /* \todo tried loop unrolling with register var, with no perf increase.  Need
     * to dig deeper */
    /* \todo Change it for stateful MPM.  Supply the state using mpm_thread_ctx */
    SC_AC_STATE_TYPE_U32 (*state_table_u32)[256] = ctx->state_table_u32;
    SCACPatternList *pid_pat_list = ctx->pid_pat_list;
    register SC_AC_STATE_TYPE_U32 state = 0;
    for (i = 0; i < buflen; i++) {
        state = state_table_u32[state & 0x00FFFFFF][u8_tolower(buf[i])];
        if (state & 0xFF000000) {
            uint32_t no_of_entries = ctx->output_table[state & 0x00FFFFFF].no_of_entries;
            uint32_t *pids = ctx->output_table[state & 0x00FFFFFF].pids;
            uint32_t k;
            for (k = 0; k < no_of_entries; k++) {
                if (pids[k] & 0xFFFF0000) {
                    if (SCMemcmp(pid_pat_list[pids[k] & 0x0000FFFF].cs,
                                 buf + i - pid_pat_list[pids[k] & 0x0000FFFF].patlen + 1,
                                 pid_pat_list[pids[k] & 0x0000FFFF].patlen) != 0) {
                        /* inside loop */
                        if (pid_pat_list[pids[k] & 0x0000FFFF].case_state != 3) {
                            continue;
                        }
                    }
                    if (pmq->pattern_id_bitarray[(pids[k] & 0x0000FFFF) / 8] & (1 << ((pids[k] & 0x0000FFFF) % 8))) {
                        ;
                    } else {
                        pmq->pattern_id_bitarray[(pids[k] & 0x0000FFFF) / 8] |= (1 << ((pids[k] & 0x0000FFFF) % 8));
                        pmq->pattern_id_array[pmq->pattern_id_array_cnt++] = pids[k] & 0x0000FFFF;
                    }
                    matches++;
                } else {
                    if (pmq->pattern_id_bitarray[pids[k] / 8] & (1 << (pids[k] % 8))) {
                        ;
                    } else {
                        pmq->pattern_id_bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                        pmq->pattern_id_array[pmq->pattern_id_array_cnt++] = pids[k];
                    }
                    matches++;
                }
                //loop1:
                //;
            }
        }
    } /* for (i = 0; i < buflen; i++) */

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
int SCACAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     uint32_t sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return SCACAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
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
int SCACAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     uint32_t sid, uint8_t flags)
{
    return SCACAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCACPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{

#ifdef SC_AC_COUNTERS
    SCACThreadCtx *ctx = (SCACThreadCtx *)mpm_thread_ctx->ctx;
    printf("AC Thread Search stats (ctx %p)\n", ctx);
    printf("Total calls: %" PRIu32 "\n", ctx->total_calls);
    printf("Total matches: %" PRIu64 "\n", ctx->total_matches);
#endif /* SC_AC_COUNTERS */

    return;
}

void SCACPrintInfo(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCACCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(SCACCtx));
    printf("  SCACPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(SCACPattern));
    printf("  SCACPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(SCACPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %" PRIu32 "\n", ctx->state_count);
    printf("\n");

    return;
}

/*************************************Unittests********************************/

#ifdef UNITTESTS

static int SCACTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcd";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* should match 30 times */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     30, 0, 0, 5, 0, 0);
    PmqSetup(&pmq, 0, 6);
    /* total matches: 135 */

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    if (SCACAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (SCACAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (SCACAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (SCACAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq, 0, 5);

    if (SCACPreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    char *buf = "he";
    result &= (SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "she";
    result &= (SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);
    buf = "his";
    result &= (SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);

 end:
    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCD";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDE";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABCDEF";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzABC";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcdefghijklmnopqrstuvwxyzAB";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    char *pat = "abcde""fghij""klmno""pqrst""uvwxy""z";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    char *pat = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)pat, strlen(pat), 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 1 */
    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq, 0, 3);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    SCACAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq, 0, 2);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "works";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "tone";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PatternMatcherQueue pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC, -1);
    SCACInitThreadCtx(&mpm_ctx, &mpm_thread_ctx, 0);

    /* 0 match */
    SCACAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq, 0, 1);

    SCACPreparePatterns(&mpm_ctx);

    char *buf = "tONE";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    SCACDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

#endif /* UNITTESTS */

void SCACRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCACTest01", SCACTest01, 1);
    UtRegisterTest("SCACTest02", SCACTest02, 1);
    UtRegisterTest("SCACTest03", SCACTest03, 1);
    UtRegisterTest("SCACTest04", SCACTest04, 1);
    UtRegisterTest("SCACTest05", SCACTest05, 1);
    UtRegisterTest("SCACTest06", SCACTest06, 1);
    UtRegisterTest("SCACTest07", SCACTest07, 1);
    UtRegisterTest("SCACTest08", SCACTest08, 1);
    UtRegisterTest("SCACTest09", SCACTest09, 1);
    UtRegisterTest("SCACTest10", SCACTest10, 1);
    UtRegisterTest("SCACTest11", SCACTest11, 1);
    UtRegisterTest("SCACTest12", SCACTest12, 1);
    UtRegisterTest("SCACTest13", SCACTest13, 1);
    UtRegisterTest("SCACTest14", SCACTest14, 1);
    UtRegisterTest("SCACTest15", SCACTest15, 1);
    UtRegisterTest("SCACTest16", SCACTest16, 1);
    UtRegisterTest("SCACTest17", SCACTest17, 1);
    UtRegisterTest("SCACTest18", SCACTest18, 1);
    UtRegisterTest("SCACTest19", SCACTest19, 1);
    UtRegisterTest("SCACTest20", SCACTest20, 1);
    UtRegisterTest("SCACTest21", SCACTest21, 1);
    UtRegisterTest("SCACTest22", SCACTest22, 1);
    UtRegisterTest("SCACTest23", SCACTest23, 1);
    UtRegisterTest("SCACTest24", SCACTest24, 1);
    UtRegisterTest("SCACTest25", SCACTest25, 1);
    UtRegisterTest("SCACTest26", SCACTest26, 1);
    UtRegisterTest("SCACTest27", SCACTest27, 1);
    UtRegisterTest("SCACTest28", SCACTest28, 1);
#endif

    return;
}
