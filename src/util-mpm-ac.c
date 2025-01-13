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
 * \todo - Do a proper analysis of our existing MPMs and suggest a good one based
 *         on the pattern distribution and the expected traffic(say http).
 *       - Tried out loop unrolling without any perf increase.  Need to dig deeper.
 *       - Irrespective of whether we cross 2 ** 16 states or not,shift to using
 *         uint32_t for state type, so that we can integrate it's status as a
 *         final state or not in the topmost byte.  We are already doing it if
 *         state_count is > 2 ** 16.
 *       - Test case-sensitive patterns if they have any ascii chars.  If they
 *         don't treat them as nocase.
 *       - Carry out other optimizations we are working on.  hashes, compression.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"

#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "util-mpm-ac.h"
#include "util-memcpy.h"
#include "util-validate.h"

void SCACInitCtx(MpmCtx *);
void SCACDestroyCtx(MpmCtx *);
int SCACAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCACAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCACPreparePatterns(MpmCtx *mpm_ctx, bool cache_to_disk);
uint32_t SCACSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen);
void SCACPrintInfo(MpmCtx *mpm_ctx);
#ifdef UNITTESTS
static void SCACRegisterTests(void);
#endif

/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_FAIL (-1)

#define STATE_QUEUE_CONTAINER_SIZE 65536

#define AC_CASE_MASK    0x80000000
#define AC_PID_MASK     0x7FFFFFFF
#define AC_CASE_BIT     31

static int construct_both_16_and_32_state_tables = 0;

/**
 * \brief Helper structure used by AC during state table creation
 */
typedef struct StateQueue_ {
    int32_t store[STATE_QUEUE_CONTAINER_SIZE];
    int top;
    int bot;
} StateQueue;

/**
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACGetConfig(void)
{
    //ConfNode *ac_conf;
    //const char *hash_val = NULL;

    // ConfNode *pm = ConfGetNode("pattern-matcher");
}

/**
 * \internal
 * \brief Check if size_t multiplication would overflow and perform operation
 *        if safe. In case of an overflow we exit().
 *
 * \param a First size_t value to multiplicate.
 * \param b Second size_t value to multiplicate.
 *
 * \retval The product of a and b, guaranteed to not overflow.
 */
static inline size_t SCACCheckSafeSizetMult(size_t a, size_t b)
{
    /* check for safety of multiplication operation */
    if (b > 0 && a > SIZE_MAX / b) {
        SCLogError("%" PRIuMAX " * %" PRIuMAX " > %" PRIuMAX
                   " would overflow size_t calculating buffer size",
                (uintmax_t)a, (uintmax_t)b, (uintmax_t)SIZE_MAX);
        exit(EXIT_FAILURE);
    }
    return a * b;
}

/**
 * \internal
 * \brief Initialize a new state in the goto and output tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval The state id, of the newly created state.
 */
static inline int SCACReallocState(SCACCtx *ctx, uint32_t cnt)
{
    void *ptmp = NULL;
    size_t size = 0;

    /* reallocate space in the goto table to include a new state */
    size = SCACCheckSafeSizetMult((size_t) cnt, (size_t) ctx->single_state_size);
    if (size > 0)
        ptmp = SCRealloc(ctx->goto_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->goto_table);
        ctx->goto_table = NULL;
        FatalError("Error allocating memory");
    }
    ctx->goto_table = ptmp;

    /* reallocate space in the output table for the new state */
    size_t oldsize = SCACCheckSafeSizetMult((size_t) ctx->state_count,
        sizeof(SCACOutputTable));
    size = SCACCheckSafeSizetMult((size_t) cnt, sizeof(SCACOutputTable));
    SCLogDebug("oldsize %"PRIuMAX" size  %"PRIuMAX" cnt %d ctx->state_count %u",
            (uintmax_t) oldsize, (uintmax_t) size, cnt, ctx->state_count);

    ptmp = NULL;
    if (size > 0)
        ptmp = SCRealloc(ctx->output_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->output_table);
        ctx->output_table = NULL;
        FatalError("Error allocating memory");
    }
    ctx->output_table = ptmp;

    memset(((uint8_t *)ctx->output_table + oldsize), 0, (size - oldsize));

    /* \todo using it temporarily now during dev, since I have restricted
     *       state var in SCACCtx->state_table to uint16_t. */
    //if (ctx->state_count > 65536) {
    //    printf("state count exceeded\n");
    //    exit(EXIT_FAILURE);
    //}

    return 0;//ctx->state_count++;
}

/** \internal
 *  \brief Shrink state after setup is done
 *
 *  Shrinks only the output table, goto table is freed after calling this
 */
static void SCACShrinkState(SCACCtx *ctx)
{
    /* reallocate space in the output table for the new state */
#ifdef DEBUG
    int oldsize = ctx->allocated_state_count * sizeof(SCACOutputTable);
#endif
    int newsize = ctx->state_count * sizeof(SCACOutputTable);

    SCLogDebug("oldsize %d newsize %d ctx->allocated_state_count %u "
               "ctx->state_count %u: shrink by %d bytes", oldsize,
               newsize, ctx->allocated_state_count, ctx->state_count,
               oldsize - newsize);

    void *ptmp = SCRealloc(ctx->output_table, newsize);
    if (ptmp == NULL) {
        SCFree(ctx->output_table);
        ctx->output_table = NULL;
        FatalError("Error allocating memory");
    }
    ctx->output_table = ptmp;
}

static inline int SCACInitNewState(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    /* Exponentially increase the allocated space when needed. */
    if (ctx->allocated_state_count < ctx->state_count + 1) {
        if (ctx->allocated_state_count == 0)
            ctx->allocated_state_count = 256;
        else
            ctx->allocated_state_count *= 2;

        SCACReallocState(ctx, ctx->allocated_state_count);

    }
#if 0
    if (ctx->allocated_state_count > 260) {
        SCACOutputTable *output_state = &ctx->output_table[260];
        SCLogInfo("output_state %p %p %u", output_state, output_state->pids, output_state->no_of_entries);
    }
#endif
    int ascii_code = 0;
    /* set all transitions for the newly assigned state as FAIL transitions */
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        ctx->goto_table[ctx->state_count][ascii_code] = SC_AC_FAIL;
    }

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
    void *ptmp;
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    SCACOutputTable *output_state = &ctx->output_table[state];
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
        FatalError("Error allocating memory");
    }
    output_state->pids = ptmp;

    output_state->pids[output_state->no_of_entries - 1] = pid;
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
}

static inline void SCACDetermineLevel1Gap(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    uint32_t u = 0;

    uint8_t map[256];
    memset(map, 0, sizeof(map));

    for (u = 0; u < mpm_ctx->pattern_cnt; u++)
        map[ctx->parray[u]->ci[0]] = 1;

    for (u = 0; u < 256; u++) {
        if (map[u] == 0)
            continue;
        int32_t newstate = SCACInitNewState(mpm_ctx);
        ctx->goto_table[0][u] = newstate;
    }
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
        FatalError("Just ran out of space in the queue. Please file a bug report on this");
    }
}

static inline int32_t SCACDequeue(StateQueue *q)
{
    if (q->bot == STATE_QUEUE_CONTAINER_SIZE)
        q->bot = 0;

    if (q->bot == q->top) {
        FatalError("StateQueue behaving weirdly. Please file a bug report on this");
    }

    return q->store[q->bot++];
}

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
    void *ptmp;
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

            ptmp = SCRealloc(output_dst_state->pids,
                             (output_dst_state->no_of_entries * sizeof(uint32_t)));
            if (ptmp == NULL) {
                SCFree(output_dst_state->pids);
                output_dst_state->pids = NULL;
                FatalError("Error allocating memory");
            }
            output_dst_state->pids = ptmp;

            output_dst_state->pids[output_dst_state->no_of_entries - 1] =
                output_src_state->pids[i];
        }
    }
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

    StateQueue *q = SCCalloc(1, sizeof(StateQueue));
    if (q == NULL) {
        FatalError("Error allocating memory");
    }

    /* allot space for the failure table.  A failure entry in the table for
     * every state(SCACCtx->state_count) */
    ctx->failure_table = SCCalloc(ctx->state_count, sizeof(int32_t));
    if (ctx->failure_table == NULL) {
        FatalError("Error allocating memory");
    }

    /* add the failure transitions for the 0th state, and add every non-fail
     * transition from the 0th state to the queue for further processing
     * of failure states */
    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        int32_t temp_state = ctx->goto_table[0][ascii_code];
        if (temp_state != 0) {
            SCACEnqueue(q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACStateQueueIsEmpty(q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACDequeue(q);
        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            int32_t temp_state = ctx->goto_table[r_state][ascii_code];
            if (temp_state == SC_AC_FAIL)
                continue;
            SCACEnqueue(q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][ascii_code] == SC_AC_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][ascii_code];
            SCACClubOutputStates(temp_state, ctx->failure_table[temp_state],
                                 mpm_ctx);
        }
    }
    SCFree(q);
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

    if ((ctx->state_count < 32767) || construct_both_16_and_32_state_tables) {
        ctx->state_table_u16 = SCCalloc(ctx->state_count, sizeof(*ctx->state_table_u16));
        if (ctx->state_table_u16 == NULL) {
            FatalError("Error allocating memory");
        }
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += (ctx->state_count * sizeof(*ctx->state_table_u16));

        StateQueue *q = SCCalloc(1, sizeof(StateQueue));
        if (q == NULL) {
            FatalError("Error allocating memory");
        }

        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            DEBUG_VALIDATE_BUG_ON(ctx->goto_table[0][ascii_code] > UINT16_MAX);
            SC_AC_STATE_TYPE_U16 temp_state = (uint16_t)ctx->goto_table[0][ascii_code];
            ctx->state_table_u16[0][ascii_code] = temp_state;
            if (temp_state != 0)
                SCACEnqueue(q, temp_state);
        }

        while (!SCACStateQueueIsEmpty(q)) {
            r_state = SCACDequeue(q);

            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                int32_t temp_state = ctx->goto_table[r_state][ascii_code];
                if (temp_state != SC_AC_FAIL) {
                    SCACEnqueue(q, temp_state);
                    DEBUG_VALIDATE_BUG_ON(temp_state > UINT16_MAX);
                    ctx->state_table_u16[r_state][ascii_code] = (uint16_t)temp_state;
                } else {
                    ctx->state_table_u16[r_state][ascii_code] =
                        ctx->state_table_u16[ctx->failure_table[r_state]][ascii_code];
                }
            }
        }
        SCFree(q);
    }

    if (!(ctx->state_count < 32767) || construct_both_16_and_32_state_tables) {
        /* create space for the state table.  We could have used the existing goto
         * table, but since we have it set to hold 32 bit state values, we will create
         * a new state table here of type SC_AC_STATE_TYPE(current set to uint16_t) */
        ctx->state_table_u32 = SCCalloc(ctx->state_count, sizeof(*ctx->state_table_u32));
        if (ctx->state_table_u32 == NULL) {
            FatalError("Error allocating memory");
        }
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += (ctx->state_count * sizeof(*ctx->state_table_u32));

        StateQueue *q = SCCalloc(1, sizeof(StateQueue));
        if (q == NULL) {
            FatalError("Error allocating memory");
        }

        for (ascii_code = 0; ascii_code < 256; ascii_code++) {
            SC_AC_STATE_TYPE_U32 temp_state = ctx->goto_table[0][ascii_code];
            ctx->state_table_u32[0][ascii_code] = temp_state;
            if (temp_state != 0)
                SCACEnqueue(q, temp_state);
        }

        while (!SCACStateQueueIsEmpty(q)) {
            r_state = SCACDequeue(q);

            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                int32_t temp_state = ctx->goto_table[r_state][ascii_code];
                if (temp_state != SC_AC_FAIL) {
                    SCACEnqueue(q, temp_state);
                    ctx->state_table_u32[r_state][ascii_code] = temp_state;
                } else {
                    ctx->state_table_u32[r_state][ascii_code] =
                        ctx->state_table_u32[ctx->failure_table[r_state]][ascii_code];
                }
            }
        }
        SCFree(q);
    }
}

static inline void SCACClubOutputStatePresenceWithDeltaTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int ascii_code = 0;
    uint32_t state = 0;
    uint32_t temp_state = 0;

    if ((ctx->state_count < 32767) || construct_both_16_and_32_state_tables) {
        for (state = 0; state < ctx->state_count; state++) {
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                temp_state = ctx->state_table_u16[state & 0x7FFF][ascii_code];
                if (ctx->output_table[temp_state & 0x7FFF].no_of_entries != 0)
                    ctx->state_table_u16[state & 0x7FFF][ascii_code] |= (1 << 15);
            }
        }
    }

    if (!(ctx->state_count < 32767) || construct_both_16_and_32_state_tables) {
        for (state = 0; state < ctx->state_count; state++) {
            for (ascii_code = 0; ascii_code < 256; ascii_code++) {
                temp_state = ctx->state_table_u32[state & 0x00FFFFFF][ascii_code];
                if (ctx->output_table[temp_state & 0x00FFFFFF].no_of_entries != 0)
                    ctx->state_table_u32[state & 0x00FFFFFF][ascii_code] |= (1 << 24);
            }
        }
    }
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
                ctx->output_table[state].pids[k] &= AC_PID_MASK;
                ctx->output_table[state].pids[k] |= ((uint32_t)1 << AC_CASE_BIT);
            }
        }
    }
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
}
#endif

/**
 * \brief Process the patterns and prepare the state table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACPrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    /* create the 0th state in the goto table and output_table */
    SCACInitNewState(mpm_ctx);

    SCACDetermineLevel1Gap(mpm_ctx);

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

    /* shrink the memory */
    SCACShrinkState(ctx);

#if 0
    SCACPrintDeltaTable(mpm_ctx);
#endif

    /* we don't need these anymore */
    SCFree(ctx->goto_table);
    ctx->goto_table = NULL;
    SCFree(ctx->failure_table);
    ctx->failure_table = NULL;
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCACPreparePatterns(MpmCtx *mpm_ctx, bool cache_to_disk)
{
    SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0 || mpm_ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (MpmPattern **)SCCalloc(mpm_ctx->pattern_cnt, sizeof(MpmPattern *));
    if (ctx->parray == NULL)
        goto error;
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(MpmPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < MPM_INIT_HASH_SIZE; i++) {
        MpmPattern *node = mpm_ctx->init_hash[i], *nnode = NULL;
        while(node != NULL) {
            nnode = node->next;
            node->next = NULL;
            ctx->parray[p++] = node;
            node = nnode;
        }
    }

    /* we no longer need the hash, so free it's memory */
    SCFree(mpm_ctx->init_hash);
    mpm_ctx->init_hash = NULL;

    /* the memory consumed by a single state in our goto table */
    ctx->single_state_size = sizeof(int32_t) * 256;

    /* handle no case patterns */
    ctx->pid_pat_list = SCCalloc((mpm_ctx->max_pat_id + 1), sizeof(SCACPatternList));
    if (ctx->pid_pat_list == NULL) {
        FatalError("Error allocating memory");
    }

    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (!(ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE)) {
            ctx->pid_pat_list[ctx->parray[i]->id].cs = SCMalloc(ctx->parray[i]->len);
            if (ctx->pid_pat_list[ctx->parray[i]->id].cs == NULL) {
                FatalError("Error allocating memory");
            }
            memcpy(ctx->pid_pat_list[ctx->parray[i]->id].cs,
                   ctx->parray[i]->original_pat, ctx->parray[i]->len);
            ctx->pid_pat_list[ctx->parray[i]->id].patlen = ctx->parray[i]->len;
        }
        ctx->pid_pat_list[ctx->parray[i]->id].offset = ctx->parray[i]->offset;
        ctx->pid_pat_list[ctx->parray[i]->id].depth = ctx->parray[i]->depth;
        ctx->pid_pat_list[ctx->parray[i]->id].endswith =
                (ctx->parray[i]->flags & MPM_PATTERN_FLAG_ENDSWITH) != 0;

        /* ACPatternList now owns this memory */
        //SCLogInfo("ctx->parray[i]->sids_size %u", ctx->parray[i]->sids_size);
        ctx->pid_pat_list[ctx->parray[i]->id].sids_size = ctx->parray[i]->sids_size;
        ctx->pid_pat_list[ctx->parray[i]->id].sids = ctx->parray[i]->sids;

        ctx->parray[i]->sids_size = 0;
        ctx->parray[i]->sids = NULL;
    }

    /* prepare the state table required by AC */
    SCACPrepareStateTable(mpm_ctx);

    /* free all the stored patterns.  Should save us a good 100-200 mbs */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (ctx->parray[i] != NULL) {
            MpmFreePattern(mpm_ctx, ctx->parray[i]);
        }
    }
    SCFree(ctx->parray);
    ctx->parray = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(MpmPattern *));

    ctx->pattern_id_bitarray_size = (mpm_ctx->max_pat_id / 8) + 1;
    SCLogDebug("ctx->pattern_id_bitarray_size %u", ctx->pattern_id_bitarray_size);

    return 0;

error:
    return -1;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 */
void SCACInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCCalloc(1, sizeof(SCACCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACCtx);

    /* initialize the hash we use to speed up pattern insertions */
    mpm_ctx->init_hash = SCCalloc(MPM_INIT_HASH_SIZE, sizeof(MpmPattern *));
    if (mpm_ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACGetConfig();

    SCReturn;
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

    if (mpm_ctx->init_hash != NULL) {
        SCFree(mpm_ctx->init_hash);
        mpm_ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (MPM_INIT_HASH_SIZE * sizeof(MpmPattern *));
    }

    if (ctx->parray != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                MpmFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        ctx->parray = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(MpmPattern *));
    }

    if (ctx->state_table_u16 != NULL) {
        SCFree(ctx->state_table_u16);
        ctx->state_table_u16 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_STATE_TYPE_U16) * 256);
    }
    if (ctx->state_table_u32 != NULL) {
        SCFree(ctx->state_table_u32);
        ctx->state_table_u32 = NULL;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 sizeof(SC_AC_STATE_TYPE_U32) * 256);
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
        uint32_t i;
        for (i = 0; i < (mpm_ctx->max_pat_id + 1); i++) {
            if (ctx->pid_pat_list[i].cs != NULL)
                SCFree(ctx->pid_pat_list[i].cs);
            if (ctx->pid_pat_list[i].sids != NULL)
                SCFree(ctx->pid_pat_list[i].sids);
        }
        SCFree(ctx->pid_pat_list);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->ctx = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACCtx);
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
 * \retval matches Match count: counts unique matches per pattern.
 */
uint32_t SCACSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen)
{
    const SCACCtx *ctx = (SCACCtx *)mpm_ctx->ctx;
    int matches = 0;

    /* \todo tried loop unrolling with register var, with no perf increase.  Need
     * to dig deeper */
    /* \todo Change it for stateful MPM.  Supply the state using mpm_thread_ctx */
    const SCACPatternList *pid_pat_list = ctx->pid_pat_list;

    uint8_t bitarray[ctx->pattern_id_bitarray_size];
    memset(bitarray, 0, ctx->pattern_id_bitarray_size);

    if (ctx->state_count < 32767) {
        register SC_AC_STATE_TYPE_U16 state = 0;
        const SC_AC_STATE_TYPE_U16(*state_table_u16)[256] = ctx->state_table_u16;
        for (uint32_t i = 0; i < buflen; i++) {
            state = state_table_u16[state & 0x7FFF][u8_tolower(buf[i])];
            if (state & 0x8000) {
                const uint32_t no_of_entries = ctx->output_table[state & 0x7FFF].no_of_entries;
                const uint32_t *pids = ctx->output_table[state & 0x7FFF].pids;
                for (uint32_t k = 0; k < no_of_entries; k++) {
                    if (pids[k] & AC_CASE_MASK) {
                        const uint32_t lower_pid = pids[k] & AC_PID_MASK;
                        const SCACPatternList *pat = &pid_pat_list[lower_pid];
                        const int offset = i - pat->patlen + 1;

                        if (offset < (int)pat->offset || (pat->depth && i > pat->depth))
                            continue;
                        if (pat->endswith && (uint32_t)offset + pat->patlen != buflen)
                            continue;

                        if (SCMemcmp(pat->cs, buf + offset, pat->patlen) != 0) {
                            /* inside loop */
                            continue;
                        }
                        if (!(bitarray[(lower_pid) / 8] & (1 << ((lower_pid) % 8)))) {
                            bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));
                            PrefilterAddSids(pmq, pat->sids, pat->sids_size);
                            matches++;
                        }
                    } else {
                        const SCACPatternList *pat = &pid_pat_list[pids[k]];
                        const int offset = i - pat->patlen + 1;

                        if (offset < (int)pat->offset || (pat->depth && i > pat->depth))
                            continue;
                        if (pat->endswith && (uint32_t)offset + pat->patlen != buflen)
                            continue;

                        if (!(bitarray[pids[k] / 8] & (1 << (pids[k] % 8)))) {
                            bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                            PrefilterAddSids(pmq, pat->sids, pat->sids_size);
                            matches++;
                        }
                    }
                }
            }
        }
    } else {
        register SC_AC_STATE_TYPE_U32 state = 0;
        const SC_AC_STATE_TYPE_U32(*state_table_u32)[256] = ctx->state_table_u32;
        for (uint32_t i = 0; i < buflen; i++) {
            state = state_table_u32[state & 0x00FFFFFF][u8_tolower(buf[i])];
            if (state & 0xFF000000) {
                const uint32_t no_of_entries = ctx->output_table[state & 0x00FFFFFF].no_of_entries;
                const uint32_t *pids = ctx->output_table[state & 0x00FFFFFF].pids;
                for (uint32_t k = 0; k < no_of_entries; k++) {
                    if (pids[k] & AC_CASE_MASK) {
                        const uint32_t lower_pid = pids[k] & 0x0000FFFF;
                        const SCACPatternList *pat = &pid_pat_list[lower_pid];
                        const int offset = i - pat->patlen + 1;

                        if (offset < (int)pat->offset || (pat->depth && i > pat->depth))
                            continue;
                        if (pat->endswith && (uint32_t)offset + pat->patlen != buflen)
                            continue;

                        if (SCMemcmp(pat->cs, buf + offset,
                                     pat->patlen) != 0) {
                            /* inside loop */
                            continue;
                        }
                        if (!(bitarray[(lower_pid) / 8] & (1 << ((lower_pid) % 8)))) {
                            bitarray[(lower_pid) / 8] |= (1 << ((lower_pid) % 8));
                            PrefilterAddSids(pmq, pat->sids, pat->sids_size);
                            matches++;
                        }
                    } else {
                        const SCACPatternList *pat = &pid_pat_list[pids[k]];
                        const int offset = i - pat->patlen + 1;

                        if (offset < (int)pat->offset || (pat->depth && i > pat->depth))
                            continue;
                        if (pat->endswith && (uint32_t)offset + pat->patlen != buflen)
                            continue;

                        if (!(bitarray[pids[k] / 8] & (1 << (pids[k] % 8)))) {
                            bitarray[pids[k] / 8] |= (1 << (pids[k] % 8));
                            PrefilterAddSids(pmq, pat->sids, pat->sids_size);
                            matches++;
                        }
                    }
                }
            }
        }
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
int SCACAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
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
                     SigIntId sid, uint8_t flags)
{
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
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
    printf("  MpmPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(MpmPattern));
    printf("  MpmPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(MpmPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %" PRIu32 "\n", ctx->state_count);
    printf("\n");
}


/************************** Mpm Registration ***************************/

/**
 * \brief Register the aho-corasick mpm.
 */
void MpmACRegister(void)
{
    mpm_table[MPM_AC].name = "ac";
    mpm_table[MPM_AC].InitCtx = SCACInitCtx;
    mpm_table[MPM_AC].DestroyCtx = SCACDestroyCtx;
    mpm_table[MPM_AC].AddPattern = SCACAddPatternCS;
    mpm_table[MPM_AC].AddPatternNocase = SCACAddPatternCI;
    mpm_table[MPM_AC].Prepare = SCACPreparePatterns;
    mpm_table[MPM_AC].CacheRuleset = NULL;
    mpm_table[MPM_AC].Search = SCACSearch;
    mpm_table[MPM_AC].PrintCtx = SCACPrintInfo;
#ifdef UNITTESTS
    mpm_table[MPM_AC].RegisterUnittests = SCACRegisterTests;
#endif
    mpm_table[MPM_AC].feature_flags = MPM_FEATURE_FLAG_DEPTH | MPM_FEATURE_FLAG_OFFSET;
}

/*************************************Unittests********************************/

#ifdef UNITTESTS
#include "detect-engine-alert.h"

static int SCACTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";

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

static int SCACTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
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

static int SCACTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcd";
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

static int SCACTest07(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

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
    PmqSetup(&pmq);
    /* total matches: 135: unique matches: 6 */

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 6);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "01234567890123456789012345678901234567890123456789"
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
    PmqFree(&pmq);
    return result;
}

static int SCACTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq);

    if (SCACPreparePatterns(&mpm_ctx, false) == -1)
        goto end;

    result = 1;

    const char *buf = "he";
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
     PmqFree(&pmq);
     return result;
}

static int SCACTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
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

static int SCACTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
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

static int SCACTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
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

static int SCACTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABC";
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

static int SCACTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyzAB";
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

static int SCACTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    const char pat[] = "abcde"
                       "fghij"
                       "klmno"
                       "pqrst"
                       "uvwxy"
                       "z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
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

static int SCACTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 */
    const char pat[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 */
    const char pat[] = "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
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

static int SCACTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                              (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "works";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "tone";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTest28(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf = "tONE";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                               (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 0);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACTest29(void)
{
    uint8_t buf[] = "onetwothreefourfivesixseveneightnine";
    uint16_t buflen = sizeof(buf) - 1;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"onetwothreefourfivesixseveneightnine\"; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"onetwothreefourfivesixseveneightnine\"; fast_pattern:3,3; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1) != 1);
    FAIL_IF(PacketAlertCheck(p, 2) != 1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v);

    UTHFreePackets(&p, 1);
    PASS;
}

/** \test endswith logic */
static int SCACTest30(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"xyz", 3, 0, 0, 0, 0, MPM_PATTERN_FLAG_ENDSWITH);
    PmqSetup(&pmq);

    SCACPreparePatterns(&mpm_ctx, false);

    const char *buf1 = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf1, strlen(buf1));
    FAIL_IF_NOT(cnt == 1);
    const char *buf2 = "xyzxyzxyzxyzxyzxyzxyza";
    cnt = SCACSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf2, strlen(buf2));
    FAIL_IF_NOT(cnt == 0);

    SCACDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

void SCACRegisterTests(void)
{
    UtRegisterTest("SCACTest01", SCACTest01);
    UtRegisterTest("SCACTest02", SCACTest02);
    UtRegisterTest("SCACTest03", SCACTest03);
    UtRegisterTest("SCACTest04", SCACTest04);
    UtRegisterTest("SCACTest05", SCACTest05);
    UtRegisterTest("SCACTest06", SCACTest06);
    UtRegisterTest("SCACTest07", SCACTest07);
    UtRegisterTest("SCACTest08", SCACTest08);
    UtRegisterTest("SCACTest09", SCACTest09);
    UtRegisterTest("SCACTest10", SCACTest10);
    UtRegisterTest("SCACTest11", SCACTest11);
    UtRegisterTest("SCACTest12", SCACTest12);
    UtRegisterTest("SCACTest13", SCACTest13);
    UtRegisterTest("SCACTest14", SCACTest14);
    UtRegisterTest("SCACTest15", SCACTest15);
    UtRegisterTest("SCACTest16", SCACTest16);
    UtRegisterTest("SCACTest17", SCACTest17);
    UtRegisterTest("SCACTest18", SCACTest18);
    UtRegisterTest("SCACTest19", SCACTest19);
    UtRegisterTest("SCACTest20", SCACTest20);
    UtRegisterTest("SCACTest21", SCACTest21);
    UtRegisterTest("SCACTest22", SCACTest22);
    UtRegisterTest("SCACTest23", SCACTest23);
    UtRegisterTest("SCACTest24", SCACTest24);
    UtRegisterTest("SCACTest25", SCACTest25);
    UtRegisterTest("SCACTest26", SCACTest26);
    UtRegisterTest("SCACTest27", SCACTest27);
    UtRegisterTest("SCACTest28", SCACTest28);
    UtRegisterTest("SCACTest29", SCACTest29);
    UtRegisterTest("SCACTest30", SCACTest30);
}
#endif /* UNITTESTS */
