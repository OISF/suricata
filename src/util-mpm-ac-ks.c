/* Copyright (C) 2013-2022 Open Information Security Foundation
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
 * \author Ken Steele <suricata@tilera.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 *         Aho-corasick MPM optimized for the Tilera Tile-Gx architecture.
 *
 *         Efficient String Matching: An Aid to Bibliographic Search
 *         Alfred V. Aho and Margaret J. Corasick
 *
 *         - Started with util-mpm-ac.c:
 *             - Uses the delta table for calculating transitions,
 *               instead of having separate goto and failure
 *               transitions.
 *             - If we cross 2 ** 16 states, we use 4 bytes in the
 *               transition table to hold each state, otherwise we use
 *               2 bytes.
 *             - This version of the MPM is heavy on memory, but it
 *               performs well.  If you can fit the ruleset with this
 *               mpm on your box without hitting swap, this is the MPM
 *               to go for.
 *
 *         - Added these optimizations:
 *             - Compress the input alphabet from 256 characters down
 *               to the actual characters used in the patterns, plus
 *               one character for all the unused characters.
 *             - Reduce the size of the delta table so that each state
 *               is the smallest power of two that is larger than the
 *               size of the compressed alphabet.
 *             - Specialized the search function based on state count
 *               (small for 8-bit large for 16-bit) and the size of
 *               the alphabet, so that it is constant inside the
 *               function for better optimization.
 *
 * \todo - Do a proper analyis of our existing MPMs and suggest a good
 *         one based on the pattern distribution and the expected
 *         traffic(say http).

 *       - Irrespective of whether we cross 2 ** 16 states or
 *         not,shift to using uint32_t for state type, so that we can
 *         integrate it's status as a final state or not in the
 *         topmost byte.  We are already doing it if state_count is >
 *         2 ** 16.
 *       - Test case-senstive patterns if they have any ascii chars.
 *         If they don't treat them as nocase.
 *       - Reorder the compressed alphabet to put the most common characters
 *         first.
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
#include "util-memcpy.h"
#include "util-validate.h"
#include "util-mpm-ac-ks.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN

void SCACTileInitCtx(MpmCtx *);
void SCACTileInitThreadCtx(MpmCtx *, MpmThreadCtx *);
void SCACTileDestroyCtx(MpmCtx *);
void SCACTileDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCACTileAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, SigIntId, uint8_t);
int SCACTileAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                         uint32_t, SigIntId, uint8_t);
int SCACTilePreparePatterns(MpmCtx *mpm_ctx);
uint32_t SCACTileSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PrefilterRuleStore *pmq, const uint8_t *buf,
                        uint32_t buflen);
void SCACTilePrintInfo(MpmCtx *mpm_ctx);
void SCACTilePrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void SCACTileRegisterTests(void);

uint32_t SCACTileSearchLarge(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                             PrefilterRuleStore *pmq,
                             const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall256(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                                PrefilterRuleStore *pmq,
                                const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall128(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                                PrefilterRuleStore *pmq,
                                const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall64(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PrefilterRuleStore *pmq,
                               const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall32(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PrefilterRuleStore *pmq,
                               const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall16(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PrefilterRuleStore *pmq,
                               const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchSmall8(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                              PrefilterRuleStore *pmq,
                              const uint8_t *buf, uint32_t buflen);

uint32_t SCACTileSearchTiny256(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PrefilterRuleStore *pmq,
                               const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchTiny128(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                               PrefilterRuleStore *pmq,
                               const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchTiny64(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                              PrefilterRuleStore *pmq,
                              const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchTiny32(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                              PrefilterRuleStore *pmq,
                              const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchTiny16(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                              PrefilterRuleStore *pmq,
                              const uint8_t *buf, uint32_t buflen);
uint32_t SCACTileSearchTiny8(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                             PrefilterRuleStore *pmq,
                             const uint8_t *buf, uint32_t buflen);


static void SCACTileDestroyInitCtx(MpmCtx *mpm_ctx);


/* a placeholder to denote a failure transition in the goto table */
#define SC_AC_TILE_FAIL (-1)

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
 * \internal
 * \brief Initialize the AC context with user specified conf parameters.  We
 *        aren't retrieving anything for AC conf now, but we will certainly
 *        need it, when we customize AC.
 */
static void SCACTileGetConfig(void)
{
}


/**
 * \internal
 * \brief Count the occurences of each character in the pattern and
 * accumulate into a histogram. Really only used to detect unused
 * characters, so could just set to 1 instead of counting.
 */
static inline void SCACTileHistogramAlphabet(SCACTileCtx *ctx,
                                             MpmPattern *p)
{
    for (int i = 0; i < p->len; i++) {
        ctx->alpha_hist[p->ci[i]]++;
    }
}

/* Use Alpahbet Histogram to create compressed alphabet.
 */
static void SCACTileInitTranslateTable(SCACTileCtx *ctx)
{
    /* Count the number of ASCII values actually appearing in any
     * pattern.  Create compressed mapping table with unused
     * characters mapping to zero.
     */
    for (int i = 0; i < 256; i++) {
        /* Move all upper case counts to lower case */
        if (i >= 'A' && i <= 'Z') {
            ctx->alpha_hist[i - 'A' + 'a'] += ctx->alpha_hist[i];
            ctx->alpha_hist[i] = 0;
        }
        if (ctx->alpha_hist[i]) {
            ctx->alphabet_size++;
            DEBUG_VALIDATE_BUG_ON(ctx->alphabet_size > UINT8_MAX);
            ctx->translate_table[i] = (uint8_t)ctx->alphabet_size;
        } else
            ctx->translate_table[i] = 0;
    }
    /* Fix up translation table for uppercase */
    for (int i = 'A'; i <= 'Z'; i++)
        ctx->translate_table[i] = ctx->translate_table[i - 'A' + 'a'];

    SCLogDebug("  Alphabet size %d", ctx->alphabet_size);

    /* Round alphabet size up to next power-of-two Leave one extra
     * space For the unused-chararacters = 0 mapping.
     */
    ctx->alphabet_size += 1; /* Extra space for unused-character */
    if (ctx->alphabet_size  <= 8) {
        ctx->alphabet_storage = 8;
    } else if (ctx->alphabet_size  <= 16) {
        ctx->alphabet_storage = 16;
    } else if (ctx->alphabet_size  <= 32) {
        ctx->alphabet_storage = 32;
    } else if (ctx->alphabet_size <= 64) {
        ctx->alphabet_storage = 64;
    } else if (ctx->alphabet_size <= 128) {
        ctx->alphabet_storage = 128;
    } else
        ctx->alphabet_storage = 256;
}

static void SCACTileReallocOutputTable(SCACTileCtx *ctx, int new_state_count)
{

    /* reallocate space in the output table for the new state */
    size_t size = ctx->allocated_state_count * sizeof(SCACTileOutputTable);
    void *ptmp = SCRealloc(ctx->output_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->output_table);
        ctx->output_table = NULL;
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    ctx->output_table = ptmp;
}

static void SCACTileReallocState(SCACTileCtx *ctx, int new_state_count)
{
    /* reallocate space in the goto table to include a new state */
    size_t size = ctx->allocated_state_count * sizeof(int32_t) * 256;
    void *ptmp = SCRealloc(ctx->goto_table, size);
    if (ptmp == NULL) {
        SCFree(ctx->goto_table);
        ctx->goto_table = NULL;
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    ctx->goto_table = ptmp;

    SCACTileReallocOutputTable(ctx, new_state_count);
}

/**
 * \internal
 * \brief Initialize a new state in the goto and output tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval The state id, of the newly created state.
 */
static inline int SCACTileInitNewState(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;
    int aa = 0;

    /* Exponentially increase the allocated space when needed. */
    if (ctx->allocated_state_count < ctx->state_count + 1) {
        if (ctx->allocated_state_count == 0)
            ctx->allocated_state_count = 256;
        else
            ctx->allocated_state_count *= 2;

        SCACTileReallocState(ctx, ctx->allocated_state_count);
    }

    /* set all transitions for the newly assigned state as FAIL transitions */
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        ctx->goto_table[ctx->state_count][aa] = SC_AC_TILE_FAIL;
    }

    memset(ctx->output_table + ctx->state_count, 0,
           sizeof(SCACTileOutputTable));

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
static void SCACTileSetOutputState(int32_t state, MpmPatternIndex pindex, MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    SCACTileOutputTable *output_state = &ctx->output_table[state];
    uint32_t i = 0;

    /* Don't add the pattern more than once to the same state. */
    for (i = 0; i < output_state->no_of_entries; i++) {
        if (output_state->patterns[i] == pindex)
            return;
    }

    /* Increase the size of the array of pids for this state and add
     * the new pid. */
    output_state->no_of_entries++;
    ptmp = SCRealloc(output_state->patterns,
                     output_state->no_of_entries * sizeof(MpmPatternIndex));
    if (ptmp == NULL) {
        SCFree(output_state->patterns);
        output_state->patterns = NULL;
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    output_state->patterns = ptmp;

    output_state->patterns[output_state->no_of_entries - 1] = pindex;
}

/**
 * \brief Helper function used by SCACTileCreateGotoTable.  Adds a
 *        pattern to the goto table.
 *
 * \param pattern     Pointer to the pattern.
 * \param pattern_len Pattern length.
 * \param pid         The pattern id, that corresponds to this pattern.  We
 *                    need it to updated the output table for this pattern.
 * \param mpm_ctx     Pointer to the mpm context.
 */
static void SCACTileEnter(uint8_t *pattern, uint16_t pattern_len,
                          MpmPatternIndex pindex, MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    int32_t state = 0;
    int32_t newstate = 0;
    int i = 0;
    int p = 0;
    int tc;

    /* Walk down the trie till we have a match for the pattern prefix */
    state = 0;
    for (i = 0; i < pattern_len; i++) {
        tc = ctx->translate_table[pattern[i]];
        if (ctx->goto_table[state][tc] == SC_AC_TILE_FAIL)
            break;
        state = ctx->goto_table[state][tc];
    }

    /* Add the non-matching pattern suffix to the trie, from the last state
     * we left off */
    for (p = i; p < pattern_len; p++) {
        newstate = SCACTileInitNewState(mpm_ctx);
        tc = ctx->translate_table[pattern[p]];
        ctx->goto_table[state][tc] = newstate;
        state = newstate;
    }

    /* Add this pattern id, to the output table of the last state, where the
     * pattern ends in the trie */
    SCACTileSetOutputState(state, pindex, mpm_ctx);
}

/**
 * \internal
 * \brief Create the goto table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACTileCreateGotoTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    uint32_t i = 0;

    /* add each pattern to create the goto table */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        SCACTileEnter(ctx->parray[i]->ci, ctx->parray[i]->len,
                      i, mpm_ctx);
    }

    int aa = 0;
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        if (ctx->goto_table[0][aa] == SC_AC_TILE_FAIL) {
            ctx->goto_table[0][aa] = 0;
        }
    }
}

static inline int SCACTileStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACTileEnqueue(StateQueue *q, int32_t state)
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
}

static inline int32_t SCACTileDequeue(StateQueue *q)
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

/**
 * \internal
 * \brief Club the output data from 2 states and store it in the 1st state.
 *        dst_state_data = {dst_state_data} UNION {src_state_data}
 *
 * \param dst_state First state(also the destination) for the union operation.
 * \param src_state Second state for the union operation.
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACTileClubOutputStates(int32_t dst_state,
                                     int32_t src_state,
                                     MpmCtx *mpm_ctx)
{
    void *ptmp;
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    uint32_t i = 0;
    uint32_t j = 0;

    SCACTileOutputTable *output_dst_state = &ctx->output_table[dst_state];
    SCACTileOutputTable *output_src_state = &ctx->output_table[src_state];

    for (i = 0; i < output_src_state->no_of_entries; i++) {
        for (j = 0; j < output_dst_state->no_of_entries; j++) {
            if (output_src_state->patterns[i] == output_dst_state->patterns[j]) {
                break;
            }
        }
        if (j == output_dst_state->no_of_entries) {
            output_dst_state->no_of_entries++;

            ptmp = SCRealloc(output_dst_state->patterns,
                             (output_dst_state->no_of_entries * sizeof(uint32_t)));
            if (ptmp == NULL) {
                SCFree(output_dst_state->patterns);
                output_dst_state->patterns = NULL;
                FatalError(SC_ERR_FATAL, "Error allocating memory");
            }
            output_dst_state->patterns = ptmp;

            output_dst_state->patterns[output_dst_state->no_of_entries - 1] =
                output_src_state->patterns[i];
        }
    }
}

/**
 * \internal
 * \brief Create the failure table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACTileCreateFailureTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    int aa = 0;
    int32_t state = 0;
    int32_t r_state = 0;

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    /* Allocate space for the failure table.  A failure entry in the table for
     * every state(SCACTileCtx->state_count) */
    ctx->failure_table = SCMalloc(ctx->state_count * sizeof(int32_t));
    if (ctx->failure_table == NULL) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    memset(ctx->failure_table, 0, ctx->state_count * sizeof(int32_t));

    /* Add the failure transitions for the 0th state, and add every non-fail
     * transition from the 0th state to the queue for further processing
     * of failure states */
    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        int32_t temp_state = ctx->goto_table[0][aa];
        if (temp_state != 0) {
            SCACTileEnqueue(&q, temp_state);
            ctx->failure_table[temp_state] = 0;
        }
    }

    while (!SCACTileStateQueueIsEmpty(&q)) {
        /* pick up every state from the queue and add failure transitions */
        r_state = SCACTileDequeue(&q);
        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            int32_t temp_state = ctx->goto_table[r_state][aa];
            if (temp_state == SC_AC_TILE_FAIL)
                continue;
            SCACTileEnqueue(&q, temp_state);
            state = ctx->failure_table[r_state];

            while(ctx->goto_table[state][aa] == SC_AC_TILE_FAIL)
                state = ctx->failure_table[state];
            ctx->failure_table[temp_state] = ctx->goto_table[state][aa];
            SCACTileClubOutputStates(temp_state, ctx->failure_table[temp_state],
                                     mpm_ctx);
        }
    }
}

/*
 * Set the next state for 1 byte next-state.
 */
static void SCACTileSetState1Byte(SCACTileCtx *ctx, int state, int aa,
                                  int next_state, int outputs)
{
    uint8_t *state_table = (uint8_t*)ctx->state_table;
    DEBUG_VALIDATE_BUG_ON(next_state < 0 || next_state > UINT8_MAX);
    uint8_t encoded_next_state = (uint8_t)next_state;

    if (next_state == SC_AC_TILE_FAIL) {
        FatalError(SC_ERR_FATAL, "Error FAIL state in output");
    }

    if (outputs == 0)
        encoded_next_state |= (1 << 7);

    state_table[state * ctx->alphabet_storage + aa] = encoded_next_state;
}

/*
 * Set the next state for 2 byte next-state.
 */
static void SCACTileSetState2Bytes(SCACTileCtx *ctx, int state, int aa,
                                   int next_state, int outputs)
{
    uint16_t *state_table = (uint16_t*)ctx->state_table;
    DEBUG_VALIDATE_BUG_ON(next_state < 0 || next_state > UINT16_MAX);
    uint16_t encoded_next_state = (uint16_t)next_state;

    if (next_state == SC_AC_TILE_FAIL) {
        FatalError(SC_ERR_FATAL, "Error FAIL state in output");
    }

    if (outputs == 0)
        encoded_next_state |= (1 << 15);

    state_table[state * ctx->alphabet_storage + aa] = encoded_next_state;
}

/*
 * Set the next state for 4 byte next-state.
 */
static void SCACTileSetState4Bytes(SCACTileCtx *ctx, int state, int aa,
                                   int next_state, int outputs)
{
    uint32_t *state_table = (uint32_t*)ctx->state_table;
    uint32_t encoded_next_state = next_state;

    if (next_state == SC_AC_TILE_FAIL) {
        FatalError(SC_ERR_FATAL, "Error FAIL state in output");
    }

    if (outputs == 0)
        encoded_next_state |= (1UL << 31);

    state_table[state * ctx->alphabet_storage + aa] = encoded_next_state;
}

/**
 * \internal
 * \brief Create the delta table.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static inline void SCACTileCreateDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    int aa = 0;
    int32_t r_state = 0;

    if (ctx->state_count < 32767) {
        if (ctx->state_count < 128) {
            ctx->bytes_per_state = 1;
            ctx->SetNextState = SCACTileSetState1Byte;

            switch(ctx->alphabet_storage) {
            case 8:
                ctx->Search = SCACTileSearchTiny8;
                break;
            case 16:
                ctx->Search = SCACTileSearchTiny16;
                break;
            case 32:
                ctx->Search = SCACTileSearchTiny32;
                break;
            case 64:
                ctx->Search = SCACTileSearchTiny64;
                break;
            case 128:
                ctx->Search = SCACTileSearchTiny128;
                break;
            default:
                ctx->Search = SCACTileSearchTiny256;
            }
        } else {
            /* 16-bit state needed */
            ctx->bytes_per_state = 2;
            ctx->SetNextState = SCACTileSetState2Bytes;

            switch(ctx->alphabet_storage) {
            case 8:
                ctx->Search = SCACTileSearchSmall8;
                break;
            case 16:
                ctx->Search = SCACTileSearchSmall16;
                break;
            case 32:
                ctx->Search = SCACTileSearchSmall32;
                break;
            case 64:
                ctx->Search = SCACTileSearchSmall64;
                break;
            case 128:
                ctx->Search = SCACTileSearchSmall128;
                break;
            default:
                ctx->Search = SCACTileSearchSmall256;
            }
        }
    } else {
        /* 32-bit next state */
        ctx->Search = SCACTileSearchLarge;
        ctx->bytes_per_state = 4;
        ctx->SetNextState = SCACTileSetState4Bytes;

        ctx->alphabet_storage = 256; /* Change? */
    }

    StateQueue q;
    memset(&q, 0, sizeof(StateQueue));

    for (aa = 0; aa < ctx->alphabet_size; aa++) {
        int temp_state = ctx->goto_table[0][aa];
        if (temp_state != 0)
            SCACTileEnqueue(&q, temp_state);
    }

    while (!SCACTileStateQueueIsEmpty(&q)) {
        r_state = SCACTileDequeue(&q);

        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            int temp_state = ctx->goto_table[r_state][aa];
            if (temp_state != SC_AC_TILE_FAIL) {
                SCACTileEnqueue(&q, temp_state);
            } else {
                int f_state = ctx->failure_table[r_state];
                ctx->goto_table[r_state][aa] = ctx->goto_table[f_state][aa];
            }
        }
    }
}

static void SCACTileClubOutputStatePresenceWithDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    int aa = 0;
    uint32_t state = 0;

    /* Allocate next-state table. */
    int size = ctx->state_count * ctx->bytes_per_state * ctx->alphabet_storage;
    void *state_table = SCMalloc(size);
    if (unlikely(state_table == NULL)) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    memset(state_table, 0, size);
    ctx->state_table = state_table;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += size;

    SCLogDebug("Delta Table size %d,  alphabet: %d, %d-byte states: %d",
              size, ctx->alphabet_size, ctx->bytes_per_state, ctx->state_count);

    /* Copy next state from Goto table, which is 32 bits and encode it into the next
     * state table, which can be 1, 2 or 4 bytes each and include if there is an
     * output.
     */
    for (state = 0; state < ctx->state_count; state++) {
        for (aa = 0; aa < ctx->alphabet_size; aa++) {
            int next_state = ctx->goto_table[state][aa];
            int next_state_outputs = ctx->output_table[next_state].no_of_entries;
            ctx->SetNextState(ctx, state, aa, next_state, next_state_outputs);
        }
    }
}

static inline void SCACTileInsertCaseSensitiveEntriesForPatterns(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    uint32_t state = 0;
    uint32_t k = 0;

    for (state = 0; state < ctx->state_count; state++) {
        if (ctx->output_table[state].no_of_entries == 0)
            continue;

        for (k = 0; k < ctx->output_table[state].no_of_entries; k++) {
            if (ctx->pattern_list[ctx->output_table[state].patterns[k]].cs != NULL) {
              /* TODO - Find better way to store this. */
                ctx->output_table[state].patterns[k] &= 0x0FFFFFFF;
                ctx->output_table[state].patterns[k] |= (uint32_t)1 << 31;
            }
        }
    }
}

#if 0
static void SCACTilePrintDeltaTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    int i = 0, j = 0;

    printf("##############Delta Table##############\n");
    for (i = 0; i < ctx->state_count; i++) {
        printf("%d: \n", i);
        for (j = 0; j < ctx->alphabet_size; j++) {
            if (SCACTileGetDelta(i, j, mpm_ctx) != 0) {
                printf("  %c -> %d\n", j, SCACTileGetDelta(i, j, mpm_ctx));
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
static void SCACTilePrepareStateTable(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    /* Create Alphabet compression and Lower Case translation table. */
    SCACTileInitTranslateTable(ctx);

    /* create the 0th state in the goto table and output_table */
    SCACTileInitNewState(mpm_ctx);

    /* create the goto table */
    SCACTileCreateGotoTable(mpm_ctx);
    /* create the failure table */
    SCACTileCreateFailureTable(mpm_ctx);
    /* create the final state(delta) table */
    SCACTileCreateDeltaTable(mpm_ctx);
    /* club the output state presence with delta transition entries */
    SCACTileClubOutputStatePresenceWithDeltaTable(mpm_ctx);

    /* club nocase entries */
    SCACTileInsertCaseSensitiveEntriesForPatterns(mpm_ctx);

#if 0
    SCACTilePrintDeltaTable(mpm_ctx);
#endif

    /* we don't need these anymore */
    SCFree(ctx->goto_table);
    ctx->goto_table = NULL;
    SCFree(ctx->failure_table);
    ctx->failure_table = NULL;
}


/**
 * \brief Process Internal AC MPM tables to create the Search Context
 *
 * The search context is only the data needed to search the MPM.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACTilePrepareSearch(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    /* Resize the output table to be only as big as its final size. */
    SCACTileReallocOutputTable(ctx, ctx->state_count);

    search_ctx->Search = ctx->Search;
    memcpy(search_ctx->translate_table, ctx->translate_table, sizeof(ctx->translate_table));

    /* Move the state table from the Init context */
    search_ctx->state_table = ctx->state_table;
    ctx->state_table = NULL; /* So that it won't get freed twice. */

    /* Move the output_table from the Init context to the Search Context */
    /* TODO: Could be made more compact */
    search_ctx->output_table = ctx->output_table;
    ctx->output_table = NULL;
    search_ctx->state_count = ctx->state_count;

    search_ctx->pattern_list = ctx->pattern_list;
    ctx->pattern_list = NULL;
    search_ctx->pattern_cnt = mpm_ctx->pattern_cnt;

    /* One bit per pattern, rounded up to the next byte size. */
    search_ctx->mpm_bitarray_size = (mpm_ctx->pattern_cnt + 7) / 8;

    /* Can now free the Initialization data */
    SCACTileDestroyInitCtx(mpm_ctx);
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCACTilePreparePatterns(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;

    if (mpm_ctx->pattern_cnt == 0 || search_ctx->init_ctx == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }
    SCACTileCtx *ctx = search_ctx->init_ctx;
    if (mpm_ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    /* alloc the pattern array */
    ctx->parray = (MpmPattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                               sizeof(MpmPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(MpmPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < MPM_INIT_HASH_SIZE; i++) {
        MpmPattern *node = mpm_ctx->init_hash[i], *nnode = NULL;
        while(node != NULL) {
            nnode = node->next;
            node->next = NULL;
            ctx->parray[p++] = node;
            SCACTileHistogramAlphabet(ctx, node);
            node = nnode;
        }
    }

    /* we no longer need the hash, so free it's memory */
    SCFree(mpm_ctx->init_hash);
    mpm_ctx->init_hash = NULL;

    /* Handle case patterns by storing a copy of the pattern to compare
     * to each possible match (no-case).
     *
     * Allocate the memory for the array and each of the strings as one block.
     */
    size_t string_space_needed = 0;
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (!(ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE)) {
            /* Round up to next 8 byte aligned length */
            uint32_t space = ((ctx->parray[i]->len + 7) / 8) * 8;
            string_space_needed += space;
        }
    }

    size_t pattern_list_size = mpm_ctx->pattern_cnt * sizeof(SCACTilePatternList);
    size_t mem_size = string_space_needed + pattern_list_size;
    void *mem_block = SCCalloc(1, mem_size);
    if (mem_block == NULL) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += mem_size;
    /* Split the allocated block into pattern list array and string space. */
    ctx->pattern_list = mem_block;
    uint8_t *string_space = mem_block + pattern_list_size;

    /* Now make the copies of the no-case strings. */
    for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
        if (!(ctx->parray[i]->flags & MPM_PATTERN_FLAG_NOCASE)) {
            uint16_t len = ctx->parray[i]->len;
            uint32_t space = ((len + 7) / 8) * 8;
            memcpy(string_space, ctx->parray[i]->original_pat, len);
            ctx->pattern_list[i].cs = string_space;
            ctx->pattern_list[i].patlen = len;
            string_space += space;
        }
        ctx->pattern_list[i].offset = ctx->parray[i]->offset;
        ctx->pattern_list[i].depth = ctx->parray[i]->depth;
        ctx->pattern_list[i].pid = ctx->parray[i]->id;

        /* ACPatternList now owns this memory */
        ctx->pattern_list[i].sids_size = ctx->parray[i]->sids_size;
        ctx->pattern_list[i].sids = ctx->parray[i]->sids;
        ctx->parray[i]->sids = NULL;
        ctx->parray[i]->sids_size = 0;
    }

    /* prepare the state table required by AC */
    SCACTilePrepareStateTable(mpm_ctx);

    /* Convert to the Search Context structure */
    SCACTilePrepareSearch(mpm_ctx);

    return 0;

error:
    return -1;
}

/**
 * \brief Init the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACTileInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = SCMalloc(sizeof(SCACTileThreadCtx));
    if (mpm_thread_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_thread_ctx->ctx, 0, sizeof(SCACTileThreadCtx));
    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCACTileThreadCtx);
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 */
void SCACTileInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    /* Search Context */
    mpm_ctx->ctx = SCMalloc(sizeof(SCACTileSearchCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->ctx, 0, sizeof(SCACTileSearchCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACTileSearchCtx);

    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;

    /* MPM Creation context */
    search_ctx->init_ctx = SCMalloc(sizeof(SCACTileCtx));
    if (search_ctx->init_ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(search_ctx->init_ctx, 0, sizeof(SCACTileCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCACTileCtx);

    /* initialize the hash we use to speed up pattern insertions */
    mpm_ctx->init_hash = SCMalloc(sizeof(MpmPattern *) * MPM_INIT_HASH_SIZE);
    if (mpm_ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(mpm_ctx->init_hash, 0, sizeof(MpmPattern *) * MPM_INIT_HASH_SIZE);

    /* get conf values for AC from our yaml file.  We have no conf values for
     * now.  We will certainly need this, as we develop the algo */
    SCACTileGetConfig();
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCACTileDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCACTilePrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCACTileThreadCtx);
    }
}

static void SCACTileDestroyInitCtx(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    if (ctx == NULL)
        return;

    if (mpm_ctx->init_hash != NULL) {
        SCFree(mpm_ctx->init_hash);
        mpm_ctx->init_hash = NULL;
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
    }

    if (ctx->state_table != NULL) {
        SCFree(ctx->state_table);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (ctx->state_count *
                                 ctx->bytes_per_state * ctx->alphabet_storage);
    }

    if (ctx->output_table != NULL) {
        uint32_t state;
        for (state = 0; state < ctx->state_count; state++) {
            if (ctx->output_table[state].patterns != NULL) {
                SCFree(ctx->output_table[state].patterns);
            }
        }
        SCFree(ctx->output_table);
    }

    if (ctx->pattern_list != NULL) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->pattern_list[i].cs != NULL)
                SCFree(ctx->pattern_list[i].cs);
            if (ctx->pattern_list[i].sids != NULL)
                SCFree(ctx->pattern_list[i].sids);
        }
        SCFree(ctx->pattern_list);
    }

    SCFree(ctx);
    search_ctx->init_ctx = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACTileCtx);
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCACTileDestroyCtx(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    if (search_ctx == NULL)
        return;

    /* Destroy Initialization data */
    SCACTileDestroyInitCtx(mpm_ctx);

    /* Free Search tables */
    SCFree(search_ctx->state_table);

    if (search_ctx->pattern_list != NULL) {
        uint32_t i;
        for (i = 0; i < search_ctx->pattern_cnt; i++) {
            if (search_ctx->pattern_list[i].sids != NULL)
                SCFree(search_ctx->pattern_list[i].sids);
        }
        SCFree(search_ctx->pattern_list);
    }

    if (search_ctx->output_table != NULL) {
        uint32_t state;
        for (state = 0; state < search_ctx->state_count; state++) {
            if (search_ctx->output_table[state].patterns != NULL) {
                SCFree(search_ctx->output_table[state].patterns);
            }
        }
        SCFree(search_ctx->output_table);
    }

    SCFree(search_ctx);
    mpm_ctx->ctx = NULL;

    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCACTileSearchCtx);
}

/*
 * Heavily optimized pattern matching routine for TILE-Gx.
 */

#define SCHECK(x) ((x) > 0)
#define BUF_TYPE int32_t
// Extract byte N=0,1,2,3 from x
#define BYTE0(x) (((x) & 0x000000ff) >>  0)
#define BYTE1(x) (((x) & 0x0000ff00) >>  8)
#define BYTE2(x) (((x) & 0x00ff0000) >> 16)
#define BYTE3(x) (((x) & 0xff000000) >> 24)
#define EXTRA 4 // need 4 extra bytes to avoid OOB reads

static int CheckMatch(const SCACTileSearchCtx *ctx, PrefilterRuleStore *pmq,
               const uint8_t *buf, uint32_t buflen,
               uint16_t state, int i, int matches,
               uint8_t *mpm_bitarray)
{
    const SCACTilePatternList *pattern_list = ctx->pattern_list;
    const uint8_t *buf_offset = buf + i + 1; // Lift out of loop
    uint32_t no_of_entries = ctx->output_table[state].no_of_entries;
    MpmPatternIndex *patterns = ctx->output_table[state].patterns;
    uint32_t k;

    for (k = 0; k < no_of_entries; k++) {
        MpmPatternIndex pindex = patterns[k] & 0x0FFFFFFF;
        if (mpm_bitarray[pindex / 8] & (1 << (pindex % 8))) {
            /* Pattern already seen by this MPM. */
            /* NOTE: This is faster then rechecking if it is a case-sensitive match
             * since we know this pattern has already been seen, but imcrementing
             * matches here could over report matches. For example if the case-sensitive
             * pattern is "Foo" and the string is "Foo bar foo", matches would be reported
             * as 2, when it should really be 1, since "foo" is not a true match.
             */
            matches++;
            continue;
        }
        const SCACTilePatternList *pat = &pattern_list[pindex];
        const int offset = i - pat->patlen + 1;
        if (offset < (int)pat->offset || (pat->depth && i > pat->depth))
            continue;

        /* Double check case-sensitve match now. */
        if (patterns[k] >> 31) {
            const uint16_t patlen = pat->patlen;
            if (SCMemcmp(pat->cs, buf_offset - patlen, patlen) != 0) {
                /* Case-sensitive match failed. */
                continue;
            }
        }
        /* New match found */
        mpm_bitarray[pindex / 8] |= (1 << (pindex % 8));

        /* Always add the Signature IDs, since they could be different in the current MPM
         * than in a previous MPM on the same PMQ when finding the same pattern.
         */
        PrefilterAddSids(pmq, pattern_list[pindex].sids,
                   pattern_list[pindex].sids_size);
        matches++;
    }

    return matches;
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
uint32_t SCACTileSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen)
{
    const SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;

    if (buflen == 0)
        return 0;

    /* Context specific matching function. */
    return search_ctx->Search(search_ctx, mpm_thread_ctx, pmq, buf, buflen);
}

/* This function handles (ctx->state_count >= 32767) */
uint32_t SCACTileSearchLarge(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                             PrefilterRuleStore *pmq,
                             const uint8_t *buf, uint32_t buflen)
{
    uint32_t i = 0;
    int matches = 0;

    uint8_t mpm_bitarray[ctx->mpm_bitarray_size];
    memset(mpm_bitarray, 0, ctx->mpm_bitarray_size);

    const uint8_t* restrict xlate = ctx->translate_table;
    register int state = 0;
    int32_t (*state_table_u32)[256] = ctx->state_table;
    for (i = 0; i < buflen; i++) {
        state = state_table_u32[state & 0x00FFFFFF][xlate[buf[i]]];
        if (SCHECK(state)) {
            DEBUG_VALIDATE_BUG_ON(state < 0 || state > UINT16_MAX);
            matches = CheckMatch(ctx, pmq, buf, buflen, (uint16_t)state, i, matches, mpm_bitarray);
        }
    } /* for (i = 0; i < buflen; i++) */

    return matches;
}

/*
 * Search with Alphabet size of 256 and 16-bit next-state entries.
 * Next state entry has MSB as "match" and 15 LSB bits as next-state index.
 */
// y = 1<<log_mult * (x & (1<<width -1))
#define SINDEX_INTERNAL(y, x, log_mult, width) \
    ((1<<log_mult) * (x & ((1<<width) - 1)))

/* Type of next_state */
#define STYPE int16_t
#define SLOAD(x) *(STYPE * restrict)(x)

#define FUNC_NAME SCACTileSearchSmall256
// y = 256 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 8, 15)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 128 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall128
// y = 128 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 7, 15)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 64 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall64
// y = 64 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 6, 15)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 32 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall32
// y = 32 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 5, 15)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 16 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall16
// y = 16 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 4, 15)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 8 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchSmall8
// y = 8 * (x & 0x7FFF)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 3, 15)
#include "util-mpm-ac-ks-small.c"

/*
 * Search with Alphabet size of 256 and 8-bit next-state entries.
 * Next state entry has MSB as "match" and 15 LSB bits as next-state index.
 */
#undef STYPE
#define STYPE int8_t

#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny256
// y = 256 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 8, 7)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 128 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny128
// y = 128 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 7, 7)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 64 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny64
// y = 64 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 6, 7)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 32 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny32
// y = 32 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 5, 7)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 16 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny16
// y = 16 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 4, 7)
#include "util-mpm-ac-ks-small.c"

/* Search with Alphabet size of 8 */
#undef FUNC_NAME
#undef SINDEX
#define FUNC_NAME SCACTileSearchTiny8
// y = 8 * (x & 0x7F)
#define SINDEX(y,x) SINDEX_INTERNAL(y, x, 3, 7)
#include "util-mpm-ac-ks-small.c"


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
int SCACTileAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth,
                              pid, sid, flags);
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
int SCACTileAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                         uint16_t offset, uint16_t depth, uint32_t pid,
                         SigIntId sid, uint8_t flags)
{
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth,
                              pid, sid, flags);
}

void SCACTilePrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
#ifdef SC_AC_TILE_COUNTERS
    SCACTileThreadCtx *ctx = (SCACTileThreadCtx *)mpm_thread_ctx->ctx;
    printf("AC Thread Search stats (ctx %p)\n", ctx);
    printf("Total calls: %" PRIu32 "\n", ctx->total_calls);
    printf("Total matches: %" PRIu64 "\n", ctx->total_matches);
#endif /* SC_AC_TILE_COUNTERS */
}

void SCACTilePrintInfo(MpmCtx *mpm_ctx)
{
    SCACTileSearchCtx *search_ctx = (SCACTileSearchCtx *)mpm_ctx->ctx;
    SCACTileCtx *ctx = search_ctx->init_ctx;

    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCACTileCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(SCACTileCtx));
    printf("  MpmPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(MpmPattern));
    printf("  MpmPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(MpmPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Total states in the state table:    %u\n", ctx->state_count);
    printf("\n");
}

/************************** Mpm Registration ***************************/

/**
 * \brief Register the aho-corasick mpm 'ks' originally developed by
 *        Ken Steele for Tilera Tile-Gx processor.
 */
void MpmACTileRegister(void)
{
    mpm_table[MPM_AC_KS].name = "ac-ks";
    mpm_table[MPM_AC_KS].InitCtx = SCACTileInitCtx;
    mpm_table[MPM_AC_KS].InitThreadCtx = SCACTileInitThreadCtx;
    mpm_table[MPM_AC_KS].DestroyCtx = SCACTileDestroyCtx;
    mpm_table[MPM_AC_KS].DestroyThreadCtx = SCACTileDestroyThreadCtx;
    mpm_table[MPM_AC_KS].AddPattern = SCACTileAddPatternCS;
    mpm_table[MPM_AC_KS].AddPatternNocase = SCACTileAddPatternCI;
    mpm_table[MPM_AC_KS].Prepare = SCACTilePreparePatterns;
    mpm_table[MPM_AC_KS].Search = SCACTileSearch;
    mpm_table[MPM_AC_KS].PrintCtx = SCACTilePrintInfo;
    mpm_table[MPM_AC_KS].PrintThreadCtx = SCACTilePrintSearchStats;
    mpm_table[MPM_AC_KS].RegisterUnittests = SCACTileRegisterTests;
}


/*************************************Unittests********************************/

#ifdef UNITTESTS

static int SCACTileTest01(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcd";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

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
    /* total matches: 135 */

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq);

    if (SCACTilePreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    const char *buf = "he";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 1);
    buf = "she";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 2);
    buf = "his";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf)) == 2);

 end:
    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    const char pat[] = "abcde"
                       "fghij"
                       "klmno"
                       "pqrst"
                       "uvwxy"
                       "z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcde""fghij""klmno""pqrst""uvwxy""z";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 */
    const char pat[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

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

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "works";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "tone";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_KS);
    SCACTileInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACTilePreparePatterns(&mpm_ctx);

    const char *buf = "tONE";
    uint32_t cnt = SCACTileSearch(&mpm_ctx, &mpm_thread_ctx, &pmq,
                                  (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    SCACTileDestroyCtx(&mpm_ctx);
    SCACTileDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACTileTest29(void)
{
    uint8_t buf[] = "onetwothreefourfivesixseveneightnine";
    uint16_t buflen = sizeof(buf) - 1;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

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

void SCACTileRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCACTileTest01", SCACTileTest01);
    UtRegisterTest("SCACTileTest02", SCACTileTest02);
    UtRegisterTest("SCACTileTest03", SCACTileTest03);
    UtRegisterTest("SCACTileTest04", SCACTileTest04);
    UtRegisterTest("SCACTileTest05", SCACTileTest05);
    UtRegisterTest("SCACTileTest06", SCACTileTest06);
    UtRegisterTest("SCACTileTest07", SCACTileTest07);
    UtRegisterTest("SCACTileTest08", SCACTileTest08);
    UtRegisterTest("SCACTileTest09", SCACTileTest09);
    UtRegisterTest("SCACTileTest10", SCACTileTest10);
    UtRegisterTest("SCACTileTest11", SCACTileTest11);
    UtRegisterTest("SCACTileTest12", SCACTileTest12);
    UtRegisterTest("SCACTileTest13", SCACTileTest13);
    UtRegisterTest("SCACTileTest14", SCACTileTest14);
    UtRegisterTest("SCACTileTest15", SCACTileTest15);
    UtRegisterTest("SCACTileTest16", SCACTileTest16);
    UtRegisterTest("SCACTileTest17", SCACTileTest17);
    UtRegisterTest("SCACTileTest18", SCACTileTest18);
    UtRegisterTest("SCACTileTest19", SCACTileTest19);
    UtRegisterTest("SCACTileTest20", SCACTileTest20);
    UtRegisterTest("SCACTileTest21", SCACTileTest21);
    UtRegisterTest("SCACTileTest22", SCACTileTest22);
    UtRegisterTest("SCACTileTest23", SCACTileTest23);
    UtRegisterTest("SCACTileTest24", SCACTileTest24);
    UtRegisterTest("SCACTileTest25", SCACTileTest25);
    UtRegisterTest("SCACTileTest26", SCACTileTest26);
    UtRegisterTest("SCACTileTest27", SCACTileTest27);
    UtRegisterTest("SCACTileTest28", SCACTileTest28);
    UtRegisterTest("SCACTileTest29", SCACTileTest29);
#endif
}

#else /* we're big endian */

void MpmACTileRegister(void)
{
    /* no-op on big endian */
}

#endif /* little endian check */
