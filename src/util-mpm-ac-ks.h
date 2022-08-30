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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Ken Steele <suricata@tilera.com>
 *
 */

#ifndef __UTIL_MPM_AC_KS__H__
#define __UTIL_MPM_AC_KS__H__

typedef struct SCACTilePatternList_ {
    uint8_t *cs;
    uint16_t patlen;

    uint16_t offset;
    uint16_t depth;

    /* Pattern Id */
    uint32_t pid;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;
} SCACTilePatternList;

typedef struct SCACTileOutputTable_ {
    /* list of pattern indexes */
    MpmPatternIndex *patterns;
    /* number of entries in pattern list */
    uint32_t no_of_entries;
} SCACTileOutputTable;

struct SCACTileSearchCtx_;

/* Reordered for Tilera cache */
typedef struct SCACTileCtx_ {

    /* Convert input character to matching alphabet */
    uint8_t translate_table[256];

    /* The all important memory hungry state_table.
     * The size of each next-state is determined by bytes_per_state.
     */
    void *state_table;

    /* Specialized search function based on size of data in delta
     * tables.  The alphabet size determines address shifting and the
     * number of states could make the next state could be 16 bits or
     * 32 bits.
     */
    uint32_t (*Search)(const struct SCACTileSearchCtx_ *ctx, struct MpmThreadCtx_ *,
                       PrefilterRuleStore *, const uint8_t *, uint32_t);

    /* Function to set the next state based on size of next state
     * (bytes_per_state).
     */
    void (*SetNextState)(struct SCACTileCtx_ *ctx, int state, int aa,
                           int new_state, int outputs);

    /* List of patterns that match for this state. Indexed by State Number */
    SCACTileOutputTable *output_table;
    /* Indexed by MpmPatternIndex */
    SCACTilePatternList *pattern_list;

    /* pattern arrays.  We need this only during the goto table
       creation phase */
    MpmPattern **parray;

    /* goto_table, failure table and output table.  Needed to create
     * state_table.  Will be freed, once we have created the
     * state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;

    /* Number of states used */
    uint32_t state_count;
    /* Number of states allocated. */
    uint32_t allocated_state_count;

    uint32_t alpha_hist[256];
    /* Number of characters in the compressed alphabet. */
    uint16_t alphabet_size;
    /* Space used to store compressed alphabet is the next
     * larger or equal power-of-2.
     */
    uint16_t alphabet_storage;

    /* How many bytes are used to store the next state. */
    uint8_t bytes_per_state;

} SCACTileCtx;


/* Only the stuff used at search time. This
 * structure is created after all the patterns are added.
 */
typedef struct SCACTileSearchCtx_ {

    /* Specialized search function based on size of data in delta
     * tables.  The alphabet size determines address shifting and the
     * number of states could make the next state could be 16 bits or
     * 32 bits.
     */
    uint32_t (*Search)(const struct SCACTileSearchCtx_ *ctx, struct MpmThreadCtx_ *,
                       PrefilterRuleStore *, const uint8_t *, uint32_t);

    /* Convert input character to matching alphabet */
    uint8_t translate_table[256];

    /* the all important memory hungry state_table */
    void *state_table;

    /* List of patterns that match for this state. Indexed by State Number */
    SCACTileOutputTable *output_table;
    SCACTilePatternList *pattern_list;

    /* Number of bytes in the array of bits. One bit per pattern in this MPM. */
    uint32_t mpm_bitarray_size;

    /* Number of states used */
    uint32_t state_count;

    uint32_t pattern_cnt;

    /* MPM Creation data, only used at initialization. */
    SCACTileCtx *init_ctx;

} SCACTileSearchCtx;


typedef struct SCACTileThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACTileThreadCtx;

void MpmACTileRegister(void);

#endif /* __UTIL_MPM_AC_KS__H__ */
