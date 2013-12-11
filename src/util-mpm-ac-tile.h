/* Copyright (C) 2013 Open Information Security Foundation
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

#ifndef __UTIL_MPM_AC_TILE__H__
#define __UTIL_MPM_AC_TILE__H__

#define SC_AC_TILE_STATE_TYPE_U16 uint16_t
#define SC_AC_TILE_STATE_TYPE_U32 uint32_t

typedef struct SCACTilePattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags decribing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* case sensitive */
    uint8_t *cs;
    /* case INsensitive */
    uint8_t *ci;
    /* pattern id */
    uint32_t id;

    struct SCACTilePattern_ *next;
} SCACTilePattern;

typedef struct SCACTilePatternList_ {
    uint8_t *cs;
    uint16_t patlen;
    uint16_t case_state;
} SCACTilePatternList;

typedef struct SCACTileOutputTable_ {
    /* list of pattern sids */
    uint32_t *pids;
    /* no of entries we have in pids */
    uint32_t no_of_entries;
} SCACTileOutputTable;

struct SCACTileSearchCtx_;

/* Reordered for Tilera cache */
typedef struct SCACTileCtx_ {

    /* Convert input character to matching alphabet */
    uint8_t translate_table[256];

    /* the all important memory hungry state_table */
    SC_AC_TILE_STATE_TYPE_U16 *state_table_u16;
    /* the all important memory hungry state_table */
    SC_AC_TILE_STATE_TYPE_U32 (*state_table_u32)[256];

    /* Specialized search function based on size of data in delta
     * tables.  The alphabet size determines address shifting and the
     * number of states could make the next state could be 16 bits or
     * 32 bits.
     */
    uint32_t (*search)(struct SCACTileSearchCtx_ *ctx, struct MpmThreadCtx_ *,
                       PatternMatcherQueue *, uint8_t *, uint16_t);


    SCACTileOutputTable *output_table;
    SCACTilePatternList *pid_pat_list;

    /* the stuff below is only used at initialization time */

    /* hash used during ctx initialization */
    SCACTilePattern **init_hash;

    /* pattern arrays.  We need this only during the goto table
       creation phase */
    SCACTilePattern **parray;

    /* goto_table, failure table and output table.  Needed to create
     * state_table.  Will be freed, once we have created the
     * state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;

    /* no of states used by ac */
    uint32_t state_count;

    /* the size of each state */
    uint16_t max_pat_id;

    uint32_t alpha_hist[256];
    uint16_t alphabet_size;

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
    uint32_t (*search)(struct SCACTileSearchCtx_ *ctx, struct MpmThreadCtx_ *,
                       PatternMatcherQueue *, uint8_t *, uint16_t);

    /* Convert input character to matching alphabet */
    uint8_t translate_table[256];

    /* the all important memory hungry state_table */
    union {
        SC_AC_TILE_STATE_TYPE_U16 *state_table_u16;
        SC_AC_TILE_STATE_TYPE_U32 (*state_table_u32)[256];
    };

    SCACTileOutputTable *output_table;
    SCACTilePatternList *pid_pat_list;

    /* MPM Creation data */
    SCACTileCtx *init_ctx;

} SCACTileSearchCtx;


typedef struct SCACTileThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACTileThreadCtx;

void MpmACTileRegister(void);

#endif /* __UTIL_MPM_AC_TILE__H__ */
