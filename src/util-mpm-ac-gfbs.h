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
 */

#define SC_AC_GFBS_STATE_TYPE_U16 uint16_t
#define SC_AC_GFBS_STATE_TYPE_U32 uint32_t

typedef struct SCACGfbsPattern_ {
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

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    struct SCACGfbsPattern_ *next;
} SCACGfbsPattern;

typedef struct SCACGfbsPatternList_ {
    uint8_t *cs;
    uint16_t patlen;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;
} SCACGfbsPatternList;

typedef struct SCACGfbsOutputTable_ {
    /* list of pattern sids */
    uint32_t *pids;
    /* no of entries we have in pids */
    uint32_t no_of_entries;
} SCACGfbsOutputTable;

typedef struct SCACGfbsGotoTableMod_ {
    /* each of these below declarations will be of type uint32_t, if the state
     * count exceeds 65535, the maximum value a 16 bit unsigned var can hold */

    /* no of entries stored below */
    uint16_t no_of_entries;

    /* the ascii codes over which we have state transitions */
    uint16_t *ascii_codes;
    /* the states that correspond to the ascii_codes above */
    uint16_t *states;
} SCACGfbsGotoTableMod_;

typedef struct SCACGfbsCtx_ {
    /* hash used during ctx initialization */
    SCACGfbsPattern **init_hash;

    /* pattern arrays.  We need this only during the goto table creation phase */
    SCACGfbsPattern **parray;

    /* no of states used by ac */
    int32_t state_count;
    /* the modified goto_table */
    uint8_t *goto_table_mod;
    uint8_t **goto_table_mod_pointers;

    /* goto_table, failure table and output table.  Needed to create state_table.
     * Will be freed, once we have created the goto_table_mod */
    int32_t (*goto_table)[256];
    int32_t *failure_table;
    SCACGfbsOutputTable *output_table;
    SCACGfbsPatternList *pid_pat_list;

    /* the size of each state */
    uint16_t single_state_size;
    uint16_t max_pat_id;
} SCACGfbsCtx;

typedef struct SCACGfbsThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACGfbsThreadCtx;

void MpmACGfbsRegister(void);
