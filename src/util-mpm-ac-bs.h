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

#include "util-mpm.h"

#define SC_AC_BS_STATE_TYPE_U16 uint16_t
#define SC_AC_BS_STATE_TYPE_U32 uint32_t

typedef struct SCACBSPatternList_ {
    uint8_t *cs;
    uint16_t patlen;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;
} SCACBSPatternList;

typedef struct SCACBSOutputTable_ {
    /* list of pattern sids */
    uint32_t *pids;
    /* no of entries we have in pids */
    uint32_t no_of_entries;
} SCACBSOutputTable;

typedef struct SCACBSCtx_ {
    /* pattern arrays.  We need this only during the goto table creation phase */
    MpmPattern **parray;

    /* no of states used by ac */
    uint32_t state_count;

    uint32_t pattern_id_bitarray_size;

    /* the all important memory hungry state_table */
    SC_AC_BS_STATE_TYPE_U16 (*state_table_u16)[256];
    /* the all important memory hungry state_table */
    SC_AC_BS_STATE_TYPE_U32 (*state_table_u32)[256];
    /* the modified goto_table */
    uint8_t *state_table_mod;
    uint8_t **state_table_mod_pointers;

    /* goto_table, failure table and output table.  Needed to create state_table.
     * Will be freed, once we have created the state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;
    SCACBSOutputTable *output_table;
    SCACBSPatternList *pid_pat_list;

    /* the size of each state */
    uint16_t single_state_size;
} SCACBSCtx;

typedef struct SCACBSThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACBSThreadCtx;

void MpmACBSRegister(void);
