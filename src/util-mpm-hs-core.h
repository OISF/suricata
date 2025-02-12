/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Jim Xu <jim.xu@windriver.com>
 * \author Justin Viiret <justin.viiret@intel.com>
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * MPM pattern matcher core function for the Hyperscan regex matcher.
 */

#ifndef SURICATA_UTIL_MPM_HS_CORE__H
#define SURICATA_UTIL_MPM_HS_CORE__H

#include "suricata-common.h"
#include "suricata.h"

#ifdef BUILD_HYPERSCAN
#include <hs.h>

typedef struct SCHSPattern_ {
    /** length of the pattern */
    uint16_t len;
    /** flags describing the pattern */
    uint8_t flags;
    /** holds the original pattern that was added */
    uint8_t *original_pat;
    /** pattern id */
    uint32_t id;

    uint16_t offset;
    uint16_t depth;

    /** sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    /** only used at ctx init time, when this structure is part of a hash
     * table. */
    struct SCHSPattern_ *next;
} SCHSPattern;

typedef struct SCHSCtx_ {
    /** hash used during ctx initialization */
    SCHSPattern **init_hash;

    /** pattern database and pattern arrays. */
    void *pattern_db;

    /** size of database, for accounting. */
    size_t hs_db_size;
} SCHSCtx;

typedef struct SCHSThreadCtx_ {
    /** Hyperscan scratch space region for this thread, capable of handling any
     * database that has been compiled. */
    void *scratch;

    /** size of scratch space, for accounting. */
    size_t scratch_size;
} SCHSThreadCtx;

typedef struct PatternDatabase_ {
    SCHSPattern **parray;
    hs_database_t *hs_db;
    uint32_t pattern_cnt;

    /** Reference count: number of MPM contexts using this pattern database. */
    uint32_t ref_cnt;
    /** Signals if the matcher has loaded/saved the pattern database to disk */
    bool cached;
    /** Matcher will not cache this pattern DB */
    bool no_cache;
} PatternDatabase;

typedef struct PatternDatabaseCache_ {
    uint32_t hs_cacheable_dbs_cnt;
    uint32_t hs_dbs_cache_loaded_cnt;
    uint32_t hs_dbs_cache_saved_cnt;
} PatternDatabaseCache;

const char *HSErrorToStr(hs_error_t error_code);

#endif /* BUILD_HYPERSCAN */
#endif /* SURICATA_UTIL_MPM_HS_CORE__H */
