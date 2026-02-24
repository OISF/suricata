/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * Hyperscan caching logic for faster database compilation.
 */

#ifndef SURICATA_UTIL_MPM_HS_CACHE__H
#define SURICATA_UTIL_MPM_HS_CACHE__H

#include "util-mpm-hs-core.h"

#ifdef BUILD_HYPERSCAN

struct HsIteratorData {
    PatternDatabaseCache *pd_stats;
    const char *cache_path;
};

/**
 * \brief Data structure to store in-use cache files.
 * Used in cache pruning to avoid deleting files that are still in use.
 */
struct HsInUseCacheFilesIteratorData {
    HashTable *tbl; // stores file paths of in-use cache files
    const char *cache_path;
};

int HSLoadCache(hs_database_t **hs_db, const char *hs_db_hash, const char *dirpath);
int HSHashDb(const PatternDatabase *pd, char *hash, size_t hash_len);
void HSSaveCacheIterator(void *data, void *aux);
void HSCacheFilenameUsedIterator(void *data, void *aux);
int SCHSCachePruneEvaluate(MpmConfig *mpm_conf, HashTable *inuse_caches);

void *SCHSCacheStatsInit(void);
void SCHSCacheStatsPrint(void *data);
void SCHSCacheStatsDeinit(void *data);
#endif /* BUILD_HYPERSCAN */

#endif /* SURICATA_UTIL_MPM_HS_CACHE__H */
