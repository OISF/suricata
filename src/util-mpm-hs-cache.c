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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * Hyperscan cache helper utilities for MPM cache files.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect-engine.h"
#include "util-debug.h"
#include "util-hash-lookup3.h"
#include "util-mpm-hs-core.h"
#include "util-mpm-hs-cache.h"
#include "util-path.h"

#ifdef BUILD_HYPERSCAN

#include "rust.h"
#include <hs.h>

#define HS_CACHE_FILE_VERSION "2"
#define HS_CACHE_FILE_SUFFIX  "_v" HS_CACHE_FILE_VERSION ".hs"

static int16_t HSCacheConstructFPath(
        const char *dir_path, const char *db_hash, char *out_path, uint16_t out_path_size)
{
    char filename[NAME_MAX];
    uint64_t r = snprintf(filename, sizeof(filename), "%s" HS_CACHE_FILE_SUFFIX, db_hash);
    if (r != (uint64_t)(strlen(db_hash) + strlen(HS_CACHE_FILE_SUFFIX)))
        return -1;

    r = PathMerge(out_path, out_path_size, dir_path, filename);
    if (r)
        return -1;

    return 0;
}

static char *HSReadStream(const char *file_path, size_t *buffer_sz)
{
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        SCLogDebug("Failed to open file %s: %s", file_path, strerror(errno));
        return NULL;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    long file_sz = ftell(file);
    if (file_sz < 0) {
        SCLogDebug("Failed to determine file size of %s: %s", file_path, strerror(errno));
        fclose(file);
        return NULL;
    }

    char *buffer = (char *)SCCalloc(file_sz, sizeof(char));
    if (!buffer) {
        SCLogWarning("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    // Rewind file pointer and read the file into the buffer
    errno = 0;
    rewind(file);
    if (errno != 0) {
        SCLogDebug("Failed to rewind file %s: %s", file_path, strerror(errno));
        SCFree(buffer);
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, file_sz, file);
    if (bytes_read != (size_t)file_sz) {
        SCLogDebug("Failed to read the entire file %s: %s", file_path, strerror(errno));
        SCFree(buffer);
        fclose(file);
        return NULL;
    }

    *buffer_sz = file_sz;
    fclose(file);
    return buffer;
}

/**
 * Function to hash the searched pattern, only things relevant to Hyperscan
 * compilation are hashed.
 */
static void SCHSCachePatternHash(const SCHSPattern *p, SCSha256 *sha256)
{
    BUG_ON(p->original_pat == NULL);
    BUG_ON(p->sids == NULL);

    SCSha256Update(sha256, (const uint8_t *)&p->len, sizeof(p->len));
    SCSha256Update(sha256, (const uint8_t *)&p->flags, sizeof(p->flags));
    SCSha256Update(sha256, (const uint8_t *)p->original_pat, p->len);
    SCSha256Update(sha256, (const uint8_t *)&p->id, sizeof(p->id));
    SCSha256Update(sha256, (const uint8_t *)&p->offset, sizeof(p->offset));
    SCSha256Update(sha256, (const uint8_t *)&p->depth, sizeof(p->depth));
    SCSha256Update(sha256, (const uint8_t *)&p->sids_size, sizeof(p->sids_size));
    SCSha256Update(sha256, (const uint8_t *)p->sids, p->sids_size * sizeof(SigIntId));
}

int HSLoadCache(hs_database_t **hs_db, const char *hs_db_hash, const char *dirpath)
{
    char hash_file_static[PATH_MAX];
    int ret = (int)HSCacheConstructFPath(
            dirpath, hs_db_hash, hash_file_static, sizeof(hash_file_static));

    if (ret != 0)
        return -1;

    SCLogDebug("Loading the cached HS DB from %s", hash_file_static);
    if (!SCPathExists(hash_file_static))
        return -1;

    FILE *db_cache = fopen(hash_file_static, "r");
    char *buffer = NULL;
    if (db_cache) {
        size_t buffer_size;
        buffer = HSReadStream(hash_file_static, &buffer_size);
        if (!buffer) {
            SCLogWarning("Hyperscan cached DB file %s cannot be read", hash_file_static);
            ret = -1;
            goto freeup;
        }

        hs_error_t error = hs_deserialize_database(buffer, buffer_size, hs_db);
        if (error != HS_SUCCESS) {
            SCLogWarning("Failed to deserialize Hyperscan database of %s: %s", hash_file_static,
                    HSErrorToStr(error));
            ret = -1;
            goto freeup;
        }

        ret = 0;
        /* Touch file to update modification time so active caches are retained. */
        if (SCTouchFile(hash_file_static) != 0) {
            SCLogDebug("Failed to update mtime for %s", hash_file_static);
        }
        goto freeup;
    }

freeup:
    if (db_cache)
        fclose(db_cache);
    if (buffer)
        SCFree(buffer);
    return ret;
}

static int HSSaveCache(hs_database_t *hs_db, const char *hs_db_hash, const char *dstpath)
{
    static bool notified = false;
    char *db_stream = NULL;
    size_t db_size;
    int ret;

    hs_error_t err = hs_serialize_database(hs_db, &db_stream, &db_size);
    if (err != HS_SUCCESS) {
        SCLogWarning("Failed to serialize Hyperscan database: %s", HSErrorToStr(err));
        ret = -1;
        goto cleanup;
    }

    char hash_file_static[PATH_MAX];
    ret = (int)HSCacheConstructFPath(
            dstpath, hs_db_hash, hash_file_static, sizeof(hash_file_static));
    if (ret != 0)
        goto cleanup;
    SCLogDebug("Caching the compiled HS at %s", hash_file_static);
    if (SCPathExists(hash_file_static)) {
        // potentially signs that it might not work as expected as we got into
        // hash collision. If this happens with older and not used caches it is
        // fine.
        // It is problematic when one ruleset yields two colliding MPM groups.
        SCLogWarning("Overwriting cache file %s. If the problem persists consider switching off "
                     "the caching",
                hash_file_static);
    }

    FILE *db_cache_out = fopen(hash_file_static, "w");
    if (!db_cache_out) {
        if (!notified) {
            SCLogWarning("Failed to create Hyperscan cache file, make sure the folder exist and is "
                         "writable or adjust sgh-mpm-caching-path setting (%s)",
                    hash_file_static);
            notified = true;
        }
        ret = -1;
        goto cleanup;
    }
    size_t r = fwrite(db_stream, sizeof(db_stream[0]), db_size, db_cache_out);
    if (r > 0 && (size_t)r != db_size) {
        SCLogWarning("Failed to write to file: %s", hash_file_static);
        if (r != db_size) {
            // possibly a corrupted DB cache was created
            r = remove(hash_file_static);
            if (r != 0) {
                SCLogWarning("Failed to remove corrupted cache file: %s", hash_file_static);
            }
        }
    }
    ret = fclose(db_cache_out);
    if (ret != 0) {
        SCLogWarning("Failed to close file: %s", hash_file_static);
        goto cleanup;
    }

cleanup:
    if (db_stream)
        SCFree(db_stream);
    return ret;
}

int HSHashDb(const PatternDatabase *pd, char *hash, size_t hash_len)
{
    SCSha256 *hasher = SCSha256New();
    if (hasher == NULL) {
        SCLogDebug("sha256 hashing failed");
        return -1;
    }
    SCSha256Update(hasher, (const uint8_t *)&pd->pattern_cnt, sizeof(pd->pattern_cnt));
    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        SCHSCachePatternHash(pd->parray[i], hasher);
    }

    if (!SCSha256FinalizeToHex(hasher, hash, hash_len)) {
        hasher = NULL;
        SCLogDebug("sha256 hashing failed");
        return -1;
    }

    hasher = NULL;
    return 0;
}

void HSSaveCacheIterator(void *data, void *aux)
{
    PatternDatabase *pd = (PatternDatabase *)data;
    struct HsIteratorData *iter_data = (struct HsIteratorData *)aux;
    if (pd->no_cache)
        return;

    // count only cacheable DBs
    iter_data->pd_stats->hs_cacheable_dbs_cnt++;
    if (pd->cached) {
        iter_data->pd_stats->hs_dbs_cache_loaded_cnt++;
        return;
    }

    char hs_db_hash[SC_SHA256_LEN * 2 + 1]; // * 2 for hex +1 for nul terminator
    if (HSHashDb(pd, hs_db_hash, ARRAY_SIZE(hs_db_hash)) != 0) {
        return;
    }
    if (HSSaveCache(pd->hs_db, hs_db_hash, iter_data->cache_path) == 0) {
        pd->cached = true; // for rule reloads
        iter_data->pd_stats->hs_dbs_cache_saved_cnt++;
    }
}

void HSCacheFilenameUsedIterator(void *data, void *aux)
{
    PatternDatabase *pd = (PatternDatabase *)data;
    struct HsInUseCacheFilesIteratorData *iter_data = (struct HsInUseCacheFilesIteratorData *)aux;
    if (pd->no_cache || !pd->cached)
        return;

    char hs_db_hash[SC_SHA256_LEN * 2 + 1]; // * 2 for hex +1 for nul terminator
    if (HSHashDb(pd, hs_db_hash, ARRAY_SIZE(hs_db_hash)) != 0) {
        return;
    }

    char *fpath = SCCalloc(PATH_MAX, sizeof(char));
    if (fpath == NULL) {
        SCLogWarning("Failed to allocate memory for cache file path");
        return;
    }
    if (HSCacheConstructFPath(iter_data->cache_path, hs_db_hash, fpath, PATH_MAX)) {
        SCFree(fpath);
        return;
    }

    int r = HashTableAdd(iter_data->tbl, (void *)fpath, (uint16_t)strlen(fpath));
    if (r < 0) {
        SCLogWarning("Failed to add used cache file path %s to hash table", fpath);
        SCFree(fpath);
    }
}

/**
 * \brief Check if HS cache file is stale by age.
 *
 * \param mtime   File modification time.
 * \param cutoff  Time cutoff (files older than this will be removed).
 *
 * \retval true if file should be pruned, false otherwise.
 */
static bool HSPruneFileByAge(time_t mtime, time_t cutoff)
{
    return mtime < cutoff;
}

/**
 * \brief Check if HS cache file is version-compatible.
 *
 * \param filename  Cache file name.
 *
 * \retval true if file should be pruned, false otherwise.
 */
static bool HSPruneFileByVersion(const char *filename)
{
    if (strlen(filename) < strlen(HS_CACHE_FILE_SUFFIX)) {
        return true;
    }

    const char *underscore = strrchr(filename, '_');
    if (underscore == NULL || strcmp(underscore, HS_CACHE_FILE_SUFFIX) != 0) {
        return true;
    }

    return false;
}

int SCHSCachePruneEvaluate(MpmConfig *mpm_conf, HashTable *inuse_caches)
{
    if (mpm_conf == NULL || mpm_conf->cache_dir_path == NULL)
        return -1;
    if (mpm_conf->cache_max_age_seconds == 0)
        return 0; // disabled

    const time_t now = time(NULL);
    if (now == (time_t)-1) {
        return -1;
    } else if (mpm_conf->cache_max_age_seconds >= (uint64_t)now) {
        return 0;
    }

    DIR *dir = opendir(mpm_conf->cache_dir_path);
    if (dir == NULL) {
        return -1;
    }

    struct dirent *ent;
    char path[PATH_MAX];
    uint32_t considered = 0, removed = 0;
    const time_t cutoff = now - (time_t)mpm_conf->cache_max_age_seconds;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t namelen = strlen(name);
        if (namelen < 3 || strcmp(name + namelen - 3, ".hs") != 0)
            continue;

        if (PathMerge(path, ARRAY_SIZE(path), mpm_conf->cache_dir_path, name) != 0)
            continue;

        struct stat st;
        /* TOCTOU: race window between stat and unlink is acceptable here.
         * On Linux somebody can still modify (use the cache file) between the
         * fstat and unlink, on Windows (HS not supported there but still relevant)
         * TOCTOU happens when closing the file descriptor and unlinking the file.
         * Cache mechanism is best-effort and e.g. not pruning or pruning an extra
         * cache file is not problematic.
         * Stat is used here to ease file handling as fstat doesn't bring any benefit */
        /* coverity[toctou] */
        if (SCStatFn(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        considered++;

        const bool prune_by_age = HSPruneFileByAge(st.st_mtime, cutoff);
        const bool prune_by_version = HSPruneFileByVersion(name);
        if (!prune_by_age && !prune_by_version)
            continue;

        void *cache_inuse = HashTableLookup(inuse_caches, path, (uint16_t)strlen(path));
        if (cache_inuse != NULL)
            continue; // in use

        /* coverity[toctou] */
        int ret = unlink(path);
        if (ret == 0 || (ret == -1 && errno == ENOENT)) {
            removed++;
            SCLogDebug("File %s removed because of %s%s%s", path, prune_by_age ? "age" : "",
                    prune_by_age && prune_by_version ? " and " : "",
                    prune_by_version ? "incompatible version" : "");
        } else {
            SCLogWarning("Failed to prune \"%s\": %s", path, strerror(errno));
        }
    }
    closedir(dir);

    PatternDatabaseCache *pd_cache_stats = mpm_conf->cache_stats;
    if (pd_cache_stats) {
        pd_cache_stats->hs_dbs_cache_pruned_cnt = removed;
        pd_cache_stats->hs_dbs_cache_pruned_considered_cnt = considered;
        pd_cache_stats->hs_dbs_cache_pruned_cutoff = cutoff;
        pd_cache_stats->cache_max_age_seconds = mpm_conf->cache_max_age_seconds;
    }
    return 0;
}

void *SCHSCacheStatsInit(void)
{
    PatternDatabaseCache *pd_cache_stats = SCCalloc(1, sizeof(PatternDatabaseCache));
    if (pd_cache_stats == NULL) {
        SCLogError("Failed to allocate memory for Hyperscan cache stats");
        return NULL;
    }
    return pd_cache_stats;
}

void SCHSCacheStatsPrint(void *data)
{
    if (data == NULL) {
        return;
    }

    PatternDatabaseCache *pd_cache_stats = (PatternDatabaseCache *)data;

    char time_str[64];
    struct tm tm_s;
    struct tm *tm_info = SCLocalTime(pd_cache_stats->hs_dbs_cache_pruned_cutoff, &tm_s);
    if (tm_info != NULL) {
        strftime(time_str, ARRAY_SIZE(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_str, ARRAY_SIZE(time_str), "%" PRIu64 " seconds",
                pd_cache_stats->cache_max_age_seconds);
    }

    if (pd_cache_stats->hs_cacheable_dbs_cnt) {
        SCLogInfo("Rule group caching - loaded: %u newly cached: %u total cacheable: %u",
                pd_cache_stats->hs_dbs_cache_loaded_cnt, pd_cache_stats->hs_dbs_cache_saved_cnt,
                pd_cache_stats->hs_cacheable_dbs_cnt);
    }
    if (pd_cache_stats->hs_dbs_cache_pruned_considered_cnt) {
        SCLogInfo("Rule group cache pruning removed %u/%u of HS caches due to "
                  "version-incompatibility (not v%s) or "
                  "age (older than %s)",
                pd_cache_stats->hs_dbs_cache_pruned_cnt,
                pd_cache_stats->hs_dbs_cache_pruned_considered_cnt, HS_CACHE_FILE_VERSION,
                time_str);
    }
}

void SCHSCacheStatsDeinit(void *data)
{
    if (data == NULL) {
        return;
    }
    PatternDatabaseCache *pd_cache_stats = (PatternDatabaseCache *)data;
    SCFree(pd_cache_stats);
}

#endif /* BUILD_HYPERSCAN */
