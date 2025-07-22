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
 * MPM pattern matcher that calls the Hyperscan regex matcher.
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

#include <hs.h>

static const char *HSCacheConstructFPath(const char *folder_path, uint64_t hs_db_hash)
{
    static char hash_file_path[PATH_MAX];

    char hash_file_path_suffix[] = "_v1.hs";
    char filename[PATH_MAX];
    uint64_t r = snprintf(
            filename, sizeof(filename), "%020" PRIu64 "%s", hs_db_hash, hash_file_path_suffix);
    if (r != (uint64_t)(20 + strlen(hash_file_path_suffix)))
        return NULL;

    r = PathMerge(hash_file_path, sizeof(hash_file_path), folder_path, filename);
    if (r)
        return NULL;

    return hash_file_path;
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
static void SCHSCachePatternHash(const SCHSPattern *p, uint32_t *h1, uint32_t *h2)
{
    BUG_ON(p->original_pat == NULL);
    BUG_ON(p->sids == NULL);

    hashlittle2_safe(&p->len, sizeof(p->len), h1, h2);
    hashlittle2_safe(&p->flags, sizeof(p->flags), h1, h2);
    hashlittle2_safe(p->original_pat, p->len, h1, h2);
    hashlittle2_safe(&p->id, sizeof(p->id), h1, h2);
    hashlittle2_safe(&p->offset, sizeof(p->offset), h1, h2);
    hashlittle2_safe(&p->depth, sizeof(p->depth), h1, h2);
    hashlittle2_safe(&p->sids_size, sizeof(p->sids_size), h1, h2);
    hashlittle2_safe(p->sids, p->sids_size * sizeof(SigIntId), h1, h2);
}

int HSLoadCache(hs_database_t **hs_db, uint64_t hs_db_hash, const char *dirpath)
{
    const char *hash_file_static = HSCacheConstructFPath(dirpath, hs_db_hash);
    if (hash_file_static == NULL)
        return -1;

    SCLogDebug("Loading the cached HS DB from %s", hash_file_static);
    if (!SCPathExists(hash_file_static))
        return -1;

    FILE *db_cache = fopen(hash_file_static, "r");
    char *buffer = NULL;
    int ret = 0;
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
        goto freeup;
    }

freeup:
    if (db_cache)
        fclose(db_cache);
    if (buffer)
        SCFree(buffer);
    return ret;
}

static int HSSaveCache(hs_database_t *hs_db, uint64_t hs_db_hash, const char *dstpath)
{
    static bool notified = false;
    char *db_stream = NULL;
    size_t db_size;
    int ret = -1;

    hs_error_t err = hs_serialize_database(hs_db, &db_stream, &db_size);
    if (err != HS_SUCCESS) {
        SCLogWarning("Failed to serialize Hyperscan database: %s", HSErrorToStr(err));
        goto cleanup;
    }

    const char *hash_file_static = HSCacheConstructFPath(dstpath, hs_db_hash);
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

    ret = 0;
cleanup:
    if (db_stream)
        SCFree(db_stream);
    return ret;
}

uint64_t HSHashDb(const PatternDatabase *pd)
{
    uint32_t hash[2] = { 0 };
    hashword2(&pd->pattern_cnt, 1, &hash[0], &hash[1]);
    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        SCHSCachePatternHash(pd->parray[i], &hash[0], &hash[1]);
    }
    return ((uint64_t)hash[1] << 32) | hash[0];
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

    if (HSSaveCache(pd->hs_db, HSHashDb(pd), iter_data->cache_path) == 0) {
        pd->cached = true; // for rule reloads
        iter_data->pd_stats->hs_dbs_cache_saved_cnt++;
    }
}

#endif /* BUILD_HYPERSCAN */
