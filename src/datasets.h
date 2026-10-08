/* Copyright (C) 2017 Open Information Security Foundation
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
 * Datasets: named in-memory sets that rules match against with the
 * 'dataset' and 'datarep' keywords.
 *
 * Each set holds one kind of value (string, MD5, SHA256, IPv4 or IP).
 * Entries may carry a reputation value, used by 'datarep'.
 *
 * Return codes, unless a function says otherwise:
 *    1  done (added, found, removed)
 *    0  nothing to do (already present, not found, busy)
 *   -1  error
 *   -2  bad input (wrong length or unparseable text)
 *
 * Locking: one global, non-recursive lock (DatasetLock()). Only the
 * functions marked "caller holds the lock" need you to take it.
 */

#ifndef SURICATA_DATASETS_H
#define SURICATA_DATASETS_H

// forward declaration to make things opaque to bindgen

/** Reputation value stored with an entry. */
typedef uint16_t DataRepType;

typedef struct Dataset Dataset;

/** \brief Add a value.
 *  \retval 1 added, 0 already present, -1 error, -2 bad length */
int SCDatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \brief Add a value with a reputation. \p rep must not be NULL.
 *  If the value already exists, its old reputation is kept.
 *  \retval 1 added, 0 already present, -1 error, -2 bad length */
int SCDatasetAddwRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep);

#ifndef SURICATA_BINDGEN_H

#include "util-thash.h"
#include "rust.h"
#include "datasets-reputation.h"

/** \name Lifecycle
 *  @{ */

/** \brief Create the sets declared in the 'datasets' YAML section.
 *  Call once at startup. Fatal on bad config. */
int DatasetsInit(void);

/** \brief Free all sets. */
void DatasetsDestroy(void);

/** \brief Write each set that has a save path to that file. */
void DatasetsSave(void);

/** \brief Start a live reload: mark static sets (load file, no save
 *  path, not from YAML) as hidden. They stay usable until
 *  DatasetPostReloadCleanup(). */
void DatasetReload(void);

/** \brief Finish a live reload: free the hidden sets. */
void DatasetPostReloadCleanup(void);

/** @} */

/** File format of a set's load/save file. */
typedef enum {
    DATASET_FORMAT_CSV = 0, /**< CSV (default) */
    DATASET_FORMAT_JSON,    /**< one JSON document */
    DATASET_FORMAT_NDJSON,  /**< one JSON object per line */
} DatasetFormats;

/** Kind of value a set holds. */
enum DatasetTypes {
#define DATASET_TYPE_NOTSET 0   /** no type yet */
    DATASET_TYPE_STRING = 1,    /**< any bytes */
    DATASET_TYPE_MD5,           /**< 16 bytes */
    DATASET_TYPE_SHA256,        /**< 32 bytes */
    DATASET_TYPE_IPV4,          /**< 4 bytes */
    DATASET_TYPE_IPV6,          /**< 16 bytes; IPv4 stored in the first 4, rest zero */
};

/** Max set name length, without the NUL. */
#define DATASET_NAME_MAX_LEN 63

/** A set. Sets are kept in a global linked list. */
typedef struct Dataset {
    char name[DATASET_NAME_MAX_LEN + 1];/**< name */
    enum DatasetTypes type;             /**< value type */
    uint32_t id;                        /**< unique id */
    bool from_yaml;                     /**< declared in suricata.yaml */
    bool hidden;                        /**< replaced by a reload, pending cleanup */
    bool remove_key;                    /**< strip value key from extra data */
    THashTableContext *hash;            /**< the values */
    char load[PATH_MAX];                /**< file read at startup, or "" */
    char save[PATH_MAX];                /**< file written by DatasetsSave(), or "" */
    struct Dataset *next;               /**< next set in the list */
} Dataset;

/** \brief Map "string", "md5", "sha256", "ipv4" or "ip" (case
 *  insensitive) to a type. Anything else gives DATASET_TYPE_NOTSET. */
enum DatasetTypes DatasetGetTypeFromString(const char *s);

/** \brief Add a fully built set to the global list.
 *  Caller holds the lock.
 *  \retval 0 ok, -1 no hash or memcap reached (caller still owns the set) */
int DatasetAppendSet(Dataset *set);

/** \brief Allocate a zeroed set with a new id. Does not set the name. */
Dataset *DatasetAlloc(const char *name);

/** \brief Take the global lock. */
void DatasetLock(void);

/** \brief Release the global lock. */
void DatasetUnlock(void);

/** \brief Find a visible set by name (case insensitive), any type.
 *  Caller holds the lock. \return the set or NULL */
Dataset *DatasetSearchByName(const char *name);

/** \brief Find a set by name. Never creates one.
 *  \return the set, or NULL if missing or of another type */
Dataset *DatasetFind(const char *name, enum DatasetTypes type);

/** \brief Get a set, creating, loading and registering it if needed.
 *  This is what rules use. Pass NULL/"" for \p save and \p load, and
 *  0 for \p memcap and \p hashsize, to use defaults.
 *  \return the set, or NULL on error (e.g. type mismatch) */
Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize);

/** \brief Building block of DatasetGet(): return an existing set, or
 *  allocate a new one with no hash and not in the list.
 *  Fills in default \p memcap / \p hashsize when they are 0.
 *  Caller holds the lock.
 *  \retval 1 existing set, 0 new set, -1 error */
int DatasetGetOrCreate(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t *memcap, uint32_t *hashsize, Dataset **ret_set);

/** \brief Remove a value.
 *  \retval 1 removed, 0 in use (retry later), -1 not found or error,
 *          -2 bad length */
int DatasetRemove(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \name Lookup
 *  @{ */

/** \brief Is the value in the set?
 *  \retval 1 found, 0 not found, -1 error or bad length */
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \brief Look up a value and get its stored reputation in .rep.
 *  \p rep must not be NULL. Not found and error both give
 *  .found = false. */
DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep);

/** @} */

/** \brief Default memcap and hash size, with 'datasets.defaults'
 *  from YAML applied. Hash size defaults to 4096. */
void DatasetGetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize);

/** \brief Parse an IPv4 or IPv6 address into the 16-byte IP format.
 *  IPv4 (and IPv4-mapped IPv6) go in the first 4 bytes, rest zero.
 *  Fatal at startup on bad input. \retval 0 ok, -1 bad address */
int DatasetParseIpv6String(Dataset *set, const char *line, struct in6_addr *in6);

/** \name Text variants
 *
 *  Same as add/lookup/remove, but the value is text: base64 for
 *  strings, hex for hashes, normal notation for IPs.
 *  Return -2 if the text can't be parsed.
 *  @{ */

int DatasetAddSerialized(Dataset *set, const char *string);
int DatasetRemoveSerialized(Dataset *set, const char *string);
int DatasetLookupSerialized(Dataset *set, const char *string);

/** @} */

#endif // SURICATA_BINDGEN_H

#endif /* SURICATA_DATASETS_H */
