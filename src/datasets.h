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
 * Public API for datasets and datarep.
 *
 * A dataset is a named in-memory set of values (string, md5, sha256,
 * ipv4 or ipv6) that rules match against with the `dataset` and
 * `datarep` keywords. Sets can be preloaded from disk, persisted on
 * exit, and reloaded at runtime. Implementation lives in datasets.c.
 */

#ifndef SURICATA_DATASETS_H
#define SURICATA_DATASETS_H

// forward declaration to make things opaque to bindgen
/** Reputation value attached to a dataset entry. Opaque to bindgen;
 *  passed and returned through the *wRep functions and
 *  DataRepResultType. */
typedef uint16_t DataRepType;

/** Forward declaration of ::Dataset. */
typedef struct Dataset Dataset;

/** \name Add operations
 *  Insert a value into a set, with or without a reputation. Each
 *  dispatches on set->type to a per-type worker in datasets.c. If
 *  the value already exists the existing entry is reused (no
 *  refcount is exposed). Per-set locking is internal, callers do
 *  not touch the global set list.
 *  @{ */

/** \brief Insert a value.
 *  \retval  1 inserted
 *  \retval  0 already present
 *  \retval -1 error (NULL set, hash failure, unknown type)
 *  \retval -2 data_len wrong for the set's type. String worker does
 *             not return this.
 *  \note The IPv6 worker here accepts 4 or 16 bytes: a 4-byte buffer
 *        is treated as IPv4-mapped. SCDatasetAddwRep is stricter and
 *        requires 16. 
 */
int SCDatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \brief Insert a value with a reputation.
 *  \param rep dereferenced unconditionally, must not be NULL.
 *  \retval  1 inserted with rep attached
 *  \retval  0 already present; stored entry (and its existing rep)
 *             untouched, incoming rep discarded. First writer wins;
 *             reps are never merged.
 *  \retval -1 error (NULL set, hash failure, unknown type)
 *  \retval -2 data_len wrong for the set's type. Not from string worker.
 *  \note Unlike SCDatasetAdd, the IPv6 path here requires exactly
 *        16 bytes; a 4-byte buffer returns -2. 
 */
int SCDatasetAddwRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep);

/** @} */

#ifndef SURICATA_BINDGEN_H
#include "util-thash.h"
#include "rust.h"
#include "datasets-reputation.h"


/** \name Lifecycle
 *  Init, teardown, persistence, live reload.
 *  @{ */
/** \brief Init the subsystem from the `datasets` YAML section.
 *
 * Creates each declared set and loads its file. Call once
 * at startup after dropping privileges. Fatal config errors
 * call FatalError() and exit.
 *  \retval 0 on success 
 */
int DatasetsInit(void);

/** \brief Free every registered set and release resources. */
void DatasetsDestroy(void);

/** \brief Persist every set that has a save path. */
void DatasetsSave(void);

/** \brief Live reload, phase 1. 
 * Marks the current sets hidden and stages replacements
 * so in-flight lookups can finish against the old versions.
 * Must be paired with DatasetPostReloadCleanup(). 
 */
void DatasetReload(void);

/** \brief Live reload, phase 2. Frees the hidden old sets. */
void DatasetPostReloadCleanup(void);

/** @} */

/** On-disk format for a dataset's load/save file. */
typedef enum {
    DATASET_FORMAT_CSV = 0, /**< legacy CSV (default) */
    DATASET_FORMAT_JSON,    /**< single JSON object */
    DATASET_FORMAT_NDJSON,  /**< newline-delimited JSON, one entry per line */
} DatasetFormats;

/** Type of value a dataset stores. NOTSET is a sentinel for
 *  uninitialised sets, not a valid runtime type. */
enum DatasetTypes {
#define DATASET_TYPE_NOTSET 0   /** sentinel: type not assigned */
    DATASET_TYPE_STRING = 1,    /**< arbitrary byte strings */
    DATASET_TYPE_MD5,           /**< 16-byte MD5 */
    DATASET_TYPE_SHA256,        /**< 32-byte SHA256 */
    DATASET_TYPE_IPV4,          /**< 4-byte IPv4 */
    DATASET_TYPE_IPV6,          /**< 16-byte IPv6 */
};

/** Max dataset name length, excluding NUL. */
#define DATASET_NAME_MAX_LEN 63

/** In-memory dataset. Sets are linked in a global list guarded by
 *  the dataset lock (DatasetLock/DatasetUnlock) which callers walking
 *  the list directly must hold. Value storage lives in the backing
 *  ::THashTableContext, set up at creation with type-specific hash,
 *  compare, set and free callbacks. */
typedef struct Dataset {
    char name[DATASET_NAME_MAX_LEN + 1];/**< NUL-terminated name */
    enum DatasetTypes type;             /**< value type */
    uint32_t id;                        /**< monotonic id */
    bool from_yaml;                     /**< declared in suricata.yaml */
    bool hidden;                        /**< superseded during a live reload */
    bool remove_key;                    /**< strip value key from extra data on insert */
    THashTableContext *hash;            /**< backing thread-safe hash */
    char load[PATH_MAX];                /**< preload file */
    char save[PATH_MAX];                /**< persist-on-exit file */
    struct Dataset *next;               /**< next in the global list, or NULL */
} Dataset;

/** \brief Textual type name to ::DatasetTypes.
 *
 * Recognises the strings used in the `datasets` YAML section
 * and in the `type` argument of the `dataset` keyword
 * ("string", "md5", "sha256", "ipv4", "ipv6"); case-insensitive.
 *
 *  \return the enumerator, or DATASET_TYPE_NOTSET if no match. 
 */
enum DatasetTypes DatasetGetTypeFromString(const char *s);

/** \brief Link a freshly built set into the global list.
 *
 * Takes ownership of \p set on success; on failure the caller still
 * owns it and must clean up. Caller must hold the dataset lock.
 *
 *  \retval  0 ok
 *  \retval -1 NULL hash, or too large for the set memcap 
 */
int DatasetAppendSet(Dataset *set);

/** \brief Allocate a bare ::Dataset.
 *
 * Zeroes the struct and assigns a unique id. The result has
 * no type, no name, no hash, and is not in the global list;
 * caller fills the rest in.
 *
 *  \param name currently unused. 
 */
 Dataset *DatasetAlloc(const char *name);

 /** \brief Take the global dataset lock.
 *
 * Serialises access to the linked list of ::Dataset objects.
 * Any code walking that list, or calling a function whose doc
 * says "caller must hold the dataset lock", must do so inside
 * a Lock/Unlock pair. Plain mutex, not recursive: taking it twice
 * from the same thread deadlocks. Does not protect the contents of
 * individual sets; per-set sync is in the backing hash. 
 */
void DatasetLock(void);

/** \brief Release the global dataset lock.
 * One Unlock per successful Lock, from the same thread. */
void DatasetUnlock(void);

/** \brief Look up a set by name in the global list.
 * Linear scan; does not check the returned set's type.
 * Caller must hold the dataset lock. 
 */
Dataset *DatasetSearchByName(const char *name);

/** \brief Look up a set by name and type without creating it.
 * A name hit with a different type is treated as no match. Takes
 * and releases the dataset lock internally; caller must NOT
 * already hold it. 
 */
Dataset *DatasetFind(const char *name, enum DatasetTypes type);

/** \brief Return an existing set or fully build a new one.
 *
 * Standard entry point used by the rule parser for the `dataset` and
 * `datarep` keywords.
 *
 * Takes and releases the dataset lock internally; caller
 * must NOT already hold it.
 *
 *  \param name     NUL-terminated, at most DATASET_NAME_MAX_LEN bytes
 *  \param type     must not be DATASET_TYPE_NOTSET when the set is new
 *  \param save     persist path, or NULL/empty for none
 *  \param load     preload path, or NULL/empty for none
 *  \param memcap   0 for the configured default; ignored on hit
 *  \param hashsize 0 for the configured default; capped by
 *                  `datasets` YAML global limits; ignored on hit
 *  \retval non-NULL fully initialised, registered set
 *  \retval NULL     any error 
 */
Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize);

/** \brief Reserve a ::Dataset slot: return an existing set or
 *         allocate a skeleton for a new one.
 *
 * Name hit: pure lookup. Existing set returned via \p ret_set ;
 * \p save / \p load (if provided) are validated against the
 *  stored values and a mismatch is a hard error.
 *
 * Name miss: allocates via DatasetAlloc() and fills in name,
 * type, save, load. Caller finishes initialisation, and on any
 * failure of that follow-up work must free the returned set.
 *
 * Also fills \p memcap and \p hashsize with configured 
 * defaults when the pointed-to value is 0.
 *
 * Caller must hold the dataset lock.
 *
 *  \param[in]     type     may be DATASET_TYPE_NOTSET only for a
 *                          pure lookup (set expected to exist);
 *                          required otherwise
 *  \param[in,out] memcap   defaults filled if 0
 *  \param[in,out] hashsize defaults filled if 0
 *  \param[out]    ret_set  receives the set on create or hit;
 *                          untouched on error
 *  \retval -1 error
 *  \retval  0 new, uninitialised set allocated
 *  \retval  1 matching set already existed and is usable 
 */
int DatasetGetOrCreate(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t *memcap, uint32_t *hashsize, Dataset **ret_set);

 /** \brief Remove a value.
 * 
 * Dispatches on set->type. Per-set locking is internal, does
 * not touch the global list.
 *  \retval  1 found and removed
 *  \retval  0 found but currently busy (in use / held); left in
 *             place. Caller may retry.
 *  \retval -1 not found, OR NULL set, OR unknown type. Note: unlike
 *             the add family, "not present" is reported as -1, not 0;
 *             the three conditions are indistinguishable from the
 *             return code alone.
 *  \retval -2 data_len wrong for the set's type. Not from string worker.
 *  \note IPv6 worker requires exactly 16 bytes here (matches
 *        SCDatasetAddwRep, stricter than SCDatasetAdd). 
 */
int DatasetRemove(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \name Lookup operations
 *  Test membership, optionally retrieving the stored reputation.
 *  Dispatch on set->type. Per-set locking is internal.
 *  @{ */

 /** \brief Checks if the value present in the dataset.
 *  \retval  1 found
 *  \retval  0 not found (normal negative, not an error)
 *  \retval -1 NULL set, unknown type, OR data_len mismatch. String
 *             worker has no length check.
 *  \note IPv6 worker accepts 4 or 16 bytes; a 4-byte buffer matches
 *        stored entries whose trailing 12 bytes are zero. Matches
 *        SCDatasetAdd's permissive behaviour. 
 */
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \brief Look up a value and return the stored reputation.
 *  \param rep present for symmetry with SCDatasetAddwRep. Does NOT
 *             select which entry matches, but the string worker
 *             dereferences it; must not be NULL.
 *  \return on hit: .found true, .rep is the reputation stored with
 *          the entry (not the input rep). On miss, NULL set,
 *          unknown type, or data_len mismatch: { .found=false, .rep=0 };
 *          errors and misses are indistinguishable from the return
 *          value alone.
 *  \note IPv6 worker accepts 4 or 16 bytes. 
 */
DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep);
/** @} */

/** \brief Fill \p memcap and \p hashsize with default dataset limits.
 *
 * Honouring `datasets.defaults.*` YAML overrides. The two are
 * handled asymmetrically:
 *
 *  \param memcap   If the YAML key is absent, *memcap is left as-is;
 *                  caller must preinitialise it. If present but
 *                  unparseable, *memcap is set to 0 and a warning is
 *                  logged. The 0 is a sentinel meaning "no default
 *                  available".
 *  \param hashsize Always initialised to DATASETS_HASHSIZE_DEFAULT
 *                  before the YAML lookup. Parseable key replaces
 *                  the default; unparseable restores it and logs a
 *                  warning. Safe to pass uninitialised. 
 */
void DatasetGetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize);

/** \brief Parse an IPv4 or IPv6 address into Suricata's internal
 *         IPv6 storage form.
 *
 * Family is inferred from a ':' in \p line. IPv4 input
 * (or IPv6 in ::ffff:a.b.c.d form) is written with the four
 * IPv4 bytes in the low positions of \p in6 and the rest zero.
 * This is NOT a standard IPv4-mapped IPv6 address, it's Suricata's
 * internal layout, and matches what SCDatasetAdd's IPv4 and
 * permissive-IPv6 paths store.
 *  \param set  used only for the set name in the fatal-error
 *              message; not read or modified, type not validated.
 *  \param in6  populated on success, undefined on failure.
 *  \retval  0 parsed
 *  \retval -1 parse failed. Only observable outside init: during
 *             init, FatalErrorOnInit aborts the process and this
 *             function does not return. 
 */
int DatasetParseIpv6String(Dataset *set, const char *line, struct in6_addr *in6);

/** \name Serialized-form membership operations.
 *
 *  Add/lookup/remove given a textual value. Parse \p string per
 *  set->type and dispatch. Callers already holding the native
 *  binary form should prefer the binary variants.
 *
 *  \param string NUL-terminated, non-empty, and (for the string
 *                type) at most UINT16_MAX bytes. Both limits are
 *                enforced before parsing and reported as -1.
 *
 *  Parse contract per type:
 *    - STRING  strict base64
 *    - MD5     exactly 32 hex chars
 *    - SHA256  exactly 64 hex chars
 *    - IPV4    dotted-quad via inet_pton
 *    - IPV6    textual IPv6 OR IPv4 dotted-quad via
 *              DatasetParseIpv6String. An IPv4 spelling is accepted
 *              even for an IPv6 set and stored in the internal
 *              4-byte-in-low-position layout.
 *
 *  Shared return semantics:
 *    -2 always means "parse failed against set's type"
 *    -1 always includes API misuse (NULL set, empty or too-long
 *       string, unknown type); individual functions may add more.
 *    A valid parse never triggers a length-mismatch -2 from the
 *    worker; the parse layer only hands it a correctly-sized buffer.
 *
 *  \note During init, an IPv6 (or IPv4-via-IPv6) parse failure
 *        aborts the process rather than returning -2, inherited
 *        from DatasetParseIpv6String's use of FatalErrorOnInit.
 *  @{ */
 
/** \brief Parse and insert.
 *  \retval  1 inserted
 *  \retval  0 already present
 *  \retval -1 API error (see group intro), or hash insert failure
 *  \retval -2 parse failed 
 */
int DatasetAddSerialized(Dataset *set, const char *string);

/** \brief Parse and remove.
 *  \retval  1 found and removed
 *  \retval  0 found but busy; left in place, may retry
 *  \retval -1 API error OR not found (indistinguishable, matches
 *             DatasetRemove)
 *  \retval -2 parse failed 
 */
int DatasetRemoveSerialized(Dataset *set, const char *string);

/** \brief Parse and test membership.
 *  \retval  1 found
 *  \retval  0 not found (normal, not an error)
 *  \retval -1 API error
 *  \retval -2 parse failed 
 */
int DatasetLookupSerialized(Dataset *set, const char *string);

/** @} */

#endif // SURICATA_BINDGEN_H

#endif /* SURICATA_DATASETS_H */
