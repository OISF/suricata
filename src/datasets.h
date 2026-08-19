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
 * \author Victor Julien <victor@inliniac.net>
 *
 * \brief Public API for Suricata's dataset and datarep subsystem.
 *
 * A dataset is a named, in-memory set of values (string, md5, sha256,
 * ipv4 or ipv6) that rules can match against via the \c dataset and
 * \c datarep keywords. Sets can be preloaded from disk at startup,
 * persisted on exit, and reloaded live at runtime.
 *
 * This header declares the ::Dataset type, the ::DatasetTypes and
 * ::DatasetFormats enumerations, and the lifecycle, lookup and
 * mutation entry points. The implementation lives in datasets.c.
 */

#ifndef SURICATA_DATASETS_H
#define SURICATA_DATASETS_H

// forward declaration to make things opaque to bindgen
/**
 * \brief Reputation value associated with a dataset entry.
 *
 * Opaque to bindgen; Callers pass and receive \c DataRepType
 * values through the \c *wRep family of functions
 * and via the \c DataRepResultType struct.
 */
typedef uint16_t DataRepType;

/**
 * \brief Forward declaration of the \c Dataset type.
 */
typedef struct Dataset Dataset;

/** \name Public add operations
 * \brief Insert a value into a dataset, with or without a reputation.
 *
 * These are the public, plugin-facing entry points for adding a
 * value to a set. Each dispatches on \c set->type to a per-type
 * worker implemented as a \c static helper in \c datasets.c.
 *
 * If the value is already present the existing entry is reused and
 * the call reports \c 0 rather than storing a duplicate; no refcount
 * is exposed at the API level.
 *
 * Shared parameters:
 *   \param set      Target dataset. Must be a fully initialized set.
 *   \param data     Value to insert, in the set's native binary form.
 *   \param data_len Length of \p data in bytes. For the fixed-size
 *                   types the worker validates this.
 * These functions do not touch the global set list; per-set hash
 * locking is handled internally.
 *
 * @{
 */
/**
 * \brief Insert a value into a dataset.
 *
 * \retval  1 value added as a new entry.
 * \retval  0 value already present.
 * \retval -1 error (NULL set, hash insert failure, or unknown type).
 * \retval -2 \p data_len does not match the expected size for the
 *            set's type. Not returned by the string worker.
 *
 * \note The IPv6 worker accepts either 4 or 16 bytes; a 4-byte
 *       buffer is treated as an IPv4-mapped IPv6 address. The
 *       rep-carrying counterpart \c SCDatasetAddwRep is stricter
 *       and requires 16.
 *
 * \sa SCDatasetAddwRep
 */
int SCDatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len);

/**
 * \brief Insert a value together with a reputation payload.
 *
 * \param rep Reputation to associate with a newly inserted entry.
 *            Dereferenced unconditionally; must not be \c NULL.
 *
 * \retval  1 value inserted with \p rep attached.
 * \retval  0 value already present; the stored entry (and its
 *            existing rep) is left untouched and \p rep is discarded.
 * \retval -1 error (NULL set, hash insert failure, or unknown type).
 * \retval -2 \p data_len does not match the expected size for the
 *            set's type. Not returned by the string worker.
 *
 * \note On collision the incoming \p rep is \b not merged into the
 *       stored entry: the first writer wins.
 * \note Unlike \c SCDatasetAdd, the IPv6 path here requires exactly
 *       16 bytes; a 4-byte (IPv4-mapped) buffer yields \c -2.
 *
 * \sa SCDatasetAdd
 */
int SCDatasetAddwRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep);

/** @} */

#ifndef SURICATA_BINDGEN_H
#include "util-thash.h"
#include "rust.h"
#include "datasets-reputation.h"


/** \name Lifecycle
 *  Initialization, teardown, persistence and live reload.
 *  @{
 */

/**
 * \brief Initialize the dataset subsystem from configuration.
 *
 * Reads the \c datasets section of suricata.yaml, creates each
 * declared set and loads its associated file. Called once during
 * startup, after privileges have been dropped.
 * In case of a fatal configuration error, \c FatalError() and
 * exits with error.
 *
 * \retval 0 on success.
 */
int DatasetsInit(void);

 /** \brief Free every registered dataset and release all resources. */
void DatasetsDestroy(void);

/** \brief Persist every dataset that has a configured save path. */
void DatasetsSave(void);

/**
 * \brief First phase of a live reload.
 *
 * Marks the current sets as hidden and stages replacements so that
 * running threads can finish their in-flight lookups against the old
 * versions. Must be paired with DatasetPostReloadCleanup().
 */
void DatasetReload(void);

/** \brief Second phase of a live reload; frees the hidden old sets. */
void DatasetPostReloadCleanup(void);

/** @} */


/**
 * \brief On-disk serialization format for a dataset's load/save file.
 */
typedef enum {
    DATASET_FORMAT_CSV = 0, /**< Legacy CSV format (default). */
    DATASET_FORMAT_JSON,    /**< File contains one single JSON object. */
    DATASET_FORMAT_NDJSON,  /**< Newline-delimited JSON, one entry per line. */
} DatasetFormats;

/**
 * \brief Type of value a dataset stores.
 *
 * ::DATASET_TYPE_NOTSET (0) is a sentinel used to mark an
 * uninitialized set and is not a valid runtime type.
 */
enum DatasetTypes {
#define DATASET_TYPE_NOTSET 0   /** Sentinel: type not yet assigned. */
    DATASET_TYPE_STRING = 1,    /**< Arbitrary byte strings. */
    DATASET_TYPE_MD5,           /**< 16-byte MD5 digests. */
    DATASET_TYPE_SHA256,        /**< 32-byte SHA256 digests. */
    DATASET_TYPE_IPV4,          /**< 4-byte IPv4 addresses. */
    DATASET_TYPE_IPV6,          /**< 16-byte IPv6 addresses. */
};

/** \brief Maximum length of a dataset name, excluding the terminating NUL. */
#define DATASET_NAME_MAX_LEN 63

/**
 * \brief In-memory representation of a single dataset.
 * 
 * Sets are linked together in a global singly-linked list protected
 * by an internal mutex; use DatasetLock() / DatasetUnlock() when
 * traversing that list directly. The actual value storage is
 * delegated to the ::THashTableContext pointed to by \c hash which
 * is initialized with type-specific hash, compare, set and free
 * callbacks at creation time.
 */
typedef struct Dataset {
    char name[DATASET_NAME_MAX_LEN + 1];/**< NUL-terminated set name. */
    enum DatasetTypes type;             /**< Value type stored in this set. */
    uint32_t id;                        /**< Monotonic id. */
    bool from_yaml;                     /**< True if declared in suricata.yaml. */
    bool hidden;                        /**< True while superseded during a live reload. */
    bool remove_key;                    /**< Strip value key from extra data on insert. */
    THashTableContext *hash;            /**< Backing thread-safe hash table. */

    char load[PATH_MAX];                /**< File to preload values from at startup. */
    char save[PATH_MAX];                /**< File to persist values to on exit. */

    struct Dataset *next;               /**< Next set in the global list, or NULL. */
} Dataset;

/**
 * \brief Convert a textual type name to a ::DatasetTypes value.
 * 
 * Recognizes the strings used in the \c datasets section of
 * suricata.yaml and in the \c type argument of the \c dataset rule
 * keyword: \c "string", \c "md5", \c "sha256", \c "ipv4", \c "ipv6".
 * The comparison is case-insensitive.
 * 
 * \param s NUL-terminated type name.
 * \return The matching ::DatasetTypes enumerator, or
        ::DATASET_TYPE_NOTSET if \p s does not match any known type.
 */
enum DatasetTypes DatasetGetTypeFromString(const char *s);

/**
 * \brief Link a freshly built set into the global set list.
 *
 * Takes ownership of the \p set : on success the pointer is now
 * reachable via the internal list and must not be freed by the caller.
 * On failure the caller retains ownership and is responsible for cleanup.
 *
 * The caller must hold the dataset lock via DatasetLock().
 * 
 * \param set Fully initialized set to register. Must have a unique name.
 * \retval  0 on success.
 * \retval -1 if the set has a NULL hash or it's too large for set memcap.
 */
int DatasetAppendSet(Dataset *set);

/**
 * \brief Allocate and minimally initialize a new ::Dataset.
 *
 * Zeros the structure and assigns a fresh unique \c id. The returned
 * set has no type, no name, no backing hash table, and is not linked
 * into the global list; the caller is expected to populate the
 * remaining fields.
 *
 * \param name Currently unused.
 *
 * \retval non-NULL newly allocated set.
 * \retval NULL     allocation failure.
 *
 * \sa DatasetGetOrCreate()
 */
Dataset *DatasetAlloc(const char *name);


/**
 * \brief Acquire the global dataset lock.
 *
 * Serializes access to the internal linked list of ::Dataset objects.
 * Any code that walks that list, or that calls a function whose
 * documentation says "caller must hold the dataset lock" must be inside
 * a DatasetLock() / DatasetUnlock() pair.
 *
 * The lock is a plain mutex and is \b not recursive: calling
 * DatasetLock() twice from the same thread will deadlock. It also
 * does not protect the contents of an individual set, per-set
 * synchronization is handled by the underlying ::THashTableContext.
 *
 * \sa DatasetUnlock()
 */
void DatasetLock(void);

/**
 * \brief Release the global dataset lock.
 *
 * Must be called exactly once for each successful DatasetLock() on
 * the same thread, and only by the thread that acquired it.
 *
 * \sa DatasetLock()
 */
void DatasetUnlock(void);

/**
 * \brief Look up a set by name in the global list.
 *
 * Performs a linear scan of the set list and does \b not check the
 * type of the returned set.
 *
 * The caller must hold the dataset lock via DatasetLock().
 *
 * \param name NUL-terminated set name to search for.
 *
 * \retval non-NULL pointer to the matching set.
 * \retval NULL if no set with that name exists.
 */
Dataset *DatasetSearchByName(const char *name);

/**
 * \brief Look up a set by name and type without creating it.
 *
 * Acquires and releases the dataset lock internally, so the caller
 * must \b not already hold it. A set whose name matches but whose
 * type differs from \p type is treated as no match.
 *
 * \param name NUL-terminated set name to search for.
 * \param type Required value type.
 *
 * \retval non-NULL pointer to the matching set.
 * \retval NULL if no set with that name and type exists.
 */
Dataset *DatasetFind(const char *name, enum DatasetTypes type);

/**
 * \brief Return an existing set or fully construct a new one.
 *
 * This is the standard entry point used by the rule parser when it
 * encounters a \c dataset or \c datarep keyword. It wraps
 * DatasetGetOrCreate() with the follow-up work that the latter
 * intentionally omits:
 *   -# reserve or allocate the ::Dataset via DatasetGetOrCreate();
 *   -# on a fresh allocation, initialize the backing
 *      ::THashTableContext with the callbacks and element size
 *      appropriate to \p type;
 *   -# preload values from \p load, if any, via the matching
 *      \c DatasetLoadXxx() helper;
 *   -# link the completed set into the global list with
 *      DatasetAppendSet().
 *
 * On any failure during the fresh-allocation path the partially
 * built set is torn down before returning. On a hit the existing set
 * is returned unchanged; \p memcap and \p hashsize are ignored in
 * that case.
 *
 * Acquires and releases the dataset lock internally, so the caller
 * must \b not already hold it.
 *
 * \param name     NUL-terminated set name, at most
 *                 #DATASET_NAME_MAX_LEN bytes.
 * \param type     Value type; must not be ::DATASET_TYPE_NOTSET when
 *                 the set does not yet exist.
 * \param save     Path to persist the set to on exit, or NULL /
 *                 empty for no persistence.
 * \param load     Path to preload values from, or NULL / empty to
 *                 start empty.
 * \param memcap   Memory cap in bytes; pass 0 for the configured
 *                 default. Ignored on a hit.
 * \param hashsize Hash-table size; pass 0 for the configured
 *                 default. Capped by the global limits from the
 *                 \c datasets section of suricata.yaml. Ignored on a
 *                 hit.
 *
 * \retval non-NULL pointer to a fully initialized, registered set.
 * \retval NULL on any error.
 *
 * \sa DatasetGetOrCreate(), DatasetFind()
 */
Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize);

/**
 * \brief Reserve a ::Dataset slot: return an existing set or allocate a
 *        skeleton for a new one.
 *
 * On a name hit this behaves as a pure lookup: the existing set is
 * returned through \p ret_set, and \p save / \p load (if provided) are
 * validated against the stored values, a mismatch is a hard error.
 *
 * On a name miss a new ::Dataset is allocated via DatasetAlloc() and
 * its \c name, \c type, \c save and \c load fields are populated, but
 * the set is \b not fully constructed: its \c hash pointer is left
 * NULL, no values are loaded from disk, and it is not linked into the
 * global set list. The caller is responsible for finishing
 * initialization. On any failure of that follow-up work the caller must
 * free the returned set.
 *
 * Also fills in \p memcap and \p hashsize with configured defaults
 * when the pointed-to value is 0.
 *
 * The caller must hold the dataset lock via DatasetLock().
 *
 * \param[in]     name     NUL-terminated set name; at most
 *                         #DATASET_NAME_MAX_LEN bytes.
 * \param[in]     type     Value type. May be ::DATASET_TYPE_NOTSET
 *                         only when the set is expected to already
 *                         exist (pure lookup); required otherwise.
 * \param[in]     save     Save-file path or NULL / empty.
 * \param[in]     load     Load-file path or NULL / empty.
 * \param[in,out] memcap   Memory cap; filled with default if 0.
 * \param[in,out] hashsize Hash-table size; filled with default if 0.
 * \param[out]    ret_set  Receives the set pointer on both creation
 *                         and hit; untouched on error.
 *
 * \retval -1 on error.
 * \retval  0 on successful allocation of a new, uninitialized set.
 * \retval  1 if a matching set already existed and is fully usable.
 *
 * \sa DatasetGet() for the wrapper that also initializes the hash
 *     table, loads the file and registers the set.
 */
int DatasetGetOrCreate(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t *memcap, uint32_t *hashsize, Dataset **ret_set);

/**
 * \brief Delete a value from a dataset.
 *
 * Dispatches on \c set->type to the appropriate type-specific
 * worker implemented as a \c static helper in \c datasets.c
 *
 * \param set      Target dataset. Must be a fully initialized set as
 *                 returned by \c DatasetGet().
 * \param data     Value to be removed, in the set's native binary form.
 * \param data_len Length of \p data in bytes. Validated for the
 *                 fixed-size types; see the \c -2 retval below.
 *
 * \retval  1 value found and removed.
 * \retval  0 value found but currently busy (in-use / held) and
 *            left in place. The caller may retry.
 * \retval -1 value not found, \b or \p set is \c NULL, \b or the
 *            set has an unknown type. These three conditions are
 *            \b not distinguishable from the return code alone,
 *            unlike the add family, a legitimate "not present"
 *            result is reported via \c -1, not \c 0.
 * \retval -2 \p data_len does not match the expected size for the
 *            set's type. Not returned by the string worker.
 *
 * \note The IPv6 worker requires exactly 16 bytes. This matches
 *       \c SCDatasetAddwRep but is stricter than \c SCDatasetAdd,
 *       whose IPv6 worker also accepts a 4-byte buffer.
 *
 * This function does not touch the global set list; per-set hash
 * locking is handled internally.
 *
 * \sa SCDatasetAdd, DatasetLookup
 */
int DatasetRemove(Dataset *set, const uint8_t *data, const uint32_t data_len);

/** \name Public lookup operations
 * \brief Test whether a value is present in a dataset, optionally
 *        retrieving its stored reputation.
 *
 * These are dispatchers on \c set->type to a per-type worker implemented
 * as a \c static helper in \c datasets.c.
 *
 * Shared parameters:
 *   \param set      Target dataset. Must be a fully initialized set.
 *   \param data     Value to look up, in the set's native binary form.
 *   \param data_len Length of \p data in bytes. Validated for the
 *                   fixed-size types.
 *
 * These functions do not touch the global set list; per-set hash
 * locking is handled internally.
 * @{
 */

/**
 * \brief Test whether a value is present in a dataset.
 *
 * \retval  1 value found.
 * \retval  0 value not found. This is a normal negative result, not
 *            an error.
 * \retval -1 \p set is \c NULL, the set has an unknown type, \b or
 *            \p data_len does not match the set's type. The string
 *            worker has no length check.
 *
 * \note The IPv6 worker accepts either 4 or 16 bytes; a 4-byte
 *       buffer matches stored entries whose trailing 12 bytes are
 *       zero. Matches \c SCDatasetAdd's permissive behavior.
 *
 * \sa DatasetLookupwRep
 */
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);

/**
 * \brief Look up a value and retrieve its stored reputation.
 *
 * \param rep Present for symmetry with \c SCDatasetAddwRep. Does not
 *            select which entry is matched, but the string worker
 *            dereferences it; must not be \c NULL.
 *
 * \return On a hit: \c .found is \c true and \c .rep is the
 *         reputation \b stored with the entry, not the input \p rep.
 *         On a miss, \c NULL \p set, unknown \c set->type, or
 *         \p data_len mismatch: <tt>{ .found = false, .rep = 0 }</tt>;
 *         errors and misses are \b not distinguishable from the
 *         return value alone.
 *
 * \note The IPv6 worker accepts 4 or 16 bytes.
 *
 * \sa DatasetLookup, SCDatasetAddwRep
 */
DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep);
/** @} */

/**
 * \brief Populate \p memcap and \p hashsize with the engine's
 *        default dataset limits, honoring YAML overrides under
 *        \c datasets.defaults.
 *
 * Reads \c datasets.defaults.memcap and \c datasets.defaults.hashsize
 * from the running configuration and writes them through the
 * out-parameters. The two are handled asymmetrically:
 *
 * \param memcap   Out. If the YAML key is absent, \p *memcap is left
 *                 untouched, the caller must preinitialize it to a
 *                 sensible starting value. If the key is present but
 *                 unparseable, \p *memcap is set to \c 0 and a
 *                 warning is logged.
 * \param hashsize Out. Always initialized to
 *                 \c DATASETS_HASHSIZE_DEFAULT before the YAML
 *                 lookup; a parseable key replaces the default,
 *                 an unparseable one restores it (and logs a
 *                 warning). Safe to pass uninitialized.
 *
 * \note The \c 0 written to \p *memcap on parse failure is a
 *       sentinel, not a valid limit; callers should treat it as
 *       "no default available" and fall back to their own value.
 */
void DatasetGetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize);

/**
 * \brief Parse a textual IP address into Suricata's internal IPv6
 *        storage form.
 *
 * Accepts either an IPv4 dotted-quad or an IPv6 textual address;
 * the family is inferred from the presence of a \c ':' in \p line.
 * The result is written to \p in6 in the layout the IPv4 and IPv6
 * dataset workers expect: for an IPv4 input (or for an IPv6 input
 * in \c ::ffff:a.b.c.d form) the four IPv4 bytes occupy the low
 * positions of \p in6 with the remainder zeroed. This is \b not a
 * standard IPv4-mapped IPv6 address: it is Suricata's internal
 * representation, and matches what \c SCDatasetAdd's IPv4 and
 * permissive-IPv6 paths store.
 *
 * \param set  Dataset being loaded. Consulted only to name the set
 *             in the fatal-error message on parse failure; the
 *             function does not read or modify its contents and
 *             does not validate that \c set->type is an IP type.
 * \param line NUL-terminated textual address.
 * \param in6  Out. Populated on success; contents undefined on
 *             failure.
 *
 * \retval  0 parse succeeded.
 * \retval -1 parse failed. Only observable outside init: during
 *            init, the underlying \c FatalErrorOnInit aborts the
 *            process and this function does not return to the
 *            caller.
 */
int DatasetParseIpv6String(Dataset *set, const char *line, struct in6_addr *in6);


/** \name Serialized-form membership operations
 * \brief Add, look up or remove a value given in its textual
 *        ("serialized") form.
 *
 * String-input counterparts to \c SCDatasetAdd, \c DatasetLookup and
 * \c DatasetRemove. Each parses \p string according to \c set->type
 * and dispatches to the corresponding per-type worker. Callers that
 * already hold the value in native binary form should prefer the
 * binary variants and skip the parse step.
 *
 * Shared parameters:
 *   \param set    Target dataset. Must be a fully initialized set
 *                 as returned by \c DatasetGet().
 *   \param string NUL-terminated textual value. Must be non-empty
 *                 and, for the string type, no longer than
 *                 \c UINT16_MAX bytes; both limits are enforced
 *                 before parsing and reported as \c -1.
 *
 * Parse contract per type:
 *   - \c DATASET_TYPE_STRING  strict base64.
 *   - \c DATASET_TYPE_MD5     exactly 32 hex characters.
 *   - \c DATASET_TYPE_SHA256  exactly 64 hex characters.
 *   - \c DATASET_TYPE_IPV4    dotted-quad, via \c inet_pton.
 *   - \c DATASET_TYPE_IPV6    textual IPv6 \b or IPv4 dotted-quad,
 *                             via \c DatasetParseIpv6String. An
 *                             IPv4 spelling is accepted even for an
 *                             IPv6 set and is stored in Suricata's
 *                             4-byte-in-low-position layout.
 *
 * Shared return code semantics:
 *   \c -2 always means the parse failed against the set's type.
 *   \c -1 always includes API misuse (\c NULL set, empty or too-long
 *   string, unknown \c set->type); individual functions document any
 *   additional \c -1 cases below. A parse of a valid input never
 *   triggers a length-mismatch \c -2 from the underlying worker,
 *   the parse layer only ever hands the worker a correctly-sized
 *   buffer.
 *
 * These functions do not touch the global set list; per-set hash
 * locking is handled internally.
 *
 * \note During init, a parse failure on an IPv6 (or IPv4-via-IPv6)
 *       input aborts the process rather than returning \c -2 ,
 *       inherited from \c DatasetParseIpv6String's use of
 *       \c FatalErrorOnInit.
 *
 * \sa SCDatasetAdd, DatasetLookup, DatasetRemove,
 *     DatasetParseIpv6String
 *
 * @{
 */

 /**
 * \brief Parse \p string and insert the resulting value into the set.
 *
 * \retval  1 value inserted as a new entry.
 * \retval  0 value already present; no duplicate stored.
 * \retval -1 API error (see group intro), or the underlying hash
 *            layer failed to insert.
 * \retval -2 \p string could not be parsed as \c set->type.
 */
int DatasetAddSerialized(Dataset *set, const char *string);

/**
 * \brief Parse \p string and remove the resulting value from the set.
 *
 * \retval  1 value found and removed.
 * \retval  0 value found but currently busy; left in place. May be
 *            retried.
 * \retval -1 API error (see group intro) \b or value not found;
 *            these two conditions are not distinguishable from the
 *            return code. Matches \c DatasetRemove.
 * \retval -2 \p string could not be parsed as \c set->type.
 */

int DatasetRemoveSerialized(Dataset *set, const char *string);

/**
 * \brief Parse \p string and test whether the value is present.
 *
 * \retval  1 value found.
 * \retval  0 value not found. Normal negative result, not an error.
 * \retval -1 API error (see group intro).
 * \retval -2 \p string could not be parsed as \c set->type.
 */
int DatasetLookupSerialized(Dataset *set, const char *string);

/** @} */

#endif // SURICATA_BINDGEN_H

#endif /* SURICATA_DATASETS_H */
