/* Copyright (C) 2017-2024 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "conf.h"
#include "datasets.h"
#include "datasets-string.h"
#include "datasets-ipv4.h"
#include "datasets-ipv6.h"
#include "datasets-md5.h"
#include "datasets-sha256.h"
#include "datasets-reputation.h"
#include "datasets-context-json.h"
#include "util-conf.h"
#include "util-mem.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-path.h"
#include "util-debug.h"
#include "util-validate.h"

SCMutex sets_lock = SCMUTEX_INITIALIZER;
static Dataset *sets = NULL;
static uint32_t set_ids = 0;

uint32_t dataset_max_one_hashsize = 65536;
uint32_t dataset_max_total_hashsize = 16777216;
uint32_t dataset_used_hashsize = 0;

int DatasetAddwRep(Dataset *set, const uint8_t *data, const uint32_t data_len, DataRepType *rep);
static void DatasetUpdateHashsize(const char *name, uint32_t hash_size);

static inline void DatasetUnlockData(THashData *d)
{
    (void) THashDecrUsecnt(d);
    THashDataUnlock(d);
}
static bool DatasetIsStatic(const char *save, const char *load);

enum DatasetTypes DatasetGetTypeFromString(const char *s)
{
    if (strcasecmp("md5", s) == 0)
        return DATASET_TYPE_MD5;
    if (strcasecmp("sha256", s) == 0)
        return DATASET_TYPE_SHA256;
    if (strcasecmp("string", s) == 0)
        return DATASET_TYPE_STRING;
    if (strcasecmp("ipv4", s) == 0)
        return DATASET_TYPE_IPV4;
    if (strcasecmp("ip", s) == 0)
        return DATASET_TYPE_IPV6;
    return DATASET_TYPE_NOTSET;
}

int DatasetAppendSet(Dataset *set)
{

    if (set->hash == NULL) {
        return -1;
    }

    if (SC_ATOMIC_GET(set->hash->memcap_reached)) {
        SCLogError("dataset too large for set memcap");
        return -1;
    }

    SCLogDebug(
            "set %p/%s type %u save %s load %s", set, set->name, set->type, set->save, set->load);

    set->next = sets;
    sets = set;

    /* hash size accounting */
    DatasetUpdateHashsize(set->name, set->hash->config.hash_size);
    return 0;
}

void DatasetLock(void)
{
    SCMutexLock(&sets_lock);
}

void DatasetUnlock(void)
{
    SCMutexUnlock(&sets_lock);
}

Dataset *DatasetAlloc(const char *name)
{
    Dataset *set = SCCalloc(1, sizeof(*set));
    if (set) {
        set->id = set_ids++;
    }
    return set;
}

Dataset *DatasetSearchByName(const char *name)
{
    Dataset *set = sets;
    while (set) {
        if (strcasecmp(name, set->name) == 0 && !set->hidden) {
            return set;
        }
        set = set->next;
    }
    return NULL;
}

static int DatasetLoadIPv4(Dataset *set)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    int retval = ParseDatasets(set, set->name, set->load, fopen_mode, DSIpv4);
    if (retval == -2) {
        FatalErrorOnInit("dataset %s could not be processed", set->name);
    } else if (retval == -1) {
        return -1;
    }

    THashConsolidateMemcap(set->hash);

    return 0;
}

int DatasetParseIpv6String(Dataset *set, const char *line, struct in6_addr *in6)
{
    /* Checking IPv6 case */
    char *got_colon = strchr(line, ':');
    if (got_colon) {
        uint32_t ip6addr[4];
        if (inet_pton(AF_INET6, line, in6) != 1) {
            FatalErrorOnInit("dataset data parse failed %s/%s: %s", set->name, set->load, line);
            return -1;
        }
        memcpy(&ip6addr, in6->s6_addr, sizeof(ip6addr));
        /* IPv4 in IPv6 notation needs transformation to internal Suricata storage */
        if (ip6addr[0] == 0 && ip6addr[1] == 0 && ip6addr[2] == 0xFFFF0000) {
            ip6addr[0] = ip6addr[3];
            ip6addr[2] = 0;
            ip6addr[3] = 0;
            memcpy(in6, ip6addr, sizeof(struct in6_addr));
        }
    } else {
        /* IPv4 case */
        struct in_addr in;
        if (inet_pton(AF_INET, line, &in) != 1) {
            FatalErrorOnInit("dataset data parse failed %s/%s: %s", set->name, set->load, line);
            return -1;
        }
        memset(in6, 0, sizeof(struct in6_addr));
        memcpy(in6, &in, sizeof(struct in_addr));
    }
    return 0;
}

static int DatasetLoadIPv6(Dataset *set)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    int retval = ParseDatasets(set, set->name, set->load, fopen_mode, DSIpv6);
    if (retval == -2) {
        FatalErrorOnInit("dataset %s could not be processed", set->name);
    } else if (retval == -1) {
        return -1;
    }

    THashConsolidateMemcap(set->hash);

    return 0;
}

static int DatasetLoadMd5(Dataset *set)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    int retval = ParseDatasets(set, set->name, set->load, fopen_mode, DSMd5);
    if (retval == -2) {
        FatalErrorOnInit("dataset %s could not be processed", set->name);
    } else if (retval == -1) {
        return -1;
    }

    THashConsolidateMemcap(set->hash);

    return 0;
}

static int DatasetLoadSha256(Dataset *set)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    int retval = ParseDatasets(set, set->name, set->load, fopen_mode, DSSha256);
    if (retval == -2) {
        FatalErrorOnInit("dataset %s could not be processed", set->name);
    } else if (retval == -1) {
        return -1;
    }

    THashConsolidateMemcap(set->hash);

    return 0;
}

static int DatasetLoadString(Dataset *set)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    int retval = ParseDatasets(set, set->name, set->load, fopen_mode, DSString);
    if (retval == -2) {
        FatalErrorOnInit("dataset %s could not be processed", set->name);
    } else if (retval == -1) {
        return -1;
    }

    THashConsolidateMemcap(set->hash);

    return 0;
}

extern bool g_system;

enum DatasetGetPathType {
    TYPE_STATE,
    TYPE_LOAD,
};

static void DatasetGetPath(
        const char *in_path, char *out_path, size_t out_size, enum DatasetGetPathType type)
{
    char path[PATH_MAX];
    struct stat st;

    if (PathIsAbsolute(in_path)) {
        strlcpy(path, in_path, sizeof(path));
        strlcpy(out_path, path, out_size);
        return;
    }

    const char *data_dir = ConfigGetDataDirectory();
    if (stat(data_dir, &st) != 0) {
        SCLogDebug("data-dir '%s': %s", data_dir, strerror(errno));
        return;
    }

    snprintf(path, sizeof(path), "%s/%s", data_dir, in_path); // TODO WINDOWS

    if (type == TYPE_LOAD) {
        if (stat(path, &st) != 0) {
            SCLogDebug("path %s: %s", path, strerror(errno));
            if (!g_system) {
                snprintf(path, sizeof(path), "%s", in_path);
            }
        }
    }
    strlcpy(out_path, path, out_size);
    SCLogDebug("in_path \'%s\' => \'%s\'", in_path, out_path);
}

/** \brief look for set by name without creating it */
Dataset *DatasetFind(const char *name, enum DatasetTypes type)
{
    DatasetLock();
    Dataset *set = DatasetSearchByName(name);
    if (set) {
        if (set->type != type) {
            DatasetUnlock();
            return NULL;
        }
    }
    DatasetUnlock();
    return set;
}

static bool DatasetCheckHashsize(const char *name, uint32_t hash_size)
{
    if (dataset_max_one_hashsize > 0 && hash_size > dataset_max_one_hashsize) {
        SCLogError("hashsize %u in dataset '%s' exceeds configured 'single-hashsize' limit (%u)",
                hash_size, name, dataset_max_one_hashsize);
        return false;
    }
    // we cannot underflow as we know from conf loading that
    // dataset_max_total_hashsize >= dataset_max_one_hashsize if dataset_max_total_hashsize > 0
    if (dataset_max_total_hashsize > 0 &&
            dataset_max_total_hashsize - hash_size < dataset_used_hashsize) {
        SCLogError("hashsize %u in dataset '%s' exceeds configured 'total-hashsizes' limit (%u, in "
                   "use %u)",
                hash_size, name, dataset_max_total_hashsize, dataset_used_hashsize);
        return false;
    }

    return true;
}

static void DatasetUpdateHashsize(const char *name, uint32_t hash_size)
{
    if (dataset_max_total_hashsize > 0) {
        dataset_used_hashsize += hash_size;
        SCLogDebug("set %s adding with hash_size %u", name, hash_size);
    }
}

/**
 * \return -1 on error
 * \return 0 on successful creation
 * \return 1 if the dataset already exists
 *
 * Calling function is responsible for locking via DatasetLock()
 */
int DatasetGetOrCreate(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t *memcap, uint32_t *hashsize, Dataset **ret_set)
{
    uint64_t default_memcap = 0;
    uint32_t default_hashsize = 0;
    if (strlen(name) > DATASET_NAME_MAX_LEN) {
        return -1;
    }

    Dataset *set = DatasetSearchByName(name);
    if (set) {
        if (type != DATASET_TYPE_NOTSET && set->type != type) {
            SCLogError("dataset %s already "
                       "exists and is of type %u",
                    set->name, set->type);
            return -1;
        }

        if ((save == NULL || strlen(save) == 0) &&
            (load == NULL || strlen(load) == 0)) {
            // OK, rule keyword doesn't have to set state/load,
            // even when yaml set has set it.
        } else {
            if ((save == NULL && strlen(set->save) > 0) ||
                    (save != NULL && strcmp(set->save, save) != 0)) {
                SCLogError("dataset %s save mismatch: %s != %s", set->name, set->save, save);
                DatasetUnlock();
                return -1;
            }
            if ((load == NULL && strlen(set->load) > 0) ||
                    (load != NULL && strcmp(set->load, load) != 0)) {
                SCLogError("dataset %s load mismatch: %s != %s", set->name, set->load, load);
                return -1;
            }
        }

        *ret_set = set;
        return 1;
    }

    if (type == DATASET_TYPE_NOTSET) {
        SCLogError("dataset %s not defined", name);
        goto out_err;
    }

    DatasetGetDefaultMemcap(&default_memcap, &default_hashsize);
    if (*hashsize == 0) {
        *hashsize = default_hashsize;
    }
    if (*memcap == 0) {
        *memcap = default_memcap;
    }

    if (!DatasetCheckHashsize(name, *hashsize)) {
        goto out_err;
    }

    set = DatasetAlloc(name);
    if (set == NULL) {
        goto out_err;
    }

    strlcpy(set->name, name, sizeof(set->name));
    set->type = type;
    if (save && strlen(save)) {
        strlcpy(set->save, save, sizeof(set->save));
        SCLogDebug("name %s save '%s'", name, set->save);
    }
    if (load && strlen(load)) {
        strlcpy(set->load, load, sizeof(set->load));
        SCLogDebug("set \'%s\' loading \'%s\' from \'%s\'", set->name, load, set->load);
    }

    *ret_set = set;
    return 0;
out_err:
    if (set) {
        SCFree(set);
    }
    return -1;
}

Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize)
{
    Dataset *set = NULL;

    DatasetLock();
    int ret = DatasetGetOrCreate(name, type, save, load, &memcap, &hashsize, &set);
    if (ret < 0) {
        SCLogError("dataset %s creation failed", name);
        DatasetUnlock();
        return NULL;
    }
    if (ret == 1) {
        SCLogDebug("dataset %s already exists", name);
        DatasetUnlock();
        return set;
    }

    char cnf_name[128];
    snprintf(cnf_name, sizeof(cnf_name), "datasets.%s.hash", name);
    switch (type) {
        case DATASET_TYPE_MD5:
            set->hash = THashInit(cnf_name, sizeof(Md5Type), Md5StrSet, Md5StrFree, Md5StrHash,
                    Md5StrCompare, NULL, NULL, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadMd5(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_STRING:
            set->hash = THashInit(cnf_name, sizeof(StringType), StringSet, StringFree, StringHash,
                    StringCompare, NULL, StringGetLength, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadString(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_SHA256:
            set->hash = THashInit(cnf_name, sizeof(Sha256Type), Sha256StrSet, Sha256StrFree,
                    Sha256StrHash, Sha256StrCompare, NULL, NULL, load != NULL ? 1 : 0, memcap,
                    hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadSha256(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV4:
            set->hash = THashInit(cnf_name, sizeof(IPv4Type), IPv4Set, IPv4Free, IPv4Hash,
                    IPv4Compare, NULL, NULL, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadIPv4(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV6:
            set->hash = THashInit(cnf_name, sizeof(IPv6Type), IPv6Set, IPv6Free, IPv6Hash,
                    IPv6Compare, NULL, NULL, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadIPv6(set) < 0)
                goto out_err;
            break;
    }

    if (DatasetAppendSet(set) < 0) {
        SCLogError("dataset %s append failed", name);
        goto out_err;
    }

    DatasetUnlock();
    return set;
out_err:
    if (set->hash) {
        THashShutdown(set->hash);
    }
    SCFree(set);
    DatasetUnlock();
    return NULL;
}

static bool DatasetIsStatic(const char *save, const char *load)
{
    /* A set is static if it does not have any dynamic properties like
     * save and/or state defined but has load defined.
     * */
    if ((load != NULL && strlen(load) > 0) &&
            (save == NULL || strlen(save) == 0)) {
        return true;
    }
    return false;
}

void DatasetReload(void)
{
    /* In order to reload the datasets, just mark the current sets as hidden
     * and clean them up later.
     * New datasets shall be created with the rule reload and do not require
     * any intervention.
     * */
    DatasetLock();
    Dataset *set = sets;
    while (set) {
        if (!DatasetIsStatic(set->save, set->load) || set->from_yaml) {
            SCLogDebug("Not a static set, skipping %s", set->name);
            set = set->next;
            continue;
        }
        set->hidden = true;
        if (dataset_max_total_hashsize > 0) {
            DEBUG_VALIDATE_BUG_ON(set->hash->config.hash_size > dataset_used_hashsize);
            dataset_used_hashsize -= set->hash->config.hash_size;
        }
        SCLogDebug("Set %s at %p hidden successfully", set->name, set);
        set = set->next;
    }
    DatasetUnlock();
}

void DatasetPostReloadCleanup(void)
{
    DatasetLock();
    SCLogDebug("Post Reload Cleanup starting.. Hidden sets will be removed");
    Dataset *cur = sets;
    Dataset *prev = NULL;
    while (cur) {
        Dataset *next = cur->next;
        if (!cur->hidden) {
            prev = cur;
            cur = next;
            continue;
        }
        // Delete the set in case it was hidden
        if (prev != NULL) {
            prev->next = next;
        } else {
            sets = next;
        }
        THashShutdown(cur->hash);
        SCFree(cur);
        cur = next;
    }
    DatasetUnlock();
}

/* Value reflects THASH_DEFAULT_HASHSIZE which is what the default was earlier,
 * despite 2048 commented out in the default yaml. */
#define DATASETS_HASHSIZE_DEFAULT 4096

void DatasetGetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize)
{
    const char *str = NULL;
    if (SCConfGet("datasets.defaults.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, memcap) < 0) {
            SCLogWarning("memcap value cannot be deduced: %s,"
                         " resetting to default",
                    str);
            *memcap = 0;
        }
    }

    *hashsize = (uint32_t)DATASETS_HASHSIZE_DEFAULT;
    if (SCConfGet("datasets.defaults.hashsize", &str) == 1) {
        if (ParseSizeStringU32(str, hashsize) < 0) {
            *hashsize = (uint32_t)DATASETS_HASHSIZE_DEFAULT;
            SCLogWarning("hashsize value cannot be deduced: %s,"
                         " resetting to default: %u",
                    str, *hashsize);
        }
    }
}

int DatasetsInit(void)
{
    SCLogDebug("datasets start");
    SCConfNode *datasets = SCConfGetNode("datasets");
    uint64_t default_memcap = 0;
    uint32_t default_hashsize = 0;
    DatasetGetDefaultMemcap(&default_memcap, &default_hashsize);
    if (datasets != NULL) {
        const char *str = NULL;
        if (SCConfGet("datasets.limits.total-hashsizes", &str) == 1) {
            if (ParseSizeStringU32(str, &dataset_max_total_hashsize) < 0) {
                FatalError("failed to parse datasets.limits.total-hashsizes value: %s", str);
            }
        }
        if (SCConfGet("datasets.limits.single-hashsize", &str) == 1) {
            if (ParseSizeStringU32(str, &dataset_max_one_hashsize) < 0) {
                FatalError("failed to parse datasets.limits.single-hashsize value: %s", str);
            }
        }
        if (dataset_max_total_hashsize > 0 &&
                dataset_max_total_hashsize < dataset_max_one_hashsize) {
            FatalError("total-hashsizes (%u) cannot be smaller than single-hashsize (%u)",
                    dataset_max_total_hashsize, dataset_max_one_hashsize);
        }
        if (dataset_max_total_hashsize > 0 && dataset_max_one_hashsize == 0) {
            // the total limit also applies for single limit
            dataset_max_one_hashsize = dataset_max_total_hashsize;
        }

        int list_pos = 0;
        SCConfNode *iter = NULL;
        TAILQ_FOREACH(iter, &datasets->head, next) {
            if (iter->name == NULL) {
                list_pos++;
                continue;
            }

            char save[PATH_MAX] = "";
            char load[PATH_MAX] = "";
            uint64_t memcap = 0;
            uint32_t hashsize = 0;

            const char *set_name = iter->name;
            if (strlen(set_name) > DATASET_NAME_MAX_LEN) {
                FatalErrorOnInit(
                        "set name '%s' too long, max %d chars", set_name, DATASET_NAME_MAX_LEN);
                continue;
            }

            SCConfNode *set_type = SCConfNodeLookupChild(iter, "type");
            if (set_type == NULL) {
                list_pos++;
                continue;
            }

            SCConfNode *set_save = SCConfNodeLookupChild(iter, "state");
            if (set_save) {
                DatasetGetPath(set_save->val, save, sizeof(save), TYPE_STATE);
                strlcpy(load, save, sizeof(load));
            } else {
                SCConfNode *set_load = SCConfNodeLookupChild(iter, "load");
                if (set_load) {
                    DatasetGetPath(set_load->val, load, sizeof(load), TYPE_LOAD);
                }
            }

            SCConfNode *set_memcap = SCConfNodeLookupChild(iter, "memcap");
            if (set_memcap) {
                if (ParseSizeStringU64(set_memcap->val, &memcap) < 0) {
                    SCLogWarning("memcap value cannot be"
                                 " deduced: %s, resetting to default",
                            set_memcap->val);
                    memcap = 0;
                }
            }
            SCConfNode *set_hashsize = SCConfNodeLookupChild(iter, "hashsize");
            if (set_hashsize) {
                if (ParseSizeStringU32(set_hashsize->val, &hashsize) < 0) {
                    SCLogWarning("hashsize value cannot be"
                                 " deduced: %s, resetting to default",
                            set_hashsize->val);
                    hashsize = 0;
                }
            }
            char conf_str[1024];
            snprintf(conf_str, sizeof(conf_str), "datasets.%d.%s", list_pos, set_name);

            SCLogDebug("set %s type %s. Conf %s", set_name, set_type->val, conf_str);

            if (strcmp(set_type->val, "md5") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_MD5, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL) {
                    FatalErrorOnInit("failed to setup dataset for %s", set_name);
                    continue;
                }
                SCLogDebug("dataset %s: id %u type %s", set_name, dset->id, set_type->val);
                dset->from_yaml = true;

            } else if (strcmp(set_type->val, "sha256") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_SHA256, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL) {
                    FatalErrorOnInit("failed to setup dataset for %s", set_name);
                    continue;
                }
                SCLogDebug("dataset %s: id %u type %s", set_name, dset->id, set_type->val);
                dset->from_yaml = true;

            } else if (strcmp(set_type->val, "string") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_STRING, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL) {
                    FatalErrorOnInit("failed to setup dataset for %s", set_name);
                    continue;
                }
                SCLogDebug("dataset %s: id %u type %s", set_name, dset->id, set_type->val);
                dset->from_yaml = true;

            } else if (strcmp(set_type->val, "ipv4") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_IPV4, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL) {
                    FatalErrorOnInit("failed to setup dataset for %s", set_name);
                    continue;
                }
                SCLogDebug("dataset %s: id %u type %s", set_name, dset->id, set_type->val);
                dset->from_yaml = true;

            } else if (strcmp(set_type->val, "ip") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_IPV6, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL) {
                    FatalErrorOnInit("failed to setup dataset for %s", set_name);
                    continue;
                }
                SCLogDebug("dataset %s: id %u type %s", set_name, dset->id, set_type->val);
                dset->from_yaml = true;
            }

            list_pos++;
        }
    }
    SCLogDebug("datasets done: %p", datasets);
    return 0;
}

void DatasetsDestroy(void)
{
    DatasetLock();
    SCLogDebug("destroying datasets: %p", sets);
    Dataset *set = sets;
    while (set) {
        SCLogDebug("destroying set %s", set->name);
        Dataset *next = set->next;
        THashShutdown(set->hash);
        SCFree(set);
        set = next;
    }
    sets = NULL;
    DatasetUnlock();
    SCLogDebug("destroying datasets done: %p", sets);
}

static int SaveCallback(void *ctx, const uint8_t *data, const uint32_t data_len)
{
    FILE *fp = ctx;
    //PrintRawDataFp(fp, data, data_len);
    if (fp) {
        return (int)fwrite(data, data_len, 1, fp);
    }
    return 0;
}

static int Md5AsAscii(const void *s, char *out, size_t out_size)
{
    const Md5Type *md5 = s;
    char str[256];
    PrintHexString(str, sizeof(str), (uint8_t *)md5->md5, sizeof(md5->md5));
    strlcat(out, str, out_size);
    strlcat(out, "\n", out_size);
    return (int)strlen(out);
}

static int Sha256AsAscii(const void *s, char *out, size_t out_size)
{
    const Sha256Type *sha = s;
    char str[256];
    PrintHexString(str, sizeof(str), (uint8_t *)sha->sha256, sizeof(sha->sha256));
    strlcat(out, str, out_size);
    strlcat(out, "\n", out_size);
    return (int)strlen(out);
}

static int IPv4AsAscii(const void *s, char *out, size_t out_size)
{
    const IPv4Type *ip4 = s;
    char str[256];
    PrintInet(AF_INET, ip4->ipv4, str, sizeof(str));
    strlcat(out, str, out_size);
    strlcat(out, "\n", out_size);
    return (int)strlen(out);
}

static int IPv6AsAscii(const void *s, char *out, size_t out_size)
{
    const IPv6Type *ip6 = s;
    char str[256];
    bool is_ipv4 = true;
    for (int i = 4; i <= 15; i++) {
        if (ip6->ipv6[i] != 0) {
            is_ipv4 = false;
            break;
        }
    }
    if (is_ipv4) {
        PrintInet(AF_INET, ip6->ipv6, str, sizeof(str));
    } else {
        PrintInet(AF_INET6, ip6->ipv6, str, sizeof(str));
    }
    strlcat(out, str, out_size);
    strlcat(out, "\n", out_size);
    return (int)strlen(out);
}

void DatasetsSave(void)
{
    DatasetLock();
    SCLogDebug("saving datasets: %p", sets);
    Dataset *set = sets;
    while (set) {
        if (strlen(set->save) == 0)
            goto next;

        FILE *fp = fopen(set->save, "w");
        if (fp == NULL)
            goto next;

        SCLogDebug("dumping %s to %s", set->name, set->save);

        switch (set->type) {
            case DATASET_TYPE_STRING:
                THashWalk(set->hash, StringAsBase64, SaveCallback, fp);
                break;
            case DATASET_TYPE_MD5:
                THashWalk(set->hash, Md5AsAscii, SaveCallback, fp);
                break;
            case DATASET_TYPE_SHA256:
                THashWalk(set->hash, Sha256AsAscii, SaveCallback, fp);
                break;
            case DATASET_TYPE_IPV4:
                THashWalk(set->hash, IPv4AsAscii, SaveCallback, fp);
                break;
            case DATASET_TYPE_IPV6:
                THashWalk(set->hash, IPv6AsAscii, SaveCallback, fp);
                break;
        }

        fclose(fp);

    next:
        set = set->next;
    }
    DatasetUnlock();
}

static int DatasetLookupString(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .rep = 0 };
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        DatasetUnlockData(rdata);
        return 1;
    }
    return 0;
}

static DataRepResultType DatasetLookupStringwRep(Dataset *set,
        const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };

    if (set == NULL)
        return rrep;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .rep = *rep };
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        StringType *found = rdata->data;
        rrep.found = true;
        rrep.rep = found->rep;
        DatasetUnlockData(rdata);
        return rrep;
    }
    return rrep;
}

static int DatasetLookupIPv4(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 4)
        return -1;

    IPv4Type lookup = { .rep = 0 };
    memcpy(lookup.ipv4, data, 4);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        DatasetUnlockData(rdata);
        return 1;
    }
    return 0;
}

static DataRepResultType DatasetLookupIPv4wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };

    if (set == NULL)
        return rrep;

    if (data_len != 4)
        return rrep;

    IPv4Type lookup = { .rep = 0 };
    memcpy(lookup.ipv4, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv4Type *found = rdata->data;
        rrep.found = true;
        rrep.rep = found->rep;
        DatasetUnlockData(rdata);
        return rrep;
    }
    return rrep;
}

static int DatasetLookupIPv6(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16 && data_len != 4)
        return -1;

    IPv6Type lookup = { .rep = 0 };
    memcpy(lookup.ipv6, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        DatasetUnlockData(rdata);
        return 1;
    }
    return 0;
}

static DataRepResultType DatasetLookupIPv6wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };

    if (set == NULL)
        return rrep;

    if (data_len != 16 && data_len != 4)
        return rrep;

    IPv6Type lookup = { .rep = 0 };
    memcpy(lookup.ipv6, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv6Type *found = rdata->data;
        rrep.found = true;
        rrep.rep = found->rep;
        DatasetUnlockData(rdata);
        return rrep;
    }
    return rrep;
}

static int DatasetLookupMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -1;

    Md5Type lookup = { .rep = 0 };
    memcpy(lookup.md5, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        DatasetUnlockData(rdata);
        return 1;
    }
    return 0;
}

static DataRepResultType DatasetLookupMd5wRep(Dataset *set,
        const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };

    if (set == NULL)
        return rrep;

    if (data_len != 16)
        return rrep;

    Md5Type lookup = { .rep = 0 };
    memcpy(lookup.md5, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Md5Type *found = rdata->data;
        rrep.found = true;
        rrep.rep = found->rep;
        DatasetUnlockData(rdata);
        return rrep;
    }
    return rrep;
}

static int DatasetLookupSha256(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 32)
        return -1;

    Sha256Type lookup = { .rep = 0 };
    memcpy(lookup.sha256, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        DatasetUnlockData(rdata);
        return 1;
    }
    return 0;
}

static DataRepResultType DatasetLookupSha256wRep(Dataset *set,
        const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };

    if (set == NULL)
        return rrep;

    if (data_len != 32)
        return rrep;

    Sha256Type lookup = { .rep = 0 };
    memcpy(lookup.sha256, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Sha256Type *found = rdata->data;
        rrep.found = true;
        rrep.rep = found->rep;
        DatasetUnlockData(rdata);
        return rrep;
    }
    return rrep;
}

/**
 *  \brief see if \a data is part of the set
 *  \param set dataset
 *  \param data data to look up
 *  \param data_len length in bytes of \a data
 *  \retval -1 error
 *  \retval 0 not found
 *  \retval 1 found
 */
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetLookupString(set, data, data_len);
        case DATASET_TYPE_MD5:
            return DatasetLookupMd5(set, data, data_len);
        case DATASET_TYPE_SHA256:
            return DatasetLookupSha256(set, data, data_len);
        case DATASET_TYPE_IPV4:
            return DatasetLookupIPv4(set, data, data_len);
        case DATASET_TYPE_IPV6:
            return DatasetLookupIPv6(set, data, data_len);
    }
    return -1;
}

DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = 0 };
    if (set == NULL)
        return rrep;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetLookupStringwRep(set, data, data_len, rep);
        case DATASET_TYPE_MD5:
            return DatasetLookupMd5wRep(set, data, data_len, rep);
        case DATASET_TYPE_SHA256:
            return DatasetLookupSha256wRep(set, data, data_len, rep);
        case DATASET_TYPE_IPV4:
            return DatasetLookupIPv4wRep(set, data, data_len, rep);
        case DATASET_TYPE_IPV6:
            return DatasetLookupIPv6wRep(set, data, data_len, rep);
    }
    return rrep;
}

/**
 *  \retval 1 data was added to the hash
 *  \retval 0 data was not added to the hash as it is already there
 *  \retval -1 failed to add data to the hash
 */
static int DatasetAddString(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .rep = 0 };
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

/**
 *  \retval 1 data was added to the hash
 *  \retval 0 data was not added to the hash as it is already there
 *  \retval -1 failed to add data to the hash
 */
static int DatasetAddStringwRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len,
        .rep = *rep };
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddIPv4(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL) {
        return -1;
    }

    if (data_len < 4) {
        return -2;
    }

    IPv4Type lookup = { .rep = 0 };
    memcpy(lookup.ipv4, data, 4);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddIPv6(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL) {
        return -1;
    }

    if (data_len != 16 && data_len != 4) {
        return -2;
    }

    IPv6Type lookup = { .rep = 0 };
    memcpy(lookup.ipv6, data, data_len);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddIPv4wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    if (data_len < 4)
        return -2;

    IPv4Type lookup = { .rep = *rep };
    memcpy(lookup.ipv4, data, 4);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddIPv6wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    IPv6Type lookup = { .rep = *rep };
    memcpy(lookup.ipv6, data, 16);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    Md5Type lookup = { .rep = 0 };
    memcpy(lookup.md5, data, 16);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddMd5wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    Md5Type lookup = { .rep = *rep };
    memcpy(lookup.md5, data, 16);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddSha256wRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    if (data_len != 32)
        return -2;

    Sha256Type lookup = { .rep = *rep };
    memcpy(lookup.sha256, data, 32);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatasetAddSha256(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 32)
        return -2;

    Sha256Type lookup = { .rep = 0 };
    memcpy(lookup.sha256, data, 32);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

int SCDatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetAddString(set, data, data_len);
        case DATASET_TYPE_MD5:
            return DatasetAddMd5(set, data, data_len);
        case DATASET_TYPE_SHA256:
            return DatasetAddSha256(set, data, data_len);
        case DATASET_TYPE_IPV4:
            return DatasetAddIPv4(set, data, data_len);
        case DATASET_TYPE_IPV6:
            return DatasetAddIPv6(set, data, data_len);
    }
    return -1;
}

int SCDatasetAddwRep(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataRepType *rep)
{
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetAddStringwRep(set, data, data_len, rep);
        case DATASET_TYPE_MD5:
            return DatasetAddMd5wRep(set, data, data_len, rep);
        case DATASET_TYPE_SHA256:
            return DatasetAddSha256wRep(set, data, data_len, rep);
        case DATASET_TYPE_IPV4:
            return DatasetAddIPv4wRep(set, data, data_len, rep);
        case DATASET_TYPE_IPV6:
            return DatasetAddIPv6wRep(set, data, data_len, rep);
    }
    return -1;
}

typedef int (*DatasetOpFunc)(Dataset *set, const uint8_t *data, const uint32_t data_len);

static int DatasetOpSerialized(Dataset *set, const char *string, DatasetOpFunc DatasetOpString,
        DatasetOpFunc DatasetOpMd5, DatasetOpFunc DatasetOpSha256, DatasetOpFunc DatasetOpIPv4,
        DatasetOpFunc DatasetOpIPv6)
{
    if (set == NULL)
        return -1;
    if (strlen(string) == 0)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING: {
            if (strlen(string) > UINT16_MAX) {
                // size check before cast and stack allocation
                return -1;
            }
            uint32_t decoded_size = SCBase64DecodeBufferSize((uint32_t)strlen(string));
            uint8_t decoded[decoded_size];
            uint32_t num_decoded = SCBase64Decode(
                    (const uint8_t *)string, strlen(string), SCBase64ModeStrict, decoded);
            if (num_decoded == 0) {
                return -2;
            }

            return DatasetOpString(set, decoded, num_decoded);
        }
        case DATASET_TYPE_MD5: {
            if (strlen(string) != 32)
                return -2;
            uint8_t hash[16];
            if (HexToRaw((const uint8_t *)string, 32, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetOpMd5(set, hash, 16);
        }
        case DATASET_TYPE_SHA256: {
            if (strlen(string) != 64)
                return -2;
            uint8_t hash[32];
            if (HexToRaw((const uint8_t *)string, 64, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetOpSha256(set, hash, 32);
        }
        case DATASET_TYPE_IPV4: {
            struct in_addr in;
            if (inet_pton(AF_INET, string, &in) != 1)
                return -2;
            return DatasetOpIPv4(set, (uint8_t *)&in.s_addr, 4);
        }
        case DATASET_TYPE_IPV6: {
            struct in6_addr in6;
            if (DatasetParseIpv6String(set, string, &in6) != 0) {
                SCLogError("Dataset failed to import %s as IPv6", string);
                return -2;
            }
            return DatasetOpIPv6(set, (uint8_t *)&in6.s6_addr, 16);
        }
    }
    return -1;
}

/** \brief add serialized data to set
 *  \retval int 1 added
 *  \retval int 0 already in hash
 *  \retval int -1 API error (not added)
 *  \retval int -2 DATA error
 */
int DatasetAddSerialized(Dataset *set, const char *string)
{
    return DatasetOpSerialized(set, string, DatasetAddString, DatasetAddMd5, DatasetAddSha256,
            DatasetAddIPv4, DatasetAddIPv6);
}

/** \brief add serialized data to set
 *  \retval int 1 added
 *  \retval int 0 already in hash
 *  \retval int -1 API error (not added)
 *  \retval int -2 DATA error
 */
int DatasetLookupSerialized(Dataset *set, const char *string)
{
    return DatasetOpSerialized(set, string, DatasetLookupString, DatasetLookupMd5,
            DatasetLookupSha256, DatasetLookupIPv4, DatasetLookupIPv6);
}

/**
 *  \retval 1 data was removed from the hash
 *  \retval 0 data not removed (busy)
 *  \retval -1 data not found
 */
static int DatasetRemoveString(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .rep = 0 };
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveIPv4(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 4)
        return -2;

    IPv4Type lookup = { .rep = 0 };
    memcpy(lookup.ipv4, data, 4);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveIPv6(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    IPv6Type lookup = { .rep = 0 };
    memcpy(lookup.ipv6, data, 16);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    Md5Type lookup = { .rep = 0 };
    memcpy(lookup.md5, data, 16);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveSha256(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 32)
        return -2;

    Sha256Type lookup = { .rep = 0 };
    memcpy(lookup.sha256, data, 32);
    return THashRemoveFromHash(set->hash, &lookup);
}

/** \brief remove serialized data from set
 *  \retval int 1 removed
 *  \retval int 0 found but busy (not removed)
 *  \retval int -1 API error (not removed)
 *  \retval int -2 DATA error */
int DatasetRemoveSerialized(Dataset *set, const char *string)
{
    return DatasetOpSerialized(set, string, DatasetRemoveString, DatasetRemoveMd5,
            DatasetRemoveSha256, DatasetRemoveIPv4, DatasetRemoveIPv6);
}

int DatasetRemove(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetRemoveString(set, data, data_len);
        case DATASET_TYPE_MD5:
            return DatasetRemoveMd5(set, data, data_len);
        case DATASET_TYPE_SHA256:
            return DatasetRemoveSha256(set, data, data_len);
        case DATASET_TYPE_IPV4:
            return DatasetRemoveIPv4(set, data, data_len);
        case DATASET_TYPE_IPV6:
            return DatasetRemoveIPv6(set, data, data_len);
    }
    return -1;
}
