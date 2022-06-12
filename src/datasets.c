/* Copyright (C) 2017-2020 Open Information Security Foundation
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
#include "conf.h"
#include "datasets.h"
#include "datasets-string.h"
#include "datasets-md5.h"
#include "datasets-sha256.h"
#include "datasets-reputation.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-base64.h"    // decode base64
#include "util-byte.h"
#include "util-misc.h"

SCMutex sets_lock = SCMUTEX_INITIALIZER;
static Dataset *sets = NULL;
static uint32_t set_ids = 0;

static int DatasetAddwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        DataRepType *rep);

static inline void DatasetUnlockData(THashData *d)
{
    (void) THashDecrUsecnt(d);
    THashDataUnlock(d);
}
static bool DatasetIsStatic(const char *save, const char *load);
static void GetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize);

enum DatasetTypes DatasetGetTypeFromString(const char *s)
{
    if (strcasecmp("md5", s) == 0)
        return DATASET_TYPE_MD5;
    if (strcasecmp("sha256", s) == 0)
        return DATASET_TYPE_SHA256;
    if (strcasecmp("string", s) == 0)
        return DATASET_TYPE_STRING;
    return DATASET_TYPE_NOTSET;
}

static Dataset *DatasetAlloc(const char *name)
{
    Dataset *set = SCCalloc(1, sizeof(*set));
    if (set) {
        set->id = set_ids++;
    }
    return set;
}

static Dataset *DatasetSearchByName(const char *name)
{
    Dataset *set = sets;
    while (set) {
        if (strcasecmp(name, set->name) == 0 && set->hidden == false) {
            return set;
        }
        set = set->next;
    }
    return NULL;
}

static int HexToRaw(const uint8_t *in, size_t ins, uint8_t *out, size_t outs)
{
    if (ins < 2)
        return -1;
    if (ins % 2 != 0)
        return -1;
    if (outs != ins / 2)
        return -1;

    uint8_t hash[outs];
    memset(hash, 0, outs);
    size_t i, x;
    for (x = 0, i = 0; i < ins; i+=2, x++) {
        char buf[3] = { 0, 0, 0 };
        buf[0] = in[i];
        buf[1] = in[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            hash[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_HASH, "hash byte out of range %ld", value);
            return -1;
        }
    }

    memcpy(out, hash, outs);
    return 0;
}

static int ParseRepLine(const char *in, size_t ins, DataRepType *rep_out)
{
    SCLogDebug("in '%s'", in);
    char raw[ins + 1];
    memcpy(raw, in, ins);
    raw[ins] = '\0';
    char *line = raw;

    char *ptrs[1] = {NULL};
    int idx = 0;

    size_t i = 0;
    while (i < ins + 1) {
        if (line[i] == ',' || line[i] == '\n' || line[i] == '\0') {
            line[i] = '\0';
            SCLogDebug("line '%s'", line);

            ptrs[idx] = line;
            idx++;

            if (idx == 1)
                break;
        } else {
            i++;
        }
    }

    if (idx != 1) {
        SCLogDebug("idx %d", idx);
        return -1;
    }

    uint16_t v = 0;
    int r = StringParseU16RangeCheck(&v, 10, strlen(ptrs[0]), ptrs[0], 0, USHRT_MAX);
    if (r != (int)strlen(ptrs[0])) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE,
                "'%s' is not a valid reputation value (0-65535)", ptrs[0]);
        return -1;
    }
    SCLogDebug("v %"PRIu16" raw %s", v, ptrs[0]);

    rep_out->value = v;
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

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError(SC_ERR_DATASET, "fopen '%s' failed: %s",
                set->load, strerror(errno));
        return -1;
    }

    uint32_t cnt = 0;
    char line[1024];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        /* straight black/white list */
        if (strlen(line) == 33) {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("line: '%s'", line);

            uint8_t hash[16];
            if (HexToRaw((const uint8_t *)line, 32, hash, sizeof(hash)) < 0)
                FatalError(SC_ERR_FATAL, "bad hash for dataset %s/%s",
                        set->name, set->load);

            if (DatasetAdd(set, (const uint8_t *)hash, 16) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);
            cnt++;

        /* list with rep data */
        } else if (strlen(line) > 33 && line[32] == ',') {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("MD5 with REP line: '%s'", line);

            uint8_t hash[16];
            if (HexToRaw((const uint8_t *)line, 32, hash, sizeof(hash)) < 0)
                FatalError(SC_ERR_FATAL, "bad hash for dataset %s/%s",
                        set->name, set->load);

            DataRepType rep = { .value = 0};
            if (ParseRepLine(line+33, strlen(line)-33, &rep) < 0)
                FatalError(SC_ERR_FATAL, "bad rep for dataset %s/%s",
                        set->name, set->load);

            SCLogDebug("rep v:%u", rep.value);
            if (DatasetAddwRep(set, hash, 16, &rep) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);

            cnt++;
        }
        else {
            FatalError(SC_ERR_FATAL, "MD5 bad line len %u: '%s'",
                    (uint32_t)strlen(line), line);
        }
    }
    THashConsolidateMemcap(set->hash);

    fclose(fp);
    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
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

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError(SC_ERR_DATASET, "fopen '%s' failed: %s",
                set->load, strerror(errno));
        return -1;
    }

    uint32_t cnt = 0;
    char line[1024];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        /* straight black/white list */
        if (strlen(line) == 65) {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("line: '%s'", line);

            uint8_t hash[32];
            if (HexToRaw((const uint8_t *)line, 64, hash, sizeof(hash)) < 0)
                FatalError(SC_ERR_FATAL, "bad hash for dataset %s/%s",
                        set->name, set->load);

            if (DatasetAdd(set, (const uint8_t *)hash, (uint32_t)32) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);
            cnt++;

            /* list with rep data */
        } else if (strlen(line) > 65 && line[64] == ',') {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("SHA-256 with REP line: '%s'", line);

            uint8_t hash[32];
            if (HexToRaw((const uint8_t *)line, 64, hash, sizeof(hash)) < 0)
                FatalError(SC_ERR_FATAL, "bad hash for dataset %s/%s",
                        set->name, set->load);

            DataRepType rep = { .value = 0 };
            if (ParseRepLine(line+65, strlen(line)-65, &rep) < 0)
                FatalError(SC_ERR_FATAL, "bad rep for dataset %s/%s",
                        set->name, set->load);

            SCLogDebug("rep %u", rep.value);

            if (DatasetAddwRep(set, hash, 32, &rep) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);
            cnt++;
        }
    }
    THashConsolidateMemcap(set->hash);

    fclose(fp);
    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
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

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError(SC_ERR_DATASET, "fopen '%s' failed: %s",
                set->load, strerror(errno));
        return -1;
    }

    uint32_t cnt = 0;
    char line[1024];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (strlen(line) <= 1)
            continue;

        char *r = strchr(line, ',');
        if (r == NULL) {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("line: '%s'", line);

            // coverity[alloc_strlen : FALSE]
            uint8_t decoded[strlen(line)];
            uint32_t consumed = 0, num_decoded = 0;
            Base64Ecode code = DecodeBase64(decoded, strlen(line), (const uint8_t *)line,
                    strlen(line), &consumed, &num_decoded, BASE64_MODE_STRICT);
            if (code == BASE64_ECODE_ERR)
                FatalError(SC_ERR_FATAL, "bad base64 encoding %s/%s",
                        set->name, set->load);

            if (DatasetAdd(set, (const uint8_t *)decoded, num_decoded) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);
            cnt++;
        } else {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("line: '%s'", line);

            *r = '\0';

            // coverity[alloc_strlen : FALSE]
            uint8_t decoded[strlen(line)];
            uint32_t consumed = 0, num_decoded = 0;
            Base64Ecode code = DecodeBase64(decoded, strlen(line), (const uint8_t *)line,
                    strlen(line), &consumed, &num_decoded, BASE64_MODE_STRICT);
            if (code == BASE64_ECODE_ERR)
                FatalError(SC_ERR_FATAL, "bad base64 encoding %s/%s",
                        set->name, set->load);

            r++;
            SCLogDebug("r '%s'", r);

            DataRepType rep = { .value = 0 };
            if (ParseRepLine(r, strlen(r), &rep) < 0)
                FatalError(SC_ERR_FATAL, "die: bad rep");
            SCLogDebug("rep %u", rep.value);

            if (DatasetAddwRep(set, (const uint8_t *)decoded, num_decoded, &rep) < 0)
                FatalError(SC_ERR_FATAL, "dataset data add failed %s/%s",
                        set->name, set->load);
            cnt++;

            SCLogDebug("line with rep %s, %s", line, r);
        }
    }
    THashConsolidateMemcap(set->hash);

    fclose(fp);
    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

extern bool g_system;

enum DatasetGetPathType {
    TYPE_STATE,
    TYPE_LOAD,
};

static void DatasetGetPath(const char *in_path,
        char *out_path, size_t out_size, enum DatasetGetPathType type)
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
    SCMutexLock(&sets_lock);
    Dataset *set = DatasetSearchByName(name);
    if (set) {
        if (set->type != type) {
            SCMutexUnlock(&sets_lock);
            return NULL;
        }
    }
    SCMutexUnlock(&sets_lock);
    return set;
}

Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize)
{
    uint64_t default_memcap = 0;
    uint32_t default_hashsize = 0;
    if (strlen(name) > DATASET_NAME_MAX_LEN) {
        return NULL;
    }

    SCMutexLock(&sets_lock);
    Dataset *set = DatasetSearchByName(name);
    if (set) {
        if (type != DATASET_TYPE_NOTSET && set->type != type) {
            SCLogError(SC_ERR_DATASET, "dataset %s already "
                    "exists and is of type %u",
                set->name, set->type);
            SCMutexUnlock(&sets_lock);
            return NULL;
        }

        if ((save == NULL || strlen(save) == 0) &&
            (load == NULL || strlen(load) == 0)) {
            // OK, rule keyword doesn't have to set state/load,
            // even when yaml set has set it.
        } else {
            if ((save == NULL && strlen(set->save) > 0) ||
                    (save != NULL && strcmp(set->save, save) != 0)) {
                SCLogError(SC_ERR_DATASET, "dataset %s save mismatch: %s != %s",
                        set->name, set->save, save);
                SCMutexUnlock(&sets_lock);
                return NULL;
            }
            if ((load == NULL && strlen(set->load) > 0) ||
                    (load != NULL && strcmp(set->load, load) != 0)) {
                SCLogError(SC_ERR_DATASET, "dataset %s load mismatch: %s != %s",
                        set->name, set->load, load);
                SCMutexUnlock(&sets_lock);
                return NULL;
            }
        }

        SCMutexUnlock(&sets_lock);
        return set;
    } else {
        if (type == DATASET_TYPE_NOTSET) {
            SCLogError(SC_ERR_DATASET, "dataset %s not defined", name);
            goto out_err;
        }
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

    char cnf_name[128];
    snprintf(cnf_name, sizeof(cnf_name), "datasets.%s.hash", name);

    GetDefaultMemcap(&default_memcap, &default_hashsize);
    switch (type) {
        case DATASET_TYPE_MD5:
            set->hash = THashInit(cnf_name, sizeof(Md5Type), Md5StrSet, Md5StrFree, Md5StrHash,
                    Md5StrCompare, load != NULL ? 1 : 0, memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadMd5(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_STRING:
            set->hash = THashInit(cnf_name, sizeof(StringType), StringSet, StringFree, StringHash,
                    StringCompare, load != NULL ? 1 : 0, memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadString(set) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_SHA256:
            set->hash = THashInit(cnf_name, sizeof(Sha256Type), Sha256StrSet, Sha256StrFree,
                    Sha256StrHash, Sha256StrCompare, load != NULL ? 1 : 0,
                    memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatasetLoadSha256(set) < 0)
                goto out_err;
            break;
    }

    SCLogDebug("set %p/%s type %u save %s load %s",
            set, set->name, set->type, set->save, set->load);

    set->next = sets;
    sets = set;

    SCMutexUnlock(&sets_lock);
    return set;
out_err:
    if (set) {
        if (set->hash) {
            THashShutdown(set->hash);
        }
        SCFree(set);
    }
    SCMutexUnlock(&sets_lock);
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
    SCMutexLock(&sets_lock);
    Dataset *set = sets;
    while (set) {
        if (!DatasetIsStatic(set->save, set->load) || set->from_yaml == true) {
            SCLogDebug("Not a static set, skipping %s", set->name);
            set = set->next;
            continue;
        }
        set->hidden = true;
        SCLogDebug("Set %s at %p hidden successfully", set->name, set);
        set = set->next;
    }
    SCMutexUnlock(&sets_lock);
}

void DatasetPostReloadCleanup(void)
{
    SCLogDebug("Post Reload Cleanup starting.. Hidden sets will be removed");
    SCMutexLock(&sets_lock);
    Dataset *cur = sets;
    Dataset *prev = NULL;
    while (cur) {
        Dataset *next = cur->next;
        if (cur->hidden == false) {
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
    SCMutexUnlock(&sets_lock);
}

static void GetDefaultMemcap(uint64_t *memcap, uint32_t *hashsize)
{
    const char *str = NULL;
    if (ConfGet("datasets.defaults.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, memcap) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "memcap value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            *memcap = 0;
        }
    }
    if (ConfGet("datasets.defaults.hashsize", &str) == 1) {
        if (ParseSizeStringU32(str, hashsize) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                    "hashsize value cannot be deduced: %s,"
                    " resetting to default",
                    str);
            *hashsize = 0;
        }
    }
}

int DatasetsInit(void)
{
    SCLogDebug("datasets start");
    int n = 0;
    ConfNode *datasets = ConfGetNode("datasets");
    uint64_t default_memcap = 0;
    uint32_t default_hashsize = 0;
    GetDefaultMemcap(&default_memcap, &default_hashsize);
    if (datasets != NULL) {
        int list_pos = 0;
        ConfNode *iter = NULL;
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
                FatalError(SC_ERR_CONF_NAME_TOO_LONG, "set name '%s' too long, max %d chars",
                        set_name, DATASET_NAME_MAX_LEN);
            }

            ConfNode *set_type =
                ConfNodeLookupChild(iter, "type");
            if (set_type == NULL) {
                list_pos++;
                continue;
            }

            ConfNode *set_save =
                ConfNodeLookupChild(iter, "state");
            if (set_save) {
                DatasetGetPath(set_save->val, save, sizeof(save), TYPE_STATE);
                strlcpy(load, save, sizeof(load));
            } else {
                ConfNode *set_load =
                    ConfNodeLookupChild(iter, "load");
                if (set_load) {
                    DatasetGetPath(set_load->val, load, sizeof(load), TYPE_LOAD);
                }
            }

            ConfNode *set_memcap = ConfNodeLookupChild(iter, "memcap");
            if (set_memcap) {
                if (ParseSizeStringU64(set_memcap->val, &memcap) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE,
                            "memcap value cannot be"
                            " deduced: %s, resetting to default",
                            set_memcap->val);
                    memcap = 0;
                }
            }
            ConfNode *set_hashsize = ConfNodeLookupChild(iter, "hashsize");
            if (set_hashsize) {
                if (ParseSizeStringU32(set_hashsize->val, &hashsize) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE,
                            "hashsize value cannot be"
                            " deduced: %s, resetting to default",
                            set_hashsize->val);
                    hashsize = 0;
                }
            }
            char conf_str[1024];
            snprintf(conf_str, sizeof(conf_str), "datasets.%d.%s", list_pos, set_name);

            SCLogDebug("(%d) set %s type %s. Conf %s", n, set_name, set_type->val, conf_str);

            if (strcmp(set_type->val, "md5") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_MD5, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL)
                    FatalError(SC_ERR_FATAL, "failed to setup dataset for %s", set_name);
                SCLogDebug("dataset %s: id %d type %s", set_name, n, set_type->val);
                dset->from_yaml = true;
                n++;

            } else if (strcmp(set_type->val, "sha256") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_SHA256, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL)
                    FatalError(SC_ERR_FATAL, "failed to setup dataset for %s", set_name);
                SCLogDebug("dataset %s: id %d type %s", set_name, n, set_type->val);
                dset->from_yaml = true;
                n++;

            } else if (strcmp(set_type->val, "string") == 0) {
                Dataset *dset = DatasetGet(set_name, DATASET_TYPE_STRING, save, load,
                        memcap > 0 ? memcap : default_memcap,
                        hashsize > 0 ? hashsize : default_hashsize);
                if (dset == NULL)
                    FatalError(SC_ERR_FATAL, "failed to setup dataset for %s", set_name);
                SCLogDebug("dataset %s: id %d type %s", set_name, n, set_type->val);
                dset->from_yaml = true;
                n++;
            }

            list_pos++;
        }
    }
    SCLogDebug("datasets done: %p", datasets);
    return 0;
}

void DatasetsDestroy(void)
{
    SCLogDebug("destroying datasets: %p", sets);
    SCMutexLock(&sets_lock);
    Dataset *set = sets;
    while (set) {
        SCLogDebug("destroying set %s", set->name);
        Dataset *next = set->next;
        THashShutdown(set->hash);
        SCFree(set);
        set = next;
    }
    sets = NULL;
    SCMutexUnlock(&sets_lock);
    SCLogDebug("destroying datasets done: %p", sets);
}

static int SaveCallback(void *ctx, const uint8_t *data, const uint32_t data_len)
{
    FILE *fp = ctx;
    //PrintRawDataFp(fp, data, data_len);
    if (fp) {
        return fwrite(data, data_len, 1, fp);
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
    return strlen(out);
}

static int Sha256AsAscii(const void *s, char *out, size_t out_size)
{
    const Sha256Type *sha = s;
    char str[256];
    PrintHexString(str, sizeof(str), (uint8_t *)sha->sha256, sizeof(sha->sha256));
    strlcat(out, str, out_size);
    strlcat(out, "\n", out_size);
    return strlen(out);
}

void DatasetsSave(void)
{
    SCLogDebug("saving datasets: %p", sets);
    SCMutexLock(&sets_lock);
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
        }

        fclose(fp);

    next:
        set = set->next;
    }
    SCMutexUnlock(&sets_lock);
}

static int DatasetLookupString(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .rep.value = 0 };
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
    DataRepResultType rrep = { .found = false, .rep = { .value = 0 }};

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

static int DatasetLookupMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -1;

    Md5Type lookup = { .rep.value = 0 };
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
    DataRepResultType rrep = { .found = false, .rep = { .value = 0 }};

    if (set == NULL)
        return rrep;

    if (data_len != 16)
        return rrep;

    Md5Type lookup = { .rep.value = 0};
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

    Sha256Type lookup = { .rep.value = 0 };
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
    DataRepResultType rrep = { .found = false, .rep = { .value = 0 }};

    if (set == NULL)
        return rrep;

    if (data_len != 32)
        return rrep;

    Sha256Type lookup = { .rep.value = 0 };
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
    }
    return -1;
}

DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep)
{
    DataRepResultType rrep = { .found = false, .rep = { .value = 0 }};
    if (set == NULL)
        return rrep;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatasetLookupStringwRep(set, data, data_len, rep);
        case DATASET_TYPE_MD5:
            return DatasetLookupMd5wRep(set, data, data_len, rep);
        case DATASET_TYPE_SHA256:
            return DatasetLookupSha256wRep(set, data, data_len, rep);
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

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len,
        .rep.value = 0 };
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

static int DatasetAddMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    Md5Type lookup = { .rep.value = 0 };
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

    Sha256Type lookup = { .rep.value = 0 };
    memcpy(lookup.sha256, data, 32);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatasetUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

int DatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len)
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
    }
    return -1;
}

static int DatasetAddwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        DataRepType *rep)
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
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING: {
            // coverity[alloc_strlen : FALSE]
            uint8_t decoded[strlen(string)];
            uint32_t consumed = 0, num_decoded = 0;
            Base64Ecode code = DecodeBase64(decoded, strlen(string), (const uint8_t *)string,
                    strlen(string), &consumed, &num_decoded, BASE64_MODE_STRICT);
            if (code == BASE64_ECODE_ERR) {
                return -2;
            }

            return DatasetAddString(set, decoded, num_decoded);
        }
        case DATASET_TYPE_MD5: {
            if (strlen(string) != 32)
                return -2;
            uint8_t hash[16];
            if (HexToRaw((const uint8_t *)string, 32, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetAddMd5(set, hash, 16);
        }
        case DATASET_TYPE_SHA256: {
            if (strlen(string) != 64)
                return -2;
            uint8_t hash[32];
            if (HexToRaw((const uint8_t *)string, 64, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetAddSha256(set, hash, 32);
        }
    }
    return -1;
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

    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len,
        .rep.value = 0 };
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveMd5(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 16)
        return -2;

    Md5Type lookup = { .rep.value = 0 };
    memcpy(lookup.md5, data, 16);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatasetRemoveSha256(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    if (set == NULL)
        return -1;

    if (data_len != 32)
        return -2;

    Sha256Type lookup = { .rep.value = 0 };
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
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING: {
            // coverity[alloc_strlen : FALSE]
            uint8_t decoded[strlen(string)];
            uint32_t consumed = 0, num_decoded = 0;
            Base64Ecode code = DecodeBase64(decoded, strlen(string), (const uint8_t *)string,
                    strlen(string), &consumed, &num_decoded, BASE64_MODE_STRICT);
            if (code == BASE64_ECODE_ERR) {
                return -2;
            }

            return DatasetRemoveString(set, decoded, num_decoded);
        }
        case DATASET_TYPE_MD5: {
            if (strlen(string) != 32)
                return -2;
            uint8_t hash[16];
            if (HexToRaw((const uint8_t *)string, 32, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetRemoveMd5(set, hash, 16);
        }
        case DATASET_TYPE_SHA256: {
            if (strlen(string) != 64)
                return -2;
            uint8_t hash[32];
            if (HexToRaw((const uint8_t *)string, 64, hash, sizeof(hash)) < 0)
                return -2;
            return DatasetRemoveSha256(set, hash, 32);
        }
    }
    return -1;
}
