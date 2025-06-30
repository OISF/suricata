/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "datasets.h"
#include "datasets-context-json.h"
#include "datasets-ipv4.h"
#include "datasets-ipv6.h"
#include "datasets-md5.h"
#include "datasets-sha256.h"
#include "datasets-string.h"
#include "util-byte.h"
#include "util-ip.h"
#include "util-debug.h"

static int DatajsonAdd(
        Dataset *set, const uint8_t *data, const uint32_t data_len, DataJsonType *json);

static inline void DatajsonUnlockData(THashData *d)
{
    (void)THashDecrUsecnt(d);
    THashDataUnlock(d);
}

void DatajsonUnlockElt(DataJsonResultType *r)
{
    if (r->hashdata) {
        DatajsonUnlockData(r->hashdata);
    }
}

int DatajsonCopyJson(DataJsonType *dst, DataJsonType *src)
{
    dst->len = src->len;
    dst->value = SCMalloc(dst->len + 1);
    if (dst->value == NULL)
        return -1;
    memcpy(dst->value, src->value, dst->len);
    dst->value[dst->len] = '\0'; // Ensure null-termination
    return 0;
}

/* return true if number is a float or an integer */
static bool IsFloat(const char *in, size_t ins)
{
    char *endptr;
    float val = strtof(in, &endptr);
    const char *end_ins = in + ins - 1;
    if (val != 0 && (endptr == end_ins)) {
        return true;
    }
    /* if value is 0 then we need to check if some parsing has been done */
    if (val == 0 && (endptr == in)) {
        return false;
    }
    return true;
}

static int ParseJsonLine(const char *in, size_t ins, DataJsonType *rep_out)
{
    if (ins > DATAJSON_JSON_LENGTH) {
        SCLogError("dataset: json string too long: %s", in);
        return -1;
    }

    json_error_t jerror;
    json_t *msg = json_loads(in, 0, &jerror);
    if (msg == NULL) {
        /* JANSSON does not see an integer, float or a string as valid JSON.
           So we need to exclude them from failure. */
        if (!IsFloat(in, ins) && !((in[0] == '"') && (in[ins - 1] == '"'))) {
            SCLogError("dataset: Invalid json: %s: '%s'", jerror.text, in);
            return -1;
        }
    } else {
        json_decref(msg);
    }
    rep_out->len = (uint16_t)ins;
    rep_out->value = SCStrndup(in, ins);
    if (rep_out->value == NULL) {
        return -1;
    }
    return 0;
}

static json_t *GetSubObjectByKey(json_t *json, const char *key)
{
    if (!json || !key || !json_is_object(json)) {
        return NULL;
    }

    const char *current_key = key;
    json_t *current = json;
    while (current_key) {
        const char *dot = strchr(current_key, '.');

        size_t key_len = dot ? (size_t)(dot - current_key) : strlen(current_key);
        char key_buffer[key_len + 1];
        strlcpy(key_buffer, current_key, key_len + 1);

        if (json_is_object(current) == false) {
            return NULL;
        }
        current = json_object_get(current, key_buffer);
        if (current == NULL) {
            return NULL;
        }
        current_key = dot ? dot + 1 : NULL;
    }
    return current;
}

static int ParseJsonFile(const char *file, json_t **array, char *key)
{
    json_t *json;
    json_error_t error;
    /* assume we have one single JSON element in FILE */
    json = json_load_file(file, 0, &error);
    if (json == NULL) {
        FatalErrorOnInit("can't load JSON, error on line %d: %s", error.line, error.text);
        return -1;
    }

    if (key == NULL || strlen(key) == 0) {
        *array = json;
    } else {
        *array = GetSubObjectByKey(json, key);
        if (*array == NULL) {
            SCLogError("dataset: %s failed to get key '%s'", file, key);
            json_decref(json);
            return -1;
        }
        json_incref(*array);
        json_decref(json);
    }
    if (!json_is_array(*array)) {
        FatalErrorOnInit("not an array");
        json_decref(*array);
        return -1;
    }
    return 0;
}

static int DatajsonSetValue(
        Dataset *set, const uint8_t *val, uint16_t val_len, json_t *value, const char *json_key)
{
    DataJsonType elt = { .value = NULL, .len = 0 };
    if (set->remove_key) {
        json_object_del(value, json_key);
    }

    elt.value = json_dumps(value, JSON_COMPACT);
    if (elt.value == NULL) {
        FatalErrorOnInit("json_dumps failed for %s/%s", set->name, set->load);
        return 0;
    }
    if (strlen(elt.value) > DATAJSON_JSON_LENGTH) {
        SCLogError("dataset: json string too long: %s/%s", set->name, set->load);
        SCFree(elt.value);
        elt.value = NULL;
        return 0;
    }
    elt.len = (uint16_t)strlen(elt.value);

    int add_ret = DatajsonAdd(set, val, val_len, &elt);
    if (add_ret < 0) {
        FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
        return 0;
    }
    return add_ret;
}

/**
 *  \retval 1 data was added to the hash
 *  \retval 0 data was not added to the hash as it is already there
 *  \retval -1 failed to add data to the hash
 */
static int DatajsonAddString(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    StringType lookup = { .ptr = (uint8_t *)data, .len = data_len, .json = *json };
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatajsonAddMd5(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    if (data_len != SC_MD5_LEN)
        return -2;

    Md5Type lookup = { .json = *json };
    memcpy(lookup.md5, data, SC_MD5_LEN);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatajsonAddSha256(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    if (data_len != SC_SHA256_LEN)
        return -2;

    Sha256Type lookup = { .json = *json };
    memcpy(lookup.sha256, data, SC_SHA256_LEN);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatajsonAddIPv4(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    if (data_len < SC_IPV4_LEN)
        return -2;

    IPv4Type lookup = { .json = *json };
    memcpy(lookup.ipv4, data, SC_IPV4_LEN);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatajsonAddIPv6(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    if (data_len != SC_IPV6_LEN)
        return -2;

    IPv6Type lookup = { .json = *json };
    memcpy(lookup.ipv6, data, SC_IPV6_LEN);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

/*
 * \brief Add data to the dataset from a JSON object.
 *
 * \param set The dataset to add data to.
 * \param data The data to add.
 * \param data_len The length of the data.
 * \param json The JSON object containing additional information.
 *
 * Memory allocated for the `json` parameter will be freed if the data
 * is not added to the hash.
 *
 * \retval 1 Data was added to the hash.
 * \retval 0 Data was not added to the hash as it is already there.
 * \retval -1 Failed to add data to the hash.
 */
static int DatajsonAdd(
        Dataset *set, const uint8_t *data, const uint32_t data_len, DataJsonType *json)
{
    if (json == NULL)
        return -1;
    if (json->value == NULL)
        return -1;

    if (set == NULL) {
        if (json->value != NULL) {
            SCFree(json->value);
            json->value = NULL;
        }
        return -1;
    }

    int add_ret = 0;
    switch (set->type) {
        case DATASET_TYPE_STRING:
            add_ret = DatajsonAddString(set, data, data_len, json);
            break;
        case DATASET_TYPE_MD5:
            add_ret = DatajsonAddMd5(set, data, data_len, json);
            break;
        case DATASET_TYPE_SHA256:
            add_ret = DatajsonAddSha256(set, data, data_len, json);
            break;
        case DATASET_TYPE_IPV4:
            add_ret = DatajsonAddIPv4(set, data, data_len, json);
            break;
        case DATASET_TYPE_IPV6:
            add_ret = DatajsonAddIPv6(set, data, data_len, json);
            break;
        default:
            add_ret = -1;
            break;
    }

    SCFree(json->value);
    json->value = NULL;

    return add_ret;
}

static int DatajsonLoadTypeFromJSON(Dataset *set, char *json_key, char *array_key,
        uint32_t (*DatajsonAddTypeElement)(Dataset *, json_t *, char *, bool *))
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    uint32_t cnt = 0;
    json_t *json;
    bool found = false;
    SCLogDebug("dataset: array_key '%s' %p", array_key, array_key);
    if (ParseJsonFile(set->load, &json, array_key) == -1) {
        SCLogError("dataset: %s failed to parse from '%s'", set->name, set->load);
        return -1;
    }

    size_t index;
    json_t *value;
    json_array_foreach (json, index, value) {
        cnt += DatajsonAddTypeElement(set, value, json_key, &found);
    }
    json_decref(json);

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return -1;
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonLoadTypeFromJsonline(Dataset *set, char *json_key,
        uint32_t (*DatajsonAddTypeElement)(Dataset *, json_t *, char *, bool *))
{
    uint32_t cnt = 0;
    FILE *fp = fopen(set->load, "r");
    bool found = false;

    if (fp == NULL) {
        SCLogError("dataset: %s failed to open file '%s'", set->name, set->load);
        return 0;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, sizeof(line), fp) != NULL) {
        json_t *json = json_loads(line, 0, NULL);
        if (json == NULL) {
            SCLogError("dataset: %s failed to parse line '%s'", set->name, line);
            goto out_err;
        }
        cnt += DatajsonAddTypeElement(set, json, json_key, &found);
        json_decref(json);
    }
    int close_op = fclose(fp);
    if (close_op != 0) {
        SCLogError("dataset: %s failed to close file '%s'", set->name, set->load);
        return 0;
    }

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return 0;
    }
    return cnt;
out_err:
    close_op = fclose(fp);
    if (close_op != 0) {
        SCLogError("dataset: %s failed to close file '%s'", set->name, set->load);
    }
    return 0;
}

static uint32_t DatajsonAddStringElement(Dataset *set, json_t *value, char *json_key, bool *found)
{
    json_t *key = GetSubObjectByKey(value, json_key);
    if (key == NULL) {
        /* ignore error as it can be a working mode where some entries
           are not in the same format */
        return 0;
    }

    *found = true;

    const char *val_key = json_string_value(key);
    if (val_key == NULL) {
        FatalErrorOnInit("dataset: %s failed to get value for key '%s'", set->name, json_key);
        return 0;
    }
    size_t val_len = strlen(val_key);

    json_incref(key);
    int ret = DatajsonSetValue(set, (const uint8_t *)val_key, (uint16_t)val_len, value, json_key);
    json_decref(key);
    if (ret < 0) {
        FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
        return 0;
    }
    return ret;
}

static int DatajsonLoadString(Dataset *set, char *json_key, char *array_key, DatasetFormats format)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    uint32_t cnt = 0;
    if (format == DATASET_FORMAT_JSON) {
        cnt = DatajsonLoadTypeFromJSON(set, json_key, array_key, DatajsonAddStringElement);
    } else if (format == DATASET_FORMAT_NDJSON) {
        cnt = DatajsonLoadTypeFromJsonline(set, json_key, DatajsonAddStringElement);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonAddMd5Element(Dataset *set, json_t *value, char *json_key, bool *found)
{
    json_t *key = GetSubObjectByKey(value, json_key);
    if (key == NULL) {
        /* ignore error as it can be a working mode where some entries
           are not in the same format */
        return 0;
    }

    *found = true;

    const char *hash_string = json_string_value(key);
    if (strlen(hash_string) != SC_MD5_HEX_LEN) {
        FatalErrorOnInit("Not correct length for a hash");
        return 0;
    }

    uint8_t hash[SC_MD5_LEN];
    if (HexToRaw((const uint8_t *)hash_string, SC_MD5_HEX_LEN, hash, sizeof(hash)) < 0) {
        FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
        return 0;
    }
    return DatajsonSetValue(set, hash, SC_MD5_LEN, value, json_key);
}

static int DatajsonLoadMd5(Dataset *set, char *json_key, char *array_key, DatasetFormats format)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    uint32_t cnt = 0;
    if (format == DATASET_FORMAT_JSON) {
        cnt = DatajsonLoadTypeFromJSON(set, json_key, array_key, DatajsonAddMd5Element);
    } else if (format == DATASET_FORMAT_NDJSON) {
        cnt = DatajsonLoadTypeFromJsonline(set, json_key, DatajsonAddMd5Element);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonAddSha256Element(Dataset *set, json_t *value, char *json_key, bool *found)
{
    json_t *key = GetSubObjectByKey(value, json_key);
    if (key == NULL) {
        /* ignore error as it can be a working mode where some entries
           are not in the same format */
        return 0;
    }

    *found = true;

    const char *hash_string = json_string_value(key);
    if (strlen(hash_string) != SC_SHA256_HEX_LEN) {
        FatalErrorOnInit("Not correct length for a hash");
        return 0;
    }

    uint8_t hash[SC_SHA256_LEN];
    if (HexToRaw((const uint8_t *)hash_string, SC_SHA256_HEX_LEN, hash, sizeof(hash)) < 0) {
        FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
        return 0;
    }

    return DatajsonSetValue(set, hash, SC_SHA256_LEN, value, json_key);
}

static int DatajsonLoadSha256(Dataset *set, char *json_key, char *array_key, DatasetFormats format)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    uint32_t cnt = 0;
    if (format == DATASET_FORMAT_JSON) {
        cnt = DatajsonLoadTypeFromJSON(set, json_key, array_key, DatajsonAddSha256Element);
    } else if (format == DATASET_FORMAT_NDJSON) {
        cnt = DatajsonLoadTypeFromJsonline(set, json_key, DatajsonAddSha256Element);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonAddIpv4Element(Dataset *set, json_t *value, char *json_key, bool *found)
{
    json_t *key = GetSubObjectByKey(value, json_key);
    if (key == NULL) {
        /* ignore error as it can be a working mode where some entries
           are not in the same format */
        return 0;
    }

    *found = true;

    const char *ip_string = json_string_value(key);
    struct in_addr in;
    if (inet_pton(AF_INET, ip_string, &in) != 1) {
        FatalErrorOnInit("datajson IPv4 parse failed %s/%s: %s", set->name, set->load, ip_string);
        return 0;
    }

    return DatajsonSetValue(set, (const uint8_t *)&in.s_addr, SC_IPV4_LEN, value, json_key);
}

static int DatajsonLoadIPv4(Dataset *set, char *json_key, char *array_key, DatasetFormats format)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    uint32_t cnt = 0;

    if (format == DATASET_FORMAT_JSON) {
        cnt = DatajsonLoadTypeFromJSON(set, json_key, array_key, DatajsonAddIpv4Element);
    } else if (format == DATASET_FORMAT_NDJSON) {
        cnt = DatajsonLoadTypeFromJsonline(set, json_key, DatajsonAddIpv4Element);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonAddIPv6Element(Dataset *set, json_t *value, char *json_key, bool *found)
{
    json_t *key = GetSubObjectByKey(value, json_key);
    if (key == NULL) {
        /* ignore error as it can be a working mode where some entries
           are not in the same format */
        return 0;
    }

    *found = true;

    const char *ip_string = json_string_value(key);
    struct in6_addr in6;
    int ret = DatasetParseIpv6String(set, ip_string, &in6);
    if (ret < 0) {
        FatalErrorOnInit("unable to parse IP address");
        return 0;
    }

    return DatajsonSetValue(set, (const uint8_t *)&in6.s6_addr, SC_IPV6_LEN, value, json_key);
}

static int DatajsonLoadIPv6(Dataset *set, char *json_key, char *array_key, DatasetFormats format)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);

    uint32_t cnt = 0;

    if (format == DATASET_FORMAT_JSON) {
        cnt = DatajsonLoadTypeFromJSON(set, json_key, array_key, DatajsonAddIPv6Element);
    } else if (format == DATASET_FORMAT_NDJSON) {
        cnt = DatajsonLoadTypeFromJsonline(set, json_key, DatajsonAddIPv6Element);
    }

    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

Dataset *DatajsonGet(const char *name, enum DatasetTypes type, const char *load, uint64_t memcap,
        uint32_t hashsize, char *json_key_value, char *json_array_key, DatasetFormats format,
        bool remove_key)
{
    Dataset *set = NULL;

    DatasetLock();
    int ret = DatasetGetOrCreate(name, type, NULL, load, &memcap, &hashsize, &set);
    if (ret < 0) {
        SCLogError("dataset with JSON %s creation failed", name);
        DatasetUnlock();
        return NULL;
    }
    if (ret == 1) {
        SCLogDebug("dataset %s already exists", name);
        if (set->remove_key != remove_key) {
            SCLogError("dataset %s remove_key mismatch: %d != %d", set->name, set->remove_key,
                    remove_key);
            DatasetUnlock();
            return NULL;
        }
        DatasetUnlock();
        return set;
    }

    set->remove_key = remove_key;

    char cnf_name[128];
    snprintf(cnf_name, sizeof(cnf_name), "datasets.%s.hash", name);
    switch (type) {
        case DATASET_TYPE_MD5:
            set->hash = THashInit(cnf_name, sizeof(Md5Type), Md5StrJsonSet, Md5StrJsonFree,
                    Md5StrHash, Md5StrCompare, NULL, Md5StrJsonGetLength, load != NULL ? 1 : 0,
                    memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadMd5(set, json_key_value, json_array_key, format) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_STRING:
            set->hash = THashInit(cnf_name, sizeof(StringType), StringJsonSet, StringJsonFree,
                    StringHash, StringCompare, NULL, StringJsonGetLength, load != NULL ? 1 : 0,
                    memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadString(set, json_key_value, json_array_key, format) < 0) {
                SCLogError("dataset %s loading failed", name);
                goto out_err;
            }
            break;
        case DATASET_TYPE_SHA256:
            set->hash = THashInit(cnf_name, sizeof(Sha256Type), Sha256StrJsonSet, Sha256StrJsonFree,
                    Sha256StrHash, Sha256StrCompare, NULL, Sha256StrJsonGetLength,
                    load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadSha256(set, json_key_value, json_array_key, format) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV4:
            set->hash = THashInit(cnf_name, sizeof(IPv4Type), IPv4JsonSet, IPv4JsonFree, IPv4Hash,
                    IPv4Compare, NULL, IPv4JsonGetLength, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadIPv4(set, json_key_value, json_array_key, format) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV6:
            set->hash = THashInit(cnf_name, sizeof(IPv6Type), IPv6JsonSet, IPv6JsonFree, IPv6Hash,
                    IPv6Compare, NULL, IPv6JsonGetLength, load != NULL ? 1 : 0, memcap, hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadIPv6(set, json_key_value, json_array_key, format) < 0)
                goto out_err;
            break;
    }

    SCLogDebug(
            "set %p/%s type %u save %s load %s", set, set->name, set->type, set->save, set->load);

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

static DataJsonResultType DatajsonLookupString(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    StringType lookup = {
        .ptr = (uint8_t *)data, .len = data_len, .json.value = NULL, .json.len = 0
    };
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        StringType *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        rrep.hashdata = rdata;
        return rrep;
    }
    return rrep;
}

static DataJsonResultType DatajsonLookupMd5(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    if (data_len != SC_MD5_LEN)
        return rrep;

    Md5Type lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.md5, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Md5Type *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        rrep.hashdata = rdata;
        return rrep;
    }
    return rrep;
}

static DataJsonResultType DatajsonLookupSha256(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    if (data_len != SC_SHA256_LEN)
        return rrep;

    Sha256Type lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.sha256, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Sha256Type *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        rrep.hashdata = rdata;
        return rrep;
    }
    return rrep;
}

static DataJsonResultType DatajsonLookupIPv4(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    if (data_len != SC_IPV4_LEN)
        return rrep;

    IPv4Type lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv4, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv4Type *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        rrep.hashdata = rdata;
        return rrep;
    }
    return rrep;
}

static DataJsonResultType DatajsonLookupIPv6(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    /* We can have IPv4 or IPV6 here due to ip.src and ip.dst implementation */
    if (data_len != SC_IPV6_LEN && data_len != SC_IPV4_LEN)
        return rrep;

    IPv6Type lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv6, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv6Type *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        rrep.hashdata = rdata;
        return rrep;
    }
    return rrep;
}

DataJsonResultType DatajsonLookup(Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = 0 } };
    if (set == NULL)
        return rrep;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatajsonLookupString(set, data, data_len);
        case DATASET_TYPE_MD5:
            return DatajsonLookupMd5(set, data, data_len);
        case DATASET_TYPE_SHA256:
            return DatajsonLookupSha256(set, data, data_len);
        case DATASET_TYPE_IPV4:
            return DatajsonLookupIPv4(set, data, data_len);
        case DATASET_TYPE_IPV6:
            return DatajsonLookupIPv6(set, data, data_len);
        default:
            break;
    }
    return rrep;
}

/** \brief add serialized data to json set
 *  \retval int 1 added
 *  \retval int 0 already in hash
 *  \retval int -1 API error (not added)
 *  \retval int -2 DATA error
 */
int DatajsonAddSerialized(Dataset *set, const char *value, const char *json)
{
    if (set == NULL)
        return -1;

    if (strlen(value) == 0)
        return -1;

    DataJsonType jvalue = { .value = NULL, .len = 0 };
    if (json) {
        if (ParseJsonLine(json, strlen(json), &jvalue) < 0) {
            SCLogNotice("bad json value for dataset %s/%s", set->name, set->load);
            return -1;
        }
    }

    int ret = -1;
    switch (set->type) {
        case DATASET_TYPE_STRING: {
            uint32_t decoded_size = SCBase64DecodeBufferSize((uint32_t)strlen(value));
            uint8_t decoded[decoded_size];
            uint32_t num_decoded = SCBase64Decode(
                    (const uint8_t *)value, strlen(value), SCBase64ModeStrict, decoded);
            if (num_decoded == 0)
                goto operror;
            ret = DatajsonAdd(set, decoded, num_decoded, &jvalue);
            break;
        }
        case DATASET_TYPE_MD5: {
            if (strlen(value) != SC_MD5_HEX_LEN)
                goto operror;
            uint8_t hash[SC_MD5_LEN];
            if (HexToRaw((const uint8_t *)value, SC_MD5_HEX_LEN, hash, sizeof(hash)) < 0)
                goto operror;
            ret = DatajsonAdd(set, hash, SC_MD5_LEN, &jvalue);
            break;
        }
        case DATASET_TYPE_SHA256: {
            if (strlen(value) != SC_SHA256_HEX_LEN)
                goto operror;
            uint8_t hash[SC_SHA256_LEN];
            if (HexToRaw((const uint8_t *)value, SC_SHA256_HEX_LEN, hash, sizeof(hash)) < 0)
                goto operror;
            ret = DatajsonAdd(set, hash, SC_SHA256_LEN, &jvalue);
            break;
        }
        case DATASET_TYPE_IPV4: {
            struct in_addr in;
            if (inet_pton(AF_INET, value, &in) != 1)
                goto operror;
            ret = DatajsonAdd(set, (uint8_t *)&in.s_addr, SC_IPV4_LEN, &jvalue);
            break;
        }
        case DATASET_TYPE_IPV6: {
            struct in6_addr in6;
            if (DatasetParseIpv6String(set, value, &in6) != 0) {
                SCLogError("Dataset failed to import %s as IPv6", value);
                goto operror;
            }
            ret = DatajsonAdd(set, (uint8_t *)&in6.s6_addr, SC_IPV6_LEN, &jvalue);
            break;
        }
    }
    SCFree(jvalue.value);
    return ret;
operror:
    SCFree(jvalue.value);
    return -2;
}
