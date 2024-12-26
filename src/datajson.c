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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "datasets.h"
#include "datajson.h"
#include "datajson-ipv4.h"
#include "datajson-ipv6.h"
#include "datajson-md5.h"
#include "datajson-sha256.h"
#include "datajson-string.h"
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
    json_error_t jerror;
    json_t *msg = json_loads(in, 0, &jerror);
    if (msg == NULL) {
        /* JANSSON does not see an integer, float or a string as valid JSON.
           So we need to exclude them from failure. */
        if (!IsFloat(in, ins) && !((in[0] == '"') && (in[ins - 1] == '"'))) {
            SCLogWarning("dataset: Invalid json: %s: '%s'\n", jerror.text, in);
            return -1;
        }
    } else {
        json_decref(msg);
    }
    rep_out->len = ins;
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

    if (key == NULL) {
        *array = json;
    } else {
        *array = GetSubObjectByKey(json, key);
        if (*array == NULL) {
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

/**
 *  \retval 1 data was added to the hash
 *  \retval 0 data was not added to the hash as it is already there
 *  \retval -1 failed to add data to the hash
 */
static int DatajsonAddString(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    StringTypeJson lookup = { .ptr = (uint8_t *)data, .len = data_len, .json = *json };
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
    if (set == NULL)
        return -1;

    if (data_len != SC_MD5_LEN)
        return -2;

    Md5TypeJson lookup = { .json = *json };
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
    if (set == NULL)
        return -1;

    if (data_len != SC_SHA256_LEN)
        return -2;

    Sha256TypeJson lookup = { .json = *json };
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
    if (set == NULL)
        return -1;

    if (data_len < SC_IPV4_LEN)
        return -2;

    IPv4TypeJson lookup = { .json = *json };
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
    if (set == NULL)
        return -1;

    if (data_len != SC_IPV6_LEN)
        return -2;

    IPv6TypeJson lookup = { .json = *json };
    memcpy(lookup.ipv6, data, SC_IPV6_LEN);
    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (res.data) {
        DatajsonUnlockData(res.data);
        return res.is_new ? 1 : 0;
    }
    return -1;
}

static int DatajsonAdd(
        Dataset *set, const uint8_t *data, const uint32_t data_len, DataJsonType *json)
{
    if (set == NULL)
        return -1;

    switch (set->type) {
        case DATASET_TYPE_STRING:
            return DatajsonAddString(set, data, data_len, json);
        case DATASET_TYPE_MD5:
            return DatajsonAddMd5(set, data, data_len, json);
        case DATASET_TYPE_SHA256:
            return DatajsonAddSha256(set, data, data_len, json);
        case DATASET_TYPE_IPV4:
            return DatajsonAddIPv4(set, data, data_len, json);
        case DATASET_TYPE_IPV6:
            return DatajsonAddIPv6(set, data, data_len, json);
        default:
            break;
    }
    return -1;
}

static uint32_t DatajsonLoadStringFromCSV(Dataset *set, const char *fopen_mode)
{
    uint32_t cnt = 0;
    int add_ret;
    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError("fopen '%s' failed: %s", set->load, strerror(errno));
        return -1;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (strlen(line) <= 1)
            continue;

        char *r = strchr(line, ',');
        if (r == NULL) {
            FatalErrorOnInit("missing separator in datajson set %s/%s", set->name, set->load);
            continue;
        }
        line[strlen(line) - 1] = '\0';
        SCLogDebug("line: '%s'", line);

        *r = '\0';

        uint32_t decoded_size = Base64DecodeBufferSize(strlen(line));
        uint8_t decoded[decoded_size];
        uint32_t num_decoded = Base64Decode(
                (const uint8_t *)line, strlen(line), Base64ModeStrict, decoded);
        if (num_decoded == 0) {
            FatalErrorOnInit("bad base64 encoding %s/%s", set->name, set->load);
            continue;
        }

        r++;
        SCLogDebug("r '%s'", r);

        // coverity[alloc_strlen : FALSE]
        DataJsonType json = { .value = NULL, .len = 0 };
        if (ParseJsonLine(r, strlen(r), &json) < 0) {
            FatalErrorOnInit("die: bad json");
            continue;
        }
        SCLogDebug("json %s", json.value);

        add_ret = DatajsonAdd(set, (const uint8_t *)decoded, num_decoded, &json);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(json.value);
        }
        cnt++;

        SCLogDebug("line with json %s, %s", line, r);
    }
    int fp_ret = fclose(fp);
    if (fp_ret != 0) {
        SCLogError("Could not close file: errno %d", errno);
    }
    return cnt;
}

static int DatajsonLoadString(Dataset *set, char *json_key, char *array_key)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    uint32_t cnt = 0;
    if (json_key == NULL) {
        cnt = DatajsonLoadStringFromCSV(set, fopen_mode);
    } else {
        json_t *json;
        bool found = false;
        if (ParseJsonFile(set->load, &json, array_key) == -1)
            return -1;

        int add_ret;
        size_t index;
        json_t *value;
        json_array_foreach (json, index, value) {
            json_t *key = GetSubObjectByKey(value, json_key);
            if (key == NULL) {
                /* ignore error as it can be a working mode where some entries
                are not in the same format */
                continue;
            }

            found = true;

            const char *val = json_string_value(key);

            DataJsonType elt = { .value = NULL, .len = 0 };
            elt.value = json_dumps(value, JSON_COMPACT);
            elt.len = strlen(elt.value);

            add_ret = DatajsonAdd(set, (const uint8_t *)val, strlen(val), &elt);
            if (add_ret < 0) {
                FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
                continue;
            }
            if (add_ret == 0) {
                SCFree(elt.value);
            }
        }
        json_decref(json);

        if (found == false) {
            FatalErrorOnInit(
                    "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
            return -1;
        }
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonLoadMd5FromCSV(Dataset *set, const char *fopen_mode)
{
    uint32_t cnt = 0;
    int add_ret;

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError("fopen '%s' failed: %s", set->load, strerror(errno));
        return -1;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        /* straight black/white list */
        if (strlen(line) == SC_MD5_HEX_LEN + 1) {
            FatalErrorOnInit("datajson without separator %s/%s", set->name, set->load);
            continue;
        }
        if (strlen(line) > SC_MD5_HEX_LEN && line[SC_MD5_HEX_LEN] == ',') {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("MD5 with JSON line: '%s'", line);

            uint8_t hash[SC_MD5_LEN];
            if (HexToRaw((const uint8_t *)line, SC_MD5_HEX_LEN, hash, sizeof(hash)) < 0) {
                FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
                continue;
            }

            DataJsonType json = { .value = NULL, .len = 0 };
            if (ParseJsonLine(line + SC_MD5_HEX_LEN + 1, strlen(line) - (SC_MD5_HEX_LEN + 1), &json) < 0) {
                FatalErrorOnInit("bad json for dataset %s/%s", set->name, set->load);
                continue;
            }

            SCLogDebug("json v:%s", json.value);
            add_ret = DatajsonAdd(set, hash, SC_MD5_LEN, &json);
            if (add_ret < 0) {
                FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
                continue;
            }
            if (add_ret == 0) {
                SCFree(json.value);
            } else {
                cnt++;
            }
        } else {
            FatalErrorOnInit("MD5 bad line len %u: '%s'", (uint32_t)strlen(line), line);
            continue;
        }
    }
    int fp_ret = fclose(fp);
    if (fp_ret != 0) {
        SCLogError("Could not close file: errno %d", errno);
    }

    return cnt;
}

static uint32_t DatajsonLoadMd5FromJSON(Dataset *set, char* array_key, char* json_key)
{
    int add_ret;
    uint32_t cnt = 0;
    json_t *json;
    bool found = false;

    if (ParseJsonFile(set->load, &json, array_key) == -1)
        return -1;

    size_t index;
    json_t *value;
    json_array_foreach (json, index, value) {
        json_t *key = GetSubObjectByKey(value, json_key);
        if (key == NULL) {
            /* ignore error as it can be a working mode where some entries
               are not in the same format */
            continue;
        }

        found = true;

        const char *hash_string = json_string_value(key);
        if (strlen(hash_string) != SC_MD5_HEX_LEN) {
            FatalErrorOnInit("Not correct length for a hash");
            continue;
        }

        uint8_t hash[SC_MD5_LEN];
        if (HexToRaw((const uint8_t *)hash_string, SC_MD5_HEX_LEN, hash, sizeof(hash)) < 0) {
            FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
            continue;
        }

        DataJsonType elt = { .value = NULL, .len = 0 };
        elt.value = json_dumps(value, JSON_COMPACT);
        elt.len = strlen(elt.value);

        add_ret = DatajsonAdd(set, (const uint8_t *)hash_string, SC_MD5_LEN, &elt);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(elt.value);
        } else {
            cnt++;
        }
    }
    json_decref(json);

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return -1;
    }

    return cnt;
}

static int DatajsonLoadMd5(Dataset *set, char *json_key, char *array_key)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    uint32_t cnt = 0;
    if (json_key == NULL) {
        cnt = DatajsonLoadMd5FromCSV(set, fopen_mode);
    } else {
        cnt = DatajsonLoadMd5FromJSON(set, array_key, json_key);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonLoadSha256fromCSV(Dataset *set, const char *fopen_mode)
{
    uint32_t cnt = 0;
    int add_ret;
    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError("fopen '%s' failed: %s", set->load, strerror(errno));
        return -1;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        /* straight black/white list */
        if (strlen(line) == SC_SHA256_HEX_LEN + 1) {
            FatalErrorOnInit("datajson missing separator %s/%s", set->name, set->load);
            continue;
        }
        if (strlen(line) > SC_SHA256_HEX_LEN + 1 && line[SC_SHA256_HEX_LEN] == ',') {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("SHA-256 with JSON line: '%s'", line);

            uint8_t hash[SC_SHA256_LEN];
            if (HexToRaw((const uint8_t *)line, SC_SHA256_HEX_LEN, hash, sizeof(hash)) < 0) {
                FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
                continue;
            }

            DataJsonType json = { .value = NULL, .len = 0 };
            if (ParseJsonLine(line + SC_SHA256_HEX_LEN + 1, strlen(line) - (SC_SHA256_HEX_LEN + 1), &json) < 0) {
                FatalErrorOnInit("bad rep for dataset %s/%s", set->name, set->load);
                continue;
            }

            SCLogDebug("json %s", json.value);

            add_ret = DatajsonAdd(set, hash, SC_SHA256_LEN, &json);
            if (add_ret < 0) {
                FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
                continue;
            }
            if (add_ret == 0) {
                SCFree(json.value);
            } else {
                cnt++;
            }
        }
    }
    int fp_ret = fclose(fp);
    if (fp_ret != 0) {
        SCLogError("Could not close file: errno %d", errno);
    }
    return cnt;
}

static uint32_t DatajsonLoadSHA256FromJSON(Dataset *set, char* array_key, char* json_key)
{
    int add_ret;
    uint32_t cnt = 0;
    json_t *json;
    bool found = false;

    if (ParseJsonFile(set->load, &json, array_key) == -1)
        return -1;

    size_t index;
    json_t *value;
    json_array_foreach (json, index, value) {
        json_t *key = GetSubObjectByKey(value, json_key);
        if (key == NULL) {
            /* ignore error as it can be a working mode where some entries
               are not in the same format */
            continue;
        }

        found = true;

        const char *hash_string = json_string_value(key);
        if (strlen(hash_string) != SC_SHA256_HEX_LEN) {
            FatalErrorOnInit("Not correct length for a hash");
            continue;
        }

        uint8_t hash[SC_SHA256_LEN];
        if (HexToRaw((const uint8_t *)hash_string, SC_SHA256_HEX_LEN, hash, sizeof(hash)) < 0) {
            FatalErrorOnInit("bad hash for dataset %s/%s", set->name, set->load);
            continue;
        }

        DataJsonType elt = { .value = NULL, .len = 0 };
        elt.value = json_dumps(value, JSON_COMPACT);
        elt.len = strlen(elt.value);

        add_ret = DatajsonAdd(set, (const uint8_t *)hash_string, SC_SHA256_LEN, &elt);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(elt.value);
        } else {
            cnt++;
        }
    }
    json_decref(json);

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return -1;
    }
    return cnt;
}

static int DatajsonLoadSha256(Dataset *set, char *json_key, char *array_key)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    uint32_t cnt = 0;
    if (json_key == NULL) {
        cnt = DatajsonLoadSha256fromCSV(set, fopen_mode);
    } else {
        cnt = DatajsonLoadSHA256FromJSON(set, array_key, json_key);
    }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonLoadIPv4fromCSV(Dataset *set, const char *fopen_mode)
{
    uint32_t cnt = 0;
    int add_ret;

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError("fopen '%s' failed: %s", set->load, strerror(errno));
        return -1;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        char *r = strchr(line, ',');
        if (r == NULL) {
            FatalErrorOnInit("datajson without separator %s/%s", set->name, set->load);
            continue;
            /* list with JSON data */
        }
        line[strlen(line) - 1] = '\0';
        *r = '\0';

        struct in_addr in;
        if (inet_pton(AF_INET, line, &in) != 1) {
            FatalErrorOnInit(
                    "datajson IPv4 parse failed %s/%s: %s", set->name, set->load, line);
            continue;
        }

        r++;

        DataJsonType json = { .value = NULL, .len = 0 };
        if (ParseJsonLine(r, strlen(r), &json) < 0) {
            FatalErrorOnInit("bad json value for dataset %s/%s", set->name, set->load);
            continue;
        }

        add_ret = DatajsonAdd(set, (const uint8_t *)&in.s_addr, SC_IPV4_LEN, &json);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(json.value);
        } else {
            cnt++;
        }
    }
    int fp_ret = fclose(fp);
    if (fp_ret != 0) {
        SCLogError("Could not close file: errno %d", errno);
    }

    return cnt;
}

static uint32_t DatajsonLoadIPv4FromJSON(Dataset *set, char* array_key, char* json_key)
{
    uint32_t cnt = 0;
    int add_ret;
    json_t *json;
    bool found = false;

    if (ParseJsonFile(set->load, &json, array_key) == -1)
        return -1;

    size_t index;
    json_t *value;
    json_array_foreach (json, index, value) {
        json_t *key = GetSubObjectByKey(value, json_key);
        if (key == NULL) {
            /* ignore error as it can be a working mode where some entries
               are not in the same format */
            continue;
        }

        found = true;

        const char *ip_string = json_string_value(key);
        struct in_addr in;
        if (inet_pton(AF_INET, ip_string, &in) != 1) {
            FatalErrorOnInit(
                    "datajson IPv4 parse failed %s/%s: %s", set->name, set->load, ip_string);
            continue;
        }
        DataJsonType elt = { .value = NULL, .len = 0 };
        elt.value = json_dumps(value, JSON_COMPACT);
        elt.len = strlen(elt.value);

        add_ret = DatajsonAdd(set, (const uint8_t *)&in.s_addr, SC_IPV4_LEN, &elt);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(elt.value);
        } else {
            cnt++;
        }
    }
    json_decref(json);

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return 0;
    }

    return cnt;
}

static int DatajsonLoadIPv4(Dataset *set, char *json_key, char *array_key)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    uint32_t cnt = 0;
    if (json_key == NULL) {
        cnt = DatajsonLoadIPv4fromCSV(set, fopen_mode);
    } else {
        cnt = DatajsonLoadIPv4FromJSON(set, array_key, json_key);
     }
    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

static uint32_t DatajsonLoadIPv6fromCSV(Dataset *set, const char *fopen_mode)
{
    uint32_t cnt = 0;
    int add_ret;

    FILE *fp = fopen(set->load, fopen_mode);
    if (fp == NULL) {
        SCLogError("fopen '%s' failed: %s", set->load, strerror(errno));
        return -1;
    }

    char line[DATAJSON_JSON_LENGTH];
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        char *r = strchr(line, ',');
        if (r == NULL) {
            FatalErrorOnInit("datajson without separator %s/%s", set->name, set->load);
            /* list with JSON data */
        } else {
            line[strlen(line) - 1] = '\0';
            SCLogDebug("IPv6 with JSON line: '%s'", line);

            *r = '\0';
            struct in6_addr in6;
            int ret = DatasetParseIpv6String(set, line, &in6);
            if (ret < 0) {
                FatalErrorOnInit("unable to parse IP address");
                continue;
            }

            r++;

            DataJsonType json = { .value = NULL, .len = 0 };
            if (ParseJsonLine(r, strlen(r), &json) < 0) {
                FatalErrorOnInit("bad json value for dataset %s/%s", set->name, set->load);
                continue;
            }

            add_ret = DatajsonAdd(set, (const uint8_t *)&in6.s6_addr, SC_IPV6_LEN, &json);
            if (add_ret < 0) {
                FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
                continue;
            }
            if (add_ret == 0) {
                SCFree(json.value);
            } else {
                cnt++;
            }
        }
    }
    int fp_ret = fclose(fp);
    if (fp_ret != 0) {
        SCLogError("Could not close file: errno %d", errno);
    }

    return cnt;
}

static uint32_t DatajsonLoadIPv6FromJSON(Dataset *set, char* array_key, char* json_key)
{
    uint32_t cnt = 0;
    int add_ret;
    json_t *json;
    bool found = false;

    if (ParseJsonFile(set->load, &json, array_key) == -1)
        return -1;

    size_t index;
    json_t *value;
    json_array_foreach (json, index, value) {
        json_t *key = GetSubObjectByKey(value, json_key);
        if (key == NULL) {
            /* ignore error as it can be a working mode where some entries
               are not in the same format */
            continue;
        }

        found = true;

        const char *ip_string = json_string_value(key);
        struct in6_addr in6;
        int ret = DatasetParseIpv6String(set, ip_string, &in6);
        if (ret < 0) {
            FatalErrorOnInit("unable to parse IP address");
            continue;
        }
        DataJsonType elt = { .value = NULL, .len = 0 };
        elt.value = json_dumps(value, JSON_COMPACT);
        elt.len = strlen(elt.value);

        add_ret = DatajsonAdd(set, (const uint8_t *)&in6.s6_addr, SC_IPV6_LEN, &elt);
        if (add_ret < 0) {
            FatalErrorOnInit("datajson data add failed %s/%s", set->name, set->load);
            continue;
        }
        if (add_ret == 0) {
            SCFree(elt.value);
        } else {
            cnt++;
        }
    }
    json_decref(json);

    if (found == false) {
        FatalErrorOnInit(
                "No valid entries for key '%s' found in the file '%s'", json_key, set->load);
        return 0;
    }
    return cnt;
}

static int DatajsonLoadIPv6(Dataset *set, char *json_key, char *array_key)
{
    if (strlen(set->load) == 0)
        return 0;

    SCLogConfig("dataset: %s loading from '%s'", set->name, set->load);
    const char *fopen_mode = "r";
    if (strlen(set->save) > 0 && strcmp(set->save, set->load) == 0) {
        fopen_mode = "a+";
    }

    uint32_t cnt = 0;
    if (json_key == NULL) {
        cnt = DatajsonLoadIPv6fromCSV(set, fopen_mode);
     } else {
        cnt = DatajsonLoadIPv6FromJSON(set, array_key, json_key);
    }

    THashConsolidateMemcap(set->hash);

    SCLogConfig("dataset: %s loaded %u records", set->name, cnt);
    return 0;
}

Dataset *DatajsonGet(const char *name, enum DatasetTypes type, const char *load, uint64_t memcap,
        uint32_t hashsize, char *json_key_value, char *json_array_key)
{
    uint64_t default_memcap = 0;
    uint32_t default_hashsize = 0;
    if (strlen(name) > DATASET_NAME_MAX_LEN) {
        return NULL;
    }

    DatasetLock();
    Dataset *set = DatasetSearchByName(name);
    if (set) {
        if (type != DATASET_TYPE_NOTSET && set->type != type) {
            SCLogError("dataset %s already "
                       "exists and is of type %u",
                    set->name, set->type);
            DatasetUnlock();
            return NULL;
        }

        if (load == NULL || strlen(load) == 0) {
            // OK, rule keyword doesn't have to set state/load,
            // even when yaml set has set it.
        } else {
            if ((load == NULL && strlen(set->load) > 0) ||
                    (load != NULL && strcmp(set->load, load) != 0)) {
                SCLogError("dataset %s load mismatch: %s != %s", set->name, set->load, load);
                DatasetUnlock();
                return NULL;
            }
        }

        DatasetUnlock();
        return set;
    }

    if (type == DATASET_TYPE_NOTSET) {
        SCLogError("dataset %s not defined", name);
        goto out_err;
    }

    set = DatasetAlloc(name);
    if (set == NULL) {
        goto out_err;
    }

    strlcpy(set->name, name, sizeof(set->name));
    set->type = type;
    if (load && strlen(load)) {
        strlcpy(set->load, load, sizeof(set->load));
        SCLogDebug("set \'%s\' loading \'%s\' from \'%s\'", set->name, load, set->load);
    }

    static const char conf_format_str[] = "datasets.%s.hash";
    char cnf_name[DATASET_NAME_MAX_LEN + (sizeof(conf_format_str)/sizeof(char))];
    int p_ret = snprintf(cnf_name, sizeof(cnf_name), conf_format_str, name);
    if (p_ret == 0) {
        SCLogError("Can't build configuration variable for set: '%s'", name);
        goto out_err;
    }

    DatasetGetDefaultMemcap(&default_memcap, &default_hashsize);
    switch (type) {
        case DATASET_TYPE_MD5:
            set->hash = THashInit(cnf_name, sizeof(Md5TypeJson), Md5StrJsonSet, Md5StrJsonFree,
                    Md5StrJsonHash, Md5StrJsonCompare, NULL, NULL, load != NULL ? 1 : 0,
                    memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadMd5(set, json_key_value, json_array_key) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_STRING:
            set->hash = THashInit(cnf_name, sizeof(StringTypeJson), StringJsonSet, StringJsonFree,
                    StringJsonHash, StringJsonCompare, NULL, NULL, load != NULL ? 1 : 0,
                    memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadString(set, json_key_value, json_array_key) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_SHA256:
            set->hash = THashInit(cnf_name, sizeof(Sha256TypeJson), Sha256StrJsonSet,
                    Sha256StrJsonFree, Sha256StrJsonHash, Sha256StrJsonCompare, NULL, NULL,
                    load != NULL ? 1 : 0, memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadSha256(set, json_key_value, json_array_key) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV4:
            set->hash = THashInit(cnf_name, sizeof(IPv4TypeJson), IPv4JsonSet, IPv4JsonFree,
                    IPv4JsonHash, IPv4JsonCompare, NULL, NULL, load != NULL ? 1 : 0,
                    memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadIPv4(set, json_key_value, json_array_key) < 0)
                goto out_err;
            break;
        case DATASET_TYPE_IPV6:
            set->hash = THashInit(cnf_name, sizeof(IPv6TypeJson), IPv6JsonSet, IPv6JsonFree,
                    IPv6JsonHash, IPv6JsonCompare, NULL, NULL, load != NULL ? 1 : 0,
                    memcap > 0 ? memcap : default_memcap,
                    hashsize > 0 ? hashsize : default_hashsize);
            if (set->hash == NULL)
                goto out_err;
            if (DatajsonLoadIPv6(set, json_key_value, json_array_key) < 0)
                goto out_err;
            break;
    }

    SCLogDebug(
            "set %p/%s type %u save %s load %s", set, set->name, set->type, set->save, set->load);

    DatasetAppendSet(set);

    DatasetUnlock();
    return set;
out_err:
    if (set) {
        if (set->hash) {
            THashShutdown(set->hash);
        }
        SCFree(set);
    }
    DatasetUnlock();
    return NULL;
}

static DataJsonResultType DatajsonLookupString(
        Dataset *set, const uint8_t *data, const uint32_t data_len)
{
    DataJsonResultType rrep = { .found = false, .json = { .value = NULL, .len = 0 } };

    if (set == NULL)
        return rrep;

    StringTypeJson lookup = {
        .ptr = (uint8_t *)data, .len = data_len, .json.value = NULL, .json.len = 0
    };
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        StringTypeJson *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        DatajsonUnlockData(rdata);
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

    Md5TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.md5, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Md5TypeJson *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        DatajsonUnlockData(rdata);
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

    Sha256TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.sha256, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        Sha256TypeJson *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        DatajsonUnlockData(rdata);
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

    IPv4TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv4, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv4TypeJson *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        DatajsonUnlockData(rdata);
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

    IPv6TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv6, data, data_len);
    THashData *rdata = THashLookupFromHash(set->hash, &lookup);
    if (rdata) {
        IPv6TypeJson *found = rdata->data;
        rrep.found = true;
        rrep.json = found->json;
        DatajsonUnlockData(rdata);
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

typedef int (*DatajsonOpFunc)(
        Dataset *set, const uint8_t *data, const uint32_t data_len, const DataJsonType *json);

static int DatajsonOpSerialized(Dataset *set, const char *string, const char *json,
        DatajsonOpFunc DatajsonOpString, DatajsonOpFunc DatajsonOpMd5,
        DatajsonOpFunc DatajsonOpSha256, DatajsonOpFunc DatajsonOpIPv4,
        DatajsonOpFunc DatajsonOpIPv6)
{
    int ret;

    if (set == NULL)
        return -1;
    if (strlen(string) == 0)
        return -1;

    DataJsonType jvalue = { .value = NULL, .len = 0 };
    if (json) {
        if (ParseJsonLine(json, strlen(json), &jvalue) < 0) {
            SCLogNotice("bad json value for dataset %s/%s", set->name, set->load);
            return -1;
        }
    }

    switch (set->type) {
        case DATASET_TYPE_STRING: {
            uint32_t decoded_size = Base64DecodeBufferSize(strlen(string));
            uint8_t decoded[decoded_size];
            uint32_t num_decoded = Base64Decode(
                    (const uint8_t *)string, strlen(string), Base64ModeStrict, decoded);
            if (num_decoded == 0)
                goto operror;
            ret = DatajsonOpString(set, decoded, num_decoded, &jvalue);
            if (ret <= 0) {
                SCFree(jvalue.value);
            }
            return ret;
        }
        case DATASET_TYPE_MD5: {
            if (strlen(string) != SC_MD5_HEX_LEN)
                goto operror;
            uint8_t hash[SC_MD5_LEN];
            if (HexToRaw((const uint8_t *)string, SC_MD5_HEX_LEN, hash, sizeof(hash)) < 0)
                goto operror;
            ret = DatajsonOpMd5(set, hash, SC_MD5_LEN, &jvalue);
            if (ret <= 0) {
                SCFree(jvalue.value);
            }
            return ret;
        }
        case DATASET_TYPE_SHA256: {
            if (strlen(string) != SC_SHA256_HEX_LEN)
                goto operror;
            uint8_t hash[SC_SHA256_LEN];
            if (HexToRaw((const uint8_t *)string, SC_SHA256_HEX_LEN, hash, sizeof(hash)) < 0)
                goto operror;
            ret = DatajsonOpSha256(set, hash, SC_SHA256_LEN, &jvalue);
            if (ret <= 0) {
                SCFree(jvalue.value);
            }
            return ret;
        }
        case DATASET_TYPE_IPV4: {
            struct in_addr in;
            if (inet_pton(AF_INET, string, &in) != 1)
                goto operror;
            ret = DatajsonOpIPv4(set, (uint8_t *)&in.s_addr, SC_IPV4_LEN, &jvalue);
            if (ret <= 0) {
                SCFree(jvalue.value);
            }
            return ret;
        }
        case DATASET_TYPE_IPV6: {
            struct in6_addr in6;
            if (DatasetParseIpv6String(set, string, &in6) != 0) {
                SCLogError("Dataset failed to import %s as IPv6", string);
                goto operror;
            }
            ret = DatajsonOpIPv6(set, (uint8_t *)&in6.s6_addr, SC_IPV6_LEN, &jvalue);
            if (ret <= 0) {
                SCFree(jvalue.value);
            }
            return ret;
        }
    }
    return -1;
operror:
    SCFree(jvalue.value);
    return -2;
}

/** \brief add serialized data to json set
 *  \retval int 1 added
 *  \retval int 0 already in hash
 *  \retval int -1 API error (not added)
 *  \retval int -2 DATA error
 */
int DatajsonAddSerialized(Dataset *set, const char *value, const char *json)
{
    return DatajsonOpSerialized(set, value, json, DatajsonAddString, DatajsonAddMd5,
            DatajsonAddSha256, DatajsonAddIPv4, DatajsonAddIPv6);
}

/**
 *  \retval 1 data was removed from the hash
 *  \retval 0 data not removed (busy)
 *  \retval -1 data not found
 */
static int DatajsonRemoveString(
        Dataset *set, const uint8_t *data, const uint32_t data_len,  __attribute__((unused)) const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    StringTypeJson lookup = {
        .ptr = (uint8_t *)data, .len = data_len, .json.value = NULL, .json.len = 0
    };
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatajsonRemoveIPv4(
        Dataset *set, const uint8_t *data, const uint32_t data_len,  __attribute__((unused)) const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    if (data_len != SC_IPV4_LEN)
        return -2;

    IPv4TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv4, data, SC_IPV4_LEN);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatajsonRemoveIPv6(
        Dataset *set, const uint8_t *data, const uint32_t data_len,  __attribute__((unused)) const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    if (data_len != SC_IPV6_LEN)
        return -2;

    IPv6TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.ipv6, data, SC_IPV6_LEN);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatajsonRemoveMd5(
        Dataset *set, const uint8_t *data, const uint32_t data_len,  __attribute__((unused)) const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    if (data_len != SC_MD5_LEN)
        return -2;

    Md5TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.md5, data, SC_MD5_LEN);
    return THashRemoveFromHash(set->hash, &lookup);
}

static int DatajsonRemoveSha256(
        Dataset *set, const uint8_t *data, const uint32_t data_len,  __attribute__((unused)) const DataJsonType *json)
{
    if (set == NULL)
        return -1;

    if (data_len != SC_SHA256_LEN)
        return -2;

    Sha256TypeJson lookup = { .json.value = NULL, .json.len = 0 };
    memcpy(lookup.sha256, data, SC_SHA256_LEN);
    return THashRemoveFromHash(set->hash, &lookup);
}

/** \brief remove serialized data from set
 *  \retval int 1 removed
 *  \retval int 0 found but busy (not removed)
 *  \retval int -1 API error (not removed)
 *  \retval int -2 DATA error */
int DatajsonRemoveSerialized(Dataset *set, const char *string)
{
    return DatajsonOpSerialized(set, string, NULL, DatajsonRemoveString, DatajsonRemoveMd5,
            DatajsonRemoveSha256, DatajsonRemoveIPv4, DatajsonRemoveIPv6);
}
