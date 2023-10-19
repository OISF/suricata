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
 *  \author Eric Leblond <el@stamus-networks.com>
 *
 * Based on detect-dataset.c by Victor Julien <victor@inliniac.net>
 *
 *  Implements the datajson keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "datasets.h"
#include "datasets-json.h"
#include "detect-datajson.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "util-debug.h"
#include "util-misc.h"
#include "util-path.h"

static int DetectDatajsonSetup(DetectEngineCtx *, Signature *, const char *);
void DetectDatajsonFree(DetectEngineCtx *, void *);

void DetectDatajsonRegister(void)
{
    sigmatch_table[DETECT_DATAJSON].name = "datajson";
    sigmatch_table[DETECT_DATAJSON].desc =
            "match sticky buffer against datasets with json extra data (experimental)";
    sigmatch_table[DETECT_DATAJSON].url = "/rules/dataset-keywords.html#datajson";
    sigmatch_table[DETECT_DATAJSON].Setup = DetectDatajsonSetup;
    sigmatch_table[DETECT_DATAJSON].Free = DetectDatajsonFree;
}

/*
    1 match
    0 no match
    -1 can't match
 */
int DetectDatajsonBufferMatch(DetectEngineThreadCtx *det_ctx, const DetectDatajsonData *sd,
        const uint8_t *data, const uint32_t data_len)
{
    if (data == NULL || data_len == 0)
        return 0;

    switch (sd->cmd) {
        case DETECT_DATAJSON_CMD_ISSET: {
            // PrintRawDataFp(stdout, data, data_len);
            DataJsonResultType r = DatasetLookupwJson(sd->set, data, data_len);
            SCLogDebug("r %d", r);
            if (!r.found)
                return 0;
            if (r.json.len > 0) {
                if ((det_ctx->json_content_len < SIG_JSON_CONTENT_ARRAY_LEN) &&
                        (r.json.len + strlen(sd->json_key) + 3 < SIG_JSON_CONTENT_ITEM_LEN)) {
                    snprintf(det_ctx->json_content[det_ctx->json_content_len].json_content,
                            SIG_JSON_CONTENT_ITEM_LEN, "\"%s\":%s", sd->json_key, r.json.value);
                    det_ctx->json_content[det_ctx->json_content_len].id = sd->id;
                    det_ctx->json_content_len++;
                }
            }
            return 1;
        }
        case DETECT_DATAJSON_CMD_ISNOTSET: {
            // PrintRawDataFp(stdout, data, data_len);
            DataJsonResultType r = DatasetLookupwJson(sd->set, data, data_len);
            SCLogDebug("r %d", r);
            if (r.found)
                return 0;
            return 1;
        }
        default:
            abort();
    }
    return 0;
}

static int DetectDatajsonParse(const char *str, char *cmd, int cmd_len, char *name, int name_len,
        enum DatasetTypes *type, char *load, size_t load_size, uint64_t *memcap, uint32_t *hashsize,
        char *json_key, size_t json_key_size)
{
    bool cmd_set = false;
    bool name_set = false;
    bool load_set = false;

    char copy[strlen(str) + 1];
    strlcpy(copy, str, sizeof(copy));
    char *xsaveptr = NULL;
    char *key = strtok_r(copy, ",", &xsaveptr);
    while (key != NULL) {
        while (*key != '\0' && isblank(*key)) {
            key++;
        }
        char *val = strchr(key, ' ');
        if (val != NULL) {
            *val++ = '\0';
            while (*val != '\0' && isblank(*val)) {
                val++;
                SCLogDebug("cmd %s val %s", key, val);
            }
        } else {
            SCLogDebug("cmd %s", key);
        }

        if (strlen(key) == 0) {
            goto next;
        }

        if (!cmd_set) {
            if (val && strlen(val) != 0) {
                return -1;
            }
            strlcpy(cmd, key, cmd_len);
            cmd_set = true;
        } else if (!name_set) {
            if (val && strlen(val) != 0) {
                return -1;
            }
            strlcpy(name, key, name_len);
            name_set = true;
        } else {
            if (val == NULL) {
                return -1;
            }

            if (strcmp(key, "type") == 0) {
                SCLogDebug("type %s", val);

                if (strcmp(val, "md5") == 0) {
                    *type = DATASET_TYPE_MD5;
                } else if (strcmp(val, "sha256") == 0) {
                    *type = DATASET_TYPE_SHA256;
                } else if (strcmp(val, "string") == 0) {
                    *type = DATASET_TYPE_STRING;
                } else if (strcmp(val, "ipv4") == 0) {
                    *type = DATASET_TYPE_IPV4;
                } else if (strcmp(val, "ipv6") == 0) {
                    *type = DATASET_TYPE_IPV6;
                } else if (strcmp(val, "ip") == 0) {
                    *type = DATASET_TYPE_IPV6;
                } else {
                    SCLogError("bad type %s", val);
                    return -1;
                }

            } else if (strcmp(key, "load") == 0) {
                if (load_set) {
                    SCLogWarning("'load' can only appear once");
                    return -1;
                }
                SCLogDebug("load %s", val);
                strlcpy(load, val, load_size);
                load_set = true;
            } else if (strcmp(key, "key") == 0) {
                if (strlen(key) > json_key_size) {
                    SCLogWarning("'key' value too long (limit is %" PRIu64 ")", json_key_size);
                    return -1;
                }
                strlcpy(json_key, val, json_key_size);
                load_set = true;
            }

            if (strcmp(key, "memcap") == 0) {
                if (ParseSizeStringU64(val, memcap) < 0) {
                    SCLogWarning("invalid value for memcap: %s,"
                                 " resetting to default",
                            val);
                    *memcap = 0;
                }
            }
            if (strcmp(key, "hashsize") == 0) {
                if (ParseSizeStringU32(val, hashsize) < 0) {
                    SCLogWarning("invalid value for hashsize: %s,"
                                 " resetting to default",
                            val);
                    *hashsize = 0;
                }
            }
        }

        SCLogDebug("key: %s, value: %s", key, val);

    next:
        key = strtok_r(NULL, ",", &xsaveptr);
    }

    /* Trim trailing whitespace. */
    while (strlen(name) > 0 && isblank(name[strlen(name) - 1])) {
        name[strlen(name) - 1] = '\0';
    }

    /* Validate name, spaces are not allowed. */
    for (size_t i = 0; i < strlen(name); i++) {
        if (isblank(name[i])) {
            SCLogError("spaces not allowed in dataset names");
            return 0;
        }
    }

    return 1;
}

/** \brief wrapper around dirname that does leave input untouched */
static void GetDirName(const char *in, char *out, size_t outs)
{
    if (strlen(in) == 0) {
        return;
    }

    size_t size = strlen(in) + 1;
    char tmp[size];
    strlcpy(tmp, in, size);

    char *dir = dirname(tmp);
    BUG_ON(dir == NULL);
    strlcpy(out, dir, outs);
    return;
}

static int SetupLoadPath(const DetectEngineCtx *de_ctx, char *load, size_t load_size)
{
    SCLogDebug("load %s", load);

    if (PathIsAbsolute(load)) {
        return 0;
    }

    bool done = false;
#ifdef HAVE_LIBGEN_H
    BUG_ON(de_ctx->rule_file == NULL);

    char dir[PATH_MAX] = "";
    GetDirName(de_ctx->rule_file, dir, sizeof(dir));

    SCLogDebug("rule_file %s dir %s", de_ctx->rule_file, dir);
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, load) >= (int)sizeof(path)) // TODO windows path
        return -1;

    if (SCPathExists(path)) {
        done = true;
        strlcpy(load, path, load_size);
        SCLogDebug("using path '%s' (HAVE_LIBGEN_H)", load);
    }
#endif
    if (!done) {
        char *loadp = DetectLoadCompleteSigPath(de_ctx, load);
        if (loadp == NULL) {
            return -1;
        }
        SCLogDebug("loadp %s", loadp);

        if (SCPathExists(loadp)) {
            strlcpy(load, loadp, load_size);
            SCLogDebug("using path '%s' (non-HAVE_LIBGEN_H)", load);
        }
        SCFree(loadp);
    }
    return 0;
}

int DetectDatajsonSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectDatajsonData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t cmd = 0;
    uint64_t memcap = 0;
    uint32_t hashsize = 0;
    char cmd_str[16] = "", name[DATASET_NAME_MAX_LEN + 1] = "";
    enum DatasetTypes type = DATASET_TYPE_NOTSET;
    char load[PATH_MAX] = "";
    char json_key[SIG_JSON_CONTENT_KEY_LEN] = "";
    size_t json_key_size = SIG_JSON_CONTENT_KEY_LEN;

    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError("datajson is only supported for sticky buffers");
        SCReturnInt(-1);
    }

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET) {
        SCLogError("datajson is only supported for sticky buffers");
        SCReturnInt(-1);
    }

    if (!DetectDatajsonParse(rawstr, cmd_str, sizeof(cmd_str), name, sizeof(name), &type, load,
                sizeof(load), &memcap, &hashsize, json_key, json_key_size)) {
        return -1;
    }

    if (strcmp(cmd_str, "isset") == 0) {
        cmd = DETECT_DATAJSON_CMD_ISSET;
    } else if (strcmp(cmd_str, "isnotset") == 0) {
        cmd = DETECT_DATAJSON_CMD_ISNOTSET;
    } else {
        SCLogError("datajson action \"%s\" is not supported.", cmd_str);
        return -1;
    }

    if (strlen(load) != 0) {
        if (SetupLoadPath(de_ctx, load, sizeof(load)) != 0)
            return -1;
    }

    if (strlen(json_key) == 0) {
        SCLogError("datajson needs a key parameter");
        return -1;
    }

    SCLogDebug("name '%s' load '%s' save '%s'", name, load, save);
    Dataset *set = DatasetJsonGet(name, type, load, memcap, hashsize);
    if (set == NULL) {
        SCLogError("failed to set up datajson '%s'.", name);
        return -1;
    }
    if (set->hash && SC_ATOMIC_GET(set->hash->memcap_reached)) {
        SCLogError("datajson too large for set memcap");
        return -1;
    }

    cd = SCCalloc(1, sizeof(DetectDatajsonData));
    if (unlikely(cd == NULL))
        goto error;

    cd->set = set;
    cd->cmd = cmd;
    strlcpy(cd->json_key, json_key, json_key_size);
    cd->id = s;

    SCLogDebug("cmd %s, name %s", cmd_str, strlen(name) ? name : "(none)");

    SigMatchAppendSMToList(de_ctx, s, DETECT_DATAJSON, (SigMatchCtx *)cd, list);
    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectDatajsonFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectDatajsonData *fd = (DetectDatajsonData *)ptr;
    if (fd == NULL)
        return;

    SCFree(fd);
}
