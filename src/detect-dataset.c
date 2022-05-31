/* Copyright (C) 2018-2020 Open Information Security Foundation
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
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Implements the dataset keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "datasets.h"
#include "detect-dataset.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-misc.h"
#include "util-path.h"
#include "util-conf.h"

int DetectDatasetMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectDatasetSetup (DetectEngineCtx *, Signature *, const char *);
void DetectDatasetFree (DetectEngineCtx *, void *);

void DetectDatasetRegister (void)
{
    sigmatch_table[DETECT_DATASET].name = "dataset";
    sigmatch_table[DETECT_DATASET].desc = "match sticky buffer against datasets (experimental)";
    sigmatch_table[DETECT_DATASET].url = "/rules/dataset-keywords.html#dataset";
    sigmatch_table[DETECT_DATASET].Setup = DetectDatasetSetup;
    sigmatch_table[DETECT_DATASET].Free  = DetectDatasetFree;
}

/*
    1 match
    0 no match
    -1 can't match
 */
int DetectDatasetBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectDatasetData *sd,
    const uint8_t *data, const uint32_t data_len)
{
    if (data == NULL || data_len == 0)
        return 0;

    switch (sd->cmd) {
        case DETECT_DATASET_CMD_ISSET: {
            //PrintRawDataFp(stdout, data, data_len);
            int r = DatasetLookup(sd->set, data, data_len);
            SCLogDebug("r %d", r);
            if (r == 1)
                return 1;
            break;
        }
        case DETECT_DATASET_CMD_ISNOTSET: {
            //PrintRawDataFp(stdout, data, data_len);
            int r = DatasetLookup(sd->set, data, data_len);
            SCLogDebug("r %d", r);
            if (r < 1)
                return 1;
            break;
        }
        case DETECT_DATASET_CMD_SET: {
            //PrintRawDataFp(stdout, data, data_len);
            int r = DatasetAdd(sd->set, data, data_len);
            if (r == 1)
                return 1;
            break;
        }
        default:
            abort();
    }
    return 0;
}

static int DetectDatasetParse(const char *str, char *cmd, int cmd_len, char *name, int name_len,
        enum DatasetTypes *type, char *load, size_t load_size, char *save, size_t save_size,
        uint64_t *memcap, uint32_t *hashsize)
{
    bool cmd_set = false;
    bool name_set = false;
    bool load_set = false;
    bool save_set = false;
    bool state_set = false;

    char copy[strlen(str)+1];
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
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "bad type %s", val);
                    return -1;
                }

            } else if (strcmp(key, "save") == 0) {
                if (save_set) {
                    SCLogWarning(SC_ERR_INVALID_SIGNATURE,
                        "'save' can only appear once");
                    return -1;
                }
                SCLogDebug("save %s", val);
                strlcpy(save, val, save_size);
                save_set = true;
            } else if (strcmp(key, "load") == 0) {
                if (load_set) {
                    SCLogWarning(SC_ERR_INVALID_SIGNATURE,
                        "'load' can only appear once");
                    return -1;
                }
                SCLogDebug("load %s", val);
                strlcpy(load, val, load_size);
                load_set = true;
            } else if (strcmp(key, "state") == 0) {
                if (state_set) {
                    SCLogWarning(SC_ERR_INVALID_SIGNATURE,
                        "'state' can only appear once");
                    return -1;
                }
                SCLogDebug("state %s", val);
                strlcpy(load, val, load_size);
                strlcpy(save, val, save_size);
                state_set = true;
            }
            if (strcmp(key, "memcap") == 0) {
                if (ParseSizeStringU64(val, memcap) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE,
                            "invalid value for memcap: %s,"
                            " resetting to default",
                            val);
                    *memcap = 0;
                }
            }
            if (strcmp(key, "hashsize") == 0) {
                if (ParseSizeStringU32(val, hashsize) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE,
                            "invalid value for hashsize: %s,"
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

    if ((load_set || save_set) && state_set) {
        SCLogWarning(SC_ERR_INVALID_SIGNATURE,
                "'state' can not be mixed with 'load' and 'save'");
        return -1;
    }

    /* Trim trailing whitespace. */
    while (strlen(name) > 0 && isblank(name[strlen(name) - 1])) {
        name[strlen(name) - 1] = '\0';
    }

    /* Validate name, spaces are not allowed. */
    for (size_t i = 0; i < strlen(name); i++) {
        if (isblank(name[i])) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "spaces not allowed in dataset names");
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

static int SetupLoadPath(const DetectEngineCtx *de_ctx,
        char *load, size_t load_size)
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

static int SetupSavePath(const DetectEngineCtx *de_ctx,
        char *save, size_t save_size)
{
    SCLogDebug("save %s", save);

    if (PathIsAbsolute(save)) {
        return 0;
    }

    // data dir
    const char *dir = ConfigGetDataDirectory();
    BUG_ON(dir == NULL); // should not be able to fail
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, save) >= (int)sizeof(path)) // TODO windows path
        return -1;

    /* TODO check if location exists and is writable */

    strlcpy(save, path, save_size);

    return 0;
}

int DetectDatasetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectDatasetData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t cmd = 0;
    uint64_t memcap = 0;
    uint32_t hashsize = 0;
    char cmd_str[16] = "", name[DATASET_NAME_MAX_LEN + 1] = "";
    enum DatasetTypes type = DATASET_TYPE_NOTSET;
    char load[PATH_MAX] = "";
    char save[PATH_MAX] = "";

    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "datasets are only supported for sticky buffers");
        SCReturnInt(-1);
    }

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "datasets are only supported for sticky buffers");
        SCReturnInt(-1);
    }

    if (!DetectDatasetParse(rawstr, cmd_str, sizeof(cmd_str), name, sizeof(name), &type, load,
                sizeof(load), save, sizeof(save), &memcap, &hashsize)) {
        return -1;
    }

    if (strcmp(cmd_str,"isset") == 0) {
        cmd = DETECT_DATASET_CMD_ISSET;
    } else if (strcmp(cmd_str,"isnotset") == 0) {
        cmd = DETECT_DATASET_CMD_ISNOTSET;
    } else if (strcmp(cmd_str,"set") == 0) {
        cmd = DETECT_DATASET_CMD_SET;
    } else if (strcmp(cmd_str,"unset") == 0) {
        cmd = DETECT_DATASET_CMD_UNSET;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE,
                "dataset action \"%s\" is not supported.", cmd_str);
        return -1;
    }

    /* if just 'load' is set, we load data from the same dir as the
     * rule file. If load+save is used, we use data dir */
    if (strlen(save) == 0 && strlen(load) != 0) {
        if (SetupLoadPath(de_ctx, load, sizeof(load)) != 0)
            return -1;
    /* if just 'save' is set, we use either full path or the
     * data-dir */
    } else if (strlen(save) != 0 && strlen(load) == 0) {
        if (SetupSavePath(de_ctx, save, sizeof(save)) != 0)
            return -1;
    /* use 'save' logic for 'state', but put the resulting
     * path into 'load' as well. */
    } else if (strlen(save) != 0 && strlen(load) != 0 &&
            strcmp(save, load) == 0) {
        if (SetupSavePath(de_ctx, save, sizeof(save)) != 0)
            return -1;
        strlcpy(load, save, sizeof(load));
    }

    SCLogDebug("name '%s' load '%s' save '%s'", name, load, save);
    Dataset *set = DatasetGet(name, type, save, load, memcap, hashsize);
    if (set == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "failed to set up dataset '%s'.", name);
        return -1;
    }
    if (set->hash && SC_ATOMIC_GET(set->hash->memcap_reached)) {
        SCLogError(SC_ERR_THASH_INIT, "dataset too large for set memcap");
        return -1;
    }

    cd = SCCalloc(1, sizeof(DetectDatasetData));
    if (unlikely(cd == NULL))
        goto error;

    cd->set = set;
    cd->cmd = cmd;

    SCLogDebug("cmd %s, name %s",
        cmd_str, strlen(name) ? name : "(none)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DATASET;
    sm->ctx = (SigMatchCtx *)cd;
    SigMatchAppendSMToList(s, sm, list);
    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectDatasetFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectDatasetData *fd = (DetectDatasetData *)ptr;
    if (fd == NULL)
        return;

    SCFree(fd);
}
