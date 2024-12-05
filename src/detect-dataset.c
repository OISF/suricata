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
#include "detect-engine-content-inspection.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-misc.h"
#include "util-path.h"
#include "util-conf.h"
#include "util-validate.h"

#define DETECT_DATASET_CMD_SET      0
#define DETECT_DATASET_CMD_UNSET    1
#define DETECT_DATASET_CMD_ISNOTSET 2
#define DETECT_DATASET_CMD_ISSET    3

#define DMD_CAP_STEP 16
typedef struct DetectDatasetMatchData_ {
    uint32_t nb;
    uint32_t *local_ids;
} DetectDatasetMatchData;

static int DetectDatasetSetup (DetectEngineCtx *, Signature *, const char *);
void DetectDatasetFree (DetectEngineCtx *, void *);

static int DetectDatasetTxMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectDatasetData *sd = (DetectDatasetData *)ctx;
    // This is only run for DETECT_SM_LIST_POSTMATCH
    DEBUG_VALIDATE_BUG_ON(sd->cmd != DETECT_DATASET_CMD_SET && sd->cmd != DETECT_DATASET_CMD_UNSET);

    // retrieve the app inspection engine associated to the list
    DetectEngineAppInspectionEngine *a = s->app_inspect;
    while (a != NULL) {
        // also check alproto as http.uri as 2 engines : http1 and http2
        if (a->sm_list == sd->list && a->alproto == f->alproto) {
            if (a->v2.Callback == DetectEngineInspectBufferGeneric) {
                // simple buffer, get data again
                const InspectionBuffer *buffer =
                        a->v2.GetData(det_ctx, a->v2.transforms, f, flags, txv, sd->list);
                if (buffer != NULL && buffer->inspect != NULL) {
                    if (sd->cmd == DETECT_DATASET_CMD_SET) {
                        DatasetAdd(sd->set, buffer->inspect, buffer->inspect_len);
                    } else if (sd->cmd == DETECT_DATASET_CMD_UNSET) {
                        DatasetRemove(sd->set, buffer->inspect, buffer->inspect_len);
                    }
                }
            } else if (a->v2.Callback == DetectEngineInspectMultiBufferGeneric) {
                DetectDatasetMatchData *dmd =
                        (DetectDatasetMatchData *)DetectThreadCtxGetKeywordThreadCtx(
                                det_ctx, sd->thread_ctx_id);
                DEBUG_VALIDATE_BUG_ON(dmd == NULL);
                uint32_t local_id = 0;
                for (uint32_t i = 0; i < dmd->nb; i++) {
                    local_id = dmd->local_ids[i];
                    InspectionBuffer *buffer = a->v2.GetMultiData(
                            det_ctx, a->v2.transforms, f, flags, txv, sd->list, local_id);
                    DEBUG_VALIDATE_BUG_ON(buffer == NULL || buffer->inspect == NULL);
                    if (sd->cmd == DETECT_DATASET_CMD_SET) {
                        DatasetAdd(sd->set, buffer->inspect, buffer->inspect_len);
                    } else if (sd->cmd == DETECT_DATASET_CMD_UNSET) {
                        DatasetRemove(sd->set, buffer->inspect, buffer->inspect_len);
                    }
                }
            }
            return 0;
        }
        a = a->next;
    }
    return 0;
}

static int DetectDatasetMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectDatasetData *sd = (DetectDatasetData *)ctx;
    // This is only run for DETECT_SM_LIST_POSTMATCH
    DEBUG_VALIDATE_BUG_ON(sd->cmd != DETECT_DATASET_CMD_SET && sd->cmd != DETECT_DATASET_CMD_UNSET);

    // retrieve the pkt inspection engine associated to the list if any (ie if list is not a app
    // inspection engine)
    DetectEnginePktInspectionEngine *e = s->pkt_inspect;
    while (e) {
        if (e->sm_list == sd->list) {
            if (e->v1.Callback == DetectEngineInspectPktBufferGeneric) {
                const InspectionBuffer *buffer =
                        e->v1.GetData(det_ctx, e->v1.transforms, p, sd->list);
                // get simple data again and add it
                if (buffer != NULL && buffer->inspect != NULL) {
                    if (sd->cmd == DETECT_DATASET_CMD_SET) {
                        DatasetAdd(sd->set, buffer->inspect, buffer->inspect_len);
                    } else if (sd->cmd == DETECT_DATASET_CMD_UNSET) {
                        DatasetRemove(sd->set, buffer->inspect, buffer->inspect_len);
                    }
                }
            }
            return 0;
        }
        e = e->next;
    }
    // return value is unused for postmatch functions
    return 0;
}

void DetectDatasetRegister (void)
{
    sigmatch_table[DETECT_DATASET].name = "dataset";
    sigmatch_table[DETECT_DATASET].desc = "match sticky buffer against datasets (experimental)";
    sigmatch_table[DETECT_DATASET].url = "/rules/dataset-keywords.html#dataset";
    sigmatch_table[DETECT_DATASET].Setup = DetectDatasetSetup;
    sigmatch_table[DETECT_DATASET].Free  = DetectDatasetFree;
    // callbacks for postmatch
    sigmatch_table[DETECT_DATASET].AppLayerTxMatch = DetectDatasetTxMatch;
    sigmatch_table[DETECT_DATASET].Match = DetectDatasetMatch;
}

/*
    1 match
    0 no match
 */
uint8_t DetectDatasetBufferMatch(DetectEngineThreadCtx *det_ctx, const DetectDatasetData *sd,
        const uint8_t *data, const uint32_t data_len, uint32_t local_id)
{
    if (data == NULL || data_len == 0)
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    int r = DatasetLookup(sd->set, data, data_len);
    SCLogDebug("r %d", r);
    switch (sd->cmd) {
        case DETECT_DATASET_CMD_ISSET: {
            if (r == 1)
                return DETECT_ENGINE_INSPECT_SIG_MATCH;
            break;
        }
        case DETECT_DATASET_CMD_ISNOTSET: {
            if (r < 1)
                return DETECT_ENGINE_INSPECT_SIG_MATCH;
            break;
        }
        case DETECT_DATASET_CMD_SET: {
            if (r == 1) {
                /* Do not match if data is already in set */
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            }
            // DatasetAdd will be performed postmatch if the rest of the sig completely matched
            DetectDatasetMatchData *dmd =
                    (DetectDatasetMatchData *)DetectThreadCtxGetKeywordThreadCtx(
                            det_ctx, sd->thread_ctx_id);
            if (dmd == NULL) {
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            }
            if (dmd->nb % DMD_CAP_STEP == 0) {
                void *tmp = SCRealloc(dmd->local_ids, sizeof(uint32_t) * (dmd->nb + DMD_CAP_STEP));
                if (tmp == NULL) {
                    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
                }
                dmd->local_ids = tmp;
            }
            dmd->local_ids[dmd->nb] = local_id;
            dmd->nb++;
            return DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_BUF;
        }
        case DETECT_DATASET_CMD_UNSET: {
            if (r == 0) {
                /* Do not match if data is not in set */
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            }
            // DatasetRemove will be performed postmatch if the rest of the sig completely matched
            DetectDatasetMatchData *dmd =
                    (DetectDatasetMatchData *)DetectThreadCtxGetKeywordThreadCtx(
                            det_ctx, sd->thread_ctx_id);
            if (dmd == NULL) {
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            }
            if (dmd->nb % DMD_CAP_STEP == 0) {
                void *tmp = SCRealloc(dmd->local_ids, sizeof(uint32_t) * (dmd->nb + DMD_CAP_STEP));
                if (tmp == NULL) {
                    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
                }
                dmd->local_ids = tmp;
            }
            dmd->local_ids[dmd->nb] = local_id;
            dmd->nb++;
            return DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_BUF;
        }
        default:
            DEBUG_VALIDATE_BUG_ON("unknown dataset command");
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
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
                    SCLogError("bad type %s", val);
                    return -1;
                }

            } else if (strcmp(key, "save") == 0) {
                if (save_set) {
                    SCLogWarning("'save' can only appear once");
                    return -1;
                }
                SCLogDebug("save %s", val);
                strlcpy(save, val, save_size);
                save_set = true;
            } else if (strcmp(key, "load") == 0) {
                if (load_set) {
                    SCLogWarning("'load' can only appear once");
                    return -1;
                }
                SCLogDebug("load %s", val);
                strlcpy(load, val, load_size);
                load_set = true;
            } else if (strcmp(key, "state") == 0) {
                if (state_set) {
                    SCLogWarning("'state' can only appear once");
                    return -1;
                }
                SCLogDebug("state %s", val);
                strlcpy(load, val, load_size);
                strlcpy(save, val, save_size);
                state_set = true;
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

    if ((load_set || save_set) && state_set) {
        SCLogWarning("'state' can not be mixed with 'load' and 'save'");
        return -1;
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

    int allow_save = 1;
    if (SCConfGetBool("datasets.rules.allow-write", &allow_save)) {
        if (!allow_save) {
            SCLogError("Rules containing save/state datasets have been disabled");
            return -1;
        }
    }

    int allow_absolute = 0;
    (void)SCConfGetBool("datasets.rules.allow-absolute-filenames", &allow_absolute);
    if (allow_absolute) {
        SCLogNotice("Allowing absolute filename for dataset rule: %s", save);
    } else {
        if (PathIsAbsolute(save)) {
            SCLogError("Absolute paths not allowed: %s", save);
            return -1;
        }

        if (SCPathContainsTraversal(save)) {
            SCLogError("Directory traversals not allowed: %s", save);
            return -1;
        }
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

static void *DetectDatasetMatchDataThreadInit(void *data)
{
    DetectDatasetMatchData *scmd = SCCalloc(1, sizeof(DetectDatasetMatchData));
    // make cocci happy
    if (unlikely(scmd == NULL))
        return NULL;
    return scmd;
}

static void DetectDatasetMatchDataThreadFree(void *ctx)
{
    if (ctx) {
        DetectDatasetMatchData *scmd = (DetectDatasetMatchData *)ctx;
        SCFree(scmd->local_ids);
        SCFree(scmd);
    }
}

int DetectDatasetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectDatasetData *cd = NULL;
    uint8_t cmd = 0;
    uint64_t memcap = 0;
    uint32_t hashsize = 0;
    char cmd_str[16] = "", name[DATASET_NAME_MAX_LEN + 1] = "";
    enum DatasetTypes type = DATASET_TYPE_NOTSET;
    char load[PATH_MAX] = "";
    char save[PATH_MAX] = "";

    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError("datasets are only supported for sticky buffers");
        SCReturnInt(-1);
    }

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET) {
        SCLogError("datasets are only supported for sticky buffers");
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
        SCLogError("dataset action \"%s\" is not supported.", cmd_str);
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
        SCLogError("failed to set up dataset '%s'.", name);
        return -1;
    }

    cd = SCCalloc(1, sizeof(DetectDatasetData));
    if (unlikely(cd == NULL))
        goto error;

    cd->set = set;
    cd->cmd = cmd;

    SCLogDebug("cmd %s, name %s",
        cmd_str, strlen(name) ? name : "(none)");

    if (cmd == DETECT_DATASET_CMD_SET || cmd == DETECT_DATASET_CMD_UNSET) {
        if (s->init_data->curbuf)
            s->init_data->curbuf->delay_postmatch = true;
        cd->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "dataset",
                DetectDatasetMatchDataThreadInit, (void *)cd, DetectDatasetMatchDataThreadFree, 0);
        if (cd->thread_ctx_id == -1)
            goto error;

        // for set operation, we need one match, and one postmatch
        DetectDatasetData *scd = SCCalloc(1, sizeof(DetectDatasetData));
        if (unlikely(scd == NULL))
            goto error;

        scd->set = set;
        scd->cmd = cmd;
        // remember the list used by match to retrieve the buffer in postmatch
        scd->list = list;
        scd->thread_ctx_id = cd->thread_ctx_id;
        if (SigMatchAppendSMToList(de_ctx, s, DETECT_DATASET, (SigMatchCtx *)scd,
                    DETECT_SM_LIST_POSTMATCH) == NULL) {
            SCFree(scd);
            goto error;
        }
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_DATASET, (SigMatchCtx *)cd, list) == NULL) {
        goto error;
    }
    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    return -1;
}

void DetectDatasetFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectDatasetData *fd = (DetectDatasetData *)ptr;
    if (fd == NULL)
        return;

    SCFree(fd);
}
