/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 *  Implements the datarep keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "datasets.h"
#include "detect-datarep.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-misc.h"

#define PARSE_REGEX         "([a-z]+)(?:,\\s*([\\-_A-z0-9\\s\\.]+)){1,4}"
static DetectParseRegex parse_regex;

int DetectDatarepMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectDatarepSetup (DetectEngineCtx *, Signature *, const char *);
void DetectDatarepFree (DetectEngineCtx *, void *);

void DetectDatarepRegister (void)
{
    sigmatch_table[DETECT_DATAREP].name = "datarep";
    sigmatch_table[DETECT_DATAREP].desc = "operate on datasets (experimental)";
    sigmatch_table[DETECT_DATAREP].url = "/rules/dataset-keywords.html#datarep";
    sigmatch_table[DETECT_DATAREP].Setup = DetectDatarepSetup;
    sigmatch_table[DETECT_DATAREP].Free  = DetectDatarepFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/*
    1 match
    0 no match
    -1 can't match
 */
int DetectDatarepBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectDatarepData *sd,
    const uint8_t *data, const uint32_t data_len)
{
    if (data == NULL || data_len == 0)
        return 0;

    DataRepResultType r = DatasetLookupwRep(sd->set, data, data_len, &sd->rep);
    if (!r.found)
        return 0;

    switch (sd->op) {
        case DATAREP_OP_GT:
            if (r.rep.value > sd->rep.value)
                return 1;
            break;
        case DATAREP_OP_LT:
            if (r.rep.value < sd->rep.value)
                return 1;
            break;
        case DATAREP_OP_EQ:
            if (r.rep.value == sd->rep.value)
                return 1;
            break;
    }
    return 0;
}

static int DetectDatarepParse(const char *str, char *cmd, int cmd_len, char *name, int name_len,
        enum DatasetTypes *type, char *load, size_t load_size, uint16_t *rep_value,
        uint64_t *memcap, uint32_t *hashsize)
{
    bool cmd_set = false;
    bool name_set = false;
    bool value_set = false;

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

        if (!name_set) {
            if (val) {
                return -1;
            }
            strlcpy(name, key, name_len);
            name_set = true;
        } else if (!cmd_set) {
            if (val) {
                return -1;
            }
            strlcpy(cmd, key, cmd_len);
            cmd_set = true;
        } else if (!value_set) {
            if (val) {
                return -1;
            }

            if (StringParseUint16(rep_value, 10, 0, key) < 0)
                return -1;

            value_set = true;
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
                } else {
                    SCLogDebug("bad type %s", val);
                    return -1;
                }

            } else if (strcmp(key, "load") == 0) {
                SCLogDebug("load %s", val);
                strlcpy(load, val, load_size);
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

    if (strlen(load) > 0 && *type == DATASET_TYPE_NOTSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "if load is used type must be set as well");
        return 0;
    }

    if (!name_set || !cmd_set || !value_set) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "missing values");
        return 0;
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
    } else {
        SCLogDebug("path '%s' does not exist (HAVE_LIBGEN_H)", path);
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
        } else {
            SCLogDebug("path '%s' does not exist (non-HAVE_LIBGEN_H)", loadp);
        }
        SCFree(loadp);

        // TODO try data-dir as well?
    }
    return 0;
}

static int DetectDatarepSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SigMatch *sm = NULL;
    char cmd_str[16] = "", name[64] = "";
    enum DatasetTypes type = DATASET_TYPE_NOTSET;
    char load[PATH_MAX] = "";
    uint16_t value = 0;
    uint64_t memcap = 0;
    uint32_t hashsize = 0;

    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "datarep is only supported for sticky buffers");
        SCReturnInt(-1);
    }

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "datarep is only supported for sticky buffers");
        SCReturnInt(-1);
    }

    if (!DetectDatarepParse(rawstr, cmd_str, sizeof(cmd_str), name, sizeof(name), &type, load,
                sizeof(load), &value, &memcap, &hashsize)) {
        return -1;
    }

    if (strlen(load) != 0) {
        if (SetupLoadPath(de_ctx, load, sizeof(load)) != 0)
            return -1;
    }

    enum DetectDatarepOp op;
    if (strcmp(cmd_str,">") == 0) {
        op = DATAREP_OP_GT;
    } else if (strcmp(cmd_str,"<") == 0) {
        op = DATAREP_OP_LT;
    } else if (strcmp(cmd_str,"==") == 0) {
        op = DATAREP_OP_EQ;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE,
                "datarep operation \"%s\" is not supported.", cmd_str);
        return -1;
    }

    Dataset *set = DatasetGet(name, type, /* no save */ NULL, load, memcap, hashsize);
    if (set == NULL) {
        SCLogError(SC_ERR_UNKNOWN_VALUE,
                "failed to set up datarep set '%s'.", name);
        return -1;
    }

    DetectDatarepData *cd = SCCalloc(1, sizeof(DetectDatarepData));
    if (unlikely(cd == NULL))
        goto error;

    cd->set = set;
    cd->op = op;
    cd->rep.value = value;

    SCLogDebug("cmd %s, name %s",
        cmd_str, strlen(name) ? name : "(none)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DATAREP;
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

void DetectDatarepFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectDatarepData *fd = (DetectDatarepData *)ptr;

    if (fd == NULL)
        return;

    SCFree(fd);
}
