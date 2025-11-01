/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 *  \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements the flowbits keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "action-globals.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-flowbits.h"
#include "util-spm.h"
#include "rust.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"
#include "detect-engine-prefilter.h"

#include "tree.h"

#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-conf.h"

#define PARSE_REGEX         "^([a-z]+)(?:,\\s*(.*))?"
static DetectParseRegex parse_regex;

#define MAX_TOKENS 100

int DetectFlowbitMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlowbitSetup (DetectEngineCtx *, Signature *, const char *);
static int FlowbitOrAddData(DetectEngineCtx *, DetectFlowbitsData *, char *);
void DetectFlowbitFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void FlowBitsRegisterTests(void);
#endif
static bool PrefilterFlowbitIsPrefilterable(const Signature *s);
static int PrefilterSetupFlowbits(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

void DetectFlowbitsRegister (void)
{
    sigmatch_table[DETECT_FLOWBITS].name = "flowbits";
    sigmatch_table[DETECT_FLOWBITS].desc = "operate on flow flag";
    sigmatch_table[DETECT_FLOWBITS].url = "/rules/flow-keywords.html#flowbits";
    sigmatch_table[DETECT_FLOWBITS].Match = DetectFlowbitMatch;
    sigmatch_table[DETECT_FLOWBITS].Setup = DetectFlowbitSetup;
    sigmatch_table[DETECT_FLOWBITS].Free  = DetectFlowbitFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FLOWBITS].RegisterTests = FlowBitsRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_FLOWBITS].flags |= (SIGMATCH_IPONLY_COMPAT | SIGMATCH_SUPPORT_FIREWALL);

    sigmatch_table[DETECT_FLOWBITS].SupportsPrefilter = PrefilterFlowbitIsPrefilterable;
    sigmatch_table[DETECT_FLOWBITS].SetupPrefilter = PrefilterSetupFlowbits;
    /* all but pre_flow */
    sigmatch_table[DETECT_FLOWBITS].tables =
            DETECT_TABLE_PACKET_PRE_STREAM_FLAG | DETECT_TABLE_PACKET_FILTER_FLAG |
            DETECT_TABLE_PACKET_TD_FLAG | DETECT_TABLE_APP_FILTER_FLAG | DETECT_TABLE_APP_TD_FLAG;
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int FlowbitOrAddData(DetectEngineCtx *de_ctx, DetectFlowbitsData *cd, char *arrptr)
{
    char *strarr[MAX_TOKENS];
    char *token;
    char *saveptr = NULL;
    uint8_t i = 0;

    while ((token = strtok_r(arrptr, "|", &saveptr))) {
        // Check for leading/trailing spaces in the token
        while(isspace((unsigned char)*token))
            token++;
        if (*token == 0)
            goto next;
        char *end = token + strlen(token) - 1;
        while(end > token && isspace((unsigned char)*end))
            *(end--) = '\0';

        // Check for spaces in between the flowbit names
        if (strchr(token, ' ') != NULL) {
            SCLogError("Spaces are not allowed in flowbit names.");
            return -1;
        }

        if (i == MAX_TOKENS) {
            SCLogError("Number of flowbits exceeds "
                       "maximum allowed: %d.",
                    MAX_TOKENS);
            return -1;
        }
        strarr[i++] = token;
    next:
        arrptr = NULL;
    }
    if (i == 0) {
        SCLogError("No valid flowbits specified");
        return -1;
    }

    cd->or_list_size = i;
    cd->or_list = SCCalloc(cd->or_list_size, sizeof(uint32_t));
    if (unlikely(cd->or_list == NULL))
        return -1;
    for (uint8_t j = 0; j < cd->or_list_size ; j++) {
        uint32_t varname_id = VarNameStoreRegister(strarr[j], VAR_TYPE_FLOW_BIT);
        if (unlikely(varname_id == 0))
            return -1;
        cd->or_list[j] = varname_id;
        de_ctx->max_fb_id = MAX(cd->or_list[j], de_ctx->max_fb_id);
    }

    return 1;
}

static int DetectFlowbitMatchToggle (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return -1;

    return FlowBitToggle(p->flow, fd->idx);
}

static int DetectFlowbitMatchUnset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    FlowBitUnset(p->flow,fd->idx);

    return 1;
}

static int DetectFlowbitMatchSet (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return -1;

    int r = FlowBitSet(p->flow, fd->idx);
    SCLogDebug("set %u", fd->idx);
    return r;
}

static int DetectFlowbitMatchIsset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;
    if (fd->or_list_size > 0) {
        for (uint8_t i = 0; i < fd->or_list_size; i++) {
            if (FlowBitIsset(p->flow, fd->or_list[i]) == 1)
                return 1;
        }
        return 0;
    }

    return FlowBitIsset(p->flow,fd->idx);
}

static int DetectFlowbitMatchIsnotset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;
    if (fd->or_list_size > 0) {
        for (uint8_t i = 0; i < fd->or_list_size; i++) {
            if (FlowBitIsnotset(p->flow, fd->or_list[i]) == 1)
                return 1;
        }
        return 0;
    }
    return FlowBitIsnotset(p->flow,fd->idx);
}

/*
 * returns 0: no match (or error)
 *         1: match
 */

int DetectFlowbitMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectFlowbitsData *fd = (const DetectFlowbitsData *)ctx;
    if (fd == NULL)
        return 0;

    switch (fd->cmd) {
        case DETECT_FLOWBITS_CMD_ISSET:
            return DetectFlowbitMatchIsset(p,fd);
        case DETECT_FLOWBITS_CMD_ISNOTSET:
            return DetectFlowbitMatchIsnotset(p,fd);
        case DETECT_FLOWBITS_CMD_SET: {
            int r = DetectFlowbitMatchSet(p, fd);
            /* only on a new "set" invoke the prefilter */
            if (r == 1 && fd->post_rule_match_prefilter) {
                SCLogDebug("flowbit set, appending to work queue");
                PostRuleMatchWorkQueueAppend(det_ctx, s, DETECT_FLOWBITS, fd->idx);
            }
            return (r != -1);
        }
        case DETECT_FLOWBITS_CMD_UNSET:
            return DetectFlowbitMatchUnset(p,fd);
        case DETECT_FLOWBITS_CMD_TOGGLE: {
            int r = DetectFlowbitMatchToggle(p, fd);
            if (r == 1 && fd->post_rule_match_prefilter) {
                SCLogDebug("flowbit set (by toggle), appending to work queue");
                PostRuleMatchWorkQueueAppend(det_ctx, s, DETECT_FLOWBITS, fd->idx);
            }
            return (r != -1);
        }
        default:
            SCLogError("unknown cmd %" PRIu32 "", fd->cmd);
            return 0;
    }

    return 0;
}

static int DetectFlowbitParse(const char *str, char *cmd, int cmd_len, char *name,
    int name_len)
{
    int rc;
    size_t pcre2len;
    pcre2_match_data *match = NULL;

    int count = DetectParsePcreExec(&parse_regex, &match, str, 0, 0);
    if (count != 2 && count != 3) {
        SCLogError("\"%s\" is not a valid setting for flowbits.", str);
        goto error;
    }

    pcre2len = cmd_len;
    rc = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)cmd, &pcre2len);
    if (rc < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        goto error;
    }

    if (count == 3) {
        pcre2len = name_len;
        rc = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)name, &pcre2len);
        if (rc < 0) {
            SCLogError("pcre2_substring_copy_bynumber failed");
            goto error;
        }

        /* Trim trailing whitespace. */
        while (strlen(name) > 0 && isblank(name[strlen(name) - 1])) {
            name[strlen(name) - 1] = '\0';
        }

        if (strchr(name, '|') == NULL) {
            /* Validate name, spaces are not allowed. */
            for (size_t i = 0; i < strlen(name); i++) {
                if (isblank(name[i])) {
                    SCLogError("spaces not allowed in flowbit names");
                    goto error;
                }
            }
        }
    }

    pcre2_match_data_free(match);
    return 1;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    return 0;
}

int DetectFlowbitSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlowbitsData *cd = NULL;
    uint8_t fb_cmd = 0;
    char fb_cmd_str[16] = "", fb_name[256] = "";

    if (!DetectFlowbitParse(rawstr, fb_cmd_str, sizeof(fb_cmd_str), fb_name,
            sizeof(fb_name))) {
        return -1;
    }

    if (strcmp(fb_cmd_str,"noalert") == 0) {
        if (strlen(fb_name) != 0)
            goto error;
        s->action &= ~ACTION_ALERT;
        return 0;
    } else if (strcmp(fb_cmd_str,"isset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISSET;
    } else if (strcmp(fb_cmd_str,"isnotset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISNOTSET;
    } else if (strcmp(fb_cmd_str,"set") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_SET;
    } else if (strcmp(fb_cmd_str,"unset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_UNSET;
    } else if (strcmp(fb_cmd_str,"toggle") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_TOGGLE;
    } else {
        SCLogError("ERROR: flowbits action \"%s\" is not supported.", fb_cmd_str);
        goto error;
    }

    switch (fb_cmd) {
        case DETECT_FLOWBITS_CMD_ISNOTSET:
        case DETECT_FLOWBITS_CMD_ISSET:
        case DETECT_FLOWBITS_CMD_SET:
        case DETECT_FLOWBITS_CMD_UNSET:
        case DETECT_FLOWBITS_CMD_TOGGLE:
        default:
            if (strlen(fb_name) == 0)
                goto error;
            break;
    }

    cd = SCCalloc(1, sizeof(DetectFlowbitsData));
    if (unlikely(cd == NULL))
        goto error;
    if (strchr(fb_name, '|') != NULL) {
        int retval = FlowbitOrAddData(de_ctx, cd, fb_name);
        if (retval == -1) {
            goto error;
        }
        cd->cmd = fb_cmd;
    } else {
        uint32_t varname_id = VarNameStoreRegister(fb_name, VAR_TYPE_FLOW_BIT);
        if (unlikely(varname_id == 0))
            goto error;
        cd->idx = varname_id;
        de_ctx->max_fb_id = MAX(cd->idx, de_ctx->max_fb_id);
        cd->cmd = fb_cmd;
        cd->or_list_size = 0;
        cd->or_list = NULL;
        SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
            cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");
    }
    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    switch (fb_cmd) {
        /* noalert can't happen here */
        case DETECT_FLOWBITS_CMD_ISNOTSET:
        case DETECT_FLOWBITS_CMD_ISSET:
            /* checks, so packet list */
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FLOWBITS, (SigMatchCtx *)cd,
                        DETECT_SM_LIST_MATCH) == NULL) {
                goto error;
            }
            break;

        case DETECT_FLOWBITS_CMD_SET:
        case DETECT_FLOWBITS_CMD_UNSET:
        case DETECT_FLOWBITS_CMD_TOGGLE:
            /* modifiers, only run when entire sig has matched */
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FLOWBITS, (SigMatchCtx *)cd,
                        DETECT_SM_LIST_POSTMATCH) == NULL) {
                goto error;
            }
            break;

        // suppress coverity warning as scan-build-7 warns w/o this.
        // coverity[deadcode : FALSE]
        default:
            goto error;
    }

    return 0;

error:
    if (cd != NULL)
        DetectFlowbitFree(de_ctx, cd);
    return -1;
}

void DetectFlowbitFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlowbitsData *fd = (DetectFlowbitsData *)ptr;
    if (fd == NULL)
        return;
    VarNameStoreUnregister(fd->idx, VAR_TYPE_FLOW_BIT);
    if (fd->or_list != NULL) {
        for (uint8_t i = 0; i < fd->or_list_size; i++) {
            VarNameStoreUnregister(fd->or_list[i], VAR_TYPE_FLOW_BIT);
        }
        SCFree(fd->or_list);
    }
    SCFree(fd);
}

struct FBAnalyzer {
    struct FBAnalyze *array;
    uint32_t array_size;
};

struct FBAnalyze {
    uint16_t cnts[DETECT_FLOWBITS_CMD_MAX];
    uint16_t state_cnts[DETECT_FLOWBITS_CMD_MAX];

    uint32_t *set_sids;
    uint32_t set_sids_idx;
    uint32_t set_sids_size;

    uint32_t *isset_sids;
    uint32_t isset_sids_idx;
    uint32_t isset_sids_size;

    uint32_t *isnotset_sids;
    uint32_t isnotset_sids_idx;
    uint32_t isnotset_sids_size;

    uint32_t *unset_sids;
    uint32_t unset_sids_idx;
    uint32_t unset_sids_size;

    uint32_t *toggle_sids;
    uint32_t toggle_sids_idx;
    uint32_t toggle_sids_size;
};

extern bool rule_engine_analysis_set;
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements);

static void FBAnalyzerArrayFree(struct FBAnalyze *array, const uint32_t array_size)
{
    if (array) {
        for (uint32_t i = 0; i < array_size; i++) {
            SCFree(array[i].set_sids);
            SCFree(array[i].unset_sids);
            SCFree(array[i].isset_sids);
            SCFree(array[i].isnotset_sids);
            SCFree(array[i].toggle_sids);
        }
        SCFree(array);
    }
}

static void FBAnalyzerFree(struct FBAnalyzer *fba)
{
    if (fba && fba->array) {
        FBAnalyzerArrayFree(fba->array, fba->array_size);
        fba->array = NULL;
        fba->array_size = 0;
    }
}

#define MAX_SIDS 8
static bool CheckExpand(const uint32_t sids_idx, uint32_t **sids, uint32_t *sids_size)
{
    if (sids_idx >= *sids_size) {
        const uint32_t old_size = *sids_size;
        const uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

        void *ptr = SCRealloc(*sids, new_size * sizeof(uint32_t));
        if (ptr == NULL)
            return false;
        *sids_size = new_size;
        *sids = ptr;
    }
    return true;
}

static int DetectFlowbitsAnalyzeSignature(const Signature *s, struct FBAnalyzer *fba)
{
    struct FBAnalyze *array = fba->array;
    if (array == NULL)
        return -1;

    /* see if the signature uses stateful matching TODO is there not a flag? */
    bool has_state = (s->init_data->buffer_index != 0);

    for (const SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL;
            sm = sm->next) {
        if (sm->type != DETECT_FLOWBITS)
            continue;
        /* figure out the flowbit action */
        const DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
        // Handle flowbit array in case of ORed flowbits
        for (uint8_t k = 0; k < fb->or_list_size; k++) {
            struct FBAnalyze *fa = &array[fb->or_list[k]];
            fa->cnts[fb->cmd]++;
            fa->state_cnts[fb->cmd] += has_state;

            if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                if (!CheckExpand(fa->isset_sids_idx, &fa->isset_sids, &fa->isset_sids_size))
                    return -1;
                fa->isset_sids[fa->isset_sids_idx] = s->iid;
                fa->isset_sids_idx++;
            } else if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET) {
                if (!CheckExpand(
                            fa->isnotset_sids_idx, &fa->isnotset_sids, &fa->isnotset_sids_size))
                    return -1;
                fa->isnotset_sids[fa->isnotset_sids_idx] = s->iid;
                fa->isnotset_sids_idx++;
            }
        }
        if (fb->or_list_size == 0) {
            struct FBAnalyze *fa = &array[fb->idx];
            fa->cnts[fb->cmd]++;
            fa->state_cnts[fb->cmd] += has_state;

            if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                if (!CheckExpand(fa->isset_sids_idx, &fa->isset_sids, &fa->isset_sids_size))
                    return -1;
                fa->isset_sids[fa->isset_sids_idx] = s->iid;
                fa->isset_sids_idx++;
            } else if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET) {
                if (!CheckExpand(
                            fa->isnotset_sids_idx, &fa->isnotset_sids, &fa->isnotset_sids_size))
                    return -1;
                fa->isnotset_sids[fa->isnotset_sids_idx] = s->iid;
                fa->isnotset_sids_idx++;
            }
        }
    }
    for (const SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_POSTMATCH]; sm != NULL;
            sm = sm->next) {
        if (sm->type != DETECT_FLOWBITS)
            continue;
        /* figure out what flowbit action */
        const DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
        struct FBAnalyze *fa = &array[fb->idx];
        fa->cnts[fb->cmd]++;
        fa->state_cnts[fb->cmd] += has_state;

        if (fb->cmd == DETECT_FLOWBITS_CMD_SET) {
            if (!CheckExpand(fa->set_sids_idx, &fa->set_sids, &fa->set_sids_size))
                return -1;
            fa->set_sids[fa->set_sids_idx] = s->iid;
            fa->set_sids_idx++;
        } else if (fb->cmd == DETECT_FLOWBITS_CMD_UNSET) {
            if (!CheckExpand(fa->unset_sids_idx, &fa->unset_sids, &fa->unset_sids_size))
                return -1;
            fa->unset_sids[fa->unset_sids_idx] = s->iid;
            fa->unset_sids_idx++;
        } else if (fb->cmd == DETECT_FLOWBITS_CMD_TOGGLE) {
            if (!CheckExpand(fa->toggle_sids_idx, &fa->toggle_sids, &fa->toggle_sids_size))
                return -1;
            fa->toggle_sids[fa->toggle_sids_idx] = s->iid;
            fa->toggle_sids_idx++;
        }
    }
    return 0;
}

int DetectFlowbitsAnalyze(DetectEngineCtx *de_ctx)
{
    const uint32_t max_fb_id = de_ctx->max_fb_id;
    if (max_fb_id == 0)
        return 0;

    struct FBAnalyzer fba = { .array = NULL, .array_size = 0 };
    const uint32_t array_size = max_fb_id + 1;
    struct FBAnalyze *array = SCCalloc(array_size, sizeof(struct FBAnalyze));
    if (array == NULL) {
        SCLogError("Unable to allocate flowbit analyze array");
        return -1;
    }
    fba.array = array;
    fba.array_size = array_size;

    SCLogDebug("fb analyzer array size: %"PRIu64,
            (uint64_t)(array_size * sizeof(struct FBAnalyze)));

    /* fill flowbit array, updating counters per sig */
    for (uint32_t i = 0; i < de_ctx->sig_array_len; i++) {
        const Signature *s = de_ctx->sig_array[i];

        int r = DetectFlowbitsAnalyzeSignature(s, &fba);
        if (r < 0) {
            FBAnalyzerFree(&fba);
            return -1;
        }
    }

    /* walk array to see if all bits make sense */
    for (uint32_t i = 0; i < array_size; i++) {
        const char *varname = VarNameStoreSetupLookup(i, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        bool to_state = false;

        if (array[i].cnts[DETECT_FLOWBITS_CMD_ISSET] &&
            array[i].cnts[DETECT_FLOWBITS_CMD_TOGGLE] == 0 &&
            array[i].cnts[DETECT_FLOWBITS_CMD_SET] == 0) {

            const Signature *s = de_ctx->sig_array[array[i].isset_sids[0]];
            SCLogWarning("flowbit '%s' is checked but not "
                         "set. Checked in %u and %u other sigs",
                    varname, s->id, array[i].isset_sids_idx - 1);
        }
        if (array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET] &&
            array[i].state_cnts[DETECT_FLOWBITS_CMD_SET] == 0)
        {
            SCLogDebug("flowbit %s/%u: isset in state, set not in state", varname, i);
        }

        /* if signature depends on 'stateful' flowbits, then turn the
         * sig into a stateful sig itself */
        if (array[i].cnts[DETECT_FLOWBITS_CMD_ISSET] > 0 &&
            array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET] == 0 &&
            array[i].state_cnts[DETECT_FLOWBITS_CMD_SET])
        {
            SCLogDebug("flowbit %s/%u: isset not in state, set in state", varname, i);
            to_state = true;
        }

        SCLogDebug("ALL flowbit %s/%u: sets %u toggles %u unsets %u isnotsets %u issets %u", varname, i,
                array[i].cnts[DETECT_FLOWBITS_CMD_SET], array[i].cnts[DETECT_FLOWBITS_CMD_TOGGLE],
                array[i].cnts[DETECT_FLOWBITS_CMD_UNSET], array[i].cnts[DETECT_FLOWBITS_CMD_ISNOTSET],
                array[i].cnts[DETECT_FLOWBITS_CMD_ISSET]);
        SCLogDebug("STATE flowbit %s/%u: sets %u toggles %u unsets %u isnotsets %u issets %u", varname, i,
                array[i].state_cnts[DETECT_FLOWBITS_CMD_SET], array[i].state_cnts[DETECT_FLOWBITS_CMD_TOGGLE],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_UNSET], array[i].state_cnts[DETECT_FLOWBITS_CMD_ISNOTSET],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET]);
        for (uint32_t x = 0; x < array[i].set_sids_idx; x++) {
            SCLogDebug("SET flowbit %s/%u: SID %u", varname, i,
                    de_ctx->sig_array[array[i].set_sids[x]]->id);
        }
        if (to_state) {
            for (uint32_t x = 0; x < array[i].isset_sids_idx; x++) {
                Signature *s = de_ctx->sig_array[array[i].isset_sids[x]];
                SCLogDebug("GET flowbit %s/%u: SID %u", varname, i, s->id);

                s->init_data->init_flags |= SIG_FLAG_INIT_STATE_MATCH;
                s->init_data->is_rule_state_dependant = true;

                uint32_t sids_array_size = array[i].set_sids_idx;

                // save information about flowbits that affect this rule's state
                if (s->init_data->rule_state_dependant_sids_array == NULL) {
                    s->init_data->rule_state_dependant_sids_array =
                            SCCalloc(sids_array_size, sizeof(uint32_t));
                    if (s->init_data->rule_state_dependant_sids_array == NULL) {
                        SCLogError("Failed to allocate memory for rule_state_dependant_ids");
                        goto error;
                    }
                    s->init_data->rule_state_flowbits_ids_size = 1;
                    s->init_data->rule_state_flowbits_ids_array =
                            SCCalloc(s->init_data->rule_state_flowbits_ids_size, sizeof(uint32_t));
                    if (s->init_data->rule_state_flowbits_ids_array == NULL) {
                        SCLogError("Failed to allocate memory for rule_state_variable_idx");
                        goto error;
                    }
                    s->init_data->rule_state_dependant_sids_size = sids_array_size;
                    SCLogDebug("alloc'ed array for rule dependency and fbs idx array, sid %u, "
                               "sizes are %u and %u",
                            s->id, s->init_data->rule_state_dependant_sids_size,
                            s->init_data->rule_state_flowbits_ids_size);
                } else {
                    uint32_t new_array_size =
                            s->init_data->rule_state_dependant_sids_size + sids_array_size;
                    void *tmp_ptr = SCRealloc(s->init_data->rule_state_dependant_sids_array,
                            new_array_size * sizeof(uint32_t));
                    if (tmp_ptr == NULL) {
                        SCLogError("Failed to allocate memory for rule_state_variable_idx");
                        goto error;
                    }
                    s->init_data->rule_state_dependant_sids_array = tmp_ptr;
                    s->init_data->rule_state_dependant_sids_size = new_array_size;
                    SCLogDebug("realloc'ed array for rule dependency, sid %u, new size is %u",
                            s->id, s->init_data->rule_state_dependant_sids_size);
                    uint32_t new_fb_array_size = s->init_data->rule_state_flowbits_ids_size + 1;
                    void *tmp_fb_ptr = SCRealloc(s->init_data->rule_state_flowbits_ids_array,
                            new_fb_array_size * sizeof(uint32_t));
                    s->init_data->rule_state_flowbits_ids_array = tmp_fb_ptr;
                    if (s->init_data->rule_state_flowbits_ids_array == NULL) {
                        SCLogError("Failed to reallocate memory for rule_state_variable_idx");
                        goto error;
                    }
                    SCLogDebug(
                            "realloc'ed array for flowbits ids, new size is %u", new_fb_array_size);
                    s->init_data->rule_state_dependant_sids_size = new_array_size;
                    s->init_data->rule_state_flowbits_ids_size = new_fb_array_size;
                }
                for (uint32_t idx = 0; idx < s->init_data->rule_state_dependant_sids_size; idx++) {
                    if (idx < array[i].set_sids_idx) {
                        s->init_data->rule_state_dependant_sids_array
                                [s->init_data->rule_state_dependant_sids_idx] =
                                de_ctx->sig_array[array[i].set_sids[idx]]->id;
                        s->init_data->rule_state_dependant_sids_idx++;
                    }
                }
                s->init_data
                        ->rule_state_flowbits_ids_array[s->init_data->rule_state_flowbits_ids_size -
                                                        1] = i;
                s->init_data->rule_state_flowbits_ids_size += 1;
                // flowbit info saving for rule made stateful rule work finished

                SCLogDebug("made SID %u stateful because it depends on "
                        "stateful rules that set flowbit %s", s->id, varname);
            }
        }
    }

    if (rule_engine_analysis_set) {
        DetectFlowbitsAnalyzeDump(de_ctx, array, array_size);
    }

    FBAnalyzerFree(&fba);
    return 0;
error:
    FBAnalyzerFree(&fba);
    return -1;
}

// TODO misses IPOnly rules. IPOnly flowbit rules are set only though.
static struct FBAnalyzer DetectFlowbitsAnalyzeForGroup(
        const DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    struct FBAnalyzer fba = { .array = NULL, .array_size = 0 };

    const uint32_t max_fb_id = de_ctx->max_fb_id;
    if (max_fb_id == 0)
        return fba;

    uint32_t array_size = max_fb_id + 1;
    struct FBAnalyze *array = SCCalloc(array_size, sizeof(struct FBAnalyze));
    if (array == NULL) {
        SCLogError("Unable to allocate flowbit analyze array");
        return fba;
    }
    SCLogDebug(
            "fb analyzer array size: %" PRIu64, (uint64_t)(array_size * sizeof(struct FBAnalyze)));
    fba.array = array;
    fba.array_size = array_size;

    /* fill flowbit array, updating counters per sig */
    for (uint32_t i = 0; i < sgh->init->sig_cnt; i++) {
        const Signature *s = sgh->init->match_array[i];
        SCLogDebug("sgh %p: s->id %u", sgh, s->id);

        int r = DetectFlowbitsAnalyzeSignature(s, &fba);
        if (r < 0) {
            FBAnalyzerFree(&fba);
            return fba;
        }
    }

    /* walk array to see if all bits make sense */
    for (uint32_t i = 0; i < array_size; i++) {
        const char *varname = VarNameStoreSetupLookup(i, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        bool to_state = false;
        if (array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET] &&
                array[i].state_cnts[DETECT_FLOWBITS_CMD_SET] == 0) {
            SCLogDebug("flowbit %s/%u: isset in state, set not in state", varname, i);
        }

        /* if signature depends on 'stateful' flowbits, then turn the
         * sig into a stateful sig itself */
        if (array[i].cnts[DETECT_FLOWBITS_CMD_ISSET] > 0 &&
                array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET] == 0 &&
                array[i].state_cnts[DETECT_FLOWBITS_CMD_SET]) {
            SCLogDebug("flowbit %s/%u: isset not in state, set in state", varname, i);
            to_state = true;
        }

        SCLogDebug("ALL flowbit %s/%u: sets %u toggles %u unsets %u isnotsets %u issets %u",
                varname, i, array[i].cnts[DETECT_FLOWBITS_CMD_SET],
                array[i].cnts[DETECT_FLOWBITS_CMD_TOGGLE], array[i].cnts[DETECT_FLOWBITS_CMD_UNSET],
                array[i].cnts[DETECT_FLOWBITS_CMD_ISNOTSET],
                array[i].cnts[DETECT_FLOWBITS_CMD_ISSET]);
        SCLogDebug("STATE flowbit %s/%u: sets %u toggles %u unsets %u isnotsets %u issets %u",
                varname, i, array[i].state_cnts[DETECT_FLOWBITS_CMD_SET],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_TOGGLE],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_UNSET],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_ISNOTSET],
                array[i].state_cnts[DETECT_FLOWBITS_CMD_ISSET]);
        for (uint32_t x = 0; x < array[i].set_sids_idx; x++) {
            SCLogDebug("SET flowbit %s/%u: SID %u", varname, i,
                    de_ctx->sig_array[array[i].set_sids[x]]->id);
        }
        for (uint32_t x = 0; x < array[i].isset_sids_idx; x++) {
            Signature *s = de_ctx->sig_array[array[i].isset_sids[x]];
            SCLogDebug("GET flowbit %s/%u: SID %u", varname, i, s->id);

            if (to_state) {
                s->init_data->init_flags |= SIG_FLAG_INIT_STATE_MATCH;
                SCLogDebug("made SID %u stateful because it depends on "
                           "stateful rules that set flowbit %s",
                        s->id, varname);
            }
        }
    }

    return fba;
}

SCMutex g_flowbits_dump_write_m = SCMUTEX_INITIALIZER;
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements)
{
    SCJsonBuilder *js = SCJbNewObject();
    if (js == NULL)
        return;

    SCJbOpenArray(js, "flowbits");
    for (uint32_t x = 0; x < elements; x++) {
        const char *varname = VarNameStoreSetupLookup(x, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        const struct FBAnalyze *e = &array[x];

        SCJbStartObject(js);
        SCJbSetString(js, "name", varname);
        SCJbSetUint(js, "internal_id", x);
        SCJbSetUint(js, "set_cnt", e->cnts[DETECT_FLOWBITS_CMD_SET]);
        SCJbSetUint(js, "unset_cnt", e->cnts[DETECT_FLOWBITS_CMD_UNSET]);
        SCJbSetUint(js, "toggle_cnt", e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]);
        SCJbSetUint(js, "isset_cnt", e->cnts[DETECT_FLOWBITS_CMD_ISSET]);
        SCJbSetUint(js, "isnotset_cnt", e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]);

        // sets
        if (e->cnts[DETECT_FLOWBITS_CMD_SET]) {
            SCJbOpenArray(js, "sets");
            for (uint32_t i = 0; i < e->set_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->set_sids[i]];
                SCJbAppendUint(js, s->id);
            }
            SCJbClose(js);
        }
        // gets
        if (e->cnts[DETECT_FLOWBITS_CMD_ISSET]) {
            SCJbOpenArray(js, "isset");
            for (uint32_t i = 0; i < e->isset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->isset_sids[i]];
                SCJbAppendUint(js, s->id);
            }
            SCJbClose(js);
        }
        // isnotset
        if (e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]) {
            SCJbOpenArray(js, "isnotset");
            for (uint32_t i = 0; i < e->isnotset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->isnotset_sids[i]];
                SCJbAppendUint(js, s->id);
            }
            SCJbClose(js);
        }
        // unset
        if (e->cnts[DETECT_FLOWBITS_CMD_UNSET]) {
            SCJbOpenArray(js, "unset");
            for (uint32_t i = 0; i < e->unset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->unset_sids[i]];
                SCJbAppendUint(js, s->id);
            }
            SCJbClose(js);
        }
        // toggle
        if (e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]) {
            SCJbOpenArray(js, "toggle");
            for (uint32_t i = 0; i < e->toggle_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->toggle_sids[i]];
                SCJbAppendUint(js, s->id);
            }
            SCJbClose(js);
        }
        SCJbClose(js);
    }
    SCJbClose(js); // array
    SCJbClose(js); // object

    const char *filename = "flowbits.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_flowbits_dump_write_m);
    FILE *fp = fopen(log_path, "w");
    if (fp != NULL) {
        fwrite(SCJbPtr(js), SCJbLen(js), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_flowbits_dump_write_m);

    SCJbFree(js);
}

static bool PrefilterFlowbitIsPrefilterable(const Signature *s)
{
    SCLogDebug("sid:%u: checking", s->id);

    for (const SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL;
            sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLOWBITS: {
                const DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
                if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                    SCLogDebug("sid:%u: FLOWBITS ISSET can prefilter", s->id);
                    return true;
                }
                break;
            }
        }
    }
    SCLogDebug("sid:%u: no flowbit prefilter", s->id);
    return false;
}

/** core flowbit data structure: map a flowbit id to the signatures that need inspecting after it is
 * found. Part of a rb-tree. */
typedef struct PrefilterFlowbit {
    uint32_t id;           /**< flowbit id */
    uint32_t rule_id_size; /**< size in elements of `rule_id` */
    uint32_t rule_id_cnt;  /**< usage in elements of `rule_id` */
    uint32_t *rule_id;     /**< array of signature iid that are part of this prefilter */
    RB_ENTRY(PrefilterFlowbit) __attribute__((__packed__)) rb;
} __attribute__((__packed__)) PrefilterFlowbit;

static int PrefilterFlowbitCompare(const PrefilterFlowbit *a, const PrefilterFlowbit *b)
{
    if (a->id > b->id)
        return 1;
    else if (a->id < b->id)
        return -1;
    else
        return 0;
}

/** red-black tree prototype for PFB (Prefilter Flow Bits) */
RB_HEAD(PFB, PrefilterFlowbit);
RB_PROTOTYPE(PFB, PrefilterFlowbit, rb, PrefilterFlowbitCompare);
RB_GENERATE(PFB, PrefilterFlowbit, rb, PrefilterFlowbitCompare);

struct PrefilterEngineFlowbits {
    struct PFB fb_tree;
};

static void PrefilterFlowbitFree(void *vctx)
{
    struct PrefilterEngineFlowbits *ctx = vctx;
    struct PrefilterFlowbit *rec, *safe = NULL;
    RB_FOREACH_SAFE (rec, PFB, &ctx->fb_tree, safe) {
        PFB_RB_REMOVE(&ctx->fb_tree, rec);
        SCFree(rec->rule_id);
        SCFree(rec);
    }

    SCFree(ctx);
}

static void PrefilterFlowbitMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    struct PrefilterEngineFlowbits *ctx = (struct PrefilterEngineFlowbits *)pectx;
    SCLogDebug("%" PRIu64 ": ctx %p", p->pcap_cnt, ctx);

    if (p->flow == NULL) {
        SCReturn;
    }

    for (GenericVar *gv = p->flow->flowvar; gv != NULL; gv = gv->next) {
        if (gv->type != DETECT_FLOWBITS)
            continue;

        PrefilterFlowbit lookup;
        memset(&lookup, 0, sizeof(lookup));
        lookup.id = gv->idx;
        SCLogDebug("flowbit %u", gv->idx);

        PrefilterFlowbit *b = PFB_RB_FIND(&ctx->fb_tree, &lookup);
        if (b == NULL) {
            SCLogDebug("flowbit %u not in the tree", lookup.id);
        } else {
            SCLogDebug("flowbit %u found in the tree: %u", lookup.id, b->id);

            PrefilterAddSids(&det_ctx->pmq, b->rule_id, b->rule_id_cnt);
#ifdef DEBUG
            for (uint32_t x = 0; x < b->rule_id_cnt; x++) {
                const Signature *s = det_ctx->de_ctx->sig_array[b->rule_id[x]];
                SCLogDebug("flowbit %u -> sig %u", gv->idx, s->id);
            }
#endif
        }
    }
}

static void PrefilterFlowbitPostRuleMatch(
        DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f)
{
    struct PrefilterEngineFlowbits *ctx = (struct PrefilterEngineFlowbits *)pectx;
    SCLogDebug("%" PRIu64 ": ctx %p", p->pcap_cnt, ctx);

    if (p->flow == NULL) {
        SCReturn;
    }

    for (uint32_t i = 0; i < det_ctx->post_rule_work_queue.len; i++) {
        const PostRuleMatchWorkQueueItem *w = &det_ctx->post_rule_work_queue.q[i];
        if (w->sm_type != DETECT_FLOWBITS)
            continue;

        PrefilterFlowbit lookup;
        memset(&lookup, 0, sizeof(lookup));
        lookup.id = w->value;

        PrefilterFlowbit *b = PFB_RB_FIND(&ctx->fb_tree, &lookup);
        if (b == NULL) {
            SCLogDebug("flowbit %u not in the tree", lookup.id);
        } else {
            SCLogDebug("flowbit %u found in the tree: %u. Adding %u sids", lookup.id, b->id,
                    b->rule_id_cnt);
            PrefilterAddSids(&det_ctx->pmq, b->rule_id, b->rule_id_cnt);
#ifdef DEBUG
            // SCLogDebug("b %u", b->rule_id_cnt);
            for (uint32_t x = 0; x < b->rule_id_cnt; x++) {
                Signature *s = det_ctx->de_ctx->sig_array[b->rule_id[x]];
                SCLogDebug("flowbit %u -> sig %u (triggered by %u)", w->value, s->id,
                        det_ctx->de_ctx->sig_array[w->id]->id);
            }
#endif
        }
    }
}

#define BLOCK_SIZE 8

static int AddBitAndSid(
        struct PrefilterEngineFlowbits *ctx, const Signature *s, const uint32_t flowbit_id)
{
    PrefilterFlowbit x;
    memset(&x, 0, sizeof(x));
    x.id = flowbit_id;

    PrefilterFlowbit *pfb = PFB_RB_FIND(&ctx->fb_tree, &x);
    if (pfb == NULL) {
        PrefilterFlowbit *add = SCCalloc(1, sizeof(*add));
        if (add == NULL)
            return -1;

        add->id = flowbit_id;
        add->rule_id = SCCalloc(1, BLOCK_SIZE * sizeof(uint32_t));
        if (add->rule_id == NULL) {
            SCFree(add);
            return -1;
        }
        add->rule_id_size = BLOCK_SIZE;
        add->rule_id_cnt = 1;
        add->rule_id[0] = s->iid;

        PrefilterFlowbit *res = PFB_RB_INSERT(&ctx->fb_tree, add);
        SCLogDebug("not found, so added (res %p)", res);
        if (res != NULL) {
            // duplicate, shouldn't be possible after the FIND above
            BUG_ON(1);
            return -1;
        }
    } else {
        SCLogDebug("found! pfb %p id %u", pfb, pfb->id);

        if (pfb->rule_id_cnt < pfb->rule_id_size) {
            pfb->rule_id[pfb->rule_id_cnt++] = s->iid;
        } else {
            uint32_t *ptr =
                    SCRealloc(pfb->rule_id, (pfb->rule_id_size + BLOCK_SIZE) * sizeof(uint32_t));
            if (ptr == NULL) {
                // memory stays in the tree
                return -1;
            }
            pfb->rule_id = ptr;
            pfb->rule_id_size += BLOCK_SIZE;
            pfb->rule_id[pfb->rule_id_cnt++] = s->iid;
        }
    }
    return 0;
}

static int AddBitsAndSid(const DetectEngineCtx *de_ctx, struct PrefilterEngineFlowbits *ctx,
        const DetectFlowbitsData *fb, const Signature *s)
{
    if (fb->or_list_size == 0) {
        if (AddBitAndSid(ctx, s, fb->idx) < 0) {
            return -1;
        }
    } else {
        for (uint8_t i = 0; i < fb->or_list_size; i++) {
            SCLogDebug("flowbit OR: bit %u", fb->or_list[i]);
            if (AddBitAndSid(ctx, s, fb->or_list[i]) < 0) {
                return -1;
            }
        }
    }
    return 0;
}

static uint32_t NextMultiple(const uint32_t v, const uint32_t m)
{
    return v + (m - v % m);
}

/** \internal
 *  \brief adds sids for 'isset' prefilter flowbits
 *  \retval int 1 if we added sid(s), 0 if we didn't, -1 on error */
// TODO skip sids that aren't set by this sgh
// TODO skip sids that doesn't have a isset in the same direction
static int AddIssetSidsForBit(const DetectEngineCtx *de_ctx, const struct FBAnalyzer *fba,
        const DetectFlowbitsData *fb, PrefilterFlowbit *add)
{
    int added = 0;
    for (uint32_t i = 0; i < fba->array[fb->idx].isset_sids_idx; i++) {
        const uint32_t sig_iid = fba->array[fb->idx].isset_sids[i];
        const Signature *s = de_ctx->sig_array[sig_iid];
        SCLogDebug("flowbit: %u => considering sid %u (iid:%u)", fb->idx, s->id, s->iid);

        /* Skip sids that aren't prefilter. These would just run all the time. */
        if (s->init_data->prefilter_sm == NULL ||
                s->init_data->prefilter_sm->type != DETECT_FLOWBITS) {
#ifdef DEBUG
            const char *name = s->init_data->prefilter_sm
                                       ? sigmatch_table[s->init_data->prefilter_sm->type].name
                                       : "none";
            SCLogDebug("flowbit: %u => rejected sid %u (iid:%u). No prefilter or prefilter not "
                       "flowbits (%p, %s, %d)",
                    fb->idx, s->id, sig_iid, s->init_data->prefilter_sm, name,
                    s->init_data->prefilter_sm ? s->init_data->prefilter_sm->type : -1);
#endif
            continue;
        }

        /* only add sids that match our bit */
        const DetectFlowbitsData *fs_fb =
                (const DetectFlowbitsData *)s->init_data->prefilter_sm->ctx;
        if (fs_fb->idx != fb->idx) {
            SCLogDebug(
                    "flowbit: %u => rejected sid %u (iid:%u). Sig prefilters on different bit %u",
                    fb->idx, s->id, sig_iid, fs_fb->idx);
            continue;
        }

        bool dup = false;
        for (uint32_t x = 0; x < add->rule_id_cnt; x++) {
            if (add->rule_id[x] == sig_iid) {
                dup = true;
            }
        }

        if (!dup) {
            if (add->rule_id_cnt < add->rule_id_size) {
                add->rule_id[add->rule_id_cnt++] = sig_iid;
            } else {
                uint32_t *ptr = SCRealloc(
                        add->rule_id, (add->rule_id_size + BLOCK_SIZE) * sizeof(uint32_t));
                if (ptr == NULL) {
                    return -1;
                }
                add->rule_id = ptr;
                add->rule_id_size += BLOCK_SIZE;
                add->rule_id[add->rule_id_cnt++] = sig_iid;
            }
            added = 1;
            SCLogDebug("flowbit: %u => accepted sid %u (iid:%u)", fb->idx, s->id, sig_iid);
        }
    }
    return added;
}

/* TODO shouldn't add sids for which Signature::num is < our num. Is this possible after sorting? */

/** \brief For set/toggle flowbits, build "set" post-rule-match engine
 *
 *  For set/toggle flowbits, a special post-rule-match engine is constructed
 *  to update the running match array during rule matching.
 */
static int AddBitSetToggle(const DetectEngineCtx *de_ctx, struct FBAnalyzer *fba,
        struct PrefilterEngineFlowbits *ctx, const DetectFlowbitsData *fb, const Signature *s)
{
    PrefilterFlowbit x;
    memset(&x, 0, sizeof(x));
    x.id = fb->idx;
    PrefilterFlowbit *pfb = PFB_RB_FIND(&ctx->fb_tree, &x);
    if (pfb == NULL) {
        PrefilterFlowbit *add = SCCalloc(1, sizeof(*add));
        if (add == NULL)
            return -1;

        add->id = fb->idx;
        add->rule_id_size = NextMultiple(fba->array[fb->idx].isset_sids_idx, BLOCK_SIZE);
        add->rule_id = SCCalloc(1, add->rule_id_size * sizeof(uint32_t));
        if (add->rule_id == NULL) {
            SCFree(add);
            return -1;
        }

        if (AddIssetSidsForBit(de_ctx, fba, fb, add) != 1) {
            SCLogDebug("no sids added");
            SCFree(add->rule_id);
            SCFree(add);
            return 0;
        }
        PrefilterFlowbit *res = PFB_RB_INSERT(&ctx->fb_tree, add);
        SCLogDebug("not found, so added (res %p)", res);
        BUG_ON(res != NULL); // TODO if res != NULL we have a duplicate which should be impossible
    } else {
        SCLogDebug("found! pfb %p id %u", pfb, pfb->id);

        int r = AddIssetSidsForBit(de_ctx, fba, fb, pfb);
        if (r < 0) {
            return -1;
        } else if (r == 0) {
            SCLogDebug("no sids added");
            return 0;
        }
    }
    return 1;
}

/** \brief build flowbit prefilter state(s)
 *
 *  Build "set" and "isset" states.
 *
 *  For each flowbit "isset" in the sgh, we need to check:
 *  1. is it supported
 *  2. is prefilter enabled
 *  3. does it match in the same dir or only opposing dir
 */
static int PrefilterSetupFlowbits(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL)
        return 0;

    SCLogDebug("sgh %p: setting up prefilter", sgh);
    struct PrefilterEngineFlowbits *isset_ctx = NULL;
    struct PrefilterEngineFlowbits *set_ctx = NULL;

    struct FBAnalyzer fb_analysis = DetectFlowbitsAnalyzeForGroup(de_ctx, sgh);
    if (fb_analysis.array == NULL)
        goto error;

    for (uint32_t i = 0; i < sgh->init->sig_cnt; i++) {
        Signature *s = sgh->init->match_array[i];
        if (s == NULL)
            continue;

        SCLogDebug("checking sid %u", s->id);

        /* first build the 'set' state */
        for (SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_POSTMATCH]; sm != NULL;
                sm = sm->next) {
            if (sm->type != DETECT_FLOWBITS) {
                SCLogDebug("skip non flowbits sm");
                continue;
            }

            DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
            if (fb->cmd == DETECT_FLOWBITS_CMD_SET) {
                SCLogDebug(
                        "DETECT_SM_LIST_POSTMATCH: sid %u DETECT_FLOWBITS set %u", s->id, fb->idx);
            } else if (fb->cmd == DETECT_FLOWBITS_CMD_TOGGLE) {
                SCLogDebug("DETECT_SM_LIST_POSTMATCH: sid %u DETECT_FLOWBITS toggle %u", s->id,
                        fb->idx);
            } else {
                SCLogDebug("unsupported flowbits setting");
                continue;
            }

            if (fb_analysis.array[fb->idx].isnotset_sids_idx ||
                    fb_analysis.array[fb->idx].unset_sids_idx) {
                SCLogDebug("flowbit %u not supported: unset in use", fb->idx);
                continue;
            }

            if (set_ctx == NULL) {
                set_ctx = SCCalloc(1, sizeof(*set_ctx));
                if (set_ctx == NULL)
                    goto error;
            }

            SCLogDebug("setting up sets/toggles for sid %u", s->id);
            if (AddBitSetToggle(de_ctx, &fb_analysis, set_ctx, fb, s) == 1) {
                // flag the set/toggle to trigger the post-rule match logic
                SCLogDebug("set up sets/toggles for sid %u", s->id);
                fb->post_rule_match_prefilter = true;
            }

            // TODO don't add for sigs that don't have isset in this sgh. Reasoning:
            // prefilter post match logic only makes sense in the same dir as otherwise
            // the regular 'isset' logic can simply run with the regular prefilters
            // before the rule loop
        }

        /* next, build the 'isset' state */
        if (s->init_data->prefilter_sm == NULL ||
                s->init_data->prefilter_sm->type != DETECT_FLOWBITS) {
            SCLogDebug("no prefilter or prefilter not flowbits");
            continue;
        }

        const DetectFlowbitsData *fb = (DetectFlowbitsData *)s->init_data->prefilter_sm->ctx;
        if (fb_analysis.array[fb->idx].isnotset_sids_idx ||
                fb_analysis.array[fb->idx].unset_sids_idx) {
            SCLogDebug("flowbit %u not supported: toggle or unset in use", fb->idx);
            s->init_data->prefilter_sm = NULL;
            s->flags &= ~SIG_FLAG_PREFILTER;
            continue;
        }

        SCLogDebug("isset: adding sid %u, flowbit %u", s->id, fb->idx);

        if (isset_ctx == NULL) {
            isset_ctx = SCCalloc(1, sizeof(*isset_ctx));
            if (isset_ctx == NULL)
                goto error;
        }
        if (AddBitsAndSid(de_ctx, isset_ctx, fb, s) < 0) {
            goto error;
        }
    }

    /* finally, register the states with their engines */
    static const char *g_prefilter_flowbits_isset = "flowbits:isset";
    if (isset_ctx != NULL) {
        enum SignatureHookPkt hook = SIGNATURE_HOOK_PKT_NOT_SET; // TODO review
        PrefilterAppendEngine(de_ctx, sgh, PrefilterFlowbitMatch, SIG_MASK_REQUIRE_FLOW, hook,
                isset_ctx, PrefilterFlowbitFree, g_prefilter_flowbits_isset);
        SCLogDebug("isset: added prefilter engine");

        if (set_ctx != NULL && !RB_EMPTY(&set_ctx->fb_tree)) {
            static const char *g_prefilter_flowbits_set = "flowbits:set";
            PrefilterAppendPostRuleEngine(de_ctx, sgh, PrefilterFlowbitPostRuleMatch, set_ctx,
                    PrefilterFlowbitFree, g_prefilter_flowbits_set);
            SCLogDebug("set/toggle: added prefilter engine");
        } else {
            if (set_ctx) {
                PrefilterFlowbitFree(set_ctx);
            }
            SCLogDebug("set/toggle: NO prefilter engine added");
        }
    } else if (set_ctx != NULL) {
        PrefilterFlowbitFree(set_ctx);
    }
    FBAnalyzerFree(&fb_analysis);
    return 0;

error:
    if (set_ctx) {
        PrefilterFlowbitFree(set_ctx);
    }
    if (isset_ctx) {
        PrefilterFlowbitFree(isset_ctx);
    }
    FBAnalyzerFree(&fb_analysis);
    return -1;
}

#ifdef UNITTESTS

static int FlowBitsTestParse01(void)
{
    char command[16] = "", name[16] = "";

    /* Single argument version. */
    FAIL_IF(!DetectFlowbitParse("noalert", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "noalert") != 0);

    /* No leading or trailing spaces. */
    FAIL_IF(!DetectFlowbitParse("set,flowbit", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Leading space. */
    FAIL_IF(!DetectFlowbitParse("set, flowbit", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Trailing space. */
    FAIL_IF(!DetectFlowbitParse("set,flowbit ", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Leading and trailing space. */
    FAIL_IF(!DetectFlowbitParse("set, flowbit ", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Spaces are not allowed in the name. */
    FAIL_IF(DetectFlowbitParse("set,namewith space", command, sizeof(command),
            name, sizeof(name)));

    PASS;
}

/**
 * \test FlowBitsTestSig01 is a test for a valid noalert flowbits option
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig01(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Noalert\"; flowbits:noalert,wrongusage; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig02 is a test for a valid isset,set,isnotset,unset,toggle flowbits options
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig02(void)
{
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset rule need an option\"; flowbits:isset; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isnotset rule need an option\"; flowbits:isnotset; content:\"GET \"; sid:2;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"set rule need an option\"; flowbits:set; content:\"GET \"; sid:3;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"unset rule need an option\"; flowbits:unset; content:\"GET \"; sid:4;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"toggle rule need an option\"; flowbits:toggle; content:\"GET \"; sid:5;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"!set is not an option\"; flowbits:!set,myerr; content:\"GET \"; sid:6;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test FlowBitsTestSig03 is a test for a invalid flowbits option
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig03(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Unknown cmd\"; flowbits:wrongcmd; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig04 is a test check idx value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig04(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int idx = 0;
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset option\"; flowbits:isset,fbt; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreRegister("fbt", VAR_TYPE_FLOW_BIT);
    FAIL_IF(idx == 0);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig05 is a test check noalert flag
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig05(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Noalert\"; flowbits:noalert; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF((s->action & ACTION_ALERT) != 0);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig06 is a test set flowbits option
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig06(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    uint32_t idx = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= (FLOW_PKT_TOSERVER | FLOW_PKT_TOSERVER_FIRST);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow; sid:10;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreRegister("myflow", VAR_TYPE_FLOW_BIT);
    FAIL_IF_NOT(idx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    gv = p->flow->flowvar;
    FAIL_IF_NULL(gv);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF_NOT(result);

    PacketFree(p);
    FLOW_DESTROY(&f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test FlowBitsTestSig07 is a test unset flowbits option
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig07(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    uint32_t idx = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow2; sid:10;)");
    FAIL_IF_NULL(s);

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit unset\"; flowbits:unset,myflow2; sid:11;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreRegister("myflow", VAR_TYPE_FLOW_BIT);
    FAIL_IF_NOT(idx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    gv = p->flow->flowvar;
    FAIL_IF_NULL(gv);

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF(result);

    PacketFree(p);
    FLOW_DESTROY(&f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test FlowBitsTestSig08 is a test toggle flowbits option
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int FlowBitsTestSig08(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    uint32_t idx = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow2; sid:10;)");
    FAIL_IF_NULL(s);

    s = s->next  = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit unset\"; flowbits:toggle,myflow2; sid:11;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreRegister("myflow", VAR_TYPE_FLOW_BIT);
    FAIL_IF_NOT(idx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    gv = p->flow->flowvar;
    FAIL_IF_NULL(gv);

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF(result);

    PacketFree(p);
    FLOW_DESTROY(&f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \brief this function registers unit tests for FlowBits
 */
void FlowBitsRegisterTests(void)
{
    UtRegisterTest("FlowBitsTestParse01", FlowBitsTestParse01);
    UtRegisterTest("FlowBitsTestSig01", FlowBitsTestSig01);
    UtRegisterTest("FlowBitsTestSig02", FlowBitsTestSig02);
    UtRegisterTest("FlowBitsTestSig03", FlowBitsTestSig03);
    UtRegisterTest("FlowBitsTestSig04", FlowBitsTestSig04);
    UtRegisterTest("FlowBitsTestSig05", FlowBitsTestSig05);
    UtRegisterTest("FlowBitsTestSig06", FlowBitsTestSig06);
    UtRegisterTest("FlowBitsTestSig07", FlowBitsTestSig07);
    UtRegisterTest("FlowBitsTestSig08", FlowBitsTestSig08);
}
#endif /* UNITTESTS */
