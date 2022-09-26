/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "flow-bit.h"
#include "detect-flowbits.h"

#include "app-layer-parser.h"

#include "detect-parse.h"

#include "util-var-name.h"

#ifdef UNITTESTS
#include "util-debug.h"
#include "util-unittest.h"
#include "detect-engine-build.h"
#include "detect-engine-state.h"
#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "util-spm.h"
#include "flow-util.h"
#include "flow.h"
#include "threads.h"
#include "detect.h"
#include "decode.h"
#endif
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
    sigmatch_table[DETECT_FLOWBITS].flags |= SIGMATCH_IPONLY_COMPAT;

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
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Spaces are not allowed in flowbit names.");
            return -1;
        }

        if (i == MAX_TOKENS) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Number of flowbits exceeds "
                       "maximum allowed: %d.", MAX_TOKENS);
            return -1;
        }
        strarr[i++] = token;
    next:
        arrptr = NULL;
    }

    cd->or_list_size = i;
    cd->or_list = SCCalloc(cd->or_list_size, sizeof(uint32_t));
    if (unlikely(cd->or_list == NULL))
        return -1;
    for (uint8_t j = 0; j < cd->or_list_size ; j++) {
        cd->or_list[j] = VarNameStoreSetupAdd(strarr[j], VAR_TYPE_FLOW_BIT);
        de_ctx->max_fb_id = MAX(cd->or_list[j], de_ctx->max_fb_id);
    }

    return 1;
}

static int DetectFlowbitMatchToggle (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    FlowBitToggle(p->flow,fd->idx);

    return 1;
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
        return 0;

    FlowBitSet(p->flow,fd->idx);

    return 1;
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
 * returns 0: no match
 *         1: match
 *        -1: error
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
        case DETECT_FLOWBITS_CMD_SET:
            return DetectFlowbitMatchSet(p,fd);
        case DETECT_FLOWBITS_CMD_UNSET:
            return DetectFlowbitMatchUnset(p,fd);
        case DETECT_FLOWBITS_CMD_TOGGLE:
            return DetectFlowbitMatchToggle(p,fd);
        default:
            SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown cmd %" PRIu32 "", fd->cmd);
            return 0;
    }

    return 0;
}

static int DetectFlowbitParse(const char *str, char *cmd, int cmd_len, char *name,
    int name_len)
{
    int count, rc;
    size_t pcre2len;

    count = DetectParsePcreExec(&parse_regex, str, 0, 0);
    if (count != 2 && count != 3) {
        SCLogError(SC_ERR_PCRE_MATCH,
            "\"%s\" is not a valid setting for flowbits.", str);
        return 0;
    }

    pcre2len = cmd_len;
    rc = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)cmd, &pcre2len);
    if (rc < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return 0;
    }

    if (count == 3) {
        pcre2len = name_len;
        rc = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)name, &pcre2len);
        if (rc < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return 0;
        }

        /* Trim trailing whitespace. */
        while (strlen(name) > 0 && isblank(name[strlen(name) - 1])) {
            name[strlen(name) - 1] = '\0';
        }

        if (strchr(name, '|') == NULL) {
            /* Validate name, spaces are not allowed. */
            for (size_t i = 0; i < strlen(name); i++) {
                if (isblank(name[i])) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE,
                        "spaces not allowed in flowbit names");
                    return 0;
                }
            }
        }
    }

    return 1;
}

int DetectFlowbitSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlowbitsData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t fb_cmd = 0;
    char fb_cmd_str[16] = "", fb_name[256] = "";

    if (!DetectFlowbitParse(rawstr, fb_cmd_str, sizeof(fb_cmd_str), fb_name,
            sizeof(fb_name))) {
        return -1;
    }

    if (strcmp(fb_cmd_str,"noalert") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_NOALERT;
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
        SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: flowbits action \"%s\" is not supported.", fb_cmd_str);
        goto error;
    }

    switch (fb_cmd) {
        case DETECT_FLOWBITS_CMD_NOALERT:
            if (strlen(fb_name) != 0)
                goto error;
            s->flags |= SIG_FLAG_NOALERT;
            return 0;
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
        cd->idx = VarNameStoreSetupAdd(fb_name, VAR_TYPE_FLOW_BIT);
        de_ctx->max_fb_id = MAX(cd->idx, de_ctx->max_fb_id);
        cd->cmd = fb_cmd;
        cd->or_list_size = 0;
        cd->or_list = NULL;
        SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
            cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");
    }
    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOWBITS;
    sm->ctx = (SigMatchCtx *)cd;

    switch (fb_cmd) {
        /* case DETECT_FLOWBITS_CMD_NOALERT can't happen here */

        case DETECT_FLOWBITS_CMD_ISNOTSET:
        case DETECT_FLOWBITS_CMD_ISSET:
            /* checks, so packet list */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
            break;

        case DETECT_FLOWBITS_CMD_SET:
        case DETECT_FLOWBITS_CMD_UNSET:
        case DETECT_FLOWBITS_CMD_TOGGLE:
            /* modifiers, only run when entire sig has matched */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
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
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectFlowbitFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlowbitsData *fd = (DetectFlowbitsData *)ptr;
    if (fd == NULL)
        return;
    if (fd->or_list != NULL)
        SCFree(fd->or_list);
    SCFree(fd);
}

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

extern int rule_engine_analysis_set;
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements);

int DetectFlowbitsAnalyze(DetectEngineCtx *de_ctx)
{
    const uint32_t max_fb_id = de_ctx->max_fb_id;
    if (max_fb_id == 0)
        return 0;

#define MAX_SIDS 8
    uint32_t array_size = max_fb_id + 1;
    struct FBAnalyze *array = SCCalloc(array_size, sizeof(struct FBAnalyze));

    if (array == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate flowbit analyze array");
        return -1;
    }

    SCLogDebug("fb analyzer array size: %"PRIu64,
            (uint64_t)(array_size * sizeof(struct FBAnalyze)));

    /* fill flowbit array, updating counters per sig */
    for (uint32_t i = 0; i < de_ctx->sig_array_len; i++) {
        const Signature *s = de_ctx->sig_array[i];
        bool has_state = false;

        /* see if the signature uses stateful matching */
        for (uint32_t x = DETECT_SM_LIST_DYNAMIC_START; x < s->init_data->smlists_array_size; x++) {
            if (s->init_data->smlists[x] == NULL)
                continue;
            has_state = true;
            break;
        }

        for (const SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
            switch (sm->type) {
                case DETECT_FLOWBITS:
                {
                    /* figure out the flowbit action */
                    const DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
                    // Handle flowbit array in case of ORed flowbits
                    for (uint8_t k = 0; k < fb->or_list_size; k++) {
                        array[fb->or_list[k]].cnts[fb->cmd]++;
                        if (has_state)
                            array[fb->or_list[k]].state_cnts[fb->cmd]++;
                        if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                            if (array[fb->or_list[k]].isset_sids_idx >= array[fb->or_list[k]].isset_sids_size) {
                                uint32_t old_size = array[fb->or_list[k]].isset_sids_size;
                                uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                                void *ptr = SCRealloc(array[fb->or_list[k]].isset_sids, new_size * sizeof(uint32_t));
                                if (ptr == NULL)
                                    goto end;
                                array[fb->or_list[k]].isset_sids_size = new_size;
                                array[fb->or_list[k]].isset_sids = ptr;
                            }

                            array[fb->or_list[k]].isset_sids[array[fb->or_list[k]].isset_sids_idx] = s->num;
                            array[fb->or_list[k]].isset_sids_idx++;
                        } else if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET) {
                            if (array[fb->or_list[k]].isnotset_sids_idx >= array[fb->or_list[k]].isnotset_sids_size) {
                                uint32_t old_size = array[fb->or_list[k]].isnotset_sids_size;
                                uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                                void *ptr = SCRealloc(array[fb->or_list[k]].isnotset_sids, new_size * sizeof(uint32_t));
                                if (ptr == NULL)
                                    goto end;
                                array[fb->or_list[k]].isnotset_sids_size = new_size;
                                array[fb->or_list[k]].isnotset_sids = ptr;
                            }

                            array[fb->or_list[k]].isnotset_sids[array[fb->or_list[k]].isnotset_sids_idx] = s->num;
                            array[fb->or_list[k]].isnotset_sids_idx++;
                        }
                    }
                    if (fb->or_list_size == 0) {
                        array[fb->idx].cnts[fb->cmd]++;
                        if (has_state)
                            array[fb->idx].state_cnts[fb->cmd]++;
                        if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                            if (array[fb->idx].isset_sids_idx >= array[fb->idx].isset_sids_size) {
                                uint32_t old_size = array[fb->idx].isset_sids_size;
                                uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                                void *ptr = SCRealloc(array[fb->idx].isset_sids, new_size * sizeof(uint32_t));
                                if (ptr == NULL)
                                    goto end;
                                array[fb->idx].isset_sids_size = new_size;
                                array[fb->idx].isset_sids = ptr;
                            }

                            array[fb->idx].isset_sids[array[fb->idx].isset_sids_idx] = s->num;
                            array[fb->idx].isset_sids_idx++;
                        } else if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET) {
                            if (array[fb->idx].isnotset_sids_idx >= array[fb->idx].isnotset_sids_size) {
                                uint32_t old_size = array[fb->idx].isnotset_sids_size;
                                uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                                void *ptr = SCRealloc(array[fb->idx].isnotset_sids, new_size * sizeof(uint32_t));
                                if (ptr == NULL)
                                    goto end;
                                array[fb->idx].isnotset_sids_size = new_size;
                                array[fb->idx].isnotset_sids = ptr;
                            }

                            array[fb->idx].isnotset_sids[array[fb->idx].isnotset_sids_idx] = s->num;
                            array[fb->idx].isnotset_sids_idx++;
                        }
                    }
                }
            }
        }
        for (const SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_POSTMATCH] ; sm != NULL; sm = sm->next) {
            switch (sm->type) {
                case DETECT_FLOWBITS:
                {
                    /* figure out what flowbit action */
                    const DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
                    array[fb->idx].cnts[fb->cmd]++;
                    if (has_state)
                        array[fb->idx].state_cnts[fb->cmd]++;
                    if (fb->cmd == DETECT_FLOWBITS_CMD_SET) {
                        if (array[fb->idx].set_sids_idx >= array[fb->idx].set_sids_size) {
                            uint32_t old_size = array[fb->idx].set_sids_size;
                            uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                            void *ptr = SCRealloc(array[fb->idx].set_sids, new_size * sizeof(uint32_t));
                            if (ptr == NULL)
                                goto end;
                            array[fb->idx].set_sids_size = new_size;
                            array[fb->idx].set_sids = ptr;
                        }

                        array[fb->idx].set_sids[array[fb->idx].set_sids_idx] = s->num;
                        array[fb->idx].set_sids_idx++;
                    }
                    else if (fb->cmd == DETECT_FLOWBITS_CMD_UNSET) {
                        if (array[fb->idx].unset_sids_idx >= array[fb->idx].unset_sids_size) {
                            uint32_t old_size = array[fb->idx].unset_sids_size;
                            uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                            void *ptr = SCRealloc(array[fb->idx].unset_sids, new_size * sizeof(uint32_t));
                            if (ptr == NULL)
                                goto end;
                            array[fb->idx].unset_sids_size = new_size;
                            array[fb->idx].unset_sids = ptr;
                        }

                        array[fb->idx].unset_sids[array[fb->idx].unset_sids_idx] = s->num;
                        array[fb->idx].unset_sids_idx++;
                    }
                    else if (fb->cmd == DETECT_FLOWBITS_CMD_TOGGLE) {
                        if (array[fb->idx].toggle_sids_idx >= array[fb->idx].toggle_sids_size) {
                            uint32_t old_size = array[fb->idx].toggle_sids_size;
                            uint32_t new_size = MAX(2 * old_size, MAX_SIDS);

                            void *ptr = SCRealloc(array[fb->idx].toggle_sids, new_size * sizeof(uint32_t));
                            if (ptr == NULL)
                                goto end;
                            array[fb->idx].toggle_sids_size = new_size;
                            array[fb->idx].toggle_sids = ptr;
                        }

                        array[fb->idx].toggle_sids[array[fb->idx].toggle_sids_idx] = s->num;
                        array[fb->idx].toggle_sids_idx++;
                    }
                }
            }
        }
    }

    /* walk array to see if all bits make sense */
    for (uint32_t i = 0; i < array_size; i++) {
        char *varname = VarNameStoreSetupLookup(i, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        bool to_state = false;

        if (array[i].cnts[DETECT_FLOWBITS_CMD_ISSET] &&
            array[i].cnts[DETECT_FLOWBITS_CMD_TOGGLE] == 0 &&
            array[i].cnts[DETECT_FLOWBITS_CMD_SET] == 0) {

            const Signature *s = de_ctx->sig_array[array[i].isset_sids[0]];
            SCLogWarning(SC_WARN_FLOWBIT, "flowbit '%s' is checked but not "
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
        for (uint32_t x = 0; x < array[i].isset_sids_idx; x++) {
            Signature *s = de_ctx->sig_array[array[i].isset_sids[x]];
            SCLogDebug("GET flowbit %s/%u: SID %u", varname, i, s->id);

            if (to_state) {
                s->init_data->init_flags |= SIG_FLAG_INIT_STATE_MATCH;
                SCLogDebug("made SID %u stateful because it depends on "
                        "stateful rules that set flowbit %s", s->id, varname);
            }
        }
        SCFree(varname);
    }

    if (rule_engine_analysis_set) {
        DetectFlowbitsAnalyzeDump(de_ctx, array, array_size);
    }

end:
    for (uint32_t i = 0; i < array_size; i++) {
        SCFree(array[i].set_sids);
        SCFree(array[i].unset_sids);
        SCFree(array[i].isset_sids);
        SCFree(array[i].isnotset_sids);
        SCFree(array[i].toggle_sids);
    }
    SCFree(array);

    return 0;
}

SCMutex g_flowbits_dump_write_m = SCMUTEX_INITIALIZER;
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements)
{
    JsonBuilder *js = jb_new_object();
    if (js == NULL)
        return;

    jb_open_array(js, "flowbits");
    for (uint32_t x = 0; x < elements; x++) {
        char *varname = VarNameStoreSetupLookup(x, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        const struct FBAnalyze *e = &array[x];

        jb_start_object(js);
        jb_set_string(js, "name", varname);
        jb_set_uint(js, "internal_id", x);
        jb_set_uint(js, "set_cnt", e->cnts[DETECT_FLOWBITS_CMD_SET]);
        jb_set_uint(js, "unset_cnt", e->cnts[DETECT_FLOWBITS_CMD_UNSET]);
        jb_set_uint(js, "toggle_cnt", e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]);
        jb_set_uint(js, "isset_cnt", e->cnts[DETECT_FLOWBITS_CMD_ISSET]);
        jb_set_uint(js, "isnotset_cnt", e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]);

        // sets
        if (e->cnts[DETECT_FLOWBITS_CMD_SET]) {
            jb_open_array(js, "sets");
            for (uint32_t i = 0; i < e->set_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->set_sids[i]];
                jb_append_uint(js, s->id);
            }
            jb_close(js);
        }
        // gets
        if (e->cnts[DETECT_FLOWBITS_CMD_ISSET]) {
            jb_open_array(js, "isset");
            for (uint32_t i = 0; i < e->isset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->isset_sids[i]];
                jb_append_uint(js, s->id);
            }
            jb_close(js);
        }
        // isnotset
        if (e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]) {
            jb_open_array(js, "isnotset");
            for (uint32_t i = 0; i < e->isnotset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->isnotset_sids[i]];
                jb_append_uint(js, s->id);
            }
            jb_close(js);
        }
        // unset
        if (e->cnts[DETECT_FLOWBITS_CMD_UNSET]) {
            jb_open_array(js, "unset");
            for (uint32_t i = 0; i < e->unset_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->unset_sids[i]];
                jb_append_uint(js, s->id);
            }
            jb_close(js);
        }
        // toggle
        if (e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]) {
            jb_open_array(js, "toggle");
            for (uint32_t i = 0; i < e->toggle_sids_idx; i++) {
                const Signature *s = de_ctx->sig_array[e->toggle_sids[i]];
                jb_append_uint(js, s->id);
            }
            jb_close(js);
        }
        SCFree(varname);
        jb_close(js);
    }
    jb_close(js); // array
    jb_close(js); // object

    const char *filename = "flowbits.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_flowbits_dump_write_m);
    FILE *fp = fopen(log_path, "w");
    if (fp != NULL) {
        fwrite(jb_ptr(js), jb_len(js), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_flowbits_dump_write_m);

    jb_free(js);
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
 *  \retval 1 on succces
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
 *  \retval 1 on succces
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
 *  \retval 1 on succces
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
 *  \retval 1 on succces
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

    idx = VarNameStoreSetupAdd("fbt", VAR_TYPE_FLOW_BIT);
    FAIL_IF(idx != 1);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig05 is a test check noalert flag
 *
 *  \retval 1 on succces
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
    FAIL_IF((s->flags & SIG_FLAG_NOALERT) != SIG_FLAG_NOALERT);

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig06 is a test set flowbits option
 *
 *  \retval 1 on succces
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
    p->flowflags |= FLOW_PKT_TOSERVER;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow; sid:10;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreSetupAdd("myflow", VAR_TYPE_FLOW_BIT);
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

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);

    SCFree(p);
    PASS;
}

/**
 * \test FlowBitsTestSig07 is a test unset flowbits option
 *
 *  \retval 1 on succces
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

    idx = VarNameStoreSetupAdd("myflow", VAR_TYPE_FLOW_BIT);
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

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);

    SCFree(p);
    PASS;
}

/**
 * \test FlowBitsTestSig08 is a test toogle flowbits option
 *
 *  \retval 1 on succces
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

    idx = VarNameStoreSetupAdd("myflow", VAR_TYPE_FLOW_BIT);
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

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);

    SCFree(p);
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
