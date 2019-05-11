/* Copyright (C) 2007-2017 Open Information Security Foundation
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
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-flowbits.h"
#include "util-spm.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"

#define PARSE_REGEX         "^([a-z]+)(?:,\\s*(.*))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowbitMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlowbitSetup (DetectEngineCtx *, Signature *, const char *);
void DetectFlowbitFree (void *);
void FlowBitsRegisterTests(void);

void DetectFlowbitsRegister (void)
{
    sigmatch_table[DETECT_FLOWBITS].name = "flowbits";
    sigmatch_table[DETECT_FLOWBITS].desc = "operate on flow flag";
    sigmatch_table[DETECT_FLOWBITS].url = DOC_URL DOC_VERSION "/rules/flow-keywords.html#flowbits";
    sigmatch_table[DETECT_FLOWBITS].Match = DetectFlowbitMatch;
    sigmatch_table[DETECT_FLOWBITS].Setup = DetectFlowbitSetup;
    sigmatch_table[DETECT_FLOWBITS].Free  = DetectFlowbitFree;
    sigmatch_table[DETECT_FLOWBITS].RegisterTests = FlowBitsRegisterTests;
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_FLOWBITS].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
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

    return FlowBitIsset(p->flow,fd->idx);
}

static int DetectFlowbitMatchIsnotset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    return FlowBitIsnotset(p->flow,fd->idx);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowbitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
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
    const int max_substrings = 30;
    int count, rc;
    int ov[max_substrings];

    count = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
        ov, max_substrings);
    if (count != 2 && count != 3) {
        SCLogError(SC_ERR_PCRE_MATCH,
            "\"%s\" is not a valid setting for flowbits.", str);
        return 0;
    }

    rc = pcre_copy_substring((char *)str, ov, max_substrings, 1, cmd, cmd_len);
    if (rc < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return 0;
    }

    if (count == 3) {
        rc = pcre_copy_substring((char *)str, ov, max_substrings, 2, name,
            name_len);
        if (rc < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
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
                    "spaces not allowed in flowbit names");
                return 0;
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

    cd = SCMalloc(sizeof(DetectFlowbitsData));
    if (unlikely(cd == NULL))
        goto error;

    cd->idx = VarNameStoreSetupAdd(fb_name, VAR_TYPE_FLOW_BIT);
    de_ctx->max_fb_id = MAX(cd->idx, de_ctx->max_fb_id);
    cd->cmd = fb_cmd;

    SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
        cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");

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
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectFlowbitFree (void *ptr)
{
    DetectFlowbitsData *fd = (DetectFlowbitsData *)ptr;

    if (fd == NULL)
        return;

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
#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements);
#endif
#endif

void DetectFlowbitsAnalyze(DetectEngineCtx *de_ctx)
{
    const uint32_t max_fb_id = de_ctx->max_fb_id;
    if (max_fb_id == 0)
        return;

#define MAX_SIDS 8
    uint32_t array_size = max_fb_id + 1;
    struct FBAnalyze array[array_size];
    memset(&array, 0, array_size * sizeof(struct FBAnalyze));

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
                    } else if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET){
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
#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
    DetectFlowbitsAnalyzeDump(de_ctx, array, array_size);
#endif
#endif

end:
    for (uint32_t i = 0; i < array_size; i++) {
        SCFree(array[i].set_sids);
        SCFree(array[i].unset_sids);
        SCFree(array[i].isset_sids);
        SCFree(array[i].isnotset_sids);
        SCFree(array[i].toggle_sids);
    }
}

#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
#include "output-json.h"
#include "util-buffer.h"
SCMutex g_flowbits_dump_write_m = SCMUTEX_INITIALIZER;
static void DetectFlowbitsAnalyzeDump(const DetectEngineCtx *de_ctx,
        struct FBAnalyze *array, uint32_t elements)
{
    json_t *js = json_object();
    if (js == NULL)
        return;

    json_t *js_array = json_array();
    uint32_t x;
    for (x = 0; x < elements; x++)
    {
        char *varname = VarNameStoreSetupLookup(x, VAR_TYPE_FLOW_BIT);
        if (varname == NULL)
            continue;

        const struct FBAnalyze *e = &array[x];

        json_t *js_fb = json_object();
        if (unlikely(js_fb != NULL)) {
            json_object_set_new(js_fb, "name", json_string(varname));
            json_object_set_new(js_fb, "internal_id", json_integer(x));
            json_object_set_new(js_fb, "set_cnt", json_integer(e->cnts[DETECT_FLOWBITS_CMD_SET]));
            json_object_set_new(js_fb, "unset_cnt", json_integer(e->cnts[DETECT_FLOWBITS_CMD_UNSET]));
            json_object_set_new(js_fb, "toggle_cnt", json_integer(e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]));
            json_object_set_new(js_fb, "isset_cnt", json_integer(e->cnts[DETECT_FLOWBITS_CMD_ISSET]));
            json_object_set_new(js_fb, "isnotset_cnt", json_integer(e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]));

            // sets
            if (e->cnts[DETECT_FLOWBITS_CMD_SET]) {
                json_t *js_set_array = json_array();
                if (js_set_array) {
                    for(uint32_t i = 0; i < e->set_sids_idx; i++) {
                        const Signature *s = de_ctx->sig_array[e->set_sids[i]];
                        json_array_append_new(js_set_array, json_integer(s->id));
                    }
                    json_object_set_new(js_fb, "sets", js_set_array);
                }
            }
            // gets
            if (e->cnts[DETECT_FLOWBITS_CMD_ISSET]) {
                json_t *js_isset_array = json_array();
                if (js_isset_array) {
                    for(uint32_t i = 0; i < e->isset_sids_idx; i++) {
                        const Signature *s = de_ctx->sig_array[e->isset_sids[i]];
                        json_array_append_new(js_isset_array, json_integer(s->id));
                    }
                    json_object_set_new(js_fb, "isset", js_isset_array);
                }
            }
            // isnotset
            if (e->cnts[DETECT_FLOWBITS_CMD_ISNOTSET]) {
                json_t *js_isnotset_array = json_array();
                if (js_isnotset_array) {
                    for(uint32_t i = 0; i < e->isnotset_sids_idx; i++) {
                        const Signature *s = de_ctx->sig_array[e->isnotset_sids[i]];
                        json_array_append_new(js_isnotset_array, json_integer(s->id));
                    }
                    json_object_set_new(js_fb, "isnotset", js_isnotset_array);
                }
            }
            // unset
            if (e->cnts[DETECT_FLOWBITS_CMD_UNSET]) {
                json_t *js_unset_array = json_array();
                if (js_unset_array) {
                    for(uint32_t i = 0; i < e->unset_sids_idx; i++) {
                        const Signature *s = de_ctx->sig_array[e->unset_sids[i]];
                        json_array_append_new(js_unset_array, json_integer(s->id));
                    }
                    json_object_set_new(js_fb, "unset", js_unset_array);
                }
            }
            // toggle
            if (e->cnts[DETECT_FLOWBITS_CMD_TOGGLE]) {
                json_t *js_toggle_array = json_array();
                if (js_toggle_array) {
                    for(uint32_t i = 0; i < e->toggle_sids_idx; i++) {
                        const Signature *s = de_ctx->sig_array[e->toggle_sids[i]];
                        json_array_append_new(js_toggle_array, json_integer(s->id));
                    }
                    json_object_set_new(js_fb, "toggle", js_toggle_array);
                }
            }

            json_array_append_new(js_array, js_fb);
        }
        SCFree(varname);
    }

    json_object_set_new(js, "flowbits", js_array);

    const char *filename = "flowbits.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    MemBuffer *mbuf = NULL;
    mbuf = MemBufferCreateNew(4096);
    BUG_ON(mbuf == NULL);

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = &mbuf,
        .expand_by = 4096,
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);
    if (r != 0) {
        SCLogWarning(SC_ERR_SOCKET, "unable to serialize JSON object");
    } else {
        MemBufferWriteString(mbuf, "\n");
        SCMutexLock(&g_flowbits_dump_write_m);
        FILE *fp = fopen(log_path, "w");
        if (fp != NULL) {
            MemBufferPrintToFPAsString(mbuf, fp);
            fclose(fp);
        }
        SCMutexUnlock(&g_flowbits_dump_write_m);
    }

    MemBufferFree(mbuf);
    json_object_clear(js);
    json_decref(js);
}
#endif /* HAVE_LIBJANSSON */
#endif /* PROFILING */

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
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    uint32_t idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
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
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    uint32_t idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
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
    Packet *p = SCMalloc(SIZE_OF_PACKET);
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

    memset(p, 0, SIZE_OF_PACKET);
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
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for FlowBits
 */
void FlowBitsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowBitsTestParse01", FlowBitsTestParse01);
    UtRegisterTest("FlowBitsTestSig01", FlowBitsTestSig01);
    UtRegisterTest("FlowBitsTestSig02", FlowBitsTestSig02);
    UtRegisterTest("FlowBitsTestSig03", FlowBitsTestSig03);
    UtRegisterTest("FlowBitsTestSig04", FlowBitsTestSig04);
    UtRegisterTest("FlowBitsTestSig05", FlowBitsTestSig05);
    UtRegisterTest("FlowBitsTestSig06", FlowBitsTestSig06);
    UtRegisterTest("FlowBitsTestSig07", FlowBitsTestSig07);
    UtRegisterTest("FlowBitsTestSig08", FlowBitsTestSig08);
#endif /* UNITTESTS */
}
