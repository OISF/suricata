/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 *
 * Simple flowvar content match part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-content.h"
#include "threads.h"
#include "flow.h"
#include "flow-var.h"
#include "pkt-var.h"
#include "detect-flowvar.h"

#include "util-spm.h"
#include "util-var-name.h"
#include "util-debug.h"
#include "util-print.h"

#define PARSE_REGEX         "(.*),(.*)"
static DetectParseRegex parse_regex;

int DetectFlowvarMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlowvarSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectFlowvarPostMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx);
static void DetectFlowvarDataFree(DetectEngineCtx *, void *ptr);

void DetectFlowvarRegister (void)
{
    sigmatch_table[DETECT_FLOWVAR].name = "flowvar";
    sigmatch_table[DETECT_FLOWVAR].Match = DetectFlowvarMatch;
    sigmatch_table[DETECT_FLOWVAR].Setup = DetectFlowvarSetup;
    sigmatch_table[DETECT_FLOWVAR].Free  = DetectFlowvarDataFree;

    /* post-match for flowvar storage */
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].name = "__flowvar__postmatch__";
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Match = DetectFlowvarPostMatch;
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Setup = NULL;
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Free  = DetectFlowvarDataFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief this function will SCFree memory associated with DetectFlowvarData
 *
 * \param cd pointer to DetectContentData
 */
static void DetectFlowvarDataFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        SCReturn;

    DetectFlowvarData *fd = (DetectFlowvarData *)ptr;
    /* leave unregistration to pcre keyword */
    if (!fd->post_match)
        VarNameStoreUnregister(fd->idx, VAR_TYPE_FLOW_VAR);

    if (fd->name)
        SCFree(fd->name);
    if (fd->content)
        SCFree(fd->content);

    SCFree(fd);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowvarMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectFlowvarData *fd = (DetectFlowvarData *)ctx;

    FlowVar *fv = FlowVarGet(p->flow, fd->idx);
    if (fv != NULL) {
        uint8_t *ptr = SpmSearch(fv->data.fv_str.value,
                                 fv->data.fv_str.value_len,
                                 fd->content, fd->content_len);
        if (ptr != NULL)
            ret = 1;
    }

    return ret;
}

static int DetectFlowvarSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlowvarData *fd = NULL;
    char varname[64], varcontent[64];
    int res = 0;
    size_t pcre2len;
    uint8_t *content = NULL;
    uint16_t contentlen = 0;
    uint32_t contentflags = s->init_data->negated ? DETECT_CONTENT_NEGATED : 0;
    pcre2_match_data *match = NULL;

    int ret = DetectParsePcreExec(&parse_regex, &match, rawstr, 0, 0);
    if (ret != 3) {
        SCLogError("\"%s\" is not a valid setting for flowvar.", rawstr);
        if (match) {
            pcre2_match_data_free(match);
        }
        return -1;
    }

    pcre2len = sizeof(varname);
    res = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)varname, &pcre2len);
    if (res < 0) {
        pcre2_match_data_free(match);
        SCLogError("pcre2_substring_copy_bynumber failed");
        return -1;
    }

    pcre2len = sizeof(varcontent);
    res = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)varcontent, &pcre2len);
    pcre2_match_data_free(match);
    if (res < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        return -1;
    }

    int varcontent_index = 0;
    if (strlen(varcontent) >= 2) {
        if (varcontent[0] == '"')
            varcontent_index++;
        if (varcontent[strlen(varcontent)-1] == '"')
            varcontent[strlen(varcontent)-1] = '\0';
    }
    SCLogDebug("varcontent %s", &varcontent[varcontent_index]);

    res = DetectContentDataParse("flowvar", &varcontent[varcontent_index], &content, &contentlen);
    if (res == -1)
        goto error;

    fd = SCCalloc(1, sizeof(DetectFlowvarData));
    if (unlikely(fd == NULL))
        goto error;

    fd->content = SCMalloc(contentlen);
    if (unlikely(fd->content == NULL))
        goto error;

    memcpy(fd->content, content, contentlen);
    fd->content_len = contentlen;
    fd->flags = contentflags;

    fd->name = SCStrdup(varname);
    if (unlikely(fd->name == NULL))
        goto error;
    fd->idx = VarNameStoreRegister(varname, VAR_TYPE_FLOW_VAR);

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOWVAR, (SigMatchCtx *)fd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    SCFree(content);
    return 0;

error:
    if (fd != NULL)
        DetectFlowvarDataFree(de_ctx, fd);
    if (content != NULL)
        SCFree(content);
    return -1;
}

/** \brief Store flowvar in det_ctx so we can exec it post-match */
int DetectVarStoreMatchKeyValue(DetectEngineThreadCtx *det_ctx, uint8_t *key, uint16_t key_len,
        uint8_t *buffer, uint16_t len, uint16_t type)
{
    DetectVarList *fs = SCCalloc(1, sizeof(*fs));
    if (unlikely(fs == NULL))
        return -1;

    fs->len = len;
    fs->type = type;
    fs->buffer = buffer;
    fs->key = key;
    fs->key_len = key_len;

    fs->next = det_ctx->varlist;
    det_ctx->varlist = fs;
    return 0;
}

/** \brief Store flowvar in det_ctx so we can exec it post-match */
int DetectVarStoreMatch(
        DetectEngineThreadCtx *det_ctx, uint32_t idx, uint8_t *buffer, uint16_t len, uint16_t type)
{
    DetectVarList *fs = det_ctx->varlist;

    /* first check if we have had a previous match for this idx */
    for ( ; fs != NULL; fs = fs->next) {
        if (fs->idx == idx) {
            /* we're replacing the older store */
            SCFree(fs->buffer);
            fs->buffer = NULL;
            break;
        }
    }

    if (fs == NULL) {
        fs = SCCalloc(1, sizeof(*fs));
        if (unlikely(fs == NULL))
            return -1;

        fs->idx = idx;

        fs->next = det_ctx->varlist;
        det_ctx->varlist = fs;
    }

    fs->len = len;
    fs->type = type;
    fs->buffer = buffer;
    return 0;
}

/** \brief Setup a post-match for flowvar storage
 *  We're piggyback riding the DetectFlowvarData struct
 */
int DetectFlowvarPostMatchSetup(DetectEngineCtx *de_ctx, Signature *s, uint32_t idx)
{
    DetectFlowvarData *fv = NULL;

    fv = SCCalloc(1, sizeof(DetectFlowvarData));
    if (unlikely(fv == NULL))
        goto error;

    /* we only need the idx */
    fv->idx = idx;
    fv->post_match = true;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOWVAR_POSTMATCH, (SigMatchCtx *)fv,
                DETECT_SM_LIST_POSTMATCH) == NULL) {
        goto error;
    }
    return 0;
error:
    if (fv != NULL)
        DetectFlowvarDataFree(de_ctx, fv);
    return -1;
}

/** \internal
 *  \brief post-match func to store flowvars in the flow
 *  \param sm sigmatch containing the idx to store
 *  \retval 1 or -1 in case of error
 */
static int DetectFlowvarPostMatch(
        DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DetectVarList *fs, *prev;
    const DetectFlowvarData *fd;

    if (det_ctx->varlist == NULL)
        return 1;

    fd = (const DetectFlowvarData *)ctx;

    prev = NULL;
    fs = det_ctx->varlist;
    while (fs != NULL) {
        if (fd->idx == 0 || fd->idx == fs->idx) {
            SCLogDebug("adding to the flow %u:", fs->idx);
            //PrintRawDataFp(stdout, fs->buffer, fs->len);

            if (fs->type == DETECT_VAR_TYPE_FLOW_POSTMATCH && p && p->flow) {
                FlowVarAddIdValue(p->flow, fs->idx, fs->buffer, fs->len);
                /* memory at fs->buffer is now the responsibility of
                 * the flowvar code. */
            } else if (fs->type == DETECT_VAR_TYPE_PKT_POSTMATCH && fs->key && p) {
                /* pkt key/value */
                if (PktVarAddKeyValue(p, (uint8_t *)fs->key, fs->key_len,
                                         (uint8_t *)fs->buffer, fs->len) == -1)
                {
                    SCFree(fs->key);
                    SCFree(fs->buffer);
                    /* the rest of fs is freed below */
                }
            } else if (fs->type == DETECT_VAR_TYPE_PKT_POSTMATCH && p) {
                if (PktVarAdd(p, fs->idx, fs->buffer, fs->len) == -1) {
                    SCFree(fs->buffer);
                    /* the rest of fs is freed below */
                }
            }

            if (fs == det_ctx->varlist) {
                det_ctx->varlist = fs->next;
                SCFree(fs);
                fs = det_ctx->varlist;
            } else {
                prev->next = fs->next;
                SCFree(fs);
                fs = prev->next;
            }
        } else {
            prev = fs;
            fs = fs->next;
        }
    }
    return 1;
}

/** \brief Handle flowvar candidate list in det_ctx: clean up the list
 *
 *   Only called from DetectVarProcessList() when varlist is not NULL.
 */
void DetectVarProcessListInternal(DetectVarList *fs, Flow *f, Packet *p)
{
    DetectVarList *next;

    do {
        next = fs->next;

        if (fs->key) {
            SCFree(fs->key);
        }
        SCFree(fs->buffer);
        SCFree(fs);
        fs = next;
    } while (fs != NULL);
}
