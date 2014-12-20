/* Copyright (C) 2007-2014 Open Information Security Foundation
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
#include "detect-flowvar.h"

#include "util-spm.h"
#include "util-var-name.h"
#include "util-debug.h"
#include "util-print.h"

#define PARSE_REGEX         "(.*),(.*)"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowvarMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFlowvarSetup (DetectEngineCtx *, Signature *, char *);
static int DetectFlowvarPostMatch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx);
static void DetectFlowvarDataFree(void *ptr);

void DetectFlowvarRegister (void)
{
    sigmatch_table[DETECT_FLOWVAR].name = "flowvar";
    sigmatch_table[DETECT_FLOWVAR].Match = DetectFlowvarMatch;
    sigmatch_table[DETECT_FLOWVAR].Setup = DetectFlowvarSetup;
    sigmatch_table[DETECT_FLOWVAR].Free  = DetectFlowvarDataFree;
    sigmatch_table[DETECT_FLOWVAR].RegisterTests  = NULL;

    /* post-match for flowvar storage */
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].name = "__flowvar__postmatch__";
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Match = DetectFlowvarPostMatch;
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Setup = NULL;
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].Free  = DetectFlowvarDataFree;
    sigmatch_table[DETECT_FLOWVAR_POSTMATCH].RegisterTests  = NULL;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    return;
}

/**
 * \brief this function will SCFree memory associated with DetectFlowvarData
 *
 * \param cd pointer to DetectCotentData
 */
static void DetectFlowvarDataFree(void *ptr)
{
    if (ptr == NULL)
        SCReturn;

    DetectFlowvarData *fd = (DetectFlowvarData *)ptr;

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

int DetectFlowvarMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectFlowvarData *fd = (DetectFlowvarData *)ctx;

    /* we need a lock */
    FLOWLOCK_RDLOCK(p->flow);

    FlowVar *fv = FlowVarGet(p->flow, fd->idx);
    if (fv != NULL) {
        uint8_t *ptr = SpmSearch(fv->data.fv_str.value,
                                 fv->data.fv_str.value_len,
                                 fd->content, fd->content_len);
        if (ptr != NULL)
            ret = 1;
    }
    FLOWLOCK_UNLOCK(p->flow);

    return ret;
}

static int DetectFlowvarSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectFlowvarData *fd = NULL;
    SigMatch *sm = NULL;
    char *varname = NULL, *varcontent = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr;
    uint8_t *content = NULL;
    uint16_t contentlen = 0;
    uint32_t contentflags = 0;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for flowvar.", rawstr);
        return -1;
    }

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }
    varname = (char *)str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }
    varcontent = (char *)str_ptr;

    res = DetectContentDataParse("flowvar", varcontent, &content, &contentlen, &contentflags);
    if (res == -1)
        goto error;

    fd = SCMalloc(sizeof(DetectFlowvarData));
    if (unlikely(fd == NULL))
        goto error;
    memset(fd, 0x00, sizeof(*fd));

    fd->content = SCMalloc(contentlen);
    if (unlikely(fd->content == NULL))
        goto error;

    memcpy(fd->content, content, contentlen);
    fd->content_len = contentlen;
    fd->flags = contentflags;

    fd->name = SCStrdup(varname);
    if (unlikely(fd->name == NULL))
        goto error;
    fd->idx = VariableNameGetIdx(de_ctx, varname, VAR_TYPE_FLOW_VAR);

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (unlikely(sm == NULL))
        goto error;

    sm->type = DETECT_FLOWVAR;
    sm->ctx = (SigMatchCtx *)fd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    SCFree(content);
    return 0;

error:
    if (fd != NULL)
        DetectFlowvarDataFree(fd);
    if (sm != NULL)
        SCFree(sm);
    if (content != NULL)
        SCFree(content);
    return -1;
}


/** \brief Store flowvar in det_ctx so we can exec it post-match */
int DetectFlowvarStoreMatch(DetectEngineThreadCtx *det_ctx, uint16_t idx,
        uint8_t *buffer, uint16_t len, int type)
{
    DetectFlowvarList *fs = det_ctx->flowvarlist;

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
        fs = SCMalloc(sizeof(*fs));
        if (unlikely(fs == NULL))
            return -1;

        fs->idx = idx;

        fs->next = det_ctx->flowvarlist;
        det_ctx->flowvarlist = fs;
    }

    fs->len = len;
    fs->type = type;
    fs->buffer = buffer;
    return 0;
}

/** \brief Setup a post-match for flowvar storage
 *  We're piggyback riding the DetectFlowvarData struct
 */
int DetectFlowvarPostMatchSetup(Signature *s, uint16_t idx)
{
    SigMatch *sm = NULL;
    DetectFlowvarData *fv = NULL;

    fv = SCMalloc(sizeof(DetectFlowvarData));
    if (unlikely(fv == NULL))
        goto error;
    memset(fv, 0x00, sizeof(*fv));

    /* we only need the idx */
    fv->idx = idx;

    sm = SigMatchAlloc();
    if (unlikely(sm == NULL))
        goto error;

    sm->type = DETECT_FLOWVAR_POSTMATCH;
    sm->ctx = (SigMatchCtx *)fv;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
    return 0;
error:
    if (fv != NULL)
        DetectFlowvarDataFree(fv);
    return -1;
}

/** \internal
 *  \brief post-match func to store flowvars in the flow
 *  \param sm sigmatch containing the idx to store
 *  \retval 1 or -1 in case of error
 */
static int DetectFlowvarPostMatch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    DetectFlowvarList *fs, *prev;
    const DetectFlowvarData *fd;
    const int flow_locked = det_ctx->flow_locked;

    if (det_ctx->flowvarlist == NULL || p->flow == NULL)
        return 1;

    fd = (const DetectFlowvarData *)ctx;

    prev = NULL;
    fs = det_ctx->flowvarlist;
    while (fs != NULL) {
        if (fd->idx == fs->idx) {
            SCLogDebug("adding to the flow %u:", fs->idx);
            //PrintRawDataFp(stdout, fs->buffer, fs->len);

            if (flow_locked)
                FlowVarAddStrNoLock(p->flow, fs->idx, fs->buffer, fs->len);
            else
                FlowVarAddStr(p->flow, fs->idx, fs->buffer, fs->len);
            /* memory at fs->buffer is now the responsibility of
             * the flowvar code. */

            if (fs == det_ctx->flowvarlist) {
                det_ctx->flowvarlist = fs->next;
                SCFree(fs);
                fs = det_ctx->flowvarlist;
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

/** \brief Handle flowvar candidate list in det_ctx:
 *         - clean up the list
 *         - enforce storage for type ALWAYS (luajit)
 *   Only called from DetectFlowvarProcessList() when flowvarlist is not NULL .
 */
void DetectFlowvarProcessListInternal(DetectFlowvarList *fs, Flow *f, const int flow_locked)
{
    DetectFlowvarList *next;

    do {
        next = fs->next;

        if (fs->type == DETECT_FLOWVAR_TYPE_ALWAYS) {
            BUG_ON(f == NULL);
            SCLogDebug("adding to the flow %u:", fs->idx);
            //PrintRawDataFp(stdout, fs->buffer, fs->len);

            if (flow_locked)
                FlowVarAddStrNoLock(f, fs->idx, fs->buffer, fs->len);
            else
                FlowVarAddStr(f, fs->idx, fs->buffer, fs->len);
            /* memory at fs->buffer is now the responsibility of
             * the flowvar code. */
        } else
            SCFree(fs->buffer);
        SCFree(fs);
        fs = next;
    } while (fs != NULL);
}
