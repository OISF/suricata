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
 * Implements the pktvar keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "threads.h"
#include "pkt-var.h"
#include "detect-pktvar.h"
#include "detect-content.h"
#include "util-spm.h"
#include "util-debug.h"
#include "util-var-name.h"

#define PARSE_REGEX         "(.*),(.*)"
static DetectParseRegex parse_regex;

static int DetectPktvarMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectPktvarSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectPktvarFree(DetectEngineCtx *, void *data);

void DetectPktvarRegister (void)
{
    sigmatch_table[DETECT_PKTVAR].name = "pktvar";
    sigmatch_table[DETECT_PKTVAR].Match = DetectPktvarMatch;
    sigmatch_table[DETECT_PKTVAR].Setup = DetectPktvarSetup;
    sigmatch_table[DETECT_PKTVAR].Free  = DetectPktvarFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

static int DetectPktvarMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectPktvarData *pd = (const DetectPktvarData *)ctx;

    PktVar *pv = PktVarGet(p, pd->id);
    if (pv != NULL) {
        uint8_t *ptr = SpmSearch(pv->value, pv->value_len, pd->content, pd->content_len);
        if (ptr != NULL)
            ret = 1;
    }

    return ret;
}

static void DetectPktvarFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectPktvarData *data = ptr;
    if (data != NULL) {
        SCFree(data->content);
        SCFree(data);
    }
}

static int DetectPktvarSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    char *varname = NULL, *varcontent = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    uint8_t *content = NULL;
    uint16_t len = 0;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for pktvar.", rawstr);
        return -1;
    }

    const char *str_ptr;
    res = pcre2_substring_get_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        return -1;
    }
    varname = (char *)str_ptr;

    res = pcre2_substring_get_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        pcre2_substring_free((PCRE2_UCHAR8 *)varname);
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        return -1;
    }
    varcontent = (char *)str_ptr;

    SCLogDebug("varname '%s', varcontent '%s'", varname, varcontent);

    char *parse_content;
    if (strlen(varcontent) >= 2 && varcontent[0] == '"' &&
            varcontent[strlen(varcontent) - 1] == '"')
    {
        parse_content = varcontent + 1;
        varcontent[strlen(varcontent) - 1] = '\0';
    } else {
        parse_content = varcontent;
    }

    ret = DetectContentDataParse("pktvar", parse_content, &content, &len);
    if (ret == -1 || content == NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)varname);
        pcre2_substring_free((PCRE2_UCHAR8 *)varcontent);
        return -1;
    }
    pcre2_substring_free((PCRE2_UCHAR8 *)varcontent);

    DetectPktvarData *cd = SCCalloc(1, sizeof(DetectPktvarData));
    if (unlikely(cd == NULL)) {
        pcre2_substring_free((PCRE2_UCHAR8 *)varname);
        SCFree(content);
        return -1;
    }

    cd->content = content;
    cd->content_len = len;
    cd->id = VarNameStoreSetupAdd(varname, VAR_TYPE_PKT_VAR);
    pcre2_substring_free((PCRE2_UCHAR8 *)varname);

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (unlikely(sm == NULL)) {
        DetectPktvarFree(de_ctx, cd);
        return -1;
    }
    sm->type = DETECT_PKTVAR;
    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;
}
