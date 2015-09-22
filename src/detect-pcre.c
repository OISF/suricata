/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Implements the pcre keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "pkt-var.h"
#include "flow-var.h"
#include "flow-util.h"

#include "detect-pcre.h"
#include "detect-flowvar.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-var-name.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-pool.h"

#include "conf.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "stream.h"
#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "stream.h"


#define PARSE_CAPTURE_REGEX "\\(\\?P\\<([A-z]+)\\_([A-z0-9_]+)\\>"
#define PARSE_REGEX         "(?<!\\\\)/(.*(?<!(?<!\\\\)\\\\))/([^\"]*)"

#define SC_MATCH_LIMIT_DEFAULT 3500
#define SC_MATCH_LIMIT_RECURSION_DEFAULT 1500

static int pcre_match_limit = 0;
static int pcre_match_limit_recursion = 0;

static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_capture_regex;
static pcre_extra *parse_capture_regex_study;

int DetectPcreMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectPcreALMatchCookie(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m);
int DetectPcreALMatchMethod(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m);
static int DetectPcreSetup (DetectEngineCtx *, Signature *, char *);
void DetectPcreFree(void *);
void DetectPcreRegisterTests(void);

void DetectPcreRegister (void)
{
    sigmatch_table[DETECT_PCRE].name = "pcre";
    sigmatch_table[DETECT_PCRE].desc = "match on regular expression";
    sigmatch_table[DETECT_PCRE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/HTTP-keywords#Pcre-Perl-Compatible-Regular-Expressions";
    sigmatch_table[DETECT_PCRE].Match = NULL;
    sigmatch_table[DETECT_PCRE].AppLayerMatch = NULL;
    sigmatch_table[DETECT_PCRE].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_PCRE].Setup = DetectPcreSetup;
    sigmatch_table[DETECT_PCRE].Free  = DetectPcreFree;
    sigmatch_table[DETECT_PCRE].RegisterTests  = DetectPcreRegisterTests;

    sigmatch_table[DETECT_PCRE].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;
    intmax_t val = 0;

    if (!ConfGetInt("pcre.match-limit", &val)) {
        pcre_match_limit = SC_MATCH_LIMIT_DEFAULT;
        SCLogDebug("Using PCRE match-limit setting of: %i", pcre_match_limit);
    }
    else    {
        pcre_match_limit = val;
        if (pcre_match_limit != SC_MATCH_LIMIT_DEFAULT) {
            SCLogInfo("Using PCRE match-limit setting of: %i", pcre_match_limit);
        } else {
            SCLogDebug("Using PCRE match-limit setting of: %i", pcre_match_limit);
        }
    }

    val = 0;

    if (!ConfGetInt("pcre.match-limit-recursion", &val)) {
        pcre_match_limit_recursion = SC_MATCH_LIMIT_RECURSION_DEFAULT;
        SCLogDebug("Using PCRE match-limit-recursion setting of: %i", pcre_match_limit_recursion);
    }
    else    {
        pcre_match_limit_recursion = val;
        if (pcre_match_limit_recursion != SC_MATCH_LIMIT_RECURSION_DEFAULT) {
            SCLogInfo("Using PCRE match-limit-recursion setting of: %i", pcre_match_limit_recursion);
        } else {
            SCLogDebug("Using PCRE match-limit-recursion setting of: %i", pcre_match_limit_recursion);
        }
    }

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

    opts |= PCRE_UNGREEDY; /* pkt_http_ua should be pkt, http_ua, for this reason the UNGREEDY */
    parse_capture_regex = pcre_compile(PARSE_CAPTURE_REGEX, opts, &eb, &eo, NULL);
    if(parse_capture_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_CAPTURE_REGEX, eo, eb);
        goto error;
    }

    parse_capture_regex_study = pcre_study(parse_capture_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/**
 * \brief Match a regex on a single payload.
 *
 * \param det_ctx     Thread detection ctx.
 * \param s           Signature.
 * \param sm          Sig match to match against.
 * \param p           Packet to set PktVars if any.
 * \param f           Flow to set FlowVars if any.
 * \param payload     Payload to inspect.
 * \param payload_len Length of the payload.
 *
 * \retval  1 Match.
 * \retval  0 No match.
 */
int DetectPcrePayloadMatch(DetectEngineThreadCtx *det_ctx, Signature *s,
                           SigMatch *sm, Packet *p, Flow *f, uint8_t *payload,
                           uint32_t payload_len)
{
    SCEnter();
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    uint8_t *ptr = NULL;
    uint16_t len = 0;
    uint16_t capture_len = 0;

    DetectPcreData *pe = (DetectPcreData *)sm->ctx;

    if (pe->flags & DETECT_PCRE_RELATIVE) {
        ptr = payload + det_ctx->buffer_offset;
        len = payload_len - det_ctx->buffer_offset;
    } else {
        ptr = payload;
        len = payload_len;
    }

    int start_offset = 0;
    if (det_ctx->pcre_match_start_offset != 0) {
        start_offset = (payload + det_ctx->pcre_match_start_offset - ptr);
    }

    /* run the actual pcre detection */
    ret = pcre_exec(pe->re, pe->sd, (char *)ptr, len, start_offset, 0, ov, MAX_SUBSTRINGS);
    SCLogDebug("ret %d (negating %s)", ret, (pe->flags & DETECT_PCRE_NEGATE) ? "set" : "not set");

    if (ret == PCRE_ERROR_NOMATCH) {
        if (pe->flags & DETECT_PCRE_NEGATE) {
            /* regex didn't match with negate option means we
             * consider it a match */
            ret = 1;
        } else {
            ret = 0;
        }
    } else if (ret >= 0) {
        if (pe->flags & DETECT_PCRE_NEGATE) {
            /* regex matched but we're negated, so not
             * considering it a match */
            ret = 0;
        } else {
            /* regex matched and we're not negated,
             * considering it a match */

            SCLogDebug("ret %d capidx %u", ret, pe->capidx);

            /* see if we need to do substring capturing. */
            if (ret > 1 && pe->capidx != 0) {
                SCLogDebug("capturing");
                const char *str_ptr;
                ret = pcre_get_substring((char *)ptr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
                if (ret) {
                    if (pe->flags & DETECT_PCRE_CAPTURE_PKT) {
                        if (p != NULL) {
                            PktVarAdd(p, pe->capname, (uint8_t *)str_ptr, ret);
                        }
                    } else if (pe->flags & DETECT_PCRE_CAPTURE_FLOW) {
                        if (f != NULL) {
                            /* store max 64k. Errors are ignored */
                            capture_len = (ret < 0xffff) ? (uint16_t)ret : 0xffff;
                            (void)DetectFlowvarStoreMatch(det_ctx, pe->capidx,
                                    (uint8_t *)str_ptr, capture_len,
                                    DETECT_FLOWVAR_TYPE_POSTMATCH);
                        }
                    }
                }
            }

            /* update offset for pcre RELATIVE */
            det_ctx->buffer_offset = (ptr + ov[1]) - payload;
            det_ctx->pcre_match_start_offset = (ptr + ov[0] + 1) - payload;

            ret = 1;
        }

    } else {
        SCLogDebug("pcre had matching error");
        ret = 0;
    }
    SCReturnInt(ret);
}

static int DetectPcreSetList(int list, int set)
{
    if (list != DETECT_SM_LIST_NOTSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "only one pcre option to specify a buffer type is allowed");
        return -1;
    }
    return set;
}

static int DetectPcreHasUpperCase(const char *re)
{
    size_t len = strlen(re);
    int is_meta = 0;

    for (size_t i = 0; i < len; i++) {
        if (is_meta) {
            is_meta = 0;
        }
        else if (re[i] == '\\') {
            is_meta = 1;
        }
        else if (isupper((unsigned char)re[i])) {
            return 1;
        }
    }

    return 0;
}

static DetectPcreData *DetectPcreParse (DetectEngineCtx *de_ctx, char *regexstr, int *sm_list)
{
    int ec;
    const char *eb;
    int eo;
    int opts = 0;
    DetectPcreData *pd = NULL;
    char *op = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    size_t slen = strlen(regexstr);
    char re[slen], op_str[64] = "";
    uint16_t pos = 0;
    uint8_t negate = 0;

    while (pos < slen && isspace((unsigned char)regexstr[pos])) {
        pos++;
    }

    if (regexstr[pos] == '!') {
        negate = 1;
        pos++;
    }

    ret = pcre_exec(parse_regex, parse_regex_study, regexstr + pos, slen-pos,
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret <= 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre parse error: %s", regexstr);
        goto error;
    }

    res = pcre_copy_substring((char *)regexstr + pos, ov, MAX_SUBSTRINGS,
            1, re, slen);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }

    if (ret > 2) {
        res = pcre_copy_substring((char *)regexstr + pos, ov, MAX_SUBSTRINGS,
                2, op_str, sizeof(op_str));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            return NULL;
        }
        op = op_str;
    }
    //printf("ret %" PRId32 " re \'%s\', op \'%s\'\n", ret, re, op);

    pd = SCMalloc(sizeof(DetectPcreData));
    if (unlikely(pd == NULL))
        goto error;
    memset(pd, 0, sizeof(DetectPcreData));

    if (negate)
        pd->flags |= DETECT_PCRE_NEGATE;

    if (op != NULL) {
        while (*op) {
            SCLogDebug("regex option %c", *op);

            switch (*op) {
                case 'A':
                    opts |= PCRE_ANCHORED;
                    break;
                case 'E':
                    opts |= PCRE_DOLLAR_ENDONLY;
                    break;
                case 'G':
                    opts |= PCRE_UNGREEDY;
                    break;

                case 'i':
                    opts |= PCRE_CASELESS;
                    pd->flags |= DETECT_PCRE_CASELESS;
                    break;
                case 'm':
                    opts |= PCRE_MULTILINE;
                    break;
                case 's':
                    opts |= PCRE_DOTALL;
                    break;
                case 'x':
                    opts |= PCRE_EXTENDED;
                    break;

                case 'O':
                    pd->flags |= DETECT_PCRE_MATCH_LIMIT;
                    break;

                case 'B': /* snort's option */
                    if (*sm_list != DETECT_SM_LIST_NOTSET) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'B' inconsistent with chosen buffer");
                        goto error;
                    }
                    pd->flags |= DETECT_PCRE_RAWBYTES;
                    break;
                case 'R': /* snort's option */
                    pd->flags |= DETECT_PCRE_RELATIVE;
                    break;

                /* buffer selection */

                case 'U': /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'U' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_UMATCH);
                    break;
                case 'V':
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'V' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HUADMATCH);
                    break;
                case 'W':
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'W' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HHHDMATCH);
                    break;
                case 'Z':
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'Z' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HRHHDMATCH);
                    break;
                case 'H': /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'H' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HHDMATCH);
                    break;
                case 'I': /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'I' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HRUDMATCH);
                    break;
                case 'D': /* snort's option */
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HRHDMATCH);
                    break;
                case 'M': /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'M' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HMDMATCH);
                    break;
                case 'C': /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'C' inconsistent with 'B'");
                        goto error;
                    }
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HCDMATCH);
                    break;
                case 'P':
                    /* snort's option (http request body inspection) */
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HCBDMATCH);
                    break;
                case 'Q':
                    /* suricata extension (http response body inspection) */
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_FILEDATA);
                    break;
                case 'Y':
                    /* snort's option */
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HSMDMATCH);
                    break;
                case 'S':
                    /* snort's option */
                    *sm_list = DetectPcreSetList(*sm_list, DETECT_SM_LIST_HSCDMATCH);
                    break;
                default:
                    SCLogError(SC_ERR_UNKNOWN_REGEX_MOD, "unknown regex modifier '%c'", *op);
                    goto error;
            }
            op++;
        }
    }
    if (*sm_list == -1)
        goto error;

    SCLogDebug("DetectPcreParse: \"%s\"", re);

    /* host header */
    if (*sm_list == DETECT_SM_LIST_HHHDMATCH) {
        if (pd->flags & DETECT_PCRE_CASELESS) {
            SCLogWarning(SC_ERR_INVALID_SIGNATURE, "http host pcre(\"W\") "
                         "specified along with \"i(caseless)\" modifier.  "
                         "Since the hostname buffer we match against "
                         "is actually lowercase, having a "
                         "nocase is redundant.");
        }
        else if (DetectPcreHasUpperCase(re)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "pcre host(\"W\") "
                "specified has an uppercase char.  "
                "Since the hostname buffer we match against "
                "is actually lowercase, please specify an "
                "all lowercase based pcre.");
            goto error;
        }
    }

    /* Try to compile as if all (...) groups had been meant as (?:...),
     * which is the common case in most rules.
     * If we fail because a capture group is later referenced (e.g., \1),
     * PCRE will let us know.
     */
    pd->re = pcre_compile2(re, opts | PCRE_NO_AUTO_CAPTURE, &ec, &eb, &eo, NULL);
    if (pd->re == NULL && ec == 15) { // reference to non-existent subpattern
        pd->re = pcre_compile(re, opts, &eb, &eo, NULL);
    }

    if(pd->re == NULL)  {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", regexstr, eo, eb);
        goto error;
    }
#ifdef PCRE_HAVE_JIT
    pd->sd = pcre_study(pd->re, PCRE_STUDY_JIT_COMPILE, &eb);
    if(eb != NULL)  {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed : %s", eb);
        goto error;
    }

    int jit = 0;
    ret = pcre_fullinfo(pd->re, pd->sd, PCRE_INFO_JIT, &jit);
    if (ret != 0 || jit != 1) {
        /* warning, so we won't print the sig after this. Adding
         * file and line to the message so the admin can figure
         * out what sig this is about */
        SCLogDebug("PCRE JIT compiler does not support: %s. "
                "Falling back to regular PCRE handling (%s:%d)",
                regexstr, de_ctx->rule_file, de_ctx->rule_line);
    }
#else
    pd->sd = pcre_study(pd->re, 0, &eb);
    if(eb != NULL)  {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed : %s", eb);
        goto error;
    }
#endif /*PCRE_HAVE_JIT*/

    if (pd->sd == NULL)
        pd->sd = (pcre_extra *) SCCalloc(1,sizeof(pcre_extra));

    if (pd->sd) {
        if(pd->flags & DETECT_PCRE_MATCH_LIMIT) {
            if(pcre_match_limit >= -1)    {
                pd->sd->match_limit = pcre_match_limit;
                pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT;
            }
#ifndef NO_PCRE_MATCH_RLIMIT
            if(pcre_match_limit_recursion >= -1)    {
                pd->sd->match_limit_recursion = pcre_match_limit_recursion;
                pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
            }
#endif /* NO_PCRE_MATCH_RLIMIT */
        } else {
            pd->sd->match_limit = SC_MATCH_LIMIT_DEFAULT;
            pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT;
#ifndef NO_PCRE_MATCH_RLIMIT
            pd->sd->match_limit_recursion = SC_MATCH_LIMIT_RECURSION_DEFAULT;
            pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
#endif /* NO_PCRE_MATCH_RLIMIT */
        }
    } else {
        goto error;
    }

    return pd;

error:
    if (pd != NULL && pd->re != NULL)
        pcre_free(pd->re);
    if (pd != NULL && pd->sd != NULL)
        pcre_free(pd->sd);
    if (pd)
        SCFree(pd);
    return NULL;
}

/** \internal
 *  \brief check if we need to extract capture settings and set them up if needed
 */
static int DetectPcreParseCapture(char *regexstr, DetectEngineCtx *de_ctx, DetectPcreData *pd)
{
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char type_str[16] = "";
    size_t cap_buffer_len = strlen(regexstr);
    char capture_str[cap_buffer_len];
    memset(capture_str, 0x00, cap_buffer_len);

    if (de_ctx == NULL)
        goto error;

    SCLogDebug("\'%s\'", regexstr);

    ret = pcre_exec(parse_capture_regex, parse_capture_regex_study, regexstr, strlen(regexstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3) {
        return 0;
    }

    res = pcre_copy_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 1, type_str, sizeof(type_str));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    res = pcre_copy_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 2, capture_str, cap_buffer_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    if (strlen(capture_str) == 0 || strlen(type_str) == 0) {
        goto error;
    }

    SCLogDebug("type \'%s\'", type_str);
    SCLogDebug("capture \'%s\'", capture_str);

    pd->capname = SCStrdup(capture_str);
    if (unlikely(pd->capname == NULL))
        goto error;

    if (strcmp(type_str, "pkt") == 0) {
        pd->flags |= DETECT_PCRE_CAPTURE_PKT;
    } else if (strcmp(type_str, "flow") == 0) {
        pd->flags |= DETECT_PCRE_CAPTURE_FLOW;
        SCLogDebug("flow capture");
    }
    if (pd->capname != NULL) {
        if (pd->flags & DETECT_PCRE_CAPTURE_PKT)
            pd->capidx = VariableNameGetIdx(de_ctx, (char *)pd->capname, VAR_TYPE_PKT_VAR);
        else if (pd->flags & DETECT_PCRE_CAPTURE_FLOW)
            pd->capidx = VariableNameGetIdx(de_ctx, (char *)pd->capname, VAR_TYPE_FLOW_VAR);
    }

    SCLogDebug("pd->capname %s", pd->capname);
    return 0;

error:
    if (pd->capname != NULL) {
        SCFree(pd->capname);
        pd->capname = NULL;
    }
    return -1;
}

static int DetectPcreSetup (DetectEngineCtx *de_ctx, Signature *s, char *regexstr)
{
    SCEnter();
    DetectPcreData *pd = NULL;
    SigMatch *sm = NULL;
    int ret = -1;
    int parsed_sm_list = DETECT_SM_LIST_NOTSET;

    pd = DetectPcreParse(de_ctx, regexstr, &parsed_sm_list);
    if (pd == NULL)
        goto error;
    if (DetectPcreParseCapture(regexstr, de_ctx, pd) < 0)
        goto error;

    if (parsed_sm_list == DETECT_SM_LIST_UMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HRUDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HCBDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_FILEDATA ||
        parsed_sm_list == DETECT_SM_LIST_HHDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HRHDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HSMDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HSCDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HHHDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HRHHDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HMDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HCDMATCH ||
        parsed_sm_list == DETECT_SM_LIST_HUADMATCH)
    {
        if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "Invalid option.  "
                       "Conflicting alprotos detected for this rule.  Http "
                       "pcre modifier found along with a different protocol "
                       "for the rule.");
            goto error;
        }
        if (s->list != DETECT_SM_LIST_NOTSET) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "pcre found with http "
                       "modifier set, with file_data/dce_stub_data sticky "
                       "option set.");
            goto error;
        }
    }

    int sm_list = -1;
    if (s->list != DETECT_SM_LIST_NOTSET) {
        if (s->list == DETECT_SM_LIST_FILEDATA) {
            SCLogDebug("adding to http server body list because of file data");
            AppLayerHtpEnableResponseBodyCallback();
        } else if (s->list == DETECT_SM_LIST_DMATCH) {
            SCLogDebug("adding to dmatch list because of dce_stub_data");
        } else if (s->list == DETECT_SM_LIST_DNSQUERYNAME_MATCH) {
            SCLogDebug("adding to DETECT_SM_LIST_DNSQUERYNAME_MATCH list because of dns_query");
        }
        s->flags |= SIG_FLAG_APPLAYER;
        sm_list = s->list;
    } else {
        switch(parsed_sm_list) {
            case DETECT_SM_LIST_HCBDMATCH:
                AppLayerHtpEnableRequestBodyCallback();
                s->flags |= SIG_FLAG_APPLAYER;
                s->alproto = ALPROTO_HTTP;
                sm_list = parsed_sm_list;
                break;

            case DETECT_SM_LIST_FILEDATA:
                AppLayerHtpEnableResponseBodyCallback();
                s->flags |= SIG_FLAG_APPLAYER;
                s->alproto = ALPROTO_HTTP;
                sm_list = parsed_sm_list;
                break;

            case DETECT_SM_LIST_UMATCH:
            case DETECT_SM_LIST_HRUDMATCH:
            case DETECT_SM_LIST_HHDMATCH:
            case DETECT_SM_LIST_HRHDMATCH:
            case DETECT_SM_LIST_HHHDMATCH:
            case DETECT_SM_LIST_HRHHDMATCH:
            case DETECT_SM_LIST_HSMDMATCH:
            case DETECT_SM_LIST_HSCDMATCH:
            case DETECT_SM_LIST_HCDMATCH:
            case DETECT_SM_LIST_HMDMATCH:
            case DETECT_SM_LIST_HUADMATCH:
                s->flags |= SIG_FLAG_APPLAYER;
                s->alproto = ALPROTO_HTTP;
                sm_list = parsed_sm_list;
                break;
            case DETECT_SM_LIST_NOTSET:
                sm_list = DETECT_SM_LIST_PMATCH;
                break;
        }
    }
    if (sm_list == -1)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_PCRE;
    sm->ctx = (void *)pd;
    SigMatchAppendSMToList(s, sm, sm_list);

    if (pd->capidx != 0) {
        if (DetectFlowvarPostMatchSetup(s, pd->capidx) < 0)
            goto error_nofree;
    }

    if (!(pd->flags & DETECT_PCRE_RELATIVE))
        goto okay;

    /* errors below shouldn't free pd */

    SigMatch *prev_pm = SigMatchGetLastSMFromLists(s, 4,
                                                   DETECT_CONTENT, sm->prev,
                                                   DETECT_PCRE, sm->prev);
    if (s->list == DETECT_SM_LIST_NOTSET && prev_pm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "pcre with /R (relative) needs "
                "preceeding match in the same buffer");
        goto error_nofree;
    /* null is allowed when we use a sticky buffer */
    } else if (prev_pm == NULL)
        goto okay;
    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *tmp = (DetectPcreData *)prev_pm->ctx;
        tmp->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

 okay:
    ret = 0;
    SCReturnInt(ret);
 error:
    DetectPcreFree(pd);
 error_nofree:
    SCReturnInt(ret);
}

void DetectPcreFree(void *ptr)
{
    if (ptr == NULL)
        return;

    DetectPcreData *pd = (DetectPcreData *)ptr;

    if (pd->capname != NULL)
        SCFree(pd->capname);
    if (pd->re != NULL)
        pcre_free(pd->re);
    if (pd->sd != NULL)
        pcre_free(pd->sd);

    SCFree(pd);
    return;
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectPcreParseTest01 make sure we don't allow invalid opts 7.
 */
static int DetectPcreParseTest01 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/7";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }

    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest02 make sure we don't allow invalid opts Ui$.
 */
static int DetectPcreParseTest02 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/Ui$";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest03 make sure we don't allow invalid opts UZi.
 */
static int DetectPcreParseTest03 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/UNi";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest04 make sure we allow escaped "
 */
static int DetectPcreParseTest04 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b\\\"lah/i";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest05 make sure we parse pcre with no opts
 */
static int DetectPcreParseTest05 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest06 make sure we parse pcre with smi opts
 */
static int DetectPcreParseTest06 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/smi";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest07 make sure we parse pcre with /Ui opts
 */
static int DetectPcreParseTest07 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/Ui";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest08 make sure we parse pcre with O opts
 */
static int DetectPcreParseTest08 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/O";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest09 make sure we parse pcre with a content
 *       that has slashes
 */
static int DetectPcreParseTest09 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/lala\\\\/";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;

    pd = DetectPcreParse(de_ctx, teststring, &list);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Test pcre option for dce sig(yeah I'm bored of writing test titles).
 */
int DetectPcreParseTest10(void)
{
    Signature *s = SigAlloc();
    int result = 1;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    s->alproto = ALPROTO_DCERPC;

    result &= (DetectPcreSetup(de_ctx, s, "/bamboo/") == 0);
    result &= (s->sm_lists[DETECT_SM_LIST_DMATCH] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(s);

    s = SigAlloc();
    /* failure since we have no preceding content/pcre/bytejump */
    result &= (DetectPcreSetup(de_ctx, s, "/bamboo/") == 0);
    result &= (s->sm_lists[DETECT_SM_LIST_DMATCH] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

 end:
    SigFree(s);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test pcre option for dce sig.
 */
int DetectPcreParseTest11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytejump_body\"; "
                               "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                               "dce_stub_data; "
                               "pcre:/bamboo/R; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "pcre:/bamboo/R; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "pcre:/bamboo/RB; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (!(data->flags & DETECT_PCRE_RAWBYTES) ||
        !(data->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "content:\"one\"; pcre:/bamboo/; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test pcre option with file data. pcre is relative to file_data,
 *       so relative flag should be unset.
 */
static int DetectPcreParseTest12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; pcre:/abc/R; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("empty server body list: ");
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->type != DETECT_PCRE) {
        printf("last sm not pcre: ");
        goto end;
    }

    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->ctx;
    if (data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE)) {
        printf("flags not right: ");
        goto end;
    }

    result = 1;
 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test pcre option with file data.
 */
static int DetectPcreParseTest13(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"abc\"; pcre:/def/R; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("empty server body list: ");
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->type != DETECT_PCRE) {
        printf("last sm not pcre: ");
        goto end;
    }

    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->ctx;
    if (data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE)) {
        printf("flags not right: ");
        goto end;
    }

    result = 1;
 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test pcre option with file data.
 */
static int DetectPcreParseTest14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; pcre:/def/; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("empty server body list: ");
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->type != DETECT_PCRE) {
        printf("last sm not pcre: ");
        goto end;
    }

    data = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_FILEDATA]->ctx;
    if (data->flags & DETECT_PCRE_RAWBYTES ||
        data->flags & DETECT_PCRE_RELATIVE) {
        printf("flags not right: ");
        goto end;
    }

    result = 1;
 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Check a signature with pcre relative method */
int DetectPcreParseTest15(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_method\"; "
                               "content:\"GET\"; "
                               "http_method; pcre:\"/abc/RM\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}


/** \test Check a signature with pcre relative cookie */
int DetectPcreParseTest16(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_cookie\"; "
                               "content:\"test\"; "
                               "http_cookie; pcre:\"/abc/RC\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative raw header */
int DetectPcreParseTest17(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_raw_header\"; "
                               "flow:to_server; content:\"test\"; "
                               "http_raw_header; pcre:\"/abc/RD\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative header */
int DetectPcreParseTest18(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_header\"; "
                               "content:\"test\"; "
                               "http_header; pcre:\"/abc/RH\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative client-body */
int DetectPcreParseTest19(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relativie http_client_body\"; "
                               "content:\"test\"; "
                               "http_client_body; pcre:\"/abc/RP\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative raw uri */
int DetectPcreParseTest20(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; "
                               "content:\"test\"; "
                               "http_raw_uri; pcre:\"/abc/RI\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative uricontent */
int DetectPcreParseTest21(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative uricontent\"; "
                               "uricontent:\"test\"; "
                               "pcre:\"/abc/RU\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with pcre relative http_uri */
int DetectPcreParseTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_uri\"; "
                               "content:\"test\"; "
                               "http_uri; pcre:\"/abc/RU\"; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with inconsistent pcre relative  */
int DetectPcreParseTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre relative\"; "
                               "content:\"GET\"; "
                               "http_cookie; pcre:\"/abc/RM\"; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    } else {
        printf("sig parse shouldn't have failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with inconsistent pcre modifiers  */
int DetectPcreParseTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/UI\"; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    } else {
        printf("sig parse should have failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with inconsistent pcre modifiers  */
int DetectPcreParseTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/DH\"; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    } else {
        printf("sig parse should have failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with inconsistent pcre modifiers  */
static int DetectPcreParseTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert http any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/F\"; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    } else {
        printf("sig parse should have failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Bug 1098 */
static int DetectPcreParseTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any 80 "
            "(content:\"baduricontent\"; http_raw_uri; "
            "pcre:\"/^[a-z]{5}\\.html/R\"; sid:2; rev:2;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    } else {
        printf("sig parse should have failed: ");
    }

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectPcreTestSig01Real(int mpm_type)
{
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;
    Flow f;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(TcpSession));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; pcre:\"/^gEt/i\"; pcre:\"/\\/two\\//U; pcre:\"/GET \\/two\\//\"; pcre:\"/\\s+HTTP/R\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 1) {
        result = 1;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);

    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}
static int DetectPcreTestSig01B2g (void)
{
    return DetectPcreTestSig01Real(MPM_B2G);
}
static int DetectPcreTestSig01B3g (void)
{
    return DetectPcreTestSig01Real(MPM_B3G);
}
static int DetectPcreTestSig01Wm (void)
{
    return DetectPcreTestSig01Real(MPM_WUMANBER);
}

static int DetectPcreTestSig02Real(int mpm_type)
{
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    pcre_match_limit = 100;
    pcre_match_limit_recursion = 100;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; pcre:\"/two/O\"; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 2) == 1) {
        result = 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FLOW_DESTROY(&f);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int DetectPcreTestSig02B2g (void)
{
    return DetectPcreTestSig02Real(MPM_B2G);
}
static int DetectPcreTestSig02B3g (void)
{
    return DetectPcreTestSig02Real(MPM_B3G);
}
static int DetectPcreTestSig02Wm (void)
{
    return DetectPcreTestSig02Real(MPM_WUMANBER);
}

/**
 * \test DetectPcreTestSig03Real negation test ! outside of "" this sig should not match
 */
static int DetectPcreTestSig03Real(int mpm_type)
{
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 1;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"GET\"; pcre:!\"/two/\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)){
        printf("sid 1 matched even though it shouldn't have:");
        result = 0;
    }
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectPcreTestSig03B2g (void)
{
    return DetectPcreTestSig03Real(MPM_B2G);
}
static int DetectPcreTestSig03B3g (void)
{
    return DetectPcreTestSig03Real(MPM_B3G);
}
static int DetectPcreTestSig03Wm (void)
{
    return DetectPcreTestSig03Real(MPM_WUMANBER);
}

/**
 * \test Check the signature with pcre modifier P (match with L7 to http body data)
 */
static int DetectPcreModifPTest04(void)
{
    int result = 0;
    uint8_t httpbuf1[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\n"
        "Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Date: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Server: Apache\r\n"
        "X-Powered-By: PHP/5.2.5\r\n"
        "P3P: CP=\"NOI ADM DEV PSAi COM NAV OUR OTRo STP IND DEM\"\r\n"
        "Expires: Mon, 1 Jan 2001 00:00:00 GMT\r\n"
        "Last-Modified: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\n"
        "Pragma: no-cache\r\n"
        "Keep-Alive: timeout=15, max=100\r\n"
        "Connection: Keep-Alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "15"
        "\r\n"
        "<!DOCTYPE html PUBLIC\r\n"
        "0\r\n\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"Pcre modifier P\"; pcre:\"/DOCTYPE/P\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\""
                          "Pcre modifier P (no match)\"; pcre:\"/blah/P\"; sid:2;)");
    if (s->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sid 2 matched but shouldn't: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Check the signature with pcre modifier P (match with L7 to http body data)
 *       over fragmented chunks (DOCTYPE fragmented)
 */
static int DetectPcreModifPTest05(void)
{
    int result = 0;
    uint8_t httpbuf1[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\n"
        "Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Date: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Server: Apache\r\n"
        "X-Powered-By: PHP/5.2.5\r\n"
        "P3P: CP=\"NOI ADM DEV PSAi COM NAV OUR OTRo STP IND DEM\"\r\n"
        "Expires: Mon, 1 Jan 2001 00:00:00 GMT\r\n"
        "Last-Modified: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\n"
        "Pragma: no-cache\r\n"
        "Keep-Alive: timeout=15, max=100\r\n"
        "Connection: Keep-Alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "15"
        "\r\n"
        "<!DOC";

    uint8_t httpbuf2[] = "<!DOCTYPE html PUBLIC\r\n0\r\n\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"Pcre modifier P\"; pcre:\"/DOC/P\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\""
                          "Pcre modifier P (no match)\"; pcre:\"/DOCTYPE/P\"; sid:2;)");
    if (s->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p1, 2)) {
        printf("sid 2 did match on p1 but shouldn't have: ");
        /* It's a partial match over 2 chunks*/
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 did match on p2 but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p2, 2))) {
        printf("sid 2 didn't match on p2 but should have: ");
        /* It's a partial match over 2 chunks*/
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

int DetectPcreTestSig06()
{
    uint8_t *buf = (uint8_t *)
                    "lalala lalala\\ lala\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; pcre:\"/ lalala\\\\/\"; sid:1;)";
    if (UTHPacketMatchSig(p, sig) == 0) {
        result = 0;
        goto end;
    }
    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test anchored pcre */
int DetectPcreTestSig07()
{
    uint8_t *buf = (uint8_t *)
                    "lalala\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; pcre:\"/^(la)+$/\"; sid:1;)";
    if (UTHPacketMatchSig(p, sig) == 0) {
        result = 0;
        goto end;
    }
    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test anchored pcre */
int DetectPcreTestSig08()
{
    /* test it also without ending in a newline "\n" */
    uint8_t *buf = (uint8_t *)
                    "lalala";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; pcre:\"/^(la)+$/\"; sid:1;)";
    if (UTHPacketMatchSig(p, sig) == 0) {
        result = 0;
        goto end;
    }
    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test Check the signature working to alert when cookie modifier is
 *       passed to pcre
 */
static int DetectPcreTestSig09(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; pcre:\"/dummy/C\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 failed to match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when cookie modifier is
 *       passed to a negated pcre
 */
static int DetectPcreTestSig10(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummoOOooooO\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP cookie\"; pcre:!\"/dummy/C\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 should match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when method modifier is
 *       passed to pcre
 */
static int DetectPcreTestSig11(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP method\"; pcre:\"/POST/M\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 failed to match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when method modifier is
 *       passed to a negated pcre
 */
static int DetectPcreTestSig12(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummoOOooooO\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP method\"; pcre:!\"/POST/M\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 should match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when header modifier is
 *       passed to pcre
 */
static int DetectPcreTestSig13(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP header\"; pcre:\"/User[-_]Agent[:]?\\sMozilla/H\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 failed to match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when header modifier is
 *       passed to a negated pcre
 */
static int DetectPcreTestSig14(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nUser-Agent: IEXPLORER/1.0\r\n"
        "Cookie: dummoOOooooO\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP header\"; pcre:!\"/User-Agent[:]?\\s+Mozilla/H\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 should match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when cookie and relative modifiers are
 *       passed to pcre
 */
static int DetectPcreTestSig15(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy 1234\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"pcre relative HTTP cookie\"; content:\"dummy\";"
                                   " http_cookie; pcre:\"/1234/RC\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 failed to match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Check the signature working to alert when method and relative modifiers are
 *       passed to pcre
 */
static int DetectPcreTestSig16(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
        "Cookie: dummy 1234\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"pcre relative HTTP method\"; content:\"PO\";"
                                   " http_method; pcre:\"/ST/RM\"; "
                                   " sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 failed to match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test Test tracking of body chunks per transactions (on requests)
 */
static int DetectPcreTxBodyChunksTest01(void)
{
    int result = 0;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "GET / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    AppLayerHtpEnableRequestBodyCallback();

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* Now we should have 2 transactions, each with it's own list
     * of request body chunks (let's test it) */

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* hardcoded check of the transactions and it's client body chunks */
    if (AppLayerParserGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);
    if (htud == NULL) {
        printf("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    HtpBodyChunk *cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (memcmp(cur->data, "Body one!!", strlen("Body one!!")) != 0) {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (memcmp(cur->data, "Body two!!", strlen("Body two!!")) != 0) {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }


    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SCMutexUnlock(&f.m);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test test pcre P modifier with multiple pipelined http transactions */
static int DetectPcreTxBodyChunksTest02(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; pcre:\"/one/P\"; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; pcre:\"/two/P\"; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* hardcoded check of the transactions and it's client body chunks */
    if (AppLayerParserGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);

    HtpBodyChunk *cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (memcmp(cur->data, "Body one!!", strlen("Body one!!")) != 0) {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (memcmp(cur->data, "Body two!!", strlen("Body two!!")) != 0) {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectPcreTxBodyChunksTest03(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; pcre:\"/one/P\"; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; pcre:\"/two/P\"; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (AppLayerParserGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/**
 * \test flowvar capture on http buffer
 */
static int DetectPcreFlowvarCapture01(void)
{
    int result = 0;
    uint8_t uabuf1[] =
        "Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13";
    uint32_t ualen1 = sizeof(uabuf1) - 1; /* minus the \0 */
    uint8_t httpbuf1[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\n"
        "Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Date: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Server: Apache\r\n"
        "\r\n"
        "<!DOCTYPE html PUBLIC\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"User-Agent: \"; http_header; pcre:\"/(?P<flow_ua>.*)\\r\\n/HR\"; sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->type != DETECT_PCRE) {
        goto end;
    }
    DetectPcreData *pd = (DetectPcreData *)s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->ctx;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, pd->capidx);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != ualen1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, ualen1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, uabuf1, ualen1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);
        PrintRawDataFp(stdout, uabuf1, ualen1);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    return result;
}

/**
 * \test flowvar capture on http buffer, capture overwrite
 */
static int DetectPcreFlowvarCapture02(void)
{
    int result = 0;
    uint8_t uabuf1[] =
        "Apache";
    uint32_t ualen1 = sizeof(uabuf1) - 1; /* minus the \0 */
    uint8_t httpbuf1[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\n"
        "Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Date: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Server: Apache\r\n"
        "\r\n"
        "<!DOCTYPE html PUBLIC\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"User-Agent: \"; http_header; pcre:\"/(?P<flow_ua>.*)\\r\\n/HR\"; priority:1; sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->type != DETECT_PCRE) {
        goto end;
    }
    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->ctx;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"Server: \"; http_header; pcre:\"/(?P<flow_ua>.*)\\r\\n/HR\"; priority:3; sid:2;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->type != DETECT_PCRE) {
        goto end;
    }
    DetectPcreData *pd2 = (DetectPcreData *)s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->ctx;

    if (pd1->capidx != pd2->capidx) {
        printf("capidx mismatch, %u != %u: ", pd1->capidx, pd2->capidx);
        goto end;
    }

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, pd1->capidx);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != ualen1) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);
        PrintRawDataFp(stdout, uabuf1, ualen1);
        printf("%u != %u: ", fv->data.fv_str.value_len, ualen1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, uabuf1, ualen1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);
        PrintRawDataFp(stdout, uabuf1, ualen1);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    return result;
}

/**
 * \test flowvar capture on http buffer, capture overwrite + no matching sigs, so flowvars should not be set.
 */
static int DetectPcreFlowvarCapture03(void)
{
    int result = 0;
    uint8_t httpbuf1[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.13) Gecko/2009080315 Ubuntu/8.10 (intrepid) Firefox/3.0.13\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8\r\n"
        "Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Date: Tue, 22 Sep 2009 19:24:48 GMT\r\n"
        "Server: Apache\r\n"
        "\r\n"
        "<!DOCTYPE html PUBLIC\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"User-Agent: \"; http_header; pcre:\"/(?P<flow_ua>.*)\\r\\n/HR\"; content:\"xyz\"; http_header; priority:1; sid:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->type != DETECT_PCRE) {
        goto end;
    }
    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->ctx;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"Server: \"; http_header; pcre:\"/(?P<flow_ua>.*)\\r\\n/HR\"; content:\"xyz\"; http_header; priority:3; sid:2;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next == NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->type != DETECT_PCRE) {
        goto end;
    }
    DetectPcreData *pd2 = (DetectPcreData *)s->sm_lists[DETECT_SM_LIST_HHDMATCH]->next->ctx;

    if (pd1->capidx != pd2->capidx) {
        printf("capidx mismatch, %u != %u: ", pd1->capidx, pd2->capidx);
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but shouldn't have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, pd1->capidx);
    if (fv != NULL) {
        printf("flowvar, shouldn't have one: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    return result;
}

/**
 * \brief Test parsing of pcre's with the W modifier set.
 */
static int DetectPcreParseHttpHost(void)
{
    int result = 0;
    DetectPcreData *pd = NULL;
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        return 0;
    }

    pd = DetectPcreParse(de_ctx, "/domain\\.com/W", &list);
    if (pd == NULL) {
        goto end;
    }
    DetectPcreFree(pd);

    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/dOmain\\.com/W", &list);
    if (pd != NULL) {
        DetectPcreFree(pd);
        goto end;
    }

    /* Uppercase meta characters are valid. */
    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/domain\\D+\\.com/W", &list);
    if (pd == NULL) {
        goto end;
    }
    DetectPcreFree(pd);

    /* This should not parse as the first \ escapes the second \, then
     * we have a D. */
    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/\\\\Ddomain\\.com/W", &list);
    if (pd != NULL) {
        DetectPcreFree(pd);
        goto end;
    }

    result = 1;

end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectPcre
 */
void DetectPcreRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectPcreParseTest01", DetectPcreParseTest01, 1);
    UtRegisterTest("DetectPcreParseTest02", DetectPcreParseTest02, 1);
    UtRegisterTest("DetectPcreParseTest03", DetectPcreParseTest03, 1);
    UtRegisterTest("DetectPcreParseTest04", DetectPcreParseTest04, 1);
    UtRegisterTest("DetectPcreParseTest05", DetectPcreParseTest05, 1);
    UtRegisterTest("DetectPcreParseTest06", DetectPcreParseTest06, 1);
    UtRegisterTest("DetectPcreParseTest07", DetectPcreParseTest07, 1);
    UtRegisterTest("DetectPcreParseTest08", DetectPcreParseTest08, 1);
    UtRegisterTest("DetectPcreParseTest09", DetectPcreParseTest09, 1);
    UtRegisterTest("DetectPcreParseTest10", DetectPcreParseTest10, 1);
    UtRegisterTest("DetectPcreParseTest11", DetectPcreParseTest11, 1);
    UtRegisterTest("DetectPcreParseTest12", DetectPcreParseTest12, 1);
    UtRegisterTest("DetectPcreParseTest13", DetectPcreParseTest13, 1);
    UtRegisterTest("DetectPcreParseTest14", DetectPcreParseTest14, 1);
    UtRegisterTest("DetectPcreParseTest15", DetectPcreParseTest15, 1);
    UtRegisterTest("DetectPcreParseTest16", DetectPcreParseTest16, 1);
    UtRegisterTest("DetectPcreParseTest17", DetectPcreParseTest17, 1);
    UtRegisterTest("DetectPcreParseTest18", DetectPcreParseTest18, 1);
    UtRegisterTest("DetectPcreParseTest19", DetectPcreParseTest19, 1);
    UtRegisterTest("DetectPcreParseTest20", DetectPcreParseTest20, 1);
    UtRegisterTest("DetectPcreParseTest21", DetectPcreParseTest21, 1);
    UtRegisterTest("DetectPcreParseTest22", DetectPcreParseTest22, 1);
    UtRegisterTest("DetectPcreParseTest23", DetectPcreParseTest23, 1);
    UtRegisterTest("DetectPcreParseTest24", DetectPcreParseTest24, 1);
    UtRegisterTest("DetectPcreParseTest25", DetectPcreParseTest25, 1);
    UtRegisterTest("DetectPcreParseTest26", DetectPcreParseTest26, 1);
    UtRegisterTest("DetectPcreParseTest27", DetectPcreParseTest27, 1);

    UtRegisterTest("DetectPcreTestSig01B2g -- pcre test", DetectPcreTestSig01B2g, 1);
    UtRegisterTest("DetectPcreTestSig01B3g -- pcre test", DetectPcreTestSig01B3g, 1);
    UtRegisterTest("DetectPcreTestSig01Wm -- pcre test", DetectPcreTestSig01Wm, 1);
    UtRegisterTest("DetectPcreTestSig02B2g -- pcre test", DetectPcreTestSig02B2g, 1);
    UtRegisterTest("DetectPcreTestSig02B3g -- pcre test", DetectPcreTestSig02B3g, 1);
    UtRegisterTest("DetectPcreTestSig02Wm -- pcre test", DetectPcreTestSig02Wm, 1);
    UtRegisterTest("DetectPcreTestSig03B2g -- negated pcre test", DetectPcreTestSig03B2g, 1);
    UtRegisterTest("DetectPcreTestSig03B3g -- negated pcre test", DetectPcreTestSig03B3g, 1);
    UtRegisterTest("DetectPcreTestSig03Wm -- negated pcre test", DetectPcreTestSig03Wm, 1);

    UtRegisterTest("DetectPcreModifPTest04 -- Modifier P", DetectPcreModifPTest04, 1);
    UtRegisterTest("DetectPcreModifPTest05 -- Modifier P fragmented", DetectPcreModifPTest05, 1);
    UtRegisterTest("DetectPcreTestSig06", DetectPcreTestSig06, 1);
    UtRegisterTest("DetectPcreTestSig07 -- anchored pcre", DetectPcreTestSig07, 1);
    UtRegisterTest("DetectPcreTestSig08 -- anchored pcre", DetectPcreTestSig08, 1);
    UtRegisterTest("DetectPcreTestSig09 -- Cookie modifier", DetectPcreTestSig09, 1);
    UtRegisterTest("DetectPcreTestSig10 -- negated Cookie modifier", DetectPcreTestSig10, 1);
    UtRegisterTest("DetectPcreTestSig11 -- Method modifier", DetectPcreTestSig11, 1);
    UtRegisterTest("DetectPcreTestSig12 -- negated Method modifier", DetectPcreTestSig12, 1);
    UtRegisterTest("DetectPcreTestSig13 -- Header modifier", DetectPcreTestSig13, 1);
    UtRegisterTest("DetectPcreTestSig14 -- negated Header modifier", DetectPcreTestSig14, 1);
    UtRegisterTest("DetectPcreTestSig15 -- relative Cookie modifier", DetectPcreTestSig15, 1);
    UtRegisterTest("DetectPcreTestSig16 -- relative Method modifier", DetectPcreTestSig16, 1);

    UtRegisterTest("DetectPcreTxBodyChunksTest01", DetectPcreTxBodyChunksTest01, 1);
    UtRegisterTest("DetectPcreTxBodyChunksTest02 -- modifier P, body chunks per tx", DetectPcreTxBodyChunksTest02, 1);
    UtRegisterTest("DetectPcreTxBodyChunksTest03 -- modifier P, body chunks per tx", DetectPcreTxBodyChunksTest03, 1);

    UtRegisterTest("DetectPcreFlowvarCapture01 -- capture for http_header", DetectPcreFlowvarCapture01, 1);
    UtRegisterTest("DetectPcreFlowvarCapture02 -- capture for http_header", DetectPcreFlowvarCapture02, 1);
    UtRegisterTest("DetectPcreFlowvarCapture03 -- capture for http_header", DetectPcreFlowvarCapture03, 1);

    UtRegisterTest("DetectPcreParseHttpHost", DetectPcreParseHttpHost, 1);

#endif /* UNITTESTS */
}

