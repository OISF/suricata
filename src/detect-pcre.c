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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the pcre keyword
 */

#include "suricata-common.h"

#include "flow-util.h"

#include "detect-pcre.h"
#include "detect-flowvar.h"

#include "detect-content.h"
#include "detect-engine.h"
#include "detect-engine-build.h"

#include "util-var-name.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"

#include "app-layer-htp.h"
#include "stream-tcp.h"
#include "app-layer-parser.h"
#include "util-pages.h"

/* pcre named substring capture supports only 32byte names, A-z0-9 plus _
 * and needs to start with non-numeric. */
#define PARSE_CAPTURE_REGEX "\\(\\?P\\<([A-z]+)\\_([A-z0-9_]+)\\>"
#define PARSE_REGEX         "(?<!\\\\)/(.*(?<!(?<!\\\\)\\\\))/([^\"]*)"

static int pcre_match_limit = 0;
static int pcre_match_limit_recursion = 0;

static DetectParseRegex *parse_regex;
static DetectParseRegex *parse_capture_regex;

#ifdef PCRE2_HAVE_JIT
static int pcre2_use_jit = 1;
#endif

// TODOpcre2 pcre2_jit_stack_create ?

/* \brief Helper function for using pcre2_match with/without JIT
 */
static inline int DetectPcreExec(DetectEngineThreadCtx *det_ctx, DetectPcreData *pd,
        const char *str, const size_t strlen, int start_offset, int options,
        pcre2_match_data *match)
{
    return pcre2_match(pd->parse_regex.regex, (PCRE2_SPTR8)str, strlen, start_offset, options,
            match, pd->parse_regex.context);
}

static int DetectPcreSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectPcreFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectPcreRegisterTests(void);
#endif

void DetectPcreRegister (void)
{
    sigmatch_table[DETECT_PCRE].name = "pcre";
    sigmatch_table[DETECT_PCRE].desc = "match on regular expression";
    sigmatch_table[DETECT_PCRE].url = "/rules/payload-keywords.html#pcre-perl-compatible-regular-expressions";
    sigmatch_table[DETECT_PCRE].Match = NULL;
    sigmatch_table[DETECT_PCRE].Setup = DetectPcreSetup;
    sigmatch_table[DETECT_PCRE].Free  = DetectPcreFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_PCRE].RegisterTests  = DetectPcreRegisterTests;
#endif
    sigmatch_table[DETECT_PCRE].flags = (SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION);

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

    parse_regex = DetectSetupPCRE2(PARSE_REGEX, 0);
    if (parse_regex == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "pcre2 compile failed for parse_regex");
    }

    /* setup the capture regex, as it needs PCRE2_UNGREEDY we do it manually */
    /* pkt_http_ua should be pkt, http_ua, for this reason the UNGREEDY */
    parse_capture_regex = DetectSetupPCRE2(PARSE_CAPTURE_REGEX, PCRE2_UNGREEDY);
    if (parse_capture_regex == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "pcre2 compile failed for parse_capture_regex");
    }

#ifdef PCRE2_HAVE_JIT
    if (PageSupportsRWX() == 0) {
        SCLogConfig("PCRE2 won't use JIT as OS doesn't allow RWX pages");
        pcre2_use_jit = 0;
    }
#endif

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
int DetectPcrePayloadMatch(DetectEngineThreadCtx *det_ctx, const Signature *s,
                           const SigMatchData *smd, Packet *p, Flow *f,
                           const uint8_t *payload, uint32_t payload_len)
{
    SCEnter();
    int ret = 0;
    const uint8_t *ptr = NULL;
    uint32_t len = 0;
    PCRE2_SIZE capture_len = 0;

    DetectPcreData *pe = (DetectPcreData *)smd->ctx;

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
    pcre2_match_data *match =
            (pcre2_match_data *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, pe->thread_ctx_id);

    ret = DetectPcreExec(det_ctx, pe, (char *)ptr, len, start_offset, 0, match);
    SCLogDebug("ret %d (negating %s)", ret, (pe->flags & DETECT_PCRE_NEGATE) ? "set" : "not set");

    if (ret == PCRE2_ERROR_NOMATCH) {
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

            SCLogDebug("ret %d pe->idx %u", ret, pe->idx);

            /* see if we need to do substring capturing. */
            if (ret > 1 && pe->idx != 0) {
                uint8_t x;
                for (x = 0; x < pe->idx; x++) {
                    SCLogDebug("capturing %u", x);
                    const char *pcre2_str_ptr = NULL;
                    ret = pcre2_substring_get_bynumber(
                            match, x + 1, (PCRE2_UCHAR8 **)&pcre2_str_ptr, &capture_len);
                    if (unlikely(ret != 0)) {
                        pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr);
                        continue;
                    }
                    /* store max 64k. Errors are ignored */
                    capture_len = (capture_len < 0xffff) ? (uint16_t)capture_len : 0xffff;
                    uint8_t *str_ptr = SCMalloc(capture_len);
                    if (unlikely(str_ptr == NULL)) {
                        pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr);
                        continue;
                    }
                    memcpy(str_ptr, pcre2_str_ptr, capture_len);
                    pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr);

                    SCLogDebug("data %p/%u, type %u id %u p %p",
                            str_ptr, ret, pe->captypes[x], pe->capids[x], p);

                    if (pe->captypes[x] == VAR_TYPE_PKT_VAR_KV) {
                        /* get the value, as first capture is the key */
                        const char *pcre2_str_ptr2 = NULL;
                        /* key length is limited to 256 chars */
                        uint16_t key_len = (capture_len < 0xff) ? (uint16_t)capture_len : 0xff;
                        int ret2 = pcre2_substring_get_bynumber(
                                match, x + 2, (PCRE2_UCHAR8 **)&pcre2_str_ptr2, &capture_len);

                        if (unlikely(ret2 != 0)) {
                            SCFree(str_ptr);
                            pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr2);
                            break;
                        }
                        capture_len = (capture_len < 0xffff) ? (uint16_t)capture_len : 0xffff;
                        uint8_t *str_ptr2 = SCMalloc(capture_len);
                        if (unlikely(str_ptr2 == NULL)) {
                            SCFree(str_ptr);
                            pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr2);
                            break;
                        }
                        memcpy(str_ptr2, pcre2_str_ptr2, capture_len);
                        pcre2_substring_free((PCRE2_UCHAR8 *)pcre2_str_ptr2);

                        (void)DetectVarStoreMatchKeyValue(det_ctx, (uint8_t *)str_ptr, key_len,
                                (uint8_t *)str_ptr2, (uint16_t)capture_len,
                                DETECT_VAR_TYPE_PKT_POSTMATCH);

                    } else if (pe->captypes[x] == VAR_TYPE_PKT_VAR) {
                        (void)DetectVarStoreMatch(det_ctx, pe->capids[x], (uint8_t *)str_ptr,
                                (uint16_t)capture_len, DETECT_VAR_TYPE_PKT_POSTMATCH);

                    } else if (pe->captypes[x] == VAR_TYPE_FLOW_VAR && f != NULL) {
                        (void)DetectVarStoreMatch(det_ctx, pe->capids[x], (uint8_t *)str_ptr,
                                (uint16_t)capture_len, DETECT_VAR_TYPE_FLOW_POSTMATCH);
                    } else {
                        BUG_ON(1); // Impossible captype
                        SCFree(str_ptr);
                    }
                }
            }

            PCRE2_SIZE *ov = pcre2_get_ovector_pointer(match);
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
    bool is_meta = false;
    bool is_meta_hex = false;
    int meta_hex_cnt = 0;

    for (size_t i = 0; i < len; i++) {
        if (is_meta_hex) {
            meta_hex_cnt++;

            if (meta_hex_cnt == 2) {
                is_meta_hex = false;
                meta_hex_cnt = 0;
            }
        } else if (is_meta) {
            if (re[i] == 'x') {
                is_meta_hex = true;
            } else {
                is_meta = false;
            }
        }
        else if (re[i] == '\\') {
            is_meta = true;
        }
        else if (isupper((unsigned char)re[i])) {
            return 1;
        }
    }

    return 0;
}

static DetectPcreData *DetectPcreParse (DetectEngineCtx *de_ctx,
        const char *regexstr, int *sm_list, char *capture_names,
        size_t capture_names_size, bool negate, AppProto *alproto)
{
    int en;
    PCRE2_SIZE eo2;
    int opts = 0;
    DetectPcreData *pd = NULL;
    char *op = NULL;
    int ret = 0, res = 0;
    int check_host_header = 0;
    char op_str[64] = "";

    int cut_capture = 0;
    char *fcap = strstr(regexstr, "flow:");
    char *pcap = strstr(regexstr, "pkt:");
    /* take the size of the whole input as buffer size for the regex we will
     * extract below. Add 1 to please Coverity's alloc_strlen test. */
    size_t slen = strlen(regexstr) + 1;
    if (fcap || pcap) {
        SCLogDebug("regexstr %s", regexstr);

        if (fcap && !pcap)
            cut_capture = fcap - regexstr;
        else if (pcap && !fcap)
            cut_capture = pcap - regexstr;
        else {
            BUG_ON(pcap == NULL); // added to assist cppcheck
            BUG_ON(fcap == NULL);
            cut_capture = MIN((pcap - regexstr), (fcap - regexstr));
        }

        SCLogDebug("cut_capture %d", cut_capture);

        if (cut_capture > 1) {
            int offset = cut_capture - 1;
            while (offset) {
                SCLogDebug("regexstr[offset] %c", regexstr[offset]);
                if (regexstr[offset] == ',' || regexstr[offset] == ' ') {
                    offset--;
                }
                else
                    break;
            }

            if (cut_capture == (offset + 1)) {
                SCLogDebug("missing separators, assume it's part of the regex");
            } else {
                slen = offset + 1;
                strlcpy(capture_names, regexstr+cut_capture, capture_names_size);
                if (capture_names[strlen(capture_names)-1] == '"')
                    capture_names[strlen(capture_names)-1] = '\0';
            }
        }
    }

    char re[slen];
    ret = pcre2_match(
            parse_regex->regex, (PCRE2_SPTR8)regexstr, slen, 0, 0, parse_regex->match, NULL);
    if (ret <= 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre parse error: %s", regexstr);
        goto error;
    }

    res = pcre2_substring_copy_bynumber(parse_regex->match, 1, (PCRE2_UCHAR8 *)re, &slen);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }

    if (ret > 2) {
        size_t copylen = sizeof(op_str);
        res = pcre2_substring_copy_bynumber(
                parse_regex->match, 2, (PCRE2_UCHAR8 *)op_str, &copylen);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return NULL;
        }
        op = op_str;
    }
    //printf("ret %" PRId32 " re \'%s\', op \'%s\'\n", ret, re, op);

    pd = SCCalloc(1, sizeof(DetectPcreData));
    if (unlikely(pd == NULL))
        goto error;

    if (negate)
        pd->flags |= DETECT_PCRE_NEGATE;

    if (op != NULL) {
        while (*op) {
            SCLogDebug("regex option %c", *op);

            switch (*op) {
                case 'A':
                    opts |= PCRE2_ANCHORED;
                    break;
                case 'E':
                    opts |= PCRE2_DOLLAR_ENDONLY;
                    break;
                case 'G':
                    opts |= PCRE2_UNGREEDY;
                    break;

                case 'i':
                    opts |= PCRE2_CASELESS;
                    pd->flags |= DETECT_PCRE_CASELESS;
                    break;
                case 'm':
                    opts |= PCRE2_MULTILINE;
                    break;
                case 's':
                    opts |= PCRE2_DOTALL;
                    break;
                case 'x':
                    opts |= PCRE2_EXTENDED;
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

                case 'U': { /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'U' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_uri");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'V': {
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'V' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_user_agent");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'W': {
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'W' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_host");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    check_host_header = 1;
                    break;
                }
                case 'Z': {
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'Z' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_raw_host");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'H': { /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'H' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_header");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                } case 'I': { /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'I' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_raw_uri");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'D': { /* snort's option */
                    int list = DetectBufferTypeGetByName("http_raw_header");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'M': { /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'M' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_method");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'C': { /* snort's option */
                    if (pd->flags & DETECT_PCRE_RAWBYTES) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "regex modifier 'C' inconsistent with 'B'");
                        goto error;
                    }
                    int list = DetectBufferTypeGetByName("http_cookie");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'P': {
                    /* snort's option (http request body inspection) */
                    int list = DetectBufferTypeGetByName("http_client_body");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'Q': {
                    int list = DetectBufferTypeGetByName("file_data");
                    /* suricata extension (http response body inspection) */
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'Y': {
                    /* snort's option */
                    int list = DetectBufferTypeGetByName("http_stat_msg");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
                case 'S': {
                    /* snort's option */
                    int list = DetectBufferTypeGetByName("http_stat_code");
                    *sm_list = DetectPcreSetList(*sm_list, list);
                    *alproto = ALPROTO_HTTP1;
                    break;
                }
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
    if (check_host_header) {
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
    if (capture_names == NULL || strlen(capture_names) == 0)
        opts |= PCRE2_NO_AUTO_CAPTURE;

    pd->parse_regex.regex =
            pcre2_compile((PCRE2_SPTR8)re, PCRE2_ZERO_TERMINATED, opts, &en, &eo2, NULL);
    if (pd->parse_regex.regex == NULL && en == 115) { // reference to non-existent subpattern
        opts &= ~PCRE2_NO_AUTO_CAPTURE;
        pd->parse_regex.regex =
                pcre2_compile((PCRE2_SPTR8)re, PCRE2_ZERO_TERMINATED, opts, &en, &eo2, NULL);
    }
    if (pd->parse_regex.regex == NULL)  {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                regexstr, (int)eo2, errbuffer);
        goto error;
    }

#ifdef PCRE2_HAVE_JIT
    if (pcre2_use_jit) {
        ret = pcre2_jit_compile(pd->parse_regex.regex, PCRE2_JIT_COMPLETE);
        if (ret != 0) {
            /* warning, so we won't print the sig after this. Adding
             * file and line to the message so the admin can figure
             * out what sig this is about */
            SCLogDebug("PCRE2 JIT compiler does not support: %s. "
                       "Falling back to regular PCRE2 handling (%s:%d)",
                    regexstr, de_ctx->rule_file, de_ctx->rule_line);
        }
    }
#endif /*PCRE2_HAVE_JIT*/

    pd->parse_regex.context = pcre2_match_context_create(NULL);
    if (pd->parse_regex.context == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre2 could not create match context");
        goto error;
    }
    pd->parse_regex.match = pcre2_match_data_create_from_pattern(pd->parse_regex.regex, NULL);

    if (pd->flags & DETECT_PCRE_MATCH_LIMIT) {
        if (pcre_match_limit >= -1) {
            pcre2_set_match_limit(pd->parse_regex.context, pcre_match_limit);
        }
        if (pcre_match_limit_recursion >= -1) {
            // pcre2_set_depth_limit unsupported on ubuntu 16.04
            pcre2_set_recursion_limit(pd->parse_regex.context, pcre_match_limit_recursion);
        }
    } else {
        pcre2_set_match_limit(pd->parse_regex.context, SC_MATCH_LIMIT_DEFAULT);
        pcre2_set_recursion_limit(pd->parse_regex.context, SC_MATCH_LIMIT_RECURSION_DEFAULT);
    }
    return pd;

error:
    DetectPcreFree(de_ctx, pd);
    return NULL;
}

/** \internal
 *  \brief check if we need to extract capture settings and set them up if needed
 */
static int DetectPcreParseCapture(const char *regexstr, DetectEngineCtx *de_ctx, DetectPcreData *pd,
    char *capture_names)
{
    int ret = 0, res = 0;
    char type_str[16] = "";
    const char *orig_right_edge = regexstr + strlen(regexstr);
    char *name_array[DETECT_PCRE_CAPTURE_MAX] = { NULL };
    int name_idx = 0;
    int capture_cnt = 0;
    int key = 0;
    size_t copylen;

    SCLogDebug("regexstr %s, pd %p", regexstr, pd);

    ret = pcre2_pattern_info(pd->parse_regex.regex, PCRE2_INFO_CAPTURECOUNT, &capture_cnt);
    SCLogDebug("ret %d capture_cnt %d", ret, capture_cnt);
    if (ret == 0 && capture_cnt && strlen(capture_names) > 0)
    {
        char *ptr = NULL;
        while ((name_array[name_idx] = strtok_r(name_idx == 0 ? capture_names : NULL, " ,", &ptr))){
            if (name_idx > (capture_cnt - 1)) {
                SCLogError(SC_ERR_VAR_LIMIT, "more pkt/flow "
                        "var capture names than capturing substrings");
                return -1;
            }
            SCLogDebug("name '%s'", name_array[name_idx]);

            if (strcmp(name_array[name_idx], "pkt:key") == 0) {
                key = 1;
                SCLogDebug("key-value/key");

                pd->captypes[pd->idx] = VAR_TYPE_PKT_VAR_KV;
                SCLogDebug("id %u type %u", pd->capids[pd->idx], pd->captypes[pd->idx]);
                pd->idx++;

            } else if (key == 1 && strcmp(name_array[name_idx], "pkt:value") == 0) {
                SCLogDebug("key-value/value");
                key = 0;

            /* kv error conditions */
            } else if (key == 0 && strcmp(name_array[name_idx], "pkt:value") == 0) {
                return -1;
            } else if (key == 1) {
                return -1;

            } else if (strncmp(name_array[name_idx], "flow:", 5) == 0) {
                pd->capids[pd->idx] = VarNameStoreSetupAdd(name_array[name_idx]+5, VAR_TYPE_FLOW_VAR);
                pd->captypes[pd->idx] = VAR_TYPE_FLOW_VAR;
                pd->idx++;

            } else if (strncmp(name_array[name_idx], "pkt:", 4) == 0) {
                pd->capids[pd->idx] = VarNameStoreSetupAdd(name_array[name_idx]+4, VAR_TYPE_PKT_VAR);
                pd->captypes[pd->idx] = VAR_TYPE_PKT_VAR;
                SCLogDebug("id %u type %u", pd->capids[pd->idx], pd->captypes[pd->idx]);
                pd->idx++;

            } else {
                SCLogError(SC_ERR_VAR_LIMIT, " pkt/flow "
                        "var capture names must start with 'pkt:' or 'flow:'");
                return -1;
            }

            name_idx++;
            if (name_idx >= DETECT_PCRE_CAPTURE_MAX)
                break;
        }
    }

    /* take the size of the whole input as buffer size for the string we will
     * extract below. Add 1 to please Coverity's alloc_strlen test. */
    size_t cap_buffer_len = strlen(regexstr) + 1;
    char capture_str[cap_buffer_len];
    memset(capture_str, 0x00, cap_buffer_len);

    if (de_ctx == NULL)
        goto error;

    while (1) {
        SCLogDebug("\'%s\'", regexstr);

        ret = pcre2_match(parse_capture_regex->regex, (PCRE2_SPTR8)regexstr, strlen(regexstr), 0, 0,
                parse_capture_regex->match, NULL);
        if (ret < 3) {
            return 0;
        }
        copylen = sizeof(type_str);
        res = pcre2_substring_copy_bynumber(
                parse_capture_regex->match, 1, (PCRE2_UCHAR8 *)type_str, &copylen);
        if (res != 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }
        cap_buffer_len = strlen(regexstr) + 1;
        res = pcre2_substring_copy_bynumber(
                parse_capture_regex->match, 2, (PCRE2_UCHAR8 *)capture_str, &cap_buffer_len);
        if (res != 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }
        if (strlen(capture_str) == 0 || strlen(type_str) == 0) {
            goto error;
        }

        SCLogDebug("type \'%s\'", type_str);
        SCLogDebug("capture \'%s\'", capture_str);

        if (pd->idx >= DETECT_PCRE_CAPTURE_MAX) {
            SCLogError(SC_ERR_VAR_LIMIT, "rule can have maximally %d pkt/flow "
                    "var captures", DETECT_PCRE_CAPTURE_MAX);
            return -1;
        }

        if (strcmp(type_str, "pkt") == 0) {
            pd->capids[pd->idx] = VarNameStoreSetupAdd((char *)capture_str, VAR_TYPE_PKT_VAR);
            pd->captypes[pd->idx] = VAR_TYPE_PKT_VAR;
            SCLogDebug("id %u type %u", pd->capids[pd->idx], pd->captypes[pd->idx]);
            pd->idx++;
        } else if (strcmp(type_str, "flow") == 0) {
            pd->capids[pd->idx] = VarNameStoreSetupAdd((char *)capture_str, VAR_TYPE_FLOW_VAR);
            pd->captypes[pd->idx] = VAR_TYPE_FLOW_VAR;
            pd->idx++;
        }

        //SCLogNotice("pd->capname %s", pd->capname);
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(parse_capture_regex->match);
        regexstr += ov[1];

        if (regexstr >= orig_right_edge)
            break;
    }
    return 0;

error:
    return -1;
}

static void *DetectPcreThreadInit(void *data)
{
    DetectPcreData *pd = (DetectPcreData *)data;
    pcre2_match_data *match = pcre2_match_data_create_from_pattern(pd->parse_regex.regex, NULL);
    return match;
}

static void DetectPcreThreadFree(void *ctx)
{
    if (ctx != NULL) {
        pcre2_match_data *match = (pcre2_match_data *)ctx;
        pcre2_match_data_free(match);
    }
}

static int DetectPcreSetup (DetectEngineCtx *de_ctx, Signature *s, const char *regexstr)
{
    SCEnter();
    DetectPcreData *pd = NULL;
    SigMatch *sm = NULL;
    int parsed_sm_list = DETECT_SM_LIST_NOTSET;
    char capture_names[1024] = "";
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, regexstr, &parsed_sm_list,
            capture_names, sizeof(capture_names), s->init_data->negated,
            &alproto);
    if (pd == NULL)
        goto error;
    if (DetectPcreParseCapture(regexstr, de_ctx, pd, capture_names) < 0)
        goto error;

    pd->thread_ctx_id = DetectRegisterThreadCtxFuncs(
            de_ctx, "pcre", DetectPcreThreadInit, (void *)pd, DetectPcreThreadFree, 0);
    if (pd->thread_ctx_id == -1)
        goto error;

    int sm_list = -1;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (parsed_sm_list != DETECT_SM_LIST_NOTSET && parsed_sm_list != s->init_data->list) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "Expression seen with a sticky buffer still set; either (1) reset sticky "
                    "buffer with pkt_data or (2) use a sticky buffer providing \"%s\".",
                    DetectEngineBufferTypeGetDescriptionById(de_ctx, parsed_sm_list));
            goto error;
        }
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        s->flags |= SIG_FLAG_APPLAYER;
        sm_list = s->init_data->list;
    } else {
        switch (parsed_sm_list) {
            case DETECT_SM_LIST_NOTSET:
                sm_list = DETECT_SM_LIST_PMATCH;
                break;
            default: {
                if (alproto != ALPROTO_UNKNOWN) {
                    /* see if the proto doesn't conflict
                     * with what we already have. */
                    if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, alproto)) {
                        goto error;
                    }
                    if (DetectSignatureSetAppProto(s, alproto) < 0)
                        goto error;
                }
                sm_list = parsed_sm_list;
                break;
            }
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

    for (uint8_t x = 0; x < pd->idx; x++) {
        if (DetectFlowvarPostMatchSetup(de_ctx, s, pd->capids[x]) < 0)
            goto error_nofree;
    }

    if (!(pd->flags & DETECT_PCRE_RELATIVE))
        goto okay;

    /* errors below shouldn't free pd */

    SigMatch *prev_pm = DetectGetLastSMByListPtr(s, sm->prev,
            DETECT_CONTENT, DETECT_PCRE, -1);
    if (s->init_data->list == DETECT_SM_LIST_NOTSET && prev_pm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "pcre with /R (relative) needs "
                "preceding match in the same buffer");
        goto error_nofree;
    /* null is allowed when we use a sticky buffer */
    } else if (prev_pm == NULL) {
        goto okay;
    }
    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *tmp = (DetectPcreData *)prev_pm->ctx;
        tmp->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

 okay:
    SCReturnInt(0);
 error:
    DetectPcreFree(de_ctx, pd);
 error_nofree:
    SCReturnInt(-1);
}

static void DetectPcreFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectPcreData *pd = (DetectPcreData *)ptr;
    DetectParseFreeRegex(&pd->parse_regex);
    DetectUnregisterThreadCtxFuncs(de_ctx, pd, "pcre");

    SCFree(pd);

    return;
}

#ifdef UNITTESTS /* UNITTESTS */
static int g_file_data_buffer_id = 0;
static int g_http_header_buffer_id = 0;
static int g_dce_stub_data_buffer_id = 0;

/**
 * \test DetectPcreParseTest01 make sure we don't allow invalid opts 7.
 */
static int DetectPcreParseTest01 (void)
{
    int result = 1;
    DetectPcreData *pd = NULL;
    const char *teststring = "/blah/7";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NOT_NULL(pd);

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
    const char *teststring = "/blah/Ui$";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NOT_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_HTTP1);

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
    const char *teststring = "/blah/UNi";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NOT_NULL(pd);

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
    const char *teststring = "/b\\\"lah/i";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_UNKNOWN);

    DetectPcreFree(de_ctx, pd);
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
    const char *teststring = "/b(l|a)h/";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_UNKNOWN);

    DetectPcreFree(de_ctx, pd);
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
    const char *teststring = "/b(l|a)h/smi";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_UNKNOWN);

    DetectPcreFree(de_ctx, pd);
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
    const char *teststring = "/blah/Ui";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_HTTP1);

    DetectPcreFree(de_ctx, pd);
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
    const char *teststring = "/b(l|a)h/O";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);
    FAIL_IF_NOT(alproto == ALPROTO_UNKNOWN);

    DetectPcreFree(de_ctx, pd);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectPcreParseTest09 make sure we parse pcre with a content
 *       that has slashes
 */
static int DetectPcreParseTest09 (void)
{
    DetectPcreData *pd = NULL;
    const char *teststring = "/lala\\\\/";
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    AppProto alproto = ALPROTO_UNKNOWN;

    pd = DetectPcreParse(de_ctx, teststring, &list, NULL, 0, false, &alproto);
    FAIL_IF_NULL(pd);

    DetectPcreFree(de_ctx, pd);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test pcre option for dce sig(yeah I'm bored of writing test titles).
 */
static int DetectPcreParseTest10(void)
{
    Signature *s = SigAlloc();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF(DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0);

    FAIL_IF_NOT(DetectPcreSetup(de_ctx, s, "/bamboo/") == 0);
    FAIL_IF_NOT(s->sm_lists[g_dce_stub_data_buffer_id] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(de_ctx, s);

    s = SigAlloc();
    FAIL_IF_NULL(s);

    /* failure since we have no preceding content/pcre/bytejump */
    FAIL_IF_NOT(DetectPcreSetup(de_ctx, s, "/bamboo/") == 0);
    FAIL_IF_NOT(s->sm_lists[g_dce_stub_data_buffer_id] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test pcre option for dce sig.
 */
static int DetectPcreParseTest11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytejump_body\"; "
                               "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                               "dce_stub_data; "
                               "pcre:/bamboo/R; sid:1;)");
    FAIL_IF(de_ctx == NULL);
    s = de_ctx->sig_list;
    FAIL_IF(s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL);
    FAIL_IF_NOT(s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    FAIL_IF(data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE));

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "pcre:/bamboo/R; sid:1;)");
    FAIL_IF_NULL(s->next);
    s = s->next;
    FAIL_IF(s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL);
    FAIL_IF_NOT(s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    FAIL_IF(data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE));

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "pcre:/bamboo/RB; sid:1;)");
    FAIL_IF(s->next == NULL);
    s = s->next;
    FAIL_IF(s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL);
    FAIL_IF_NOT(s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_PCRE);
    data = (DetectPcreData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    FAIL_IF(!(data->flags & DETECT_PCRE_RAWBYTES) ||
        !(data->flags & DETECT_PCRE_RELATIVE));

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "content:\"one\"; pcre:/bamboo/; sid:1;)");
    FAIL_IF(s->next == NULL);
    s = s->next;
    FAIL_IF(s->sm_lists_tail[g_dce_stub_data_buffer_id] != NULL);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test pcre option with file data. pcre is relative to file_data,
 *       so relative flag should be unset.
 */
static int DetectPcreParseTest12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; pcre:/abc/R; sid:1;)");
    FAIL_IF (de_ctx->sig_list == NULL);

    s = de_ctx->sig_list;
    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id] == NULL);

    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_PCRE);

    data = (DetectPcreData *)s->sm_lists_tail[g_file_data_buffer_id]->ctx;
    FAIL_IF(data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test pcre option with file data.
 */
static int DetectPcreParseTest13(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"abc\"; pcre:/def/R; sid:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    s = de_ctx->sig_list;
    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id] == NULL);

    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_PCRE);

    data = (DetectPcreData *)s->sm_lists_tail[g_file_data_buffer_id]->ctx;
    FAIL_IF(data->flags & DETECT_PCRE_RAWBYTES ||
        !(data->flags & DETECT_PCRE_RELATIVE));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test pcre option with file data.
 */
static int DetectPcreParseTest14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    DetectPcreData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; pcre:/def/; sid:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    s = de_ctx->sig_list;
    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id] == NULL);

    FAIL_IF(s->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_PCRE);

    data = (DetectPcreData *)s->sm_lists_tail[g_file_data_buffer_id]->ctx;
    FAIL_IF(data->flags & DETECT_PCRE_RAWBYTES ||
        data->flags & DETECT_PCRE_RELATIVE);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/** \test Check a signature with pcre relative method */
static int DetectPcreParseTest15(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_method\"; "
                               "content:\"GET\"; "
                               "http_method; pcre:\"/abc/RM\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}


/** \test Check a signature with pcre relative cookie */
static int DetectPcreParseTest16(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_cookie\"; "
                               "content:\"test\"; "
                               "http_cookie; pcre:\"/abc/RC\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative raw header */
static int DetectPcreParseTest17(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_raw_header\"; "
                               "flow:to_server; content:\"test\"; "
                               "http_raw_header; pcre:\"/abc/RD\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative header */
static int DetectPcreParseTest18(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_header\"; "
                               "content:\"test\"; "
                               "http_header; pcre:\"/abc/RH\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative client-body */
static int DetectPcreParseTest19(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_client_body\"; "
                               "content:\"test\"; "
                               "http_client_body; pcre:\"/abc/RP\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative raw uri */
static int DetectPcreParseTest20(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; "
                               "content:\"test\"; "
                               "http_raw_uri; pcre:\"/abc/RI\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative uricontent */
static int DetectPcreParseTest21(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative uricontent\"; "
                               "uricontent:\"test\"; "
                               "pcre:\"/abc/RU\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with pcre relative http_uri */
static int DetectPcreParseTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing pcre relative http_uri\"; "
                               "content:\"test\"; "
                               "http_uri; pcre:\"/abc/RU\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with inconsistent pcre relative  */
static int DetectPcreParseTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre relative\"; "
                               "content:\"GET\"; "
                               "http_cookie; pcre:\"/abc/RM\"; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with inconsistent pcre modifiers  */
static int DetectPcreParseTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/UI\"; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with inconsistent pcre modifiers  */
static int DetectPcreParseTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/DH\"; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with inconsistent pcre modifiers  */
static int DetectPcreParseTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert http any any -> any any "
                               "(msg:\"Testing inconsistent pcre modifiers\"; "
                               "pcre:\"/abc/F\"; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Bug 1098 */
static int DetectPcreParseTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any 80 "
            "(content:\"baduricontent\"; http_raw_uri; "
            "pcre:\"/^[a-z]{5}\\.html/R\"; sid:2; rev:2;)");
    FAIL_IF_NOT(de_ctx->sig_list == NULL);

    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Bug 1957 */
static int DetectPcreParseTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;

    FAIL_IF( (de_ctx = DetectEngineCtxInit()) == NULL);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any 80 "
            "(content:\"|2E|suricata\"; http_host; pcre:\"/\\x2Esuricata$/W\"; "
            "sid:2; rev:2;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectPcreTestSig01(void)
{
    uint8_t *buf = (uint8_t *)"lalala lalala\\ lala\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; pcre:\"/ "
                 "lalala\\\\/\"; sid:1;)";
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
static int DetectPcreTestSig02(void)
{
    uint8_t *buf = (uint8_t *)"lalala\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; "
                 "pcre:\"/^(la)+$/\"; sid:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);

    if (p != NULL)
        UTHFreePacket(p);
    PASS;
}

/** \test anchored pcre */
static int DetectPcreTestSig03(void)
{
    /* test it also without ending in a newline "\n" */
    uint8_t *buf = (uint8_t *)"lalala";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with an ending slash\"; "
                 "pcre:\"/^(la)+$/\"; sid:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);

    if (p != NULL)
        UTHFreePacket(p);
    PASS;
}

/** \test Test tracking of body chunks per transactions (on requests)
 */
static int DetectPcreTxBodyChunksTest01(void)
{
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
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    AppLayerHtpEnableRequestBodyCallback();

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    FAIL_IF(r != 0);

    /* Now we should have 2 transactions, each with it's own list
     * of request body chunks (let's test it) */

    HtpState *htp_state = f.alstate;
    FAIL_IF(htp_state == NULL);

    /* hardcoded check of the transactions and it's client body chunks */
    FAIL_IF(AppLayerParserGetTxCnt(&f, htp_state) != 2);

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);
    FAIL_IF(htud == NULL);

    HtpBodyChunk *cur = htud->request_body.first;
    FAIL_IF(htud->request_body.first == NULL);

    FAIL_IF(StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg, (uint8_t *)"Body one!!", 10) != 1);

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    FAIL_IF(htud->request_body.first == NULL);

    FAIL_IF(StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg, (uint8_t *)"Body two!!", 10) != 1);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test test pcre P modifier with multiple pipelined http transactions */
static int DetectPcreTxBodyChunksTest02(void)
{
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
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; pcre:\"/one/P\"; sid:1; rev:1;)");
    FAIL_IF(s == NULL);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; pcre:\"/two/P\"; sid:2; rev:1;)");
    FAIL_IF(s == NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    FAIL_IF(htp_state == NULL);

    /* hardcoded check of the transactions and it's client body chunks */
    FAIL_IF(AppLayerParserGetTxCnt(&f, htp_state) != 2);

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);

    HtpBodyChunk *cur = htud->request_body.first;
    FAIL_IF(htud->request_body.first == NULL);

    FAIL_IF(StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg, (uint8_t *)"Body one!!", 10) != 1);

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    FAIL_IF(htud->request_body.first == NULL);

    FAIL_IF(StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg, (uint8_t *)"Body two!!", 10) != 1);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectPcreTxBodyChunksTest03(void)
{
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
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; pcre:\"/one/P\"; sid:1; rev:1;)");
    FAIL_IF(s == NULL);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; pcre:\"/two/P\"; sid:2; rev:1;)");
    FAIL_IF(s == NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    FAIL_IF(htp_state == NULL);

    FAIL_IF(AppLayerParserGetTxCnt(&f, htp_state) != 2);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/**
 * \brief Test parsing of pcre's with the W modifier set.
 */
static int DetectPcreParseHttpHost(void)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    int list = DETECT_SM_LIST_NOTSET;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF(de_ctx == NULL);

    DetectPcreData *pd = DetectPcreParse(de_ctx, "/domain\\.com/W", &list, NULL, 0, false, &alproto);
    FAIL_IF(pd == NULL);
    DetectPcreFree(de_ctx, pd);

    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/dOmain\\.com/W", &list, NULL, 0, false, &alproto);
    FAIL_IF(pd != NULL);

    /* Uppercase meta characters are valid. */
    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/domain\\D+\\.com/W", &list, NULL, 0, false, &alproto);
    FAIL_IF(pd == NULL);
    DetectPcreFree(de_ctx, pd);

    /* This should not parse as the first \ escapes the second \, then
     * we have a D. */
    list = DETECT_SM_LIST_NOTSET;
    pd = DetectPcreParse(de_ctx, "/\\\\Ddomain\\.com/W", &list, NULL, 0, false, &alproto);
    FAIL_IF(pd != NULL);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief Test parsing of capture extension
 */
static int DetectPcreParseCaptureTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
            "(content:\"Server: \"; http_header; pcre:\"/(.*)\\r\\n/HR, flow:somecapture\"; content:\"xyz\"; http_header; sid:1;)");
    FAIL_IF(s == NULL);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
            "(content:\"Server: \"; http_header; pcre:\"/(flow:.*)\\r\\n/HR\"; content:\"xyz\"; http_header; sid:2;)");
    FAIL_IF(s == NULL);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
            "(content:\"Server: \"; http_header; pcre:\"/([a-z]+)([0-9]+)\\r\\n/HR, flow:somecapture, pkt:anothercap\"; content:\"xyz\"; http_header; sid:3;)");
    FAIL_IF(s == NULL);
    s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any "
            "(content:\"Server: \"; http_header; pcre:\"/([a-z]+)\\r\\n/HR, flow:somecapture, "
            "pkt:anothercap\"; content:\"xyz\"; http_header; sid:3;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupBuild(de_ctx);

    uint32_t capid = VarNameStoreLookupByName("somecapture", VAR_TYPE_FLOW_VAR);
    FAIL_IF (capid != 1);
    capid = VarNameStoreLookupByName("anothercap", VAR_TYPE_PKT_VAR);
    FAIL_IF (capid != 2);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectPcre
 */
static void DetectPcreRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_http_header_buffer_id = DetectBufferTypeGetByName("http_header");
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

    UtRegisterTest("DetectPcreParseTest01", DetectPcreParseTest01);
    UtRegisterTest("DetectPcreParseTest02", DetectPcreParseTest02);
    UtRegisterTest("DetectPcreParseTest03", DetectPcreParseTest03);
    UtRegisterTest("DetectPcreParseTest04", DetectPcreParseTest04);
    UtRegisterTest("DetectPcreParseTest05", DetectPcreParseTest05);
    UtRegisterTest("DetectPcreParseTest06", DetectPcreParseTest06);
    UtRegisterTest("DetectPcreParseTest07", DetectPcreParseTest07);
    UtRegisterTest("DetectPcreParseTest08", DetectPcreParseTest08);
    UtRegisterTest("DetectPcreParseTest09", DetectPcreParseTest09);
    UtRegisterTest("DetectPcreParseTest10", DetectPcreParseTest10);
    UtRegisterTest("DetectPcreParseTest11", DetectPcreParseTest11);
    UtRegisterTest("DetectPcreParseTest12", DetectPcreParseTest12);
    UtRegisterTest("DetectPcreParseTest13", DetectPcreParseTest13);
    UtRegisterTest("DetectPcreParseTest14", DetectPcreParseTest14);
    UtRegisterTest("DetectPcreParseTest15", DetectPcreParseTest15);
    UtRegisterTest("DetectPcreParseTest16", DetectPcreParseTest16);
    UtRegisterTest("DetectPcreParseTest17", DetectPcreParseTest17);
    UtRegisterTest("DetectPcreParseTest18", DetectPcreParseTest18);
    UtRegisterTest("DetectPcreParseTest19", DetectPcreParseTest19);
    UtRegisterTest("DetectPcreParseTest20", DetectPcreParseTest20);
    UtRegisterTest("DetectPcreParseTest21", DetectPcreParseTest21);
    UtRegisterTest("DetectPcreParseTest22", DetectPcreParseTest22);
    UtRegisterTest("DetectPcreParseTest23", DetectPcreParseTest23);
    UtRegisterTest("DetectPcreParseTest24", DetectPcreParseTest24);
    UtRegisterTest("DetectPcreParseTest25", DetectPcreParseTest25);
    UtRegisterTest("DetectPcreParseTest26", DetectPcreParseTest26);
    UtRegisterTest("DetectPcreParseTest27", DetectPcreParseTest27);
    UtRegisterTest("DetectPcreParseTest28", DetectPcreParseTest28);

    UtRegisterTest("DetectPcreTestSig01", DetectPcreTestSig01);
    UtRegisterTest("DetectPcreTestSig02 -- anchored pcre", DetectPcreTestSig02);
    UtRegisterTest("DetectPcreTestSig03 -- anchored pcre", DetectPcreTestSig03);

    UtRegisterTest("DetectPcreTxBodyChunksTest01",
                   DetectPcreTxBodyChunksTest01);
    UtRegisterTest("DetectPcreTxBodyChunksTest02 -- modifier P, body chunks per tx",
                   DetectPcreTxBodyChunksTest02);
    UtRegisterTest("DetectPcreTxBodyChunksTest03 -- modifier P, body chunks per tx",
                   DetectPcreTxBodyChunksTest03);

    UtRegisterTest("DetectPcreParseHttpHost", DetectPcreParseHttpHost);
    UtRegisterTest("DetectPcreParseCaptureTest", DetectPcreParseCaptureTest);

}
#endif /* UNITTESTS */
