/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the fast_pattern keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-fast-pattern.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#define PARSE_REGEX "^(\\s*only\\s*)|\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

static int DetectFastPatternSetup(DetectEngineCtx *, Signature *, const char *);
void DetectFastPatternRegisterTests(void);

/* holds the list of sm match lists that need to be searched for a keyword
 * that has fp support */
SCFPSupportSMList *sm_fp_support_smlist_list = NULL;

/**
 * \brief Lets one add a sm list id to be searched for potential fp supported
 *        keywords later.
 *
 * \param list_id SM list id.
 * \param priority Priority for this list.
 */
void SupportFastPatternForSigMatchList(int list_id, int priority)
{
    SCFPSupportSMList *ip = NULL;
    /* insertion point - ip */
    for (SCFPSupportSMList *tmp = sm_fp_support_smlist_list; tmp != NULL; tmp = tmp->next) {
        if (list_id == tmp->list_id) {
            SCLogDebug("SM list already registered.");
            return;
        }

        if (priority <= tmp->priority)
            break;

        ip = tmp;
    }

    if (sm_fp_support_smlist_list == NULL) {
        SCFPSupportSMList *new = SCMalloc(sizeof(SCFPSupportSMList));
        if (unlikely(new == NULL))
            exit(EXIT_FAILURE);
        memset(new, 0, sizeof(SCFPSupportSMList));
        new->list_id = list_id;
        new->priority = priority;

        sm_fp_support_smlist_list = new;

        return;
    }

    SCFPSupportSMList *new = SCMalloc(sizeof(SCFPSupportSMList));
    if (unlikely(new == NULL))
        exit(EXIT_FAILURE);
    memset(new, 0, sizeof(SCFPSupportSMList));
    new->list_id = list_id;
    new->priority = priority;
    if (ip == NULL) {
        new->next = sm_fp_support_smlist_list;
        sm_fp_support_smlist_list = new;
    } else {
        new->next = ip->next;
        ip->next = new;
    }

    return;
}

/**
 * \brief Registers the keywords(SMs) that should be given fp support.
 */
void SupportFastPatternForSigMatchTypes(void)
{
    SupportFastPatternForSigMatchList(DETECT_SM_LIST_PMATCH, 3);

    /* other types are handled by DetectMpmAppLayerRegister() */

#if 0
    SCFPSupportSMList *tmp = sm_fp_support_smlist_list;
    while (tmp != NULL) {
        printf("%d - %d\n", tmp->list_id, tmp->priority);

        tmp = tmp->next;
    }
#endif

    return;
}

/**
 * \brief Registration function for fast_pattern keyword
 */
void DetectFastPatternRegister(void)
{
    sigmatch_table[DETECT_FAST_PATTERN].name = "fast_pattern";
    sigmatch_table[DETECT_FAST_PATTERN].desc = "force using preceding content in the multi pattern matcher";
    sigmatch_table[DETECT_FAST_PATTERN].url = DOC_URL DOC_VERSION "/rules/http-keywords.html#fast-pattern";
    sigmatch_table[DETECT_FAST_PATTERN].Match = NULL;
    sigmatch_table[DETECT_FAST_PATTERN].Setup = DetectFastPatternSetup;
    sigmatch_table[DETECT_FAST_PATTERN].Free  = NULL;
    sigmatch_table[DETECT_FAST_PATTERN].RegisterTests = DetectFastPatternRegisterTests;

    sigmatch_table[DETECT_FAST_PATTERN].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

//static int DetectFastPatternParseArg(

/**
 * \brief Configures the previous content context for a fast_pattern modifier
 *        keyword used in the rule.
 *
 * \param de_ctx   Pointer to the Detection Engine Context.
 * \param s        Pointer to the Signature to which the current keyword belongs.
 * \param null_str Should hold an empty string always.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectFastPatternSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char arg_substr[128] = "";
    DetectContentData *cd = NULL;
    const int nlists = DetectBufferTypeMaxId();

    SigMatch *pm1 = DetectGetLastSMFromMpmLists(s);
    SigMatch *pm2 = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm1 == NULL && pm2 == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "fast_pattern found inside "
                "the rule, without a content context. Please use a "
                "content based keyword before using fast_pattern");
        return -1;
    }

    SigMatch *pm = NULL;
    if (pm1 && pm2) {
        if (pm1->idx > pm2->idx)
            pm = pm1;
        else
            pm = pm2;
    } else if (pm1 && !pm2) {
        pm = pm1;
    } else {
        pm = pm2;
    }

    cd = (DetectContentData *)pm->ctx;
    if ((cd->flags & DETECT_CONTENT_NEGATED) &&
        ((cd->flags & DETECT_CONTENT_DISTANCE) ||
         (cd->flags & DETECT_CONTENT_WITHIN) ||
         (cd->flags & DETECT_CONTENT_OFFSET) ||
         (cd->flags & DETECT_CONTENT_DEPTH))) {

        /* we can't have any of these if we are having "only" */
        SCLogError(SC_ERR_INVALID_SIGNATURE, "fast_pattern; cannot be "
                   "used with negated content, along with relative modifiers");
        goto error;
    }

    if (arg == NULL|| strcmp(arg, "") == 0) {
        if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple fast_pattern "
                    "options for the same content");
            goto error;
        }
        else { /*allow only one content to have fast_pattern modifier*/
            int list_id = 0;
            for (list_id = 0; list_id < nlists; list_id++) {
                SigMatch *sm = NULL;
                for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) {
                    if (sm->type == DETECT_CONTENT) {
                        DetectContentData *tmp_cd = (DetectContentData *)sm->ctx;
                        if (tmp_cd->flags & DETECT_CONTENT_FAST_PATTERN) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "fast_pattern "
                                        "can be used on only one content in a rule");
                            goto error;
                        }
                    }
                } /* for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) */
            }
        }
        cd->flags |= DETECT_CONTENT_FAST_PATTERN;
        return 0;
    }

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, arg,
                    strlen(arg), 0, 0, ov, MAX_SUBSTRINGS);
    /* fast pattern only */
    if (ret == 2) {
        if ((cd->flags & DETECT_CONTENT_NEGATED) ||
            (cd->flags & DETECT_CONTENT_DISTANCE) ||
            (cd->flags & DETECT_CONTENT_WITHIN) ||
            (cd->flags & DETECT_CONTENT_OFFSET) ||
            (cd->flags & DETECT_CONTENT_DEPTH)) {

            /* we can't have any of these if we are having "only" */
            SCLogError(SC_ERR_INVALID_SIGNATURE, "fast_pattern: only; cannot be "
                       "used with negated content or with any of the relative "
                       "modifiers like distance, within, offset, depth");
            goto error;
        }
        cd->flags |= DETECT_CONTENT_FAST_PATTERN_ONLY;

        /* fast pattern chop */
    } else if (ret == 4) {
        res = pcre_copy_substring((char *)arg, ov, MAX_SUBSTRINGS,
                                 2, arg_substr, sizeof(arg_substr));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed "
                       "for fast_pattern offset");
            goto error;
        }
        int offset = atoi(arg_substr);
        if (offset > 65535) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Fast pattern offset exceeds "
                       "limit");
            goto error;
        }

        res = pcre_copy_substring((char *)arg, ov, MAX_SUBSTRINGS,
                                 3, arg_substr, sizeof(arg_substr));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed "
                       "for fast_pattern offset");
            goto error;
        }
        int length = atoi(arg_substr);
        if (length > 65535) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Fast pattern length exceeds "
                       "limit");
            goto error;
        }

        if (offset + length > 65535) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Fast pattern (length + offset) "
                       "exceeds limit pattern length limit");
            goto error;
        }

        if (offset + length > cd->content_len) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Fast pattern (length + "
                       "offset (%u)) exceeds pattern length (%u)",
                       offset + length, cd->content_len);
            goto error;
        }

        cd->fp_chop_offset = offset;
        cd->fp_chop_len = length;
        cd->flags |= DETECT_CONTENT_FAST_PATTERN_CHOP;

    } else {
        SCLogError(SC_ERR_PCRE_PARSE, "parse error, ret %" PRId32
                   ", string %s", ret, arg);
        goto error;
    }

    //int args;
    //args = 0;
    //printf("ret-%d\n", ret);
    //for (args = 0; args < ret; args++) {
    //    res = pcre_get_substring((char *)arg, ov, MAX_SUBSTRINGS,
    //                             args, &arg_substr);
    //    if (res < 0) {
    //        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed "
    //                   "for arg 1");
    //        goto error;
    //    }
    //    printf("%d-%s\n", args, arg_substr);
    //}

    cd->flags |= DETECT_CONTENT_FAST_PATTERN;

    return 0;

 error:
    return -1;
}

/*----------------------------------Unittests---------------------------------*/

#ifdef UNITTESTS
static int g_file_data_buffer_id = 0;
static int g_http_method_buffer_id = 0;
static int g_http_uri_buffer_id = 0;
static int g_http_ua_buffer_id = 0;
static int g_http_cookie_buffer_id = 0;
static int g_http_host_buffer_id = 0;
static int g_http_raw_host_buffer_id = 0;
static int g_http_stat_code_buffer_id = 0;
static int g_http_stat_msg_buffer_id = 0;
static int g_http_raw_header_buffer_id = 0;
static int g_http_header_buffer_id = 0;
static int g_http_client_body_buffer_id = 0;
static int g_http_raw_uri_buffer_id = 0;

/**
 * \test Checks if a fast_pattern is registered in a Signature
 */
static int DetectFastPatternTest01(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; tcpv4-csum:valid; fast_pattern; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature
 */
static int DetectFastPatternTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern; "
                               "content:\"boo\"; fast_pattern; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks that we have no fast_pattern registerd for a Signature when the
 *       Signature doesn't contain a fast_pattern
 */
static int DetectFastPatternTest03(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( !(((DetectContentData *)sm->ctx)->flags &
                   DETECT_CONTENT_FAST_PATTERN)) {
                result = 1;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks that a fast_pattern is not registered in a Signature, when we
 *       supply a fast_pattern with an argument
 */
static int DetectFastPatternTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:boo; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks to make sure that other sigs work that should when fast_pattern is inspecting on the same payload
 *
 */
static int DetectFastPatternTest14(void)
{
    uint8_t *buf = (uint8_t *) "Dummy is our name.  Oh yes.  From right here "
        "right now, all the way to hangover.  right.  strings5_imp now here "
        "comes our dark knight strings_string5.  Yes here is our dark knight";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int alertcnt = 0;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf,buflen,IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    FlowInitConfig(FLOW_QUIET);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"fast_pattern test\"; content:\"strings_string5\"; content:\"knight\"; fast_pattern; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    de_ctx->sig_list->next = SigInit(de_ctx, "alert tcp any any -> any any "
                                     "(msg:\"test different content\"; content:\"Dummy is our name\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)){
        alertcnt++;
    }else{
        SCLogInfo("could not match on sig 1 with when fast_pattern is inspecting payload");
        goto end;
    }
    if (PacketAlertCheck(p, 2)){
        result = 1;
    }else{
        SCLogInfo("match on sig 1 fast_pattern no match sig 2 inspecting same payload");
    }
end:
    UTHFreePackets(&p, 1);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    DetectEngineCtxFree(de_ctx);
    FlowShutdown();
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature
 */
static int DetectFastPatternTest15(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature
 */
static int DetectFastPatternTest16(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest17(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
            cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            cd->fp_chop_offset == 0 &&
            cd->fp_chop_len == 0) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest18(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            cd->fp_chop_offset == 3 &&
            cd->fp_chop_len == 4) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest19(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:only; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest20(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; distance:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest21(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:only; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; within:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:only; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; offset:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:only; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; depth:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; content:\"two\"; distance:30; content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        cd->fp_chop_offset == 0 &&
        cd->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; within:30; content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        cd->fp_chop_offset == 0 &&
        cd->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; offset:30; content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        cd->fp_chop_offset == 0 &&
        cd->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; depth:30; content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        cd->fp_chop_offset == 0 &&
        cd->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; content:\"two\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_NEGATED &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        cd->fp_chop_offset == 0 &&
        cd->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; fast_pattern; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; fast_pattern; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; fast_pattern; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; fast_pattern; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest37(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; content:\"oneonetwo\"; fast_pattern:3,4; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest38(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"twotwotwo\"; fast_pattern:3,4; content:\"three\"; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest39(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"twotwotwo\"; fast_pattern:3,4; content:\"three\"; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest40(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"twotwotwo\"; fast_pattern:3,4; content:\"three\"; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest41(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"twotwotwo\"; fast_pattern:3,4; content:\"three\"; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest42(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; distance:10; content:\"threethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest43(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; within:10; content:\"threethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest44(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; offset:10; content:\"threethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest45(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; depth:10; content:\"threethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest46(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:65977,4; content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest47(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"twooneone\"; fast_pattern:3,65977; content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest48(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; fast_pattern:65534,4; content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest49(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *cd = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN &&
        cd->flags & DETECT_CONTENT_NEGATED &&
        !(cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        cd->fp_chop_offset == 3 &&
        cd->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest50(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; distance:10; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest51(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; within:10; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest52(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; offset:10; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest53(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; depth:10; content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/*    content fast_pattern tests ^ */
/* uricontent fast_pattern tests v */


/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest54(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"/one/\"; fast_pattern:only; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest55(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"oneoneone\"; fast_pattern:3,4; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest56(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest57(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"oneoneone\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest58(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:only; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest59(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; distance:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest60(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:only; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest61(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; within:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest62(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:only; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest63(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; offset:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest64(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:only; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest65(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; depth:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest66(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest67(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent: \"one\"; uricontent:\"two\"; distance:30; uricontent:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest68(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; within:30; uricontent:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest69(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; offset:30; uricontent:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest70(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; depth:30; uricontent:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest71(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:!\"one\"; fast_pattern; uricontent:\"two\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest72(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; uricontent:!\"one\"; fast_pattern; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest73(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; uricontent:!\"one\"; fast_pattern; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest74(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; uricontent:!\"one\"; fast_pattern; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest75(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; uricontent:!\"one\"; fast_pattern; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest76(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest77(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest78(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest79(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest80(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest81(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; distance:10; uricontent:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest82(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; within:10; uricontent:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest83(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; offset:10; uricontent:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest84(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; depth:10; uricontent:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest85(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:65977,4; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest86(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"oneonetwo\"; fast_pattern:3,65977; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest87(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; fast_pattern:65534,4; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest88(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"oneonetwo\"; fast_pattern:3,4; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest89(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"oneonetwo\"; fast_pattern:3,4; distance:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest90(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"oneonetwo\"; fast_pattern:3,4; within:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest91(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"oneonetwo\"; fast_pattern:3,4; offset:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest92(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:!\"oneonetwo\"; fast_pattern:3,4; depth:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* uricontent fast_pattern tests ^ */
/*   http_uri fast_pattern tests v */


static int DetectFastPatternTest93(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest94(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_uri; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest95(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_uri; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            if ( ((DetectContentData *)sm->ctx)->flags &
                 DETECT_CONTENT_FAST_PATTERN) {
                result = 1;
                break;
            } else {
                result = 0;
                break;
            }
        }
        sm = sm->next;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest96(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest97(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (sm->type == DETECT_CONTENT) {
        if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest98(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:only; http_uri; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest99(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; distance:10; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest100(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:only; http_uri; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest101(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; within:10; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest102(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:only; http_uri; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest103(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; offset:10; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest104(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:only; http_uri; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest105(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; depth:10; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest106(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"two\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest107(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent: \"one\"; uricontent:\"two\"; distance:30; content:\"two\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest108(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; within:30; content:\"two\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest109(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; offset:30; content:\"two\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest110(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; depth:30; content:\"two\"; fast_pattern:only; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest111(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_uri; uricontent:\"two\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest112(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; content:!\"one\"; fast_pattern; http_uri; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest113(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; content:!\"one\"; fast_pattern; http_uri; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest114(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; content:!\"one\"; fast_pattern; http_uri; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest115(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"two\"; content:!\"one\"; fast_pattern; http_uri; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest116(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest117(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest118(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest119(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest120(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest121(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest122(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest123(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest124(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; uricontent:\"two\"; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest125(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:65977,4; http_uri; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest126(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"oneonetwo\"; fast_pattern:3,65977; http_uri; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest127(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:\"two\"; fast_pattern:65534,4; http_uri; uricontent:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest128(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest129(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; distance:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest130(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; within:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest131(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"twooneone\"; fast_pattern:3,4; http_uri; offset:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest132(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; depth:10; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest133(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(uricontent:\"one\"; content:!\"oneonetwo\"; fast_pattern:3,4; http_uri; uricontent:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/*         http_uri fast_pattern tests ^ */
/* http_client_body fast_pattern tests v */


static int DetectFastPatternTest134(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest135(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_client_body; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest136(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_client_body; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest137(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest138(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest139(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:only; http_client_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest140(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; distance:10; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest141(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:only; http_client_body; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest142(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; within:10; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest143(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:only; http_client_body; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest144(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; offset:10; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest145(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:only; http_client_body; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest146(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; depth:10; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest147(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"two\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest148(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; http_client_body; content:\"two\"; http_client_body; distance:30; content:\"two\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest149(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; within:30; content:\"two\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest150(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; offset:30; content:\"two\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest151(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; depth:30; content:\"two\"; fast_pattern:only; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest152(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_client_body; content:\"two\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest153(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_client_body; content:!\"one\"; fast_pattern; http_client_body; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest154(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_client_body; content:!\"one\"; fast_pattern; http_client_body; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest155(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_client_body; content:!\"one\"; fast_pattern; http_client_body; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest156(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_client_body; content:!\"one\"; fast_pattern; http_client_body; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest157(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest158(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest159(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest160(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest161(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest162(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest163(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest164(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest165(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; http_client_body; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest166(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:65977,4; http_client_body; content:\"three\"; http_client_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest167(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_client_body; content:\"oneonetwo\"; fast_pattern:3,65977; http_client_body; content:\"three\"; distance:10; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest168(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:\"two\"; fast_pattern:65534,4; http_client_body; content:\"three\"; http_client_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest169(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest170(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; distance:10; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest171(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; within:10; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest172(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"twooneone\"; fast_pattern:3,4; http_client_body; offset:10; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest173(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; depth:10; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest174(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_client_body; content:!\"oneonetwo\"; fast_pattern:3,4; http_client_body; content:\"three\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_client_body fast_pattern tests ^ */
/*          content fast_pattern tests v */


static int DetectFastPatternTest175(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; distance:20; fast_pattern; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest176(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; within:20; fast_pattern; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest177(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; offset:20; fast_pattern; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest178(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; content:!\"one\"; depth:20; fast_pattern; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/*     content fast_pattern tests ^ */
/* http_header fast_pattern tests v */


static int DetectFastPatternTest179(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_header; "
                               "content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest180(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_header; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_header_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest181(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_header; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_header_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest182(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_header_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest183(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_header_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest184(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:only; http_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest185(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; distance:10; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest186(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:only; http_header; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest187(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; within:10; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest188(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:only; http_header; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest189(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; offset:10; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest190(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:only; http_header; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest191(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; depth:10; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest192(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"two\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest193(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; http_header; content:\"two\"; http_header; distance:30; content:\"two\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest194(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; within:30; content:\"two\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest195(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; offset:30; content:\"two\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest196(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; depth:30; content:\"two\"; fast_pattern:only; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest197(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_header; content:\"two\"; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest198(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_header; content:!\"one\"; fast_pattern; http_header; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest199(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_header; content:!\"one\"; fast_pattern; http_header; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest200(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_header; content:!\"one\"; fast_pattern; http_header; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest201(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_header; content:!\"one\"; fast_pattern; http_header; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest202(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest203(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest204(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest205(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest206(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest207(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest208(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest209(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest210(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; http_header; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest211(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:65977,4; http_header; content:\"three\"; http_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest212(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_header; content:\"oneonetwo\"; fast_pattern:3,65977; http_header; content:\"three\"; distance:10; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest213(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:\"two\"; fast_pattern:65534,4; http_header; content:\"three\"; http_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest214(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest215(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; distance:10; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest216(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; within:10; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest217(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; offset:10; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest218(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; depth:10; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest219(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_header; content:\"three\"; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/*     http_header fast_pattern tests ^ */
/* http_raw_header fast_pattern tests v */


static int DetectFastPatternTest220(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; "
                               "content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest221(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"/one/\"; fast_pattern:only; http_raw_header; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_header_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest222(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"oneoneone\"; fast_pattern:3,4; http_raw_header; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_header_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest223(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_header_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest224(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"oneoneone\"; fast_pattern:3,4; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_header_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest225(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:only; http_raw_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest226(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; distance:10; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest227(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:only; http_raw_header; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest228(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; within:10; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest229(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:only; http_raw_header; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest230(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; offset:10; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest231(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:only; http_raw_header; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest232(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; depth:10; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest233(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"two\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest234(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content: \"one\"; http_raw_header; content:\"two\"; http_raw_header; distance:30; content:\"two\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest235(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; within:30; content:\"two\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest236(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; offset:30; content:\"two\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest237(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; depth:30; content:\"two\"; fast_pattern:only; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest238(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:!\"one\"; fast_pattern; http_raw_header; content:\"two\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest239(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"two\"; http_raw_header; content:!\"one\"; fast_pattern; http_raw_header; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest240(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"two\"; http_raw_header; content:!\"one\"; fast_pattern; http_raw_header; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest241(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"two\"; http_raw_header; content:!\"one\"; fast_pattern; http_raw_header; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest242(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"two\"; http_raw_header; content:!\"one\"; fast_pattern; http_raw_header; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest243(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest244(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest245(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest246(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest247(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest248(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest249(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest250(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest251(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; http_raw_header; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest252(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:65977,4; http_raw_header; content:\"three\"; http_raw_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest253(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\";  http_raw_header; content:\"oneonetwo\"; fast_pattern:3,65977; http_raw_header; content:\"three\"; distance:10; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest254(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:\"two\"; fast_pattern:65534,4; http_raw_header; content:\"three\"; http_raw_header; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest255(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest256(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; distance:10; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest257(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; within:10; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest258(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; offset:10; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest259(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; depth:10; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest260(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                               "(flow:to_server; content:\"one\"; http_raw_header; content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_header; content:\"three\"; http_raw_header; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_header_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_raw_header fast_pattern tests ^ */
/*     http_method fast_pattern tests v */


static int DetectFastPatternTest261(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_method; "
                               "content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest262(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_method; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_method_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest263(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_method; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_method_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest264(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_method_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest265(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_method_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest266(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:only; http_method; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest267(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; distance:10; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest268(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:only; http_method; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest269(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; within:10; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest270(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:only; http_method; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest271(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; offset:10; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest272(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:only; http_method; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest273(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; depth:10; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest274(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"two\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest275(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; http_method; content:\"two\"; http_method; distance:30; content:\"two\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest276(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; within:30; content:\"two\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest277(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; offset:30; content:\"two\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest278(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; depth:30; content:\"two\"; fast_pattern:only; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest279(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_method; content:\"two\"; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest280(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_method; content:!\"one\"; fast_pattern; http_method; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest281(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_method; content:!\"one\"; fast_pattern; http_method; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest282(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_method; content:!\"one\"; fast_pattern; http_method; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest283(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_method; content:!\"one\"; fast_pattern; http_method; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest284(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest285(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest286(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest287(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest288(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest289(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest290(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest291(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest292(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; http_method; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest293(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:65977,4; http_method; content:\"three\"; http_method; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest294(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_method; content:\"oneonetwo\"; fast_pattern:3,65977; http_method; content:\"three\"; distance:10; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest295(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:\"two\"; fast_pattern:65534,4; http_method; content:\"three\"; http_method; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest296(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest297(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; distance:10; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest298(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; within:10; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest299(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; offset:10; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest300(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; depth:10; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest301(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_method; content:!\"oneonetwo\"; fast_pattern:3,4; http_method; content:\"three\"; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_method_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_method fast_pattern tests ^ */
/* http_cookie fast_pattern tests v */


static int DetectFastPatternTest302(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; "
                               "content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest303(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_cookie; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_cookie_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest304(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_cookie; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_cookie_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest305(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_cookie_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest306(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_cookie_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest307(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:only; http_cookie; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest308(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; distance:10; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest309(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:only; http_cookie; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest310(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; within:10; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest311(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:only; http_cookie; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest312(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; offset:10; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest313(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:only; http_cookie; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest314(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; depth:10; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest315(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"two\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest316(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; http_cookie; content:\"two\"; http_cookie; distance:30; content:\"two\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest317(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; within:30; content:\"two\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest318(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; offset:30; content:\"two\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest319(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; depth:30; content:\"two\"; fast_pattern:only; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest320(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_cookie; content:\"two\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest321(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_cookie; content:!\"one\"; fast_pattern; http_cookie; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest322(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_cookie; content:!\"one\"; fast_pattern; http_cookie; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest323(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_cookie; content:!\"one\"; fast_pattern; http_cookie; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest324(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_cookie; content:!\"one\"; fast_pattern; http_cookie; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest325(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest326(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest327(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest328(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest329(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest330(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; distance:10; content:\"oneonethree\"; fast_pattern:3,4; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest331(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; within:10; content:\"oneonethree\"; fast_pattern:3,4; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest332(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; offset:10; content:\"oneonethree\"; fast_pattern:3,4; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest333(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; http_cookie; depth:10; content:\"oneonethree\"; fast_pattern:3,4; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest334(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:65977,4; http_cookie; content:\"three\"; http_cookie; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest335(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_cookie; content:\"oneonetwo\"; fast_pattern:3,65977; http_cookie; content:\"three\"; distance:10; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest336(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:\"two\"; fast_pattern:65534,4; http_cookie; content:\"three\"; http_cookie; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest337(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest338(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; distance:10; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest339(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; within:10; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest340(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; offset:10; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest341(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; depth:10; content:\"three2\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest342(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_cookie; content:!\"oneonetwo\"; fast_pattern:3,4; http_cookie; content:\"three\"; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_cookie_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_cookie fast_pattern tests ^ */
/* http_raw_uri fast_pattern tests v */


static int DetectFastPatternTest343(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest344(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"/one/\"; fast_pattern:only; http_raw_uri; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_uri_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest345(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_raw_uri; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_uri_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest346(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest347(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_uri_buffer_id];
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest348(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest349(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest350(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest351(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; within:10; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest352(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest353(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest354(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest355(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest356(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"two\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest357(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content: \"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest358(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; within:30; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest359(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest360(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest361(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest362(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_uri; "
                               "content:!\"one\"; fast_pattern; http_raw_uri; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest363(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_uri; "
                               "content:!\"one\"; fast_pattern; http_raw_uri; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest364(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_uri; "
                               "content:!\"one\"; fast_pattern; http_raw_uri; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest365(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_uri; "
                               "content:!\"one\"; fast_pattern; http_raw_uri; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest366(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest367(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest368(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest369(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest370(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest371(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest372(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest373(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest374(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest375(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:65977,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest376(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_raw_uri; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_raw_uri; "
                               "content:\"three\"; distance:10; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest377(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; fast_pattern:65534,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest378(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest379(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; distance:10; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest380(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; within:10; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest381(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; offset:10; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest382(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; depth:10; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest383(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_uri_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_raw_uri fast_pattern tests ^ */
/* http_stat_msg fast_pattern tests v */


static int DetectFastPatternTest384(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest385(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_stat_msg; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_stat_msg_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest386(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_stat_msg; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_stat_msg_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest387(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_stat_msg_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest388(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_stat_msg_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest389(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest390(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest391(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest392(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; within:10; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest393(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest394(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest395(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest396(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest397(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"two\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest398(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest399(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; within:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest400(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest401(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest402(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest403(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_msg; "
                               "content:!\"one\"; fast_pattern; http_stat_msg; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest404(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_msg; "
                               "content:!\"one\"; fast_pattern; http_stat_msg; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest405(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_msg; "
                               "content:!\"one\"; fast_pattern; http_stat_msg; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest406(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_msg; "
                               "content:!\"one\"; fast_pattern; http_stat_msg; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest407(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest408(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest409(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest410(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest411(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest412(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest413(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest414(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest415(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; http_stat_msg; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest416(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:65977,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest417(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_stat_msg; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_stat_msg; "
                               "content:\"three\"; distance:10; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest418(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:\"two\"; fast_pattern:65534,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest419(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest420(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; distance:10; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest421(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; within:10; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest422(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; offset:10; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest423(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; depth:10; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest424(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_msg; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_msg; "
                               "content:\"three\"; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_msg_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_stat_msg fast_pattern tests ^ */
/* http_stat_code fast_pattern tests v */


static int DetectFastPatternTest425(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest426(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_stat_code; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_stat_code_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest427(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_stat_code; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_stat_code_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest428(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_stat_code_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest429(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_stat_code_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest430(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest431(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest432(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest433(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; within:10; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest434(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest435(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest436(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest437(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest438(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"two\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest439(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest440(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; within:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest441(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest442(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest443(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_stat_code; "
                               "content:\"two\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest444(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_code; "
                               "content:!\"one\"; fast_pattern; http_stat_code; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest445(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_code; "
                               "content:!\"one\"; fast_pattern; http_stat_code; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest446(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_code; "
                               "content:!\"one\"; fast_pattern; http_stat_code; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest447(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_stat_code; "
                               "content:!\"one\"; fast_pattern; http_stat_code; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest448(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest449(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest450(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest451(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest452(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest453(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest454(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest455(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest456(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; http_stat_code; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest457(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:65977,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest458(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_stat_code; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_stat_code; "
                               "content:\"three\"; distance:10; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest459(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:\"two\"; fast_pattern:65534,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest460(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest461(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; distance:10; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest462(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; within:10; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest463(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; offset:10; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest464(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; depth:10; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest465(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_stat_code; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_stat_code; "
                               "content:\"three\"; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_stat_code_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_stat_code fast_pattern tests ^ */
/* http_server_body fast_pattern tests v */


static int DetectFastPatternTest466(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest467(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_server_body; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest468(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_server_body; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest469(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest470(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest471(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:only; http_server_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest472(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest473(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:only; http_server_body; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest474(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; within:10; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest475(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:only; http_server_body; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest476(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest477(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:only; http_server_body; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest478(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest479(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"two\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest480(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_server_body; "
                               "content:\"two\"; http_server_body; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest481(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; within:30; "
                               "content:\"two\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest482(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest483(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest484(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_server_body; "
                               "content:\"two\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest485(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_server_body; "
                               "content:!\"one\"; fast_pattern; http_server_body; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest486(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_server_body; "
                               "content:!\"one\"; fast_pattern; http_server_body; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest487(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_server_body; "
                               "content:!\"one\"; fast_pattern; http_server_body; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest488(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_server_body; "
                               "content:!\"one\"; fast_pattern; http_server_body; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest489(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest490(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest491(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest492(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest493(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest494(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest495(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest496(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest497(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; http_server_body; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest498(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:65977,4; http_server_body; "
                               "content:\"three\"; http_server_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest499(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_server_body; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_server_body; "
                               "content:\"three\"; distance:10; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest500(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; fast_pattern:65534,4; http_server_body; "
                               "content:\"three\"; http_server_body; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest501(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest502(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; distance:10; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest503(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; within:10; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest504(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; offset:10; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest505(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; depth:10; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest506(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_server_body; "
                               "content:\"three\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_server_body fast_pattern tests ^ */
/* file_data fast_pattern tests v */

/** \test file_data and icmp don't mix */
static int DetectFastPatternTest507(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert icmp any any -> any any "
            "(file_data; content:\"one\"; "
            "content:!\"oneonetwo\"; fast_pattern:3,4; "
            "content:\"three\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest508(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; fast_pattern:only; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest509(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"oneoneone\"; fast_pattern:3,4; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest510(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest511(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"oneoneone\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest512(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:only; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest513(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; distance:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest514(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:only; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest515(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; within:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest516(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:only;  offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest517(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; offset:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest518(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:only; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest519(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; depth:10; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest520(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest521(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\" one\"; "
                               "content:\"two\"; distance:30; "
                               "content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest522(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; within:30; "
                               "content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest523(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; offset:30; "
                               "content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest524(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; depth:30; "
                               "content:\"two\"; fast_pattern:only; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest525(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:!\"one\"; fast_pattern; "
                               "content:\"two\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest526(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"two\"; "
                               "content:!\"one\"; fast_pattern; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest527(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"two\"; "
                               "content:!\"one\"; fast_pattern; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest528(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"two\"; "
                               "content:!\"one\"; fast_pattern; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest529(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"two\"; "
                               "content:!\"one\"; fast_pattern; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest530(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,4;  "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest531(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest532(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest533(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest534(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest535(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest536(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest537(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest538(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest539(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:65977,4; "
                               "content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest540(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; "
                               "content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest541(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:\"two\"; fast_pattern:65534,4; "
                               "content:\"three\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest542(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest543(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; distance:10; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest544(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; within:10; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest545(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; offset:10; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest546(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; depth:10; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest547(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"one\"; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; "
                               "content:\"three\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* file_data fast_pattern tests ^ */
/* http_user_agent fast_pattern tests v */


static int DetectFastPatternTest548(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest549(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_user_agent; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_ua_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest550(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_user_agent; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_ua_buffer_id];
    if (sm != NULL) {
        if ( ((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest551(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_ua_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest552(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_ua_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest553(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest554(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest555(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest556(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; within:10; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest557(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest558(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest559(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest560(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest561(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"two\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest562(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest563(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; within:30; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest564(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest565(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest566(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_user_agent; "
                               "content:\"two\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest567(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_user_agent; "
                               "content:!\"one\"; fast_pattern; http_user_agent; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest568(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_user_agent; "
                               "content:!\"one\"; fast_pattern; http_user_agent; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest569(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_user_agent; "
                               "content:!\"one\"; fast_pattern; http_user_agent; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest570(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_user_agent; "
                               "content:!\"one\"; fast_pattern; http_user_agent; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest571(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest572(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest573(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest574(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest575(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest576(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest577(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest578(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest579(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; http_user_agent; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest580(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:65977,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest581(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_user_agent; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_user_agent; "
                               "content:\"three\"; distance:10; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest582(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:\"two\"; fast_pattern:65534,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest583(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest584(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; distance:10; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest585(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; within:10; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest586(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; offset:10; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest587(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; depth:10; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest588(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_user_agent; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_user_agent; "
                               "content:\"three\"; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_user_agent fast_pattern tests ^ */
/* http_host fast_pattern tests v */


static int DetectFastPatternTest589(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest590(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_host;  "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_host_buffer_id];
    if (sm != NULL) {
        if ( (((DetectContentData *)sm->ctx)->flags &
              DETECT_CONTENT_FAST_PATTERN)) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest591(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_host; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_host_buffer_id];
    if (sm != NULL) {
        if ( (((DetectContentData *)sm->ctx)->flags &
              DETECT_CONTENT_FAST_PATTERN)) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest592(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_host_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest593(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_host_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest594(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:only; http_host; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest595(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest596(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:only; http_host; within:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest597(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; within:10; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest598(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:only; http_host; offset:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest599(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest600(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:only; http_host; depth:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest601(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest602(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"two\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest603(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_host; "
                               "content:\"two\"; http_host; distance:30; "
                               "content:\"two\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest604(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; within:30; "
                               "content:\"two\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest605(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; offset:30; "
                               "content:\"two\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest606(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; depth:30; "
                               "content:\"two\"; fast_pattern:only; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest607(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_host; "
                               "content:\"two\"; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest608(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_host; "
                               "content:!\"one\"; fast_pattern; http_host; distance:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest609(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_host; "
                               "content:!\"one\"; fast_pattern; http_host; within:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest610(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_host; "
                               "content:!\"one\"; fast_pattern; http_host; offset:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest611(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_host; "
                               "content:!\"one\"; fast_pattern; http_host; depth:20; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest612(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest613(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; distance:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest614(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; within:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest615(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; offset:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest616(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; depth:30; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest617(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; distance:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest618(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; within:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest619(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; offset:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest620(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; http_host; depth:10; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest621(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:65977,4; http_host; "
                               "content:\"three\"; http_host; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest622(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_host; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_host; "
                               "content:\"three\"; distance:10; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest623(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; fast_pattern:65534,4; http_host; "
                               "content:\"three\"; http_host; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest624(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest625(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; distance:10; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest626(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; within:10; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest627(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; offset:10; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest628(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; depth:10; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest629(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_host; "
                               "content:\"three\"; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/* http_host fast_pattern tests ^ */
/* http_rawhost fast_pattern tests v */


static int DetectFastPatternTest630(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest631(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_raw_host; nocase; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id];
    if (sm != NULL) {
        if ( (((DetectContentData *)sm->ctx)->flags &
             DETECT_CONTENT_FAST_PATTERN) &&
             (((DetectContentData *)sm->ctx)->flags &
              DETECT_CONTENT_NOCASE)) {
            result = 1;
        } else {
            result = 0;
        }
    }


 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature for uricontent.
 */
static int DetectFastPatternTest632(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "msg:\"Testing fast_pattern\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    result = 0;
    sm = de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id];
    if (sm != NULL) {
        if ( (((DetectContentData *)sm->ctx)->flags &
              DETECT_CONTENT_FAST_PATTERN) &&
             (((DetectContentData *)sm->ctx)->flags &
              DETECT_CONTENT_NOCASE)) {
            result = 1;
        } else {
            result = 0;
        }
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest633(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id];
    if (sm == NULL) {
        goto end;
    }
    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
            !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
            ud->fp_chop_offset == 0 &&
            ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest634(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"oneoneone\"; fast_pattern:3,4; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    sm = de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    DetectContentData *ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
            ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
            ud->fp_chop_offset == 3 &&
            ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest635(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; distance:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest636(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; distance:10; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest637(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; within:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest638(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; within:10; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest639(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; offset:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest640(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; offset:10; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest641(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; depth:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest642(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; depth:10; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest643(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"two\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest644(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\" one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; distance:30; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest645(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; within:30; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest646(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; offset:30; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest647(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; depth:30; nocase; "
                               "content:\"two\"; fast_pattern:only; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest648(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:!\"one\"; fast_pattern; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) &&
        ud->fp_chop_offset == 0 &&
        ud->fp_chop_len == 0) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest649(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_host; nocase; "
                               "content:!\"one\"; fast_pattern; http_raw_host; distance:20; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest650(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_host; nocase; "
                               "content:!\"one\"; fast_pattern; http_raw_host; within:20; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest651(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_host; nocase; "
                               "content:!\"one\"; fast_pattern; http_raw_host; offset:20; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest652(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_host; nocase; "
                               "content:!\"one\"; fast_pattern; http_raw_host; depth:20; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest653(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest654(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; distance:30; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest655(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; within:30; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest656(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; offset:30; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest657(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; depth:30; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest658(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; distance:10; nocase; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest659(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; within:10; nocase; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest660(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; offset:10; nocase; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest661(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; http_raw_host; depth:10; nocase; "
                               "content:\"oneonethree\"; fast_pattern:3,4; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }


    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest662(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:65977,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; distance:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest663(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\";  http_raw_host; nocase; "
                               "content:\"oneonetwo\"; fast_pattern:3,65977; http_raw_host; nocase; "
                               "content:\"three\"; distance:10; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest664(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:\"two\"; fast_pattern:65534,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; distance:10; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest665(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest666(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; distance:10; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest667(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; within:10; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest668(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; offset:10; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest669(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; depth:10; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectFastPatternTest670(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; "
                               "content:!\"oneonetwo\"; fast_pattern:3,4; http_raw_host; nocase; "
                               "content:\"three\"; http_raw_host; nocase; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    DetectContentData *ud = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    if (ud->flags & DETECT_CONTENT_FAST_PATTERN &&
        ud->flags & DETECT_CONTENT_NOCASE &&
        ud->flags & DETECT_CONTENT_NEGATED &&
        !(ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) &&
        ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP &&
        ud->fp_chop_offset == 3 &&
        ud->fp_chop_len == 4) {
        result = 1;
    } else {
        result = 0;
    }

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


/**
 * Unittest to check
 * - if we assign different content_ids to duplicate patterns, but one of the
 *   patterns has a fast_pattern chop set.
 * - if 2 unique patterns get unique ids.
 * - if 2 duplicate patterns, with no chop set get unique ids.
 */
static int DetectFastPatternTest671(void)
{
    int no_of_sigs = 6;
    const char *sigs[no_of_sigs];
    Signature *s[no_of_sigs];
    DetectEngineCtx *de_ctx = NULL;
    DetectContentData *cd = NULL;
    SigMatchData *smd = NULL;
    int i = 0;

    sigs[0] = "alert tcp any any -> any any "
        "(content:\"onetwothreefour\"; sid:1;)";
    sigs[1] = "alert tcp any any -> any any "
        "(content:\"onetwothreefour\"; sid:2;)";
    sigs[2] = "alert tcp any any -> any any "
        "(content:\"uniquepattern\"; sid:3;)";
    sigs[3] = "alert tcp any any -> any any "
        "(content:\"onetwothreefour\"; fast_pattern:3,5; sid:4;)";
    sigs[4] = "alert tcp any any -> any any "
        "(content:\"twoth\"; sid:5;)";
    sigs[5] = "alert tcp any any -> any any "
        "(content:\"onetwothreefour\"; fast_pattern:0,15; sid:6;)";

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    for (i = 0; i < no_of_sigs; i++) {
        s[i] = DetectEngineAppendSig(de_ctx, sigs[i]);
        FAIL_IF_NULL(s[i]);
    }

    SigGroupBuild(de_ctx);

    smd = s[0]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 0);

    smd = s[1]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 0);

    smd = s[2]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 2);

    smd = s[3]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 1);

    smd = s[4]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 1);

    smd = s[5]->sm_arrays[DETECT_SM_LIST_PMATCH];
    cd = (DetectContentData *)smd->ctx;
    FAIL_IF(cd->id != 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif

void DetectFastPatternRegisterTests(void)
{
#ifdef UNITTESTS
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_http_method_buffer_id = DetectBufferTypeGetByName("http_method");
    g_http_uri_buffer_id = DetectBufferTypeGetByName("http_uri");
    g_http_ua_buffer_id = DetectBufferTypeGetByName("http_user_agent");
    g_http_cookie_buffer_id = DetectBufferTypeGetByName("http_cookie");
    g_http_host_buffer_id = DetectBufferTypeGetByName("http_host");
    g_http_raw_host_buffer_id = DetectBufferTypeGetByName("http_raw_host");
    g_http_stat_code_buffer_id = DetectBufferTypeGetByName("http_stat_code");
    g_http_stat_msg_buffer_id = DetectBufferTypeGetByName("http_stat_msg");
    g_http_header_buffer_id = DetectBufferTypeGetByName("http_header");
    g_http_raw_header_buffer_id = DetectBufferTypeGetByName("http_raw_header");
    g_http_client_body_buffer_id = DetectBufferTypeGetByName("http_client_body");
    g_http_raw_uri_buffer_id = DetectBufferTypeGetByName("http_raw_uri");

    UtRegisterTest("DetectFastPatternTest01", DetectFastPatternTest01);
    UtRegisterTest("DetectFastPatternTest02", DetectFastPatternTest02);
    UtRegisterTest("DetectFastPatternTest03", DetectFastPatternTest03);
    UtRegisterTest("DetectFastPatternTest04", DetectFastPatternTest04);
    UtRegisterTest("DetectFastPatternTest14", DetectFastPatternTest14);
    UtRegisterTest("DetectFastPatternTest15", DetectFastPatternTest15);
    UtRegisterTest("DetectFastPatternTest16", DetectFastPatternTest16);
    UtRegisterTest("DetectFastPatternTest17", DetectFastPatternTest17);
    UtRegisterTest("DetectFastPatternTest18", DetectFastPatternTest18);
    UtRegisterTest("DetectFastPatternTest19", DetectFastPatternTest19);
    UtRegisterTest("DetectFastPatternTest20", DetectFastPatternTest20);
    UtRegisterTest("DetectFastPatternTest21", DetectFastPatternTest21);
    UtRegisterTest("DetectFastPatternTest22", DetectFastPatternTest22);
    UtRegisterTest("DetectFastPatternTest23", DetectFastPatternTest23);
    UtRegisterTest("DetectFastPatternTest24", DetectFastPatternTest24);
    UtRegisterTest("DetectFastPatternTest25", DetectFastPatternTest25);
    UtRegisterTest("DetectFastPatternTest26", DetectFastPatternTest26);
    UtRegisterTest("DetectFastPatternTest27", DetectFastPatternTest27);
    UtRegisterTest("DetectFastPatternTest28", DetectFastPatternTest28);
    UtRegisterTest("DetectFastPatternTest29", DetectFastPatternTest29);
    UtRegisterTest("DetectFastPatternTest30", DetectFastPatternTest30);
    UtRegisterTest("DetectFastPatternTest31", DetectFastPatternTest31);
    UtRegisterTest("DetectFastPatternTest32", DetectFastPatternTest32);
    UtRegisterTest("DetectFastPatternTest33", DetectFastPatternTest33);
    UtRegisterTest("DetectFastPatternTest34", DetectFastPatternTest34);
    UtRegisterTest("DetectFastPatternTest35", DetectFastPatternTest35);
    UtRegisterTest("DetectFastPatternTest36", DetectFastPatternTest36);
    UtRegisterTest("DetectFastPatternTest37", DetectFastPatternTest37);
    UtRegisterTest("DetectFastPatternTest38", DetectFastPatternTest38);
    UtRegisterTest("DetectFastPatternTest39", DetectFastPatternTest39);
    UtRegisterTest("DetectFastPatternTest40", DetectFastPatternTest40);
    UtRegisterTest("DetectFastPatternTest41", DetectFastPatternTest41);
    UtRegisterTest("DetectFastPatternTest42", DetectFastPatternTest42);
    UtRegisterTest("DetectFastPatternTest43", DetectFastPatternTest43);
    UtRegisterTest("DetectFastPatternTest44", DetectFastPatternTest44);
    UtRegisterTest("DetectFastPatternTest45", DetectFastPatternTest45);
    UtRegisterTest("DetectFastPatternTest46", DetectFastPatternTest46);
    UtRegisterTest("DetectFastPatternTest47", DetectFastPatternTest47);
    UtRegisterTest("DetectFastPatternTest48", DetectFastPatternTest48);
    UtRegisterTest("DetectFastPatternTest49", DetectFastPatternTest49);
    UtRegisterTest("DetectFastPatternTest50", DetectFastPatternTest50);
    UtRegisterTest("DetectFastPatternTest51", DetectFastPatternTest51);
    UtRegisterTest("DetectFastPatternTest52", DetectFastPatternTest52);
    UtRegisterTest("DetectFastPatternTest53", DetectFastPatternTest53);
    /*    content fast_pattern tests ^ */
    /* uricontent fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest54", DetectFastPatternTest54);
    UtRegisterTest("DetectFastPatternTest55", DetectFastPatternTest55);
    UtRegisterTest("DetectFastPatternTest56", DetectFastPatternTest56);
    UtRegisterTest("DetectFastPatternTest57", DetectFastPatternTest57);
    UtRegisterTest("DetectFastPatternTest58", DetectFastPatternTest58);
    UtRegisterTest("DetectFastPatternTest59", DetectFastPatternTest59);
    UtRegisterTest("DetectFastPatternTest60", DetectFastPatternTest60);
    UtRegisterTest("DetectFastPatternTest61", DetectFastPatternTest61);
    UtRegisterTest("DetectFastPatternTest62", DetectFastPatternTest62);
    UtRegisterTest("DetectFastPatternTest63", DetectFastPatternTest63);
    UtRegisterTest("DetectFastPatternTest64", DetectFastPatternTest64);
    UtRegisterTest("DetectFastPatternTest65", DetectFastPatternTest65);
    UtRegisterTest("DetectFastPatternTest66", DetectFastPatternTest66);
    UtRegisterTest("DetectFastPatternTest67", DetectFastPatternTest67);
    UtRegisterTest("DetectFastPatternTest68", DetectFastPatternTest68);
    UtRegisterTest("DetectFastPatternTest69", DetectFastPatternTest69);
    UtRegisterTest("DetectFastPatternTest70", DetectFastPatternTest70);
    UtRegisterTest("DetectFastPatternTest71", DetectFastPatternTest71);
    UtRegisterTest("DetectFastPatternTest72", DetectFastPatternTest72);
    UtRegisterTest("DetectFastPatternTest73", DetectFastPatternTest73);
    UtRegisterTest("DetectFastPatternTest74", DetectFastPatternTest74);
    UtRegisterTest("DetectFastPatternTest75", DetectFastPatternTest75);
    UtRegisterTest("DetectFastPatternTest76", DetectFastPatternTest76);
    UtRegisterTest("DetectFastPatternTest77", DetectFastPatternTest77);
    UtRegisterTest("DetectFastPatternTest78", DetectFastPatternTest78);
    UtRegisterTest("DetectFastPatternTest79", DetectFastPatternTest79);
    UtRegisterTest("DetectFastPatternTest80", DetectFastPatternTest80);
    UtRegisterTest("DetectFastPatternTest81", DetectFastPatternTest81);
    UtRegisterTest("DetectFastPatternTest82", DetectFastPatternTest82);
    UtRegisterTest("DetectFastPatternTest83", DetectFastPatternTest83);
    UtRegisterTest("DetectFastPatternTest84", DetectFastPatternTest84);
    UtRegisterTest("DetectFastPatternTest85", DetectFastPatternTest85);
    UtRegisterTest("DetectFastPatternTest86", DetectFastPatternTest86);
    UtRegisterTest("DetectFastPatternTest87", DetectFastPatternTest87);
    UtRegisterTest("DetectFastPatternTest88", DetectFastPatternTest88);
    UtRegisterTest("DetectFastPatternTest89", DetectFastPatternTest89);
    UtRegisterTest("DetectFastPatternTest90", DetectFastPatternTest90);
    UtRegisterTest("DetectFastPatternTest91", DetectFastPatternTest91);
    UtRegisterTest("DetectFastPatternTest92", DetectFastPatternTest92);
    /* uricontent fast_pattern tests ^ */
    /*   http_uri fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest93", DetectFastPatternTest93);
    UtRegisterTest("DetectFastPatternTest94", DetectFastPatternTest94);
    UtRegisterTest("DetectFastPatternTest95", DetectFastPatternTest95);
    UtRegisterTest("DetectFastPatternTest96", DetectFastPatternTest96);
    UtRegisterTest("DetectFastPatternTest97", DetectFastPatternTest97);
    UtRegisterTest("DetectFastPatternTest98", DetectFastPatternTest98);
    UtRegisterTest("DetectFastPatternTest99", DetectFastPatternTest99);
    UtRegisterTest("DetectFastPatternTest100", DetectFastPatternTest100);
    UtRegisterTest("DetectFastPatternTest101", DetectFastPatternTest101);
    UtRegisterTest("DetectFastPatternTest102", DetectFastPatternTest102);
    UtRegisterTest("DetectFastPatternTest103", DetectFastPatternTest103);
    UtRegisterTest("DetectFastPatternTest104", DetectFastPatternTest104);
    UtRegisterTest("DetectFastPatternTest105", DetectFastPatternTest105);
    UtRegisterTest("DetectFastPatternTest106", DetectFastPatternTest106);
    UtRegisterTest("DetectFastPatternTest107", DetectFastPatternTest107);
    UtRegisterTest("DetectFastPatternTest108", DetectFastPatternTest108);
    UtRegisterTest("DetectFastPatternTest109", DetectFastPatternTest109);
    UtRegisterTest("DetectFastPatternTest110", DetectFastPatternTest110);
    UtRegisterTest("DetectFastPatternTest111", DetectFastPatternTest111);
    UtRegisterTest("DetectFastPatternTest112", DetectFastPatternTest112);
    UtRegisterTest("DetectFastPatternTest113", DetectFastPatternTest113);
    UtRegisterTest("DetectFastPatternTest114", DetectFastPatternTest114);
    UtRegisterTest("DetectFastPatternTest115", DetectFastPatternTest115);
    UtRegisterTest("DetectFastPatternTest116", DetectFastPatternTest116);
    UtRegisterTest("DetectFastPatternTest117", DetectFastPatternTest117);
    UtRegisterTest("DetectFastPatternTest118", DetectFastPatternTest118);
    UtRegisterTest("DetectFastPatternTest119", DetectFastPatternTest119);
    UtRegisterTest("DetectFastPatternTest120", DetectFastPatternTest120);
    UtRegisterTest("DetectFastPatternTest121", DetectFastPatternTest121);
    UtRegisterTest("DetectFastPatternTest122", DetectFastPatternTest122);
    UtRegisterTest("DetectFastPatternTest123", DetectFastPatternTest123);
    UtRegisterTest("DetectFastPatternTest124", DetectFastPatternTest124);
    UtRegisterTest("DetectFastPatternTest125", DetectFastPatternTest125);
    UtRegisterTest("DetectFastPatternTest126", DetectFastPatternTest126);
    UtRegisterTest("DetectFastPatternTest127", DetectFastPatternTest127);
    UtRegisterTest("DetectFastPatternTest128", DetectFastPatternTest128);
    UtRegisterTest("DetectFastPatternTest129", DetectFastPatternTest129);
    UtRegisterTest("DetectFastPatternTest130", DetectFastPatternTest130);
    UtRegisterTest("DetectFastPatternTest131", DetectFastPatternTest131);
    UtRegisterTest("DetectFastPatternTest132", DetectFastPatternTest132);
    UtRegisterTest("DetectFastPatternTest133", DetectFastPatternTest133);
    /*         http_uri fast_pattern tests ^ */
    /* http_client_body fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest134", DetectFastPatternTest134);
    UtRegisterTest("DetectFastPatternTest135", DetectFastPatternTest135);
    UtRegisterTest("DetectFastPatternTest136", DetectFastPatternTest136);
    UtRegisterTest("DetectFastPatternTest137", DetectFastPatternTest137);
    UtRegisterTest("DetectFastPatternTest138", DetectFastPatternTest138);
    UtRegisterTest("DetectFastPatternTest139", DetectFastPatternTest139);
    UtRegisterTest("DetectFastPatternTest140", DetectFastPatternTest140);
    UtRegisterTest("DetectFastPatternTest141", DetectFastPatternTest141);
    UtRegisterTest("DetectFastPatternTest142", DetectFastPatternTest142);
    UtRegisterTest("DetectFastPatternTest143", DetectFastPatternTest143);
    UtRegisterTest("DetectFastPatternTest144", DetectFastPatternTest144);
    UtRegisterTest("DetectFastPatternTest145", DetectFastPatternTest145);
    UtRegisterTest("DetectFastPatternTest146", DetectFastPatternTest146);
    UtRegisterTest("DetectFastPatternTest147", DetectFastPatternTest147);
    UtRegisterTest("DetectFastPatternTest148", DetectFastPatternTest148);
    UtRegisterTest("DetectFastPatternTest149", DetectFastPatternTest149);
    UtRegisterTest("DetectFastPatternTest150", DetectFastPatternTest150);
    UtRegisterTest("DetectFastPatternTest151", DetectFastPatternTest151);
    UtRegisterTest("DetectFastPatternTest152", DetectFastPatternTest152);
    UtRegisterTest("DetectFastPatternTest153", DetectFastPatternTest153);
    UtRegisterTest("DetectFastPatternTest154", DetectFastPatternTest154);
    UtRegisterTest("DetectFastPatternTest155", DetectFastPatternTest155);
    UtRegisterTest("DetectFastPatternTest156", DetectFastPatternTest156);
    UtRegisterTest("DetectFastPatternTest157", DetectFastPatternTest157);
    UtRegisterTest("DetectFastPatternTest158", DetectFastPatternTest158);
    UtRegisterTest("DetectFastPatternTest159", DetectFastPatternTest159);
    UtRegisterTest("DetectFastPatternTest160", DetectFastPatternTest160);
    UtRegisterTest("DetectFastPatternTest161", DetectFastPatternTest161);
    UtRegisterTest("DetectFastPatternTest162", DetectFastPatternTest162);
    UtRegisterTest("DetectFastPatternTest163", DetectFastPatternTest163);
    UtRegisterTest("DetectFastPatternTest164", DetectFastPatternTest164);
    UtRegisterTest("DetectFastPatternTest165", DetectFastPatternTest165);
    UtRegisterTest("DetectFastPatternTest166", DetectFastPatternTest166);
    UtRegisterTest("DetectFastPatternTest167", DetectFastPatternTest167);
    UtRegisterTest("DetectFastPatternTest168", DetectFastPatternTest168);
    UtRegisterTest("DetectFastPatternTest169", DetectFastPatternTest169);
    UtRegisterTest("DetectFastPatternTest170", DetectFastPatternTest170);
    UtRegisterTest("DetectFastPatternTest171", DetectFastPatternTest171);
    UtRegisterTest("DetectFastPatternTest172", DetectFastPatternTest172);
    UtRegisterTest("DetectFastPatternTest173", DetectFastPatternTest173);
    UtRegisterTest("DetectFastPatternTest174", DetectFastPatternTest174);
    /* http_client_body fast_pattern tests ^ */
    /*          content fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest175", DetectFastPatternTest175);
    UtRegisterTest("DetectFastPatternTest176", DetectFastPatternTest176);
    UtRegisterTest("DetectFastPatternTest177", DetectFastPatternTest177);
    UtRegisterTest("DetectFastPatternTest178", DetectFastPatternTest178);
    /*     content fast_pattern tests ^ */
    /* http_header fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest179", DetectFastPatternTest179);
    UtRegisterTest("DetectFastPatternTest180", DetectFastPatternTest180);
    UtRegisterTest("DetectFastPatternTest181", DetectFastPatternTest181);
    UtRegisterTest("DetectFastPatternTest182", DetectFastPatternTest182);
    UtRegisterTest("DetectFastPatternTest183", DetectFastPatternTest183);
    UtRegisterTest("DetectFastPatternTest184", DetectFastPatternTest184);
    UtRegisterTest("DetectFastPatternTest185", DetectFastPatternTest185);
    UtRegisterTest("DetectFastPatternTest186", DetectFastPatternTest186);
    UtRegisterTest("DetectFastPatternTest187", DetectFastPatternTest187);
    UtRegisterTest("DetectFastPatternTest188", DetectFastPatternTest188);
    UtRegisterTest("DetectFastPatternTest189", DetectFastPatternTest189);
    UtRegisterTest("DetectFastPatternTest190", DetectFastPatternTest190);
    UtRegisterTest("DetectFastPatternTest191", DetectFastPatternTest191);
    UtRegisterTest("DetectFastPatternTest192", DetectFastPatternTest192);
    UtRegisterTest("DetectFastPatternTest193", DetectFastPatternTest193);
    UtRegisterTest("DetectFastPatternTest194", DetectFastPatternTest194);
    UtRegisterTest("DetectFastPatternTest195", DetectFastPatternTest195);
    UtRegisterTest("DetectFastPatternTest196", DetectFastPatternTest196);
    UtRegisterTest("DetectFastPatternTest197", DetectFastPatternTest197);
    UtRegisterTest("DetectFastPatternTest198", DetectFastPatternTest198);
    UtRegisterTest("DetectFastPatternTest199", DetectFastPatternTest199);
    UtRegisterTest("DetectFastPatternTest200", DetectFastPatternTest200);
    UtRegisterTest("DetectFastPatternTest201", DetectFastPatternTest201);
    UtRegisterTest("DetectFastPatternTest202", DetectFastPatternTest202);
    UtRegisterTest("DetectFastPatternTest203", DetectFastPatternTest203);
    UtRegisterTest("DetectFastPatternTest204", DetectFastPatternTest204);
    UtRegisterTest("DetectFastPatternTest205", DetectFastPatternTest205);
    UtRegisterTest("DetectFastPatternTest206", DetectFastPatternTest206);
    UtRegisterTest("DetectFastPatternTest207", DetectFastPatternTest207);
    UtRegisterTest("DetectFastPatternTest208", DetectFastPatternTest208);
    UtRegisterTest("DetectFastPatternTest209", DetectFastPatternTest209);
    UtRegisterTest("DetectFastPatternTest210", DetectFastPatternTest210);
    UtRegisterTest("DetectFastPatternTest211", DetectFastPatternTest211);
    UtRegisterTest("DetectFastPatternTest212", DetectFastPatternTest212);
    UtRegisterTest("DetectFastPatternTest213", DetectFastPatternTest213);
    UtRegisterTest("DetectFastPatternTest214", DetectFastPatternTest214);
    UtRegisterTest("DetectFastPatternTest215", DetectFastPatternTest215);
    UtRegisterTest("DetectFastPatternTest216", DetectFastPatternTest216);
    UtRegisterTest("DetectFastPatternTest217", DetectFastPatternTest217);
    UtRegisterTest("DetectFastPatternTest218", DetectFastPatternTest218);
    UtRegisterTest("DetectFastPatternTest219", DetectFastPatternTest219);
    /*     http_header fast_pattern tests ^ */
    /* http_raw_header fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest220", DetectFastPatternTest220);
    UtRegisterTest("DetectFastPatternTest221", DetectFastPatternTest221);
    UtRegisterTest("DetectFastPatternTest222", DetectFastPatternTest222);
    UtRegisterTest("DetectFastPatternTest223", DetectFastPatternTest223);
    UtRegisterTest("DetectFastPatternTest224", DetectFastPatternTest224);
    UtRegisterTest("DetectFastPatternTest225", DetectFastPatternTest225);
    UtRegisterTest("DetectFastPatternTest226", DetectFastPatternTest226);
    UtRegisterTest("DetectFastPatternTest227", DetectFastPatternTest227);
    UtRegisterTest("DetectFastPatternTest228", DetectFastPatternTest228);
    UtRegisterTest("DetectFastPatternTest229", DetectFastPatternTest229);
    UtRegisterTest("DetectFastPatternTest230", DetectFastPatternTest230);
    UtRegisterTest("DetectFastPatternTest231", DetectFastPatternTest231);
    UtRegisterTest("DetectFastPatternTest232", DetectFastPatternTest232);
    UtRegisterTest("DetectFastPatternTest233", DetectFastPatternTest233);
    UtRegisterTest("DetectFastPatternTest234", DetectFastPatternTest234);
    UtRegisterTest("DetectFastPatternTest235", DetectFastPatternTest235);
    UtRegisterTest("DetectFastPatternTest236", DetectFastPatternTest236);
    UtRegisterTest("DetectFastPatternTest237", DetectFastPatternTest237);
    UtRegisterTest("DetectFastPatternTest238", DetectFastPatternTest238);
    UtRegisterTest("DetectFastPatternTest239", DetectFastPatternTest239);
    UtRegisterTest("DetectFastPatternTest240", DetectFastPatternTest240);
    UtRegisterTest("DetectFastPatternTest241", DetectFastPatternTest241);
    UtRegisterTest("DetectFastPatternTest242", DetectFastPatternTest242);
    UtRegisterTest("DetectFastPatternTest243", DetectFastPatternTest243);
    UtRegisterTest("DetectFastPatternTest244", DetectFastPatternTest244);
    UtRegisterTest("DetectFastPatternTest245", DetectFastPatternTest245);
    UtRegisterTest("DetectFastPatternTest246", DetectFastPatternTest246);
    UtRegisterTest("DetectFastPatternTest247", DetectFastPatternTest247);
    UtRegisterTest("DetectFastPatternTest248", DetectFastPatternTest248);
    UtRegisterTest("DetectFastPatternTest249", DetectFastPatternTest249);
    UtRegisterTest("DetectFastPatternTest250", DetectFastPatternTest250);
    UtRegisterTest("DetectFastPatternTest251", DetectFastPatternTest251);
    UtRegisterTest("DetectFastPatternTest252", DetectFastPatternTest252);
    UtRegisterTest("DetectFastPatternTest253", DetectFastPatternTest253);
    UtRegisterTest("DetectFastPatternTest254", DetectFastPatternTest254);
    UtRegisterTest("DetectFastPatternTest255", DetectFastPatternTest255);
    UtRegisterTest("DetectFastPatternTest256", DetectFastPatternTest256);
    UtRegisterTest("DetectFastPatternTest257", DetectFastPatternTest257);
    UtRegisterTest("DetectFastPatternTest258", DetectFastPatternTest258);
    UtRegisterTest("DetectFastPatternTest259", DetectFastPatternTest259);
    UtRegisterTest("DetectFastPatternTest260", DetectFastPatternTest260);
    /* http_raw_header fast_pattern tests ^ */
    /*     http_method fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest261", DetectFastPatternTest261);
    UtRegisterTest("DetectFastPatternTest262", DetectFastPatternTest262);
    UtRegisterTest("DetectFastPatternTest263", DetectFastPatternTest263);
    UtRegisterTest("DetectFastPatternTest264", DetectFastPatternTest264);
    UtRegisterTest("DetectFastPatternTest265", DetectFastPatternTest265);
    UtRegisterTest("DetectFastPatternTest266", DetectFastPatternTest266);
    UtRegisterTest("DetectFastPatternTest267", DetectFastPatternTest267);
    UtRegisterTest("DetectFastPatternTest268", DetectFastPatternTest268);
    UtRegisterTest("DetectFastPatternTest269", DetectFastPatternTest269);
    UtRegisterTest("DetectFastPatternTest270", DetectFastPatternTest270);
    UtRegisterTest("DetectFastPatternTest271", DetectFastPatternTest271);
    UtRegisterTest("DetectFastPatternTest272", DetectFastPatternTest272);
    UtRegisterTest("DetectFastPatternTest273", DetectFastPatternTest273);
    UtRegisterTest("DetectFastPatternTest274", DetectFastPatternTest274);
    UtRegisterTest("DetectFastPatternTest275", DetectFastPatternTest275);
    UtRegisterTest("DetectFastPatternTest276", DetectFastPatternTest276);
    UtRegisterTest("DetectFastPatternTest277", DetectFastPatternTest277);
    UtRegisterTest("DetectFastPatternTest278", DetectFastPatternTest278);
    UtRegisterTest("DetectFastPatternTest279", DetectFastPatternTest279);
    UtRegisterTest("DetectFastPatternTest280", DetectFastPatternTest280);
    UtRegisterTest("DetectFastPatternTest281", DetectFastPatternTest281);
    UtRegisterTest("DetectFastPatternTest282", DetectFastPatternTest282);
    UtRegisterTest("DetectFastPatternTest283", DetectFastPatternTest283);
    UtRegisterTest("DetectFastPatternTest284", DetectFastPatternTest284);
    UtRegisterTest("DetectFastPatternTest285", DetectFastPatternTest285);
    UtRegisterTest("DetectFastPatternTest286", DetectFastPatternTest286);
    UtRegisterTest("DetectFastPatternTest287", DetectFastPatternTest287);
    UtRegisterTest("DetectFastPatternTest288", DetectFastPatternTest288);
    UtRegisterTest("DetectFastPatternTest289", DetectFastPatternTest289);
    UtRegisterTest("DetectFastPatternTest290", DetectFastPatternTest290);
    UtRegisterTest("DetectFastPatternTest291", DetectFastPatternTest291);
    UtRegisterTest("DetectFastPatternTest292", DetectFastPatternTest292);
    UtRegisterTest("DetectFastPatternTest293", DetectFastPatternTest293);
    UtRegisterTest("DetectFastPatternTest294", DetectFastPatternTest294);
    UtRegisterTest("DetectFastPatternTest295", DetectFastPatternTest295);
    UtRegisterTest("DetectFastPatternTest296", DetectFastPatternTest296);
    UtRegisterTest("DetectFastPatternTest297", DetectFastPatternTest297);
    UtRegisterTest("DetectFastPatternTest298", DetectFastPatternTest298);
    UtRegisterTest("DetectFastPatternTest299", DetectFastPatternTest299);
    UtRegisterTest("DetectFastPatternTest300", DetectFastPatternTest300);
    UtRegisterTest("DetectFastPatternTest301", DetectFastPatternTest301);
    /* http_method fast_pattern tests ^ */
    /* http_cookie fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest302", DetectFastPatternTest302);
    UtRegisterTest("DetectFastPatternTest303", DetectFastPatternTest303);
    UtRegisterTest("DetectFastPatternTest304", DetectFastPatternTest304);
    UtRegisterTest("DetectFastPatternTest305", DetectFastPatternTest305);
    UtRegisterTest("DetectFastPatternTest306", DetectFastPatternTest306);
    UtRegisterTest("DetectFastPatternTest307", DetectFastPatternTest307);
    UtRegisterTest("DetectFastPatternTest308", DetectFastPatternTest308);
    UtRegisterTest("DetectFastPatternTest309", DetectFastPatternTest309);
    UtRegisterTest("DetectFastPatternTest310", DetectFastPatternTest310);
    UtRegisterTest("DetectFastPatternTest311", DetectFastPatternTest311);
    UtRegisterTest("DetectFastPatternTest312", DetectFastPatternTest312);
    UtRegisterTest("DetectFastPatternTest313", DetectFastPatternTest313);
    UtRegisterTest("DetectFastPatternTest314", DetectFastPatternTest314);
    UtRegisterTest("DetectFastPatternTest315", DetectFastPatternTest315);
    UtRegisterTest("DetectFastPatternTest316", DetectFastPatternTest316);
    UtRegisterTest("DetectFastPatternTest317", DetectFastPatternTest317);
    UtRegisterTest("DetectFastPatternTest318", DetectFastPatternTest318);
    UtRegisterTest("DetectFastPatternTest319", DetectFastPatternTest319);
    UtRegisterTest("DetectFastPatternTest320", DetectFastPatternTest320);
    UtRegisterTest("DetectFastPatternTest321", DetectFastPatternTest321);
    UtRegisterTest("DetectFastPatternTest322", DetectFastPatternTest322);
    UtRegisterTest("DetectFastPatternTest323", DetectFastPatternTest323);
    UtRegisterTest("DetectFastPatternTest324", DetectFastPatternTest324);
    UtRegisterTest("DetectFastPatternTest325", DetectFastPatternTest325);
    UtRegisterTest("DetectFastPatternTest326", DetectFastPatternTest326);
    UtRegisterTest("DetectFastPatternTest327", DetectFastPatternTest327);
    UtRegisterTest("DetectFastPatternTest328", DetectFastPatternTest328);
    UtRegisterTest("DetectFastPatternTest329", DetectFastPatternTest329);
    UtRegisterTest("DetectFastPatternTest330", DetectFastPatternTest330);
    UtRegisterTest("DetectFastPatternTest331", DetectFastPatternTest331);
    UtRegisterTest("DetectFastPatternTest332", DetectFastPatternTest332);
    UtRegisterTest("DetectFastPatternTest333", DetectFastPatternTest333);
    UtRegisterTest("DetectFastPatternTest334", DetectFastPatternTest334);
    UtRegisterTest("DetectFastPatternTest335", DetectFastPatternTest335);
    UtRegisterTest("DetectFastPatternTest336", DetectFastPatternTest336);
    UtRegisterTest("DetectFastPatternTest337", DetectFastPatternTest337);
    UtRegisterTest("DetectFastPatternTest338", DetectFastPatternTest338);
    UtRegisterTest("DetectFastPatternTest339", DetectFastPatternTest339);
    UtRegisterTest("DetectFastPatternTest340", DetectFastPatternTest340);
    UtRegisterTest("DetectFastPatternTest341", DetectFastPatternTest341);
    UtRegisterTest("DetectFastPatternTest342", DetectFastPatternTest342);
    /* http_cookie fast_pattern tests ^ */
    /* http_raw_uri fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest343", DetectFastPatternTest343);
    UtRegisterTest("DetectFastPatternTest344", DetectFastPatternTest344);
    UtRegisterTest("DetectFastPatternTest345", DetectFastPatternTest345);
    UtRegisterTest("DetectFastPatternTest346", DetectFastPatternTest346);
    UtRegisterTest("DetectFastPatternTest347", DetectFastPatternTest347);
    UtRegisterTest("DetectFastPatternTest348", DetectFastPatternTest348);
    UtRegisterTest("DetectFastPatternTest349", DetectFastPatternTest349);
    UtRegisterTest("DetectFastPatternTest350", DetectFastPatternTest350);
    UtRegisterTest("DetectFastPatternTest351", DetectFastPatternTest351);
    UtRegisterTest("DetectFastPatternTest352", DetectFastPatternTest352);
    UtRegisterTest("DetectFastPatternTest353", DetectFastPatternTest353);
    UtRegisterTest("DetectFastPatternTest354", DetectFastPatternTest354);
    UtRegisterTest("DetectFastPatternTest355", DetectFastPatternTest355);
    UtRegisterTest("DetectFastPatternTest356", DetectFastPatternTest356);
    UtRegisterTest("DetectFastPatternTest357", DetectFastPatternTest357);
    UtRegisterTest("DetectFastPatternTest358", DetectFastPatternTest358);
    UtRegisterTest("DetectFastPatternTest359", DetectFastPatternTest359);
    UtRegisterTest("DetectFastPatternTest360", DetectFastPatternTest360);
    UtRegisterTest("DetectFastPatternTest361", DetectFastPatternTest361);
    UtRegisterTest("DetectFastPatternTest362", DetectFastPatternTest362);
    UtRegisterTest("DetectFastPatternTest363", DetectFastPatternTest363);
    UtRegisterTest("DetectFastPatternTest364", DetectFastPatternTest364);
    UtRegisterTest("DetectFastPatternTest365", DetectFastPatternTest365);
    UtRegisterTest("DetectFastPatternTest366", DetectFastPatternTest366);
    UtRegisterTest("DetectFastPatternTest367", DetectFastPatternTest367);
    UtRegisterTest("DetectFastPatternTest368", DetectFastPatternTest368);
    UtRegisterTest("DetectFastPatternTest369", DetectFastPatternTest369);
    UtRegisterTest("DetectFastPatternTest370", DetectFastPatternTest370);
    UtRegisterTest("DetectFastPatternTest371", DetectFastPatternTest371);
    UtRegisterTest("DetectFastPatternTest372", DetectFastPatternTest372);
    UtRegisterTest("DetectFastPatternTest373", DetectFastPatternTest373);
    UtRegisterTest("DetectFastPatternTest374", DetectFastPatternTest374);
    UtRegisterTest("DetectFastPatternTest375", DetectFastPatternTest375);
    UtRegisterTest("DetectFastPatternTest376", DetectFastPatternTest376);
    UtRegisterTest("DetectFastPatternTest377", DetectFastPatternTest377);
    UtRegisterTest("DetectFastPatternTest378", DetectFastPatternTest378);
    UtRegisterTest("DetectFastPatternTest379", DetectFastPatternTest379);
    UtRegisterTest("DetectFastPatternTest380", DetectFastPatternTest380);
    UtRegisterTest("DetectFastPatternTest381", DetectFastPatternTest381);
    UtRegisterTest("DetectFastPatternTest382", DetectFastPatternTest382);
    UtRegisterTest("DetectFastPatternTest383", DetectFastPatternTest383);
    /* http_raw_uri fast_pattern tests ^ */
    /* http_stat_msg fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest384", DetectFastPatternTest384);
    UtRegisterTest("DetectFastPatternTest385", DetectFastPatternTest385);
    UtRegisterTest("DetectFastPatternTest386", DetectFastPatternTest386);
    UtRegisterTest("DetectFastPatternTest387", DetectFastPatternTest387);
    UtRegisterTest("DetectFastPatternTest388", DetectFastPatternTest388);
    UtRegisterTest("DetectFastPatternTest389", DetectFastPatternTest389);
    UtRegisterTest("DetectFastPatternTest390", DetectFastPatternTest390);
    UtRegisterTest("DetectFastPatternTest391", DetectFastPatternTest391);
    UtRegisterTest("DetectFastPatternTest392", DetectFastPatternTest392);
    UtRegisterTest("DetectFastPatternTest393", DetectFastPatternTest393);
    UtRegisterTest("DetectFastPatternTest394", DetectFastPatternTest394);
    UtRegisterTest("DetectFastPatternTest395", DetectFastPatternTest395);
    UtRegisterTest("DetectFastPatternTest396", DetectFastPatternTest396);
    UtRegisterTest("DetectFastPatternTest397", DetectFastPatternTest397);
    UtRegisterTest("DetectFastPatternTest398", DetectFastPatternTest398);
    UtRegisterTest("DetectFastPatternTest399", DetectFastPatternTest399);
    UtRegisterTest("DetectFastPatternTest400", DetectFastPatternTest400);
    UtRegisterTest("DetectFastPatternTest401", DetectFastPatternTest401);
    UtRegisterTest("DetectFastPatternTest402", DetectFastPatternTest402);
    UtRegisterTest("DetectFastPatternTest403", DetectFastPatternTest403);
    UtRegisterTest("DetectFastPatternTest404", DetectFastPatternTest404);
    UtRegisterTest("DetectFastPatternTest405", DetectFastPatternTest405);
    UtRegisterTest("DetectFastPatternTest406", DetectFastPatternTest406);
    UtRegisterTest("DetectFastPatternTest407", DetectFastPatternTest407);
    UtRegisterTest("DetectFastPatternTest408", DetectFastPatternTest408);
    UtRegisterTest("DetectFastPatternTest409", DetectFastPatternTest409);
    UtRegisterTest("DetectFastPatternTest410", DetectFastPatternTest410);
    UtRegisterTest("DetectFastPatternTest411", DetectFastPatternTest411);
    UtRegisterTest("DetectFastPatternTest412", DetectFastPatternTest412);
    UtRegisterTest("DetectFastPatternTest413", DetectFastPatternTest413);
    UtRegisterTest("DetectFastPatternTest414", DetectFastPatternTest414);
    UtRegisterTest("DetectFastPatternTest415", DetectFastPatternTest415);
    UtRegisterTest("DetectFastPatternTest416", DetectFastPatternTest416);
    UtRegisterTest("DetectFastPatternTest417", DetectFastPatternTest417);
    UtRegisterTest("DetectFastPatternTest418", DetectFastPatternTest418);
    UtRegisterTest("DetectFastPatternTest419", DetectFastPatternTest419);
    UtRegisterTest("DetectFastPatternTest420", DetectFastPatternTest420);
    UtRegisterTest("DetectFastPatternTest421", DetectFastPatternTest421);
    UtRegisterTest("DetectFastPatternTest422", DetectFastPatternTest422);
    UtRegisterTest("DetectFastPatternTest423", DetectFastPatternTest423);
    UtRegisterTest("DetectFastPatternTest424", DetectFastPatternTest424);
    /* http_stat_msg fast_pattern tests ^ */
    /* http_stat_code fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest425", DetectFastPatternTest425);
    UtRegisterTest("DetectFastPatternTest426", DetectFastPatternTest426);
    UtRegisterTest("DetectFastPatternTest427", DetectFastPatternTest427);
    UtRegisterTest("DetectFastPatternTest428", DetectFastPatternTest428);
    UtRegisterTest("DetectFastPatternTest429", DetectFastPatternTest429);
    UtRegisterTest("DetectFastPatternTest430", DetectFastPatternTest430);
    UtRegisterTest("DetectFastPatternTest431", DetectFastPatternTest431);
    UtRegisterTest("DetectFastPatternTest432", DetectFastPatternTest432);
    UtRegisterTest("DetectFastPatternTest433", DetectFastPatternTest433);
    UtRegisterTest("DetectFastPatternTest434", DetectFastPatternTest434);
    UtRegisterTest("DetectFastPatternTest435", DetectFastPatternTest435);
    UtRegisterTest("DetectFastPatternTest436", DetectFastPatternTest436);
    UtRegisterTest("DetectFastPatternTest437", DetectFastPatternTest437);
    UtRegisterTest("DetectFastPatternTest438", DetectFastPatternTest438);
    UtRegisterTest("DetectFastPatternTest439", DetectFastPatternTest439);
    UtRegisterTest("DetectFastPatternTest440", DetectFastPatternTest440);
    UtRegisterTest("DetectFastPatternTest441", DetectFastPatternTest441);
    UtRegisterTest("DetectFastPatternTest442", DetectFastPatternTest442);
    UtRegisterTest("DetectFastPatternTest443", DetectFastPatternTest443);
    UtRegisterTest("DetectFastPatternTest444", DetectFastPatternTest444);
    UtRegisterTest("DetectFastPatternTest445", DetectFastPatternTest445);
    UtRegisterTest("DetectFastPatternTest446", DetectFastPatternTest446);
    UtRegisterTest("DetectFastPatternTest447", DetectFastPatternTest447);
    UtRegisterTest("DetectFastPatternTest448", DetectFastPatternTest448);
    UtRegisterTest("DetectFastPatternTest449", DetectFastPatternTest449);
    UtRegisterTest("DetectFastPatternTest450", DetectFastPatternTest450);
    UtRegisterTest("DetectFastPatternTest451", DetectFastPatternTest451);
    UtRegisterTest("DetectFastPatternTest452", DetectFastPatternTest452);
    UtRegisterTest("DetectFastPatternTest453", DetectFastPatternTest453);
    UtRegisterTest("DetectFastPatternTest454", DetectFastPatternTest454);
    UtRegisterTest("DetectFastPatternTest455", DetectFastPatternTest455);
    UtRegisterTest("DetectFastPatternTest456", DetectFastPatternTest456);
    UtRegisterTest("DetectFastPatternTest457", DetectFastPatternTest457);
    UtRegisterTest("DetectFastPatternTest458", DetectFastPatternTest458);
    UtRegisterTest("DetectFastPatternTest459", DetectFastPatternTest459);
    UtRegisterTest("DetectFastPatternTest460", DetectFastPatternTest460);
    UtRegisterTest("DetectFastPatternTest461", DetectFastPatternTest461);
    UtRegisterTest("DetectFastPatternTest462", DetectFastPatternTest462);
    UtRegisterTest("DetectFastPatternTest463", DetectFastPatternTest463);
    UtRegisterTest("DetectFastPatternTest464", DetectFastPatternTest464);
    UtRegisterTest("DetectFastPatternTest465", DetectFastPatternTest465);
    /* http_stat_code fast_pattern tests ^ */
    /* http_server_body fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest466", DetectFastPatternTest466);
    UtRegisterTest("DetectFastPatternTest467", DetectFastPatternTest467);
    UtRegisterTest("DetectFastPatternTest468", DetectFastPatternTest468);
    UtRegisterTest("DetectFastPatternTest469", DetectFastPatternTest469);
    UtRegisterTest("DetectFastPatternTest470", DetectFastPatternTest470);
    UtRegisterTest("DetectFastPatternTest471", DetectFastPatternTest471);
    UtRegisterTest("DetectFastPatternTest472", DetectFastPatternTest472);
    UtRegisterTest("DetectFastPatternTest473", DetectFastPatternTest473);
    UtRegisterTest("DetectFastPatternTest474", DetectFastPatternTest474);
    UtRegisterTest("DetectFastPatternTest475", DetectFastPatternTest475);
    UtRegisterTest("DetectFastPatternTest476", DetectFastPatternTest476);
    UtRegisterTest("DetectFastPatternTest477", DetectFastPatternTest477);
    UtRegisterTest("DetectFastPatternTest478", DetectFastPatternTest478);
    UtRegisterTest("DetectFastPatternTest479", DetectFastPatternTest479);
    UtRegisterTest("DetectFastPatternTest480", DetectFastPatternTest480);
    UtRegisterTest("DetectFastPatternTest481", DetectFastPatternTest481);
    UtRegisterTest("DetectFastPatternTest482", DetectFastPatternTest482);
    UtRegisterTest("DetectFastPatternTest483", DetectFastPatternTest483);
    UtRegisterTest("DetectFastPatternTest484", DetectFastPatternTest484);
    UtRegisterTest("DetectFastPatternTest485", DetectFastPatternTest485);
    UtRegisterTest("DetectFastPatternTest486", DetectFastPatternTest486);
    UtRegisterTest("DetectFastPatternTest487", DetectFastPatternTest487);
    UtRegisterTest("DetectFastPatternTest488", DetectFastPatternTest488);
    UtRegisterTest("DetectFastPatternTest489", DetectFastPatternTest489);
    UtRegisterTest("DetectFastPatternTest490", DetectFastPatternTest490);
    UtRegisterTest("DetectFastPatternTest491", DetectFastPatternTest491);
    UtRegisterTest("DetectFastPatternTest492", DetectFastPatternTest492);
    UtRegisterTest("DetectFastPatternTest493", DetectFastPatternTest493);
    UtRegisterTest("DetectFastPatternTest494", DetectFastPatternTest494);
    UtRegisterTest("DetectFastPatternTest495", DetectFastPatternTest495);
    UtRegisterTest("DetectFastPatternTest496", DetectFastPatternTest496);
    UtRegisterTest("DetectFastPatternTest497", DetectFastPatternTest497);
    UtRegisterTest("DetectFastPatternTest498", DetectFastPatternTest498);
    UtRegisterTest("DetectFastPatternTest499", DetectFastPatternTest499);
    UtRegisterTest("DetectFastPatternTest500", DetectFastPatternTest500);
    UtRegisterTest("DetectFastPatternTest501", DetectFastPatternTest501);
    UtRegisterTest("DetectFastPatternTest502", DetectFastPatternTest502);
    UtRegisterTest("DetectFastPatternTest503", DetectFastPatternTest503);
    UtRegisterTest("DetectFastPatternTest504", DetectFastPatternTest504);
    UtRegisterTest("DetectFastPatternTest505", DetectFastPatternTest505);
    UtRegisterTest("DetectFastPatternTest506", DetectFastPatternTest506);
    /* http_server_body fast_pattern tests ^ */
    /* file_data fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest507", DetectFastPatternTest507);
    UtRegisterTest("DetectFastPatternTest508", DetectFastPatternTest508);
    UtRegisterTest("DetectFastPatternTest509", DetectFastPatternTest509);
    UtRegisterTest("DetectFastPatternTest510", DetectFastPatternTest510);
    UtRegisterTest("DetectFastPatternTest511", DetectFastPatternTest511);
    UtRegisterTest("DetectFastPatternTest512", DetectFastPatternTest512);
    UtRegisterTest("DetectFastPatternTest513", DetectFastPatternTest513);
    UtRegisterTest("DetectFastPatternTest514", DetectFastPatternTest514);
    UtRegisterTest("DetectFastPatternTest515", DetectFastPatternTest515);
    UtRegisterTest("DetectFastPatternTest516", DetectFastPatternTest516);
    UtRegisterTest("DetectFastPatternTest517", DetectFastPatternTest517);
    UtRegisterTest("DetectFastPatternTest518", DetectFastPatternTest518);
    UtRegisterTest("DetectFastPatternTest519", DetectFastPatternTest519);
    UtRegisterTest("DetectFastPatternTest520", DetectFastPatternTest520);
    UtRegisterTest("DetectFastPatternTest521", DetectFastPatternTest521);
    UtRegisterTest("DetectFastPatternTest522", DetectFastPatternTest522);
    UtRegisterTest("DetectFastPatternTest523", DetectFastPatternTest523);
    UtRegisterTest("DetectFastPatternTest524", DetectFastPatternTest524);
    UtRegisterTest("DetectFastPatternTest525", DetectFastPatternTest525);
    UtRegisterTest("DetectFastPatternTest526", DetectFastPatternTest526);
    UtRegisterTest("DetectFastPatternTest527", DetectFastPatternTest527);
    UtRegisterTest("DetectFastPatternTest528", DetectFastPatternTest528);
    UtRegisterTest("DetectFastPatternTest529", DetectFastPatternTest529);
    UtRegisterTest("DetectFastPatternTest530", DetectFastPatternTest530);
    UtRegisterTest("DetectFastPatternTest531", DetectFastPatternTest531);
    UtRegisterTest("DetectFastPatternTest532", DetectFastPatternTest532);
    UtRegisterTest("DetectFastPatternTest533", DetectFastPatternTest533);
    UtRegisterTest("DetectFastPatternTest534", DetectFastPatternTest534);
    UtRegisterTest("DetectFastPatternTest535", DetectFastPatternTest535);
    UtRegisterTest("DetectFastPatternTest536", DetectFastPatternTest536);
    UtRegisterTest("DetectFastPatternTest537", DetectFastPatternTest537);
    UtRegisterTest("DetectFastPatternTest538", DetectFastPatternTest538);
    UtRegisterTest("DetectFastPatternTest539", DetectFastPatternTest539);
    UtRegisterTest("DetectFastPatternTest540", DetectFastPatternTest540);
    UtRegisterTest("DetectFastPatternTest541", DetectFastPatternTest541);
    UtRegisterTest("DetectFastPatternTest542", DetectFastPatternTest542);
    UtRegisterTest("DetectFastPatternTest543", DetectFastPatternTest543);
    UtRegisterTest("DetectFastPatternTest544", DetectFastPatternTest544);
    UtRegisterTest("DetectFastPatternTest545", DetectFastPatternTest545);
    UtRegisterTest("DetectFastPatternTest546", DetectFastPatternTest546);
    UtRegisterTest("DetectFastPatternTest547", DetectFastPatternTest547);
    /* file_data fast_pattern tests ^ */
    /* http_user_agent fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest548", DetectFastPatternTest548);
    UtRegisterTest("DetectFastPatternTest549", DetectFastPatternTest549);
    UtRegisterTest("DetectFastPatternTest550", DetectFastPatternTest550);
    UtRegisterTest("DetectFastPatternTest551", DetectFastPatternTest551);
    UtRegisterTest("DetectFastPatternTest552", DetectFastPatternTest552);
    UtRegisterTest("DetectFastPatternTest553", DetectFastPatternTest553);
    UtRegisterTest("DetectFastPatternTest554", DetectFastPatternTest554);
    UtRegisterTest("DetectFastPatternTest555", DetectFastPatternTest555);
    UtRegisterTest("DetectFastPatternTest556", DetectFastPatternTest556);
    UtRegisterTest("DetectFastPatternTest557", DetectFastPatternTest557);
    UtRegisterTest("DetectFastPatternTest558", DetectFastPatternTest558);
    UtRegisterTest("DetectFastPatternTest559", DetectFastPatternTest559);
    UtRegisterTest("DetectFastPatternTest560", DetectFastPatternTest560);
    UtRegisterTest("DetectFastPatternTest561", DetectFastPatternTest561);
    UtRegisterTest("DetectFastPatternTest562", DetectFastPatternTest562);
    UtRegisterTest("DetectFastPatternTest563", DetectFastPatternTest563);
    UtRegisterTest("DetectFastPatternTest564", DetectFastPatternTest564);
    UtRegisterTest("DetectFastPatternTest565", DetectFastPatternTest565);
    UtRegisterTest("DetectFastPatternTest566", DetectFastPatternTest566);
    UtRegisterTest("DetectFastPatternTest567", DetectFastPatternTest567);
    UtRegisterTest("DetectFastPatternTest568", DetectFastPatternTest568);
    UtRegisterTest("DetectFastPatternTest569", DetectFastPatternTest569);
    UtRegisterTest("DetectFastPatternTest570", DetectFastPatternTest570);
    UtRegisterTest("DetectFastPatternTest571", DetectFastPatternTest571);
    UtRegisterTest("DetectFastPatternTest572", DetectFastPatternTest572);
    UtRegisterTest("DetectFastPatternTest573", DetectFastPatternTest573);
    UtRegisterTest("DetectFastPatternTest574", DetectFastPatternTest574);
    UtRegisterTest("DetectFastPatternTest575", DetectFastPatternTest575);
    UtRegisterTest("DetectFastPatternTest576", DetectFastPatternTest576);
    UtRegisterTest("DetectFastPatternTest577", DetectFastPatternTest577);
    UtRegisterTest("DetectFastPatternTest578", DetectFastPatternTest578);
    UtRegisterTest("DetectFastPatternTest579", DetectFastPatternTest579);
    UtRegisterTest("DetectFastPatternTest580", DetectFastPatternTest580);
    UtRegisterTest("DetectFastPatternTest581", DetectFastPatternTest581);
    UtRegisterTest("DetectFastPatternTest582", DetectFastPatternTest582);
    UtRegisterTest("DetectFastPatternTest583", DetectFastPatternTest583);
    UtRegisterTest("DetectFastPatternTest584", DetectFastPatternTest584);
    UtRegisterTest("DetectFastPatternTest585", DetectFastPatternTest585);
    UtRegisterTest("DetectFastPatternTest586", DetectFastPatternTest586);
    UtRegisterTest("DetectFastPatternTest587", DetectFastPatternTest587);
    UtRegisterTest("DetectFastPatternTest588", DetectFastPatternTest588);
    /* http_user_agent fast_pattern tests ^ */
    /* http_host fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest589", DetectFastPatternTest589);
    UtRegisterTest("DetectFastPatternTest590", DetectFastPatternTest590);
    UtRegisterTest("DetectFastPatternTest591", DetectFastPatternTest591);
    UtRegisterTest("DetectFastPatternTest592", DetectFastPatternTest592);
    UtRegisterTest("DetectFastPatternTest593", DetectFastPatternTest593);
    UtRegisterTest("DetectFastPatternTest594", DetectFastPatternTest594);
    UtRegisterTest("DetectFastPatternTest595", DetectFastPatternTest595);
    UtRegisterTest("DetectFastPatternTest596", DetectFastPatternTest596);
    UtRegisterTest("DetectFastPatternTest597", DetectFastPatternTest597);
    UtRegisterTest("DetectFastPatternTest598", DetectFastPatternTest598);
    UtRegisterTest("DetectFastPatternTest599", DetectFastPatternTest599);
    UtRegisterTest("DetectFastPatternTest600", DetectFastPatternTest600);
    UtRegisterTest("DetectFastPatternTest601", DetectFastPatternTest601);
    UtRegisterTest("DetectFastPatternTest602", DetectFastPatternTest602);
    UtRegisterTest("DetectFastPatternTest603", DetectFastPatternTest603);
    UtRegisterTest("DetectFastPatternTest604", DetectFastPatternTest604);
    UtRegisterTest("DetectFastPatternTest605", DetectFastPatternTest605);
    UtRegisterTest("DetectFastPatternTest606", DetectFastPatternTest606);
    UtRegisterTest("DetectFastPatternTest607", DetectFastPatternTest607);
    UtRegisterTest("DetectFastPatternTest608", DetectFastPatternTest608);
    UtRegisterTest("DetectFastPatternTest609", DetectFastPatternTest609);
    UtRegisterTest("DetectFastPatternTest610", DetectFastPatternTest610);
    UtRegisterTest("DetectFastPatternTest611", DetectFastPatternTest611);
    UtRegisterTest("DetectFastPatternTest612", DetectFastPatternTest612);
    UtRegisterTest("DetectFastPatternTest613", DetectFastPatternTest613);
    UtRegisterTest("DetectFastPatternTest614", DetectFastPatternTest614);
    UtRegisterTest("DetectFastPatternTest615", DetectFastPatternTest615);
    UtRegisterTest("DetectFastPatternTest616", DetectFastPatternTest616);
    UtRegisterTest("DetectFastPatternTest617", DetectFastPatternTest617);
    UtRegisterTest("DetectFastPatternTest618", DetectFastPatternTest618);
    UtRegisterTest("DetectFastPatternTest619", DetectFastPatternTest619);
    UtRegisterTest("DetectFastPatternTest620", DetectFastPatternTest620);
    UtRegisterTest("DetectFastPatternTest621", DetectFastPatternTest621);
    UtRegisterTest("DetectFastPatternTest622", DetectFastPatternTest622);
    UtRegisterTest("DetectFastPatternTest623", DetectFastPatternTest623);
    UtRegisterTest("DetectFastPatternTest624", DetectFastPatternTest624);
    UtRegisterTest("DetectFastPatternTest625", DetectFastPatternTest625);
    UtRegisterTest("DetectFastPatternTest626", DetectFastPatternTest626);
    UtRegisterTest("DetectFastPatternTest627", DetectFastPatternTest627);
    UtRegisterTest("DetectFastPatternTest628", DetectFastPatternTest628);
    UtRegisterTest("DetectFastPatternTest629", DetectFastPatternTest629);
    /* http_host fast_pattern tests ^ */
    /* http_rawhost fast_pattern tests v */
    UtRegisterTest("DetectFastPatternTest630", DetectFastPatternTest630);
    UtRegisterTest("DetectFastPatternTest631", DetectFastPatternTest631);
    UtRegisterTest("DetectFastPatternTest632", DetectFastPatternTest632);
    UtRegisterTest("DetectFastPatternTest633", DetectFastPatternTest633);
    UtRegisterTest("DetectFastPatternTest634", DetectFastPatternTest634);
    UtRegisterTest("DetectFastPatternTest635", DetectFastPatternTest635);
    UtRegisterTest("DetectFastPatternTest636", DetectFastPatternTest636);
    UtRegisterTest("DetectFastPatternTest637", DetectFastPatternTest637);
    UtRegisterTest("DetectFastPatternTest638", DetectFastPatternTest638);
    UtRegisterTest("DetectFastPatternTest639", DetectFastPatternTest639);
    UtRegisterTest("DetectFastPatternTest640", DetectFastPatternTest640);
    UtRegisterTest("DetectFastPatternTest641", DetectFastPatternTest641);
    UtRegisterTest("DetectFastPatternTest642", DetectFastPatternTest642);
    UtRegisterTest("DetectFastPatternTest643", DetectFastPatternTest643);
    UtRegisterTest("DetectFastPatternTest644", DetectFastPatternTest644);
    UtRegisterTest("DetectFastPatternTest645", DetectFastPatternTest645);
    UtRegisterTest("DetectFastPatternTest646", DetectFastPatternTest646);
    UtRegisterTest("DetectFastPatternTest647", DetectFastPatternTest647);
    UtRegisterTest("DetectFastPatternTest648", DetectFastPatternTest648);
    UtRegisterTest("DetectFastPatternTest649", DetectFastPatternTest649);
    UtRegisterTest("DetectFastPatternTest650", DetectFastPatternTest650);
    UtRegisterTest("DetectFastPatternTest651", DetectFastPatternTest651);
    UtRegisterTest("DetectFastPatternTest652", DetectFastPatternTest652);
    UtRegisterTest("DetectFastPatternTest653", DetectFastPatternTest653);
    UtRegisterTest("DetectFastPatternTest654", DetectFastPatternTest654);
    UtRegisterTest("DetectFastPatternTest655", DetectFastPatternTest655);
    UtRegisterTest("DetectFastPatternTest656", DetectFastPatternTest656);
    UtRegisterTest("DetectFastPatternTest657", DetectFastPatternTest657);
    UtRegisterTest("DetectFastPatternTest658", DetectFastPatternTest658);
    UtRegisterTest("DetectFastPatternTest659", DetectFastPatternTest659);
    UtRegisterTest("DetectFastPatternTest660", DetectFastPatternTest660);
    UtRegisterTest("DetectFastPatternTest661", DetectFastPatternTest661);
    UtRegisterTest("DetectFastPatternTest662", DetectFastPatternTest662);
    UtRegisterTest("DetectFastPatternTest663", DetectFastPatternTest663);
    UtRegisterTest("DetectFastPatternTest664", DetectFastPatternTest664);
    UtRegisterTest("DetectFastPatternTest665", DetectFastPatternTest665);
    UtRegisterTest("DetectFastPatternTest666", DetectFastPatternTest666);
    UtRegisterTest("DetectFastPatternTest667", DetectFastPatternTest667);
    UtRegisterTest("DetectFastPatternTest668", DetectFastPatternTest668);
    UtRegisterTest("DetectFastPatternTest669", DetectFastPatternTest669);
    UtRegisterTest("DetectFastPatternTest670", DetectFastPatternTest670);

    /* Unittest to check
     * - if we assign different content_ids to duplicate patterns, but one of the
     *   patterns has a fast_pattern chop set.
     * - if 2 unique patterns get unique ids.
     * - if 2 duplicate patterns, with no chop set get unique ids.
     */
    UtRegisterTest("DetectFastPatternTest671", DetectFastPatternTest671);
#endif

    return;
}
