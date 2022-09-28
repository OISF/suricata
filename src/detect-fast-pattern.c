/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#include "detect-content.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-fast-pattern.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#define PARSE_REGEX "^(\\s*only\\s*)|\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*$"

static DetectParseRegex parse_regex;

static int DetectFastPatternSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFastPatternRegisterTests(void);
#endif

/* holds the list of sm match lists that need to be searched for a keyword
 * that has fp support */
static SCFPSupportSMList *g_fp_support_smlist_list = NULL;

/**
 * \brief Checks if a particular list(Signature->sm_lists[]) is in the list
 *        of lists that need to be searched for a keyword that has fp support.
 *
 * \param list_id The list id.
 *
 * \retval 1 If supported.
 * \retval 0 If not.
 */
int FastPatternSupportEnabledForSigMatchList(const DetectEngineCtx *de_ctx,
        const int list_id)
{
    if (de_ctx->fp_support_smlist_list == NULL) {
        return 0;
    }

    if (list_id == DETECT_SM_LIST_PMATCH)
        return 1;

    return DetectEngineBufferTypeSupportsMpmGetById(de_ctx, list_id);
}

static void Add(SCFPSupportSMList **list, const int list_id, const int priority)
{
    SCFPSupportSMList *ip = NULL;
    /* insertion point - ip */
    for (SCFPSupportSMList *tmp = *list; tmp != NULL; tmp = tmp->next) {
        if (list_id == tmp->list_id) {
            SCLogDebug("SM list already registered.");
            return;
        }

        /* We need a strict check to be sure that the current list
         * was not already registered
         * and other lists with the same priority hide it.
         */
        if (priority < tmp->priority)
            break;

        ip = tmp;
    }

    if (*list == NULL) {
        SCFPSupportSMList *new = SCMalloc(sizeof(SCFPSupportSMList));
        if (unlikely(new == NULL))
            exit(EXIT_FAILURE);
        memset(new, 0, sizeof(SCFPSupportSMList));
        new->list_id = list_id;
        new->priority = priority;

        *list = new;
        return;
    }

    SCFPSupportSMList *new = SCMalloc(sizeof(SCFPSupportSMList));
    if (unlikely(new == NULL))
        exit(EXIT_FAILURE);
    memset(new, 0, sizeof(SCFPSupportSMList));
    new->list_id = list_id;
    new->priority = priority;
    if (ip == NULL) {
        new->next = *list;
        *list = new;
    } else {
        new->next = ip->next;
        ip->next = new;
    }
    return;
}

/**
 * \brief Lets one add a sm list id to be searched for potential fp supported
 *        keywords later.
 *
 * \param list_id SM list id.
 * \param priority Priority for this list.
 */
void SupportFastPatternForSigMatchList(int list_id, int priority)
{
    Add(&g_fp_support_smlist_list, list_id, priority);
}

void DetectEngineRegisterFastPatternForId(DetectEngineCtx *de_ctx, int list_id, int priority)
{
    Add(&de_ctx->fp_support_smlist_list, list_id, priority);
}

/**
 * \brief Registers the keywords(SMs) that should be given fp support.
 */
void SupportFastPatternForSigMatchTypes(void)
{
    SupportFastPatternForSigMatchList(DETECT_SM_LIST_PMATCH, 3);

    /* other types are handled by DetectMpmAppLayerRegister() */
}

void DetectEngineInitializeFastPatternList(DetectEngineCtx *de_ctx)
{
    SCFPSupportSMList *last = NULL;
    for (SCFPSupportSMList *tmp = g_fp_support_smlist_list; tmp != NULL; tmp = tmp->next) {
        SCFPSupportSMList *n = SCCalloc(1, sizeof(*n));
        if (n == NULL) {
            FatalError(SC_ERR_FATAL, "out of memory: %s", strerror(errno));
        }
        n->list_id = tmp->list_id;
        n->priority = tmp->priority;

        // append
        if (de_ctx->fp_support_smlist_list == NULL) {
            last = de_ctx->fp_support_smlist_list = n;
        } else {
            BUG_ON(last == NULL);
            last->next = n;
            last = n;
        }
    }
}

void DetectEngineFreeFastPatternList(DetectEngineCtx *de_ctx)
{
    for (SCFPSupportSMList *tmp = de_ctx->fp_support_smlist_list; tmp != NULL;) {
        SCFPSupportSMList *next = tmp->next;
        SCFree(tmp);
        tmp = next;
    }
    de_ctx->fp_support_smlist_list = NULL;
}

/**
 * \brief Registration function for fast_pattern keyword
 */
void DetectFastPatternRegister(void)
{
    sigmatch_table[DETECT_FAST_PATTERN].name = "fast_pattern";
    sigmatch_table[DETECT_FAST_PATTERN].desc = "force using preceding content in the multi pattern matcher";
    sigmatch_table[DETECT_FAST_PATTERN].url = "/rules/prefilter-keywords.html#fast-pattern";
    sigmatch_table[DETECT_FAST_PATTERN].Match = NULL;
    sigmatch_table[DETECT_FAST_PATTERN].Setup = DetectFastPatternSetup;
    sigmatch_table[DETECT_FAST_PATTERN].Free  = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FAST_PATTERN].RegisterTests = DetectFastPatternRegisterTests;
#endif
    sigmatch_table[DETECT_FAST_PATTERN].flags |= SIGMATCH_OPTIONAL_OPT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief Configures the previous content context for a fast_pattern modifier
 *        keyword used in the rule.
 *
 * \param de_ctx   Pointer to the Detection Engine Context.
 * \param s        Pointer to the Signature to which the current keyword belongs.
 * \param arg      May hold an argument
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectFastPatternSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    int ret = 0, res = 0;
    size_t pcre2len;
    char arg_substr[128] = "";
    DetectContentData *cd = NULL;

    SigMatch *pm1 = DetectGetLastSMFromMpmLists(de_ctx, s);
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
            uint32_t list_id = 0;
            for (list_id = 0; list_id < s->init_data->smlists_array_size; list_id++) {
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
    ret = DetectParsePcreExec(&parse_regex, arg, 0, 0);
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
        pcre2len = sizeof(arg_substr);
        res = pcre2_substring_copy_bynumber(
                parse_regex.match, 2, (PCRE2_UCHAR8 *)arg_substr, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed "
                                                  "for fast_pattern offset");
            goto error;
        }
        uint16_t offset;
        if (StringParseUint16(&offset, 10, 0,
                              (const char *)arg_substr) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid fast pattern offset:"
                       " \"%s\"", arg_substr);
            goto error;
        }

        pcre2len = sizeof(arg_substr);
        res = pcre2_substring_copy_bynumber(
                parse_regex.match, 3, (PCRE2_UCHAR8 *)arg_substr, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed "
                                                  "for fast_pattern offset");
            goto error;
        }
        uint16_t length;
        if (StringParseUint16(&length, 10, 0,
                              (const char *)arg_substr) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid value for fast "
                       "pattern: \"%s\"", arg_substr);
            goto error;
        }

        // Avoiding integer overflow
        if (offset > (65535 - length)) {
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

    cd->flags |= DETECT_CONTENT_FAST_PATTERN;

    return 0;

 error:
    return -1;
}

/*----------------------------------Unittests---------------------------------*/

#ifdef UNITTESTS
static int DetectFastPatternStickySingle(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; fast_pattern; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & DETECT_CONTENT_FAST_PATTERN) == DETECT_CONTENT_FAST_PATTERN);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternModifierSingle(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & DETECT_CONTENT_FAST_PATTERN) == DETECT_CONTENT_FAST_PATTERN);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternStickySingleNoFP(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & DETECT_CONTENT_FAST_PATTERN) == 0);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternModifierSingleNoFP(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%ssid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & DETECT_CONTENT_FAST_PATTERN) == 0);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternStickySingleBadArg(const char *sticky)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    /* bogus argument to fast_pattern */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; fast_pattern:boo; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with distance */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; fast_pattern:only; content:\"two\"; distance:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with distance */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; content:\"two\"; fast_pattern:only; distance:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with distance */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; content:\"two\"; distance:10; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; fast_pattern:5,6; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternModifierBadRules(const char *sticky)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    /* bogus argument to fast_pattern */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:boo; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with distance */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:only; content:\"two\"; %s%sdistance:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
#if 0 // TODO bug?
    /* fast_pattern only with distance */
    snprintf(string, sizeof(string), "alert tcp any any -> any any "
            "(content:\"one\"; %s%s content:\"two\"; %s%sdistance:10; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
#endif
    /* fast_pattern only with within */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:only; content:\"two\"; %s%swithin:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with within */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%s content:\"two\"; %s%swithin:10; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with offset */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:only; offset:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with offset */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%s offset:10; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with depth */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:only; depth:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only with depth */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%s depth:10; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern only negate */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%s content:!\"two\"; %s%sfast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:5,6; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:65977,2; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:2,65977; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:2,65534; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* fast_pattern chop with invalid values */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:65534,2; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* negated fast_pattern with distance */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:!\"two\"; fast_pattern:1,2; %s%sdistance:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* negated fast_pattern with within */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:!\"two\"; fast_pattern:1,2; %s%swithin:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* negated fast_pattern with depth */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:!\"two\"; fast_pattern:1,2; %s%sdepth:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    /* negated fast_pattern with offset */
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:!\"two\"; fast_pattern:1,2; %s%soffset:10; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternStickySingleFPOnly(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"one\"; fast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternModifierFPOnly(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%sfast_pattern:only; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:\"two\"; %s%sfast_pattern:only; sid:2;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:\"two\"; distance:10; %s%scontent:\"three\"; "
            "%s%sfast_pattern:only; sid:3;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NOT_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:\"two\"; within:10; %s%scontent:\"three\"; "
            "%s%sfast_pattern:only; sid:4;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NOT_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:\"two\"; offset:10; %s%scontent:\"three\"; "
            "%s%sfast_pattern:only; sid:5;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NOT_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"one\"; %s%scontent:\"two\"; depth:10; %s%scontent:\"three\"; "
            "%s%sfast_pattern:only; sid:6;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);
    sm = sm->next;
    FAIL_IF_NOT_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY));

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:!\"one\"; %s%sfast_pattern; content:\"two\"; depth:10; %s%ssid:7;)",
            sticky ? sticky : "", sticky ? "; " : " ", sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY |
                                     DETECT_CONTENT_NEGATED)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_NEGATED));
    sm = sm->next;
    FAIL_IF_NOT_NULL(sm->next);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT(
            (cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_ONLY)) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternStickyFPChop(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"onetwothree\"; fast_pattern:3,4; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP |
                                     DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP));
    FAIL_IF_NOT(cd->fp_chop_offset == 3);
    FAIL_IF_NOT(cd->fp_chop_len == 4);

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(%s%scontent:\"onetwothree\"; fast_pattern:3,4; content:\"xyz\"; distance:10; sid:2;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP |
                                     DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP));
    FAIL_IF_NOT(cd->fp_chop_offset == 3);
    FAIL_IF_NOT(cd->fp_chop_len == 4);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFastPatternModifierFPChop(const char *sticky, const int list)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    char string[1024];
    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:\"onetwothree\"; %s%sfast_pattern:3,4; sid:1;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP |
                                     DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_FAST_PATTERN | DETECT_CONTENT_FAST_PATTERN_CHOP));
    FAIL_IF_NOT(cd->fp_chop_offset == 3);
    FAIL_IF_NOT(cd->fp_chop_len == 4);

    snprintf(string, sizeof(string),
            "alert tcp any any -> any any "
            "(content:!\"onetwothree\"; %s%sfast_pattern:3,4; sid:2;)",
            sticky ? sticky : "", sticky ? "; " : " ");
    s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    sm = de_ctx->sig_list->sm_lists[list];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & (DETECT_CONTENT_NEGATED | DETECT_CONTENT_FAST_PATTERN |
                                     DETECT_CONTENT_FAST_PATTERN_CHOP |
                                     DETECT_CONTENT_FAST_PATTERN_ONLY)) ==
                (DETECT_CONTENT_NEGATED | DETECT_CONTENT_FAST_PATTERN |
                        DETECT_CONTENT_FAST_PATTERN_CHOP));
    FAIL_IF_NOT(cd->fp_chop_offset == 3);
    FAIL_IF_NOT(cd->fp_chop_len == 4);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Checks if a fast_pattern is registered in a Signature
 */
static int DetectFastPatternTest01(void)
{
    FAIL_IF_NOT(DetectFastPatternStickySingle(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternModifierSingle(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternStickySingleNoFP(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternModifierSingleNoFP(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternStickySingleBadArg(NULL));
    FAIL_IF_NOT(DetectFastPatternModifierBadRules(NULL));
    FAIL_IF_NOT(DetectFastPatternStickySingleFPOnly(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternModifierFPOnly(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternStickyFPChop(NULL, DETECT_SM_LIST_PMATCH));
    FAIL_IF_NOT(DetectFastPatternModifierFPChop(NULL, DETECT_SM_LIST_PMATCH));

    struct {
        const char *buffer_name;
        const char *sb_name;
        const char *mod_name;
    } keywords[] = {
        { "file_data", "file.data", NULL },
        { "http_uri", "http.uri", "http_uri" },
        { "http_raw_uri", "http.uri.raw", "http_raw_uri" },
        { "http_user_agent", "http.user_agent", "http_user_agent" },
        { "http_header", "http.header", "http_header" },
        // http_raw_header requires sigs to have a direction
        //{ "http_raw_header", "http.header.raw", "http_raw_header" },
        { "http_method", "http.method", "http_method" },
        { "http_cookie", "http.cookie", "http_cookie" },
        { "http_host", "http.host", "http_host" },
        { "http_raw_host", "http.host.raw", "http_raw_host" },
        { "http_stat_code", "http.stat_code", "http_stat_code" },
        { "http_stat_msg", "http.stat_msg", "http_stat_msg" },
        { "http_client_body", "http.request_body", "http_client_body" },
        { NULL, NULL, NULL },
    };

    for (int i = 0; keywords[i].buffer_name != NULL; i++) {
        const int list_id = DetectBufferTypeGetByName(keywords[i].buffer_name);
        FAIL_IF(list_id == -1);

        const char *k = keywords[i].sb_name;
        if (k) {
            FAIL_IF_NOT(DetectFastPatternStickySingle(k, list_id));
            FAIL_IF_NOT(DetectFastPatternStickySingleNoFP(k, list_id));
            FAIL_IF_NOT(DetectFastPatternStickySingleBadArg(k));
            FAIL_IF_NOT(DetectFastPatternStickySingleFPOnly(k, list_id));
            FAIL_IF_NOT(DetectFastPatternStickyFPChop(k, list_id));
        }
        k = keywords[i].mod_name;
        if (k) {
            FAIL_IF_NOT(DetectFastPatternModifierSingle(k, list_id));
            FAIL_IF_NOT(DetectFastPatternModifierSingleNoFP(k, list_id));
            FAIL_IF_NOT(DetectFastPatternModifierBadRules(k));
            FAIL_IF_NOT(DetectFastPatternModifierFPOnly(k, list_id));
            FAIL_IF_NOT(DetectFastPatternModifierFPChop(k, list_id));
        }
    }

    PASS;
}

/**
 * \test Checks to make sure that other sigs work that should when fast_pattern is inspecting on the
 * same payload
 *
 */
static int DetectFastPatternTest14(void)
{
    uint8_t *buf = (uint8_t *)"Dummy is our name.  Oh yes.  From right here "
                              "right now, all the way to hangover.  right.  strings5_imp now here "
                              "comes our dark knight strings_string5.  Yes here is our dark knight";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FlowInitConfig(FLOW_QUIET);

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(msg:\"fast_pattern test\"; content:\"strings_string5\"; content:\"knight\"; "
            "fast_pattern; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(msg:\"test different content\"; content:\"Dummy is our name\"; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 2));

    UTHFreePackets(&p, 1);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();
    PASS;
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s[6];
    s[0] = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"onetwothreefour\"; sid:1;)");
    FAIL_IF_NULL(s[0]);
    s[1] = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"onetwothreefour\"; sid:2;)");
    FAIL_IF_NULL(s[1]);
    s[2] = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"uniquepattern\"; sid:3;)");
    FAIL_IF_NULL(s[2]);
    s[3] = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (content:\"onetwothreefour\"; fast_pattern:3,5; sid:4;)");
    FAIL_IF_NULL(s[3]);
    s[4] = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"twoth\"; sid:5;)");
    FAIL_IF_NULL(s[4]);
    s[5] = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (content:\"onetwothreefour\"; fast_pattern:0,15; "
            "sid:6;)");
    FAIL_IF_NULL(s[5]);

    SigGroupBuild(de_ctx);

    SigMatchData *smd = s[0]->sm_arrays[DETECT_SM_LIST_PMATCH];
    DetectContentData *cd = (DetectContentData *)smd->ctx;
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

static int DetectFastPatternPrefilter(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    const char *string = "alert tcp any any -> any any "
                         "(content:\"one\"; prefilter; sid:1;)";
    Signature *s = DetectEngineAppendSig(de_ctx, string);
    FAIL_IF_NULL(s);
    SigMatch *sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(cd));
    FAIL_IF_NOT((cd->flags & DETECT_CONTENT_FAST_PATTERN) == DETECT_CONTENT_FAST_PATTERN);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectFastPatternRegisterTests(void)
{
    UtRegisterTest("DetectFastPatternTest01", DetectFastPatternTest01);
    UtRegisterTest("DetectFastPatternTest14", DetectFastPatternTest14);
    /* Unittest to check
     * - if we assign different content_ids to duplicate patterns, but one of the
     *   patterns has a fast_pattern chop set.
     * - if 2 unique patterns get unique ids.
     * - if 2 duplicate patterns, with no chop set get unique ids.
     */
    UtRegisterTest("DetectFastPatternTest671", DetectFastPatternTest671);

    UtRegisterTest("DetectFastPatternPrefilter", DetectFastPatternPrefilter);
}
#endif
