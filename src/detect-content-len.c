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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "util-misc.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "detect-content-len.h"

#define PARSE_REGEX  "^\\s*(<|>|<=|>=|=|!=)\\s*,\\s*([0-9]{1,5})\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectContentLenSetup(DetectEngineCtx *, Signature *, char *);
void DetectContentLenFree(void *);
void DetectContentLenRegisterTests(void);

void DetectContentLenRegister(void)
{
    sigmatch_table[DETECT_CONTENT_LEN].name = "content_len";
    sigmatch_table[DETECT_CONTENT_LEN].desc = "match on the length of the corresponding buffer";
    sigmatch_table[DETECT_CONTENT_LEN].Match = NULL;
    sigmatch_table[DETECT_CONTENT_LEN].AppLayerMatch = NULL;
    sigmatch_table[DETECT_CONTENT_LEN].Setup = DetectContentLenSetup;
    sigmatch_table[DETECT_CONTENT_LEN].Free = DetectContentLenFree;
    sigmatch_table[DETECT_CONTENT_LEN].RegisterTests = DetectContentLenRegisterTests;
    sigmatch_table[DETECT_CONTENT_LEN].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed "
                   "at offset %d : %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    if (parse_regex != NULL)
        SCFree(parse_regex);
    if (parse_regex_study != NULL)
        SCFree(parse_regex_study);
    return;
}

static DetectContentLenData *DetectContentLenParse(char *len_str)
{

    DetectContentLenData *cld = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    const char *op = NULL;
    const char *op_arg = NULL;

    ret = pcre_exec(parse_regex, parse_regex_study, len_str, strlen(len_str),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_PARSE, "invalid len_str arg option sent "
                   "to content_len: \"%s\"", len_str);
        goto error;
    }

    ret = pcre_get_substring(len_str, ov, MAX_SUBSTRINGS, 1, &op);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    SCLogDebug("op - \"%s\"", op);

    ret = pcre_get_substring((char *)len_str, ov, MAX_SUBSTRINGS, 2, &op_arg);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    SCLogDebug("op_arg - \"%s\"", op_arg);

    cld = SCMalloc(sizeof(*cld));
    if (unlikely(cld == NULL))
        goto error;
    memset(cld, 0, sizeof(*cld));

    if (strcmp("<", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_LT;
    } else if (strcmp(">", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_GT;
    } else if (strcmp(">=", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_GE;
    } else if (strcmp("<=", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_LE;
    } else if (strcmp("=", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_EQ;
    } else if (strcmp("!=", op) == 0) {
        cld->op = DETECT_CONTENT_LEN_NE;
    }

    if (ParseSizeStringU32(op_arg, &cld->len) < 0)
        goto error;
    if (cld->len < 1 || cld->len > 65536) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "content_len has invalid - "
                   "%s.  Please eneter a value between 1 - 65536", op_arg);
        goto error;
    }

    pcre_free_substring(op);
    pcre_free_substring(op_arg);

    return cld;

 error:
    if (op != NULL)
        pcre_free_substring(op);
    if (op_arg != NULL)
        pcre_free_substring(op_arg);
    if (cld != NULL)
        SCFree(cld);
    return NULL;
}

static int DetectContentLenSetup(DetectEngineCtx *de_ctx, Signature *s, char *len_str)
{
    DetectContentLenData *cld = NULL;
    SigMatch *sm = NULL;

    cld = DetectContentLenParse(len_str);
    if (cld == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CONTENT_LEN;
    sm->ctx = (void *)cld;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_PMATCH);

    return 0;

error:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return -1;
}

void DetectContentLenFree(void *ptr)
{
    SCFree(ptr);
}

/************Unittests************/

#ifdef UNITTESTS

#include "detect.h"
#include "detect-content.h"
#include "detect-engine.h"
#include "util-memcmp.h"

static int DetectContentLenTest01(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest02(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest03(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<=,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_LE || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LE || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest04(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">=,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_GE || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GE || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest05(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("=,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_EQ || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_EQ || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest06(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("!=,10");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_NE || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_NE || cld->len != 10)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}




static int DetectContentLenTest07(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest08(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest09(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<=,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_LE || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LE || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest10(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">=,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_GE || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GE || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest11(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("=,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_EQ || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_EQ || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest12(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("!=,65536");
    if (cld == NULL) {
        printf("if (cld == NULL)\n");
        goto end;
    }

    if (cld->op != DETECT_CONTENT_LEN_NE || cld->len != 65536) {
        printf("if (cld->op != DETECT_CONTENT_LEN_NE || cld->len != 65536)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}




static int DetectContentLenTest13(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest14(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest15(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse(">=,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest16(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("<=,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest17(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("=,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest18(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("!=,65537");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest19(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("!==,10");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest20(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("=,xx");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest21(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("=,");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}

static int DetectContentLenTest22(void)
{
    int result = 0;

    DetectContentLenData *cld = DetectContentLenParse("");
    if (cld != NULL) {
        printf("if (cld != NULL)\n");
        goto end;
    }

    result = 1;
 end:
    if (cld != NULL)
        DetectContentLenFree(cld);
    return result;
}





int DetectContentLenTest23(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest24(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest25(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest26(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest27(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_raw_header; flow:to_server; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest28(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest29(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest30(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest31(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest32(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest33(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest34(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL || "
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL)\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}










int DetectContentLenTest35(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest36(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest37(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest38(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_header; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest39(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_raw_header; flow:to_server; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN)");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


int DetectContentLenTest40(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest41(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest42(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_stat_code; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest43(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_stat_msg; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest44(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_method; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest45(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_cookie; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest46(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:>,10; content_len:<,15; http_user_agent; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}











int DetectContentLenTest47(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest48(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_uri; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest49(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_raw_uri; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest50(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_header; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest51(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(flow:to_server; content_len:<,15; http_raw_header; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]->type != DETECT_FLOW ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->type != DETECT_CONTENT_LEN)");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRHDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}


int DetectContentLenTest52(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_client_body; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest53(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_server_body; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSBDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest54(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_stat_code; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest55(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_stat_msg; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HSMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest56(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_method; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HMDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest57(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_cookie; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectContentLenTest58(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content_len:<,15; http_user_agent; content_len:>,10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next != NULL)");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld;

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}






int DetectContentLenTest59(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_uri; "
                               "content_len:<,15; http_user_agent; "
                               "content:\"two\"; "
                               "content:\"three\"; http_uri; "
                               "content_len:>,20; http_cookie; "
                               "content_len:>,10; "
                               "content_len:>,15; http_uri; "
                               "content:\"four\"; http_cookie; "
                               "content_len:>,25; http_uri; "
                               "content_len:>,30; http_user_agent; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next->next != NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next == NULL ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next->next != NULL) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next->next != NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next-> == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next == NULL ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next->next != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->type != DETECT_CONTENT_LEN ||
        de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next->type != DETECT_CONTENT_LEN) {
        printf("if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next->type != DETECT_CONTENT ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->type != DETECT_CONTENT ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->type != DETECT_CONTENT_LEN ||"
               "de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next->type != DETECT_CONTENT_LEN)\n");
        goto end;
    }

    DetectContentLenData *cld = NULL;
    DetectContentData *cd = NULL;

    cd = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->ctx;
    if (strlen("two") != cd->content_len || SCMemcmp("two", (char *)cd->content, cd->content_len) != 0) {
        printf("if (SCMemcmp(\"two\", cd->content) != 0)\n");
        goto end;
    }
    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 10)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 20) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 20)\n");
        goto end;
    }
    cd = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HCDMATCH]->next->ctx;
    if (strlen("four") != cd->content_len || SCMemcmp("four", (char *)cd->content, cd->content_len) != 0) {
        printf("if (SCMemcmp(\"four\", cd->content) != 0)\n");
        goto end;
    }

    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->ctx;
    if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_LT || cld->len != 15)\n");
        goto end;
    }
    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HUADMATCH]->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 30) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 30)\n");
        goto end;
    }

    cd = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->ctx;
    if (strlen("one") != cd->content_len || SCMemcmp("one", (char *)cd->content, cd->content_len) != 0) {
        printf("if (SCMemcmp(\"one\", cd->content) != 0)\n");
        goto end;
    }
    cd = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->ctx;
    if (strlen("three") != cd->content_len || SCMemcmp("three", (char *)cd->content, cd->content_len) != 0) {
        printf("if (SCMemcmp(\"three\", cd->content) != 0)\n");
        goto end;
    }
    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 15) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 15)\n");
        goto end;
    }
    cld = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH]->next->next->next->ctx;
    if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 25) {
        printf("if (cld->op != DETECT_CONTENT_LEN_GT || cld->len != 25)\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

void DetectContentLenRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectContentLenTest01", DetectContentLenTest01, 1);
    UtRegisterTest("DetectContentLenTest02", DetectContentLenTest02, 1);
    UtRegisterTest("DetectContentLenTest03", DetectContentLenTest03, 1);
    UtRegisterTest("DetectContentLenTest04", DetectContentLenTest04, 1);
    UtRegisterTest("DetectContentLenTest05", DetectContentLenTest05, 1);
    UtRegisterTest("DetectContentLenTest06", DetectContentLenTest06, 1);

    UtRegisterTest("DetectContentLenTest07", DetectContentLenTest07, 1);
    UtRegisterTest("DetectContentLenTest08", DetectContentLenTest08, 1);
    UtRegisterTest("DetectContentLenTest09", DetectContentLenTest09, 1);
    UtRegisterTest("DetectContentLenTest10", DetectContentLenTest10, 1);
    UtRegisterTest("DetectContentLenTest11", DetectContentLenTest11, 1);
    UtRegisterTest("DetectContentLenTest12", DetectContentLenTest12, 1);

    UtRegisterTest("DetectContentLenTest13", DetectContentLenTest13, 1);
    UtRegisterTest("DetectContentLenTest14", DetectContentLenTest14, 1);
    UtRegisterTest("DetectContentLenTest15", DetectContentLenTest15, 1);
    UtRegisterTest("DetectContentLenTest16", DetectContentLenTest16, 1);
    UtRegisterTest("DetectContentLenTest17", DetectContentLenTest17, 1);
    UtRegisterTest("DetectContentLenTest18", DetectContentLenTest18, 1);

    UtRegisterTest("DetectContentLenTest19", DetectContentLenTest19, 1);
    UtRegisterTest("DetectContentLenTest20", DetectContentLenTest20, 1);
    UtRegisterTest("DetectContentLenTest21", DetectContentLenTest21, 1);
    UtRegisterTest("DetectContentLenTest22", DetectContentLenTest22, 1);

    UtRegisterTest("DetectContentLenTest23", DetectContentLenTest23, 1);
    UtRegisterTest("DetectContentLenTest24", DetectContentLenTest24, 1);
    UtRegisterTest("DetectContentLenTest25", DetectContentLenTest25, 1);
    UtRegisterTest("DetectContentLenTest26", DetectContentLenTest26, 1);
    UtRegisterTest("DetectContentLenTest27", DetectContentLenTest27, 1);
    UtRegisterTest("DetectContentLenTest28", DetectContentLenTest28, 1);
    UtRegisterTest("DetectContentLenTest29", DetectContentLenTest29, 1);
    UtRegisterTest("DetectContentLenTest30", DetectContentLenTest30, 1);
    UtRegisterTest("DetectContentLenTest31", DetectContentLenTest31, 1);
    UtRegisterTest("DetectContentLenTest32", DetectContentLenTest32, 1);
    UtRegisterTest("DetectContentLenTest33", DetectContentLenTest33, 1);
    UtRegisterTest("DetectContentLenTest34", DetectContentLenTest34, 1);

    UtRegisterTest("DetectContentLenTest35", DetectContentLenTest35, 1);
    UtRegisterTest("DetectContentLenTest36", DetectContentLenTest36, 1);
    UtRegisterTest("DetectContentLenTest37", DetectContentLenTest37, 1);
    UtRegisterTest("DetectContentLenTest38", DetectContentLenTest38, 1);
    UtRegisterTest("DetectContentLenTest39", DetectContentLenTest39, 1);
    UtRegisterTest("DetectContentLenTest40", DetectContentLenTest40, 1);
    UtRegisterTest("DetectContentLenTest41", DetectContentLenTest41, 1);
    UtRegisterTest("DetectContentLenTest42", DetectContentLenTest42, 1);
    UtRegisterTest("DetectContentLenTest43", DetectContentLenTest43, 1);
    UtRegisterTest("DetectContentLenTest44", DetectContentLenTest44, 1);
    UtRegisterTest("DetectContentLenTest45", DetectContentLenTest45, 1);
    UtRegisterTest("DetectContentLenTest46", DetectContentLenTest46, 1);

    UtRegisterTest("DetectContentLenTest47", DetectContentLenTest47, 1);
    UtRegisterTest("DetectContentLenTest48", DetectContentLenTest48, 1);
    UtRegisterTest("DetectContentLenTest49", DetectContentLenTest49, 1);
    UtRegisterTest("DetectContentLenTest50", DetectContentLenTest50, 1);
    UtRegisterTest("DetectContentLenTest51", DetectContentLenTest51, 1);
    UtRegisterTest("DetectContentLenTest52", DetectContentLenTest52, 1);
    UtRegisterTest("DetectContentLenTest53", DetectContentLenTest53, 1);
    UtRegisterTest("DetectContentLenTest54", DetectContentLenTest54, 1);
    UtRegisterTest("DetectContentLenTest55", DetectContentLenTest55, 1);
    UtRegisterTest("DetectContentLenTest56", DetectContentLenTest56, 1);
    UtRegisterTest("DetectContentLenTest57", DetectContentLenTest57, 1);
    UtRegisterTest("DetectContentLenTest58", DetectContentLenTest58, 1);

    UtRegisterTest("DetectContentLenTest59", DetectContentLenTest59, 1);
#endif /* UNITTESTS */
}
