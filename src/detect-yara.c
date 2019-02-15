/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Ingve Skåra <isk@ingve.org>
 * \author magenbluten <magenbluten@codemonkey.cc>
 *
 * match with yara
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-debug.h"
#include "conf.h"

#include "detect-yara.h"

#ifndef HAVE_LIBYARA

static int DetectYaraSetupNoSupport(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogError(SC_ERR_NO_YARA_SUPPORT, "no libyara support built in, needed for yara keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: yara
 */
void DetectYaraRegister(void)
{
    sigmatch_table[DETECT_YARA].name = "yara";
    sigmatch_table[DETECT_YARA].alias = "yarac";
    sigmatch_table[DETECT_YARA].desc = "match via yara";
    sigmatch_table[DETECT_YARA].url = DOC_URL DOC_VERSION "/rules/yara-keyword.html";
    sigmatch_table[DETECT_YARA].Setup = DetectYaraSetupNoSupport;
    sigmatch_table[DETECT_YARA].flags = SIGMATCH_NOT_BUILT;
}

#else /* HAVE_LIBYARA */

typedef struct DetectYaraThreadData DetectYaraThreadData;
struct DetectYaraThreadData {
    int matches;
    YR_SCANNER *scanner;
};

#define YARA_DEFAULT_TIMEOUT 1
#define YARA_DEFAULT_FAST_SCAN 1

static int yara_timeout = YARA_DEFAULT_TIMEOUT;
static int yara_fast_scan = YARA_DEFAULT_FAST_SCAN;

static int DetectYaraMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *,
        uint8_t, File *, const Signature *, const SigMatchCtx *);
static int DetectYaraSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectYaraFree(void *);
static void DetectYaraRegisterTests(void);

static void* DetectYaraThreadInit(void *);
static void DetectYaraThreadTeardown(void *);

static int g_file_match_list_id = 0;

/**
 * \brief Registration function for yara: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectYaraRegister(void)
{
    sigmatch_table[DETECT_YARA].name = "yara";
    sigmatch_table[DETECT_YARA].alias = "yarac";
    sigmatch_table[DETECT_YARA].desc = "match via yara";
    sigmatch_table[DETECT_YARA].url = DOC_URL DOC_VERSION "/rules/yara-keyword.html";
    sigmatch_table[DETECT_YARA].FileMatch = DetectYaraMatch;
    sigmatch_table[DETECT_YARA].Setup = DetectYaraSetup;
    sigmatch_table[DETECT_YARA].Free = DetectYaraFree;
    sigmatch_table[DETECT_YARA].RegisterTests = DetectYaraRegisterTests;
    sigmatch_table[DETECT_YARA].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION;

    g_file_match_list_id = DetectBufferTypeRegister("files");

    int enabled = 0;
    intmax_t val = 0;

    yara_timeout = ConfGetInt("yara.timeout", &val) ? val : YARA_DEFAULT_TIMEOUT;
    yara_fast_scan = ConfGetBool("yara.fast-scan", &enabled) ? enabled : YARA_DEFAULT_FAST_SCAN;

    SCLogDebug("registering yara rule option");
}

static const char* YaraStrError(int error)
{
    switch (error) {
        case ERROR_SUCCESS:
            return "success";
        case ERROR_INSUFFICIENT_MEMORY:
            return "insufficient memory";
        case ERROR_COULD_NOT_OPEN_FILE:
            return "yara rule file could not be opened";
        case ERROR_INVALID_FILE:
            return "file is not a valid yara rule file";
        case ERROR_CORRUPT_FILE:
            return "yara rule file is corrupt";
        case ERROR_UNSUPPORTED_FILE_VERSION:
            return "yara rule file compiled with different yara version";
        case ERROR_TOO_MANY_SCAN_THREADS:
            return "too many scan threads";
        case ERROR_SCAN_TIMEOUT:
            return "yara scan timed out";
        case ERROR_CALLBACK_ERROR:
            return "yara callback returned an error";
        case ERROR_TOO_MANY_MATCHES:
            return "too many yara string matches";
        case ERROR_COULD_NOT_MAP_FILE:
            return "file could not be mapped to memory";
        default:
            return "unknown yara error code";
    }
}

/**
 * \brief count yara matches
 *
 * \param message int error type
 * \param message_data void not used
 * \param user_data void match counter
 *
 * \retval CALLBACK_CONTINUE
 */
static int YaraScanCallback(int message, void *message_data, void *usr)
{
    if (message == CALLBACK_MSG_RULE_MATCHING && usr != NULL) {
        DetectYaraThreadData *data = usr;
        data->matches++;
    }

    return CALLBACK_CONTINUE;
}

/**
 * \brief match the specified yara rule
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectYaraData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectYaraMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    DetectYaraData *yara = (DetectYaraData *)m;
    DetectYaraThreadData *yara_ctx = (DetectYaraThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, yara->thread_ctx_id);
    if (yara_ctx == NULL || yara_ctx->scanner == NULL || file == NULL )
        SCReturnInt(0);

    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint64_t offset = 0;
    StreamingBufferGetData(file->sb, &data, &data_len, &offset);
    if (data == NULL || data_len == 0 || offset != 0)
        SCReturnInt(0);

    /* Perform the YARA scan. Require at least one YARA match */
    yara_ctx->matches = 0;
    int result = yr_scanner_scan_mem(yara_ctx->scanner, data, data_len);
    if (result == ERROR_SUCCESS) {
        if (yara_ctx->matches >= 1)
            SCReturnInt((yara->negated ? 0 : 1));
        else
            SCReturnInt((yara->negated ? 1 : 0));
    } else {
        SCLogWarning(SC_WARN_YARA_ERROR, "yara scanner return error: %s",
                YaraStrError(result));
        SCReturnInt(0);
    }

    SCReturnInt(0);
}

/**
 * \brief This function is used to parse yara options passed via yara: keyword
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param str Pointer to the user provided yara options
 * \param negate flag to indicate if the rule is negated
 *
 * \retval yara pointer to DetectYaraData on success
 * \retval NULL on failure
 */
static DetectYaraData *DetectYaraParse(const DetectEngineCtx *de_ctx,
        const char *str, int negate)
{
    SCEnter();
    DetectYaraData *yara = NULL;

    yara = SCMalloc(sizeof(DetectYaraData));
    if (unlikely(yara == NULL))
        goto error;

    memset(yara, 0x00, sizeof(DetectYaraData));

    if (negate)
        yara->negated = 1;

    /* get full filename */
    yara->filename = DetectLoadCompleteSigPath(de_ctx, str);
    if (yara->filename == NULL)
        goto error;

    return yara;

error:
    if (yara != NULL) {
        if( yara->filename != NULL ) {
            SCFree(yara->filename);
        }
        SCFree(yara);
    }
    return NULL;
}

void *DetectYaraThreadInit(void *usr)
{
    DetectYaraData* yara = usr;
    if (yara == NULL || yara->rules == NULL )
        return NULL;

    DetectYaraThreadData *yara_ctx = SCMalloc(sizeof(DetectYaraThreadData));
    if (yara_ctx == NULL){
        return NULL;
    }
    memset(yara_ctx, 0x00, sizeof(DetectYaraThreadData));

    int result = yr_scanner_create(yara->rules, &yara_ctx->scanner);
    if (result != ERROR_SUCCESS) {
        SCLogWarning(SC_WARN_YARA_ERROR, "error creating scanner error: %d", result);
        SCFree(yara_ctx);
        return NULL;
    }

    yr_scanner_set_timeout(yara_ctx->scanner, yara_timeout);
    if (yara_fast_scan > 0) {
        yr_scanner_set_flags(yara_ctx->scanner, SCAN_FLAGS_FAST_MODE);
    }
    yr_scanner_set_callback(yara_ctx->scanner, YaraScanCallback, yara_ctx);

    return yara_ctx;
}

static void DetectYaraThreadTeardown(void *usr)
{
    DetectYaraThreadData *yara_ctx = usr;

    if (yara_ctx->scanner == NULL ) {
        SCLogWarning(SC_WARN_YARA_ERROR, "no valid scanner found");
        return;
    }

    yr_scanner_destroy(yara_ctx->scanner);
    SCFree(yara_ctx);
}

/**
 * \brief parse the options from the 'yara' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided yara options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectYaraSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectYaraData *yara = NULL;
    SigMatch *sm = NULL;
    int result = 0;

    yara = DetectYaraParse(de_ctx, str, s->init_data->negated);
    if (unlikely(yara == NULL))
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (unlikely(sm == NULL))
        goto error;

    /* try loading the yara rule file as pre-compiled */
    result = yr_rules_load(yara->filename, &yara->rules);
    if (result != ERROR_SUCCESS &&
        result != ERROR_COULD_NOT_OPEN_FILE &&
        result != ERROR_INVALID_FILE) {
        /* rule file does not exist or is not readable */
        SCLogError(SC_WARN_YARA_OPEN, "unable to open file %s: error: %s",
                yara->filename, YaraStrError(result));
        goto error;
    } else if (result == ERROR_SUCCESS) {
        /* pre-compiled rules were successfully loaded */
        SCLogDebug("loaded pre-compiled yara rule %s", yara->filename);
    } else {
        /* not pre-compiled rules? trying compile as yara rule file */
        FILE *yara_rule_file = fopen(yara->filename, "r");
        if (yara_rule_file == NULL) {
            SCLogWarning(SC_ERR_FOPEN,"error opening yara rule file: %s",
                    yara->filename);
            goto error;
        }

        YR_COMPILER *compiler;
        result = yr_compiler_create(&compiler);
        if (result != ERROR_SUCCESS) {
            fclose(yara_rule_file);
            yr_compiler_destroy(compiler);
            SCLogWarning(SC_WARN_YARA_ERROR,
                    "error creating yara compiler for yara rule: %s error: %s",
                    yara->filename, YaraStrError(result));
            goto error;
        }

        result = yr_compiler_add_file(compiler, yara_rule_file, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            fclose(yara_rule_file);
            yr_compiler_destroy(compiler);
            SCLogWarning(SC_WARN_YARA_ERROR,
                    "error compiling yara rule from file: %s error: %s",
                    yara->filename, YaraStrError(result));
            goto error;
        }

        result = yr_compiler_get_rules(compiler, &yara->rules);
        if (result != ERROR_SUCCESS) {
            fclose(yara_rule_file);
            yr_compiler_destroy(compiler);
            SCLogWarning(SC_WARN_YARA_ERROR,
                    "error accessing compiled yara rules error: %s",
                    YaraStrError(result));
            goto error;
        }

        fclose(yara_rule_file);

        yr_compiler_destroy(compiler);

        SCLogConfig("loaded yara rule file %s", yara->filename);
    }

    sm->type = DETECT_YARA;
    sm->ctx = (void *)yara;

    yara->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "yara-engine",
            DetectYaraThreadInit, yara, DetectYaraThreadTeardown, 1);
    if (yara->thread_ctx_id == -1)
        goto error;

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_SIZE);
    SigMatchAppendSMToList(s, sm, g_file_match_list_id);

    SCReturnInt(0);

error:
    if (sm != NULL)
        sm->ctx = NULL;
    if (yara != NULL)
        DetectYaraFree(yara);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectYaraData
 *
 * \param ptr pointer to DetectYaraData
 */
static void DetectYaraFree(void *ptr)
{
    if (ptr != NULL) {
        DetectYaraData *yara = (DetectYaraData *)ptr;
        if (yara->filename != NULL)
            SCFree(yara->filename);
        if (yara->rules != NULL)
            yr_rules_destroy(yara->rules);
        SCFree(yara);
    }
}

#ifdef UNITTESTS


/**
 * \test DetectYaraParseTest01
 */
static int DetectYaraParseTest01(void)
{
    int ret = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    DetectYaraData *yara = DetectYaraParse(de_ctx, "non-existent.yara", 0);
    FAIL_IF_NULL(yara);
    if (yara != NULL) {
        DetectYaraFree(yara);
        ret = 1;
    }
    return ret;
}

/**
 * \test DetectYaraParseTest02
 */
static int DetectYaraParseTest02(void)
{
    int ret = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    DetectYaraData *yara = DetectYaraParse(de_ctx, "non-existent.yara", 0);
    FAIL_IF_NULL(yara);
    if (yara != NULL) {
        if (yara->negated == 0)
            ret = 1;
        DetectYaraFree(yara);
    }
    return ret;
}

/**
 * \test DetectYaraParseTest03
 */
static int DetectYaraParseTest03(void)
{
    int ret = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    DetectYaraData *yara = DetectYaraParse(de_ctx, "non-existent.yara", 1);
    FAIL_IF_NULL(yara);
    if (yara != NULL) {
        if (yara->negated == 1)
            ret = 1;
        DetectYaraFree(yara);
    }
    return ret;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectYara
 */
void DetectYaraRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectYaraParseTest01", DetectYaraParseTest01);
    UtRegisterTest("DetectYaraParseTest02", DetectYaraParseTest02);
    UtRegisterTest("DetectYaraParseTest03", DetectYaraParseTest03);
#endif /* UNITTESTS */
}

#endif /* HAVE_LIBYARA */

