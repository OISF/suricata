/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Includes yara rules matching as a signature keyword
 *
 * Example: alert http any any -> any any (msg:"YARA matched"; yara; sid:2; rev:1;)
 *
 */
#include "suricata-common.h"

#ifdef HAVE_LIBYARA

#include "detect-parse.h"
#include "util-conf.h"

#include <yara.h>
#include <yara/error.h>

#include "detect-yara-rule.h"

/* Global pointer to loaded rules */
/* Threads will share and use the same set of rules */
YR_RULES  *g_rules = NULL;

static int DetectYaraRulesSetup (DetectEngineCtx *, Signature *, char *);
static int DetectYaraRulesMatch (ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, Signature *, SigMatch *);
static void DetectYaraRulesFree(void *);

/**
 * \brief YaraRuleCompilerCallback Prints information about a yara compiler error
 * \param error_level // FIXME - Use this to match suricata error level
 * \param file_name yara rule file name were error was detected
 * \param line_number yara rule file line number were error was detected
 * \param message  yara compiler message
 * \param opaque callback data not setted and unused
 *
 */
void YaraRuleCompilerCallback(
        int error_level,
        const char* file_name,
        int line_number,
        const char* message,
        void* user_data)
{
    SCLogWarning(SC_WARN_YARA_COMPILE_ERR, "yara compile error [%s] at [%s]:[%d]",
        message, file_name, line_number);
}

/**
 * \brief YaraRulesClean() destroys global yara rules and finalizes libyara
 *
 */
void YaraRulesClean()
{
    SCEnter();

    if (g_rules)
        yr_rules_destroy(g_rules);

    yr_finalize();
}

/**
 * \brief YaraLoadRules Compiles and loads yara rules files
 * \param de_ctx detection engine
 *
 * \reval  0 on success
 * \reval -1 on error
 */
int YaraLoadRules(DetectEngineCtx *de_ctx)
{
    SCEnter();

    ConfNode *file = NULL;
    ConfNode *rule_files = NULL;
    const char *varname = "yara-rules-files";
    const char *varname_default_path = "default-yara-rules-path";
    uint8_t files_loaded = 0;

    if (de_ctx == NULL) {
        SCReturnInt(-1);
    }

    if ( yr_initialize() != ERROR_SUCCESS) {
        SCLogError(SC_ERR_YARA_INITIALIZATION, "Failed to initialize yara library!");
        exit(EXIT_FAILURE);
    }

    /* tries to create a yara compiler */
    YR_COMPILER *compiler = NULL;
    int ret = yr_compiler_create(&compiler);
    if (ret != ERROR_SUCCESS) {
        if (ret == ERROR_INSUFICIENT_MEMORY) {
            SCLogWarning(SC_ERR_MEM_ALLOC, "insuficent memory for yara compiler!");
            SCReturnInt(-1);
        }
    }

    yr_compiler_set_callback(compiler, YaraRuleCompilerCallback, NULL);

    /* ok, let's load signature files from the general config */
    rule_files = ConfGetNode(varname);
    if (rule_files != NULL) {
        if (!ConfNodeIsSequence(rule_files)) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid yara-rule-files configuration section: "
                    "expected a list of filenames.");
            SCReturnInt(-1);
        }

        TAILQ_FOREACH(file, &rule_files->head, next) {
            const char *filename = DetectLoadCompleteSigPathWithDefaultPath(de_ctx, file->val,
                    varname_default_path);

            int num_errors = 0;

            if (unlikely(filename == NULL)) {
                continue;

            }

            /* Processes each yara rule add adds it to compilation */
            FILE *fp = fopen(filename, "r");
            if (fp == NULL) {
                SCLogError(SC_ERR_FOPEN, "failed to open yara rule %s: %s",
                        filename, strerror(errno));
                continue;

            }
            num_errors = yr_compiler_add_file(compiler, fp, NULL /*default ns */, NULL);
            fclose(fp);
            SCLogInfo("Added yara rules file [%s] errors:[%d]", filename, num_errors);
            ++files_loaded;
        }
    }

    if (files_loaded) {
        SCLogInfo("%u yara rules files processed.", files_loaded);
        ret = yr_compiler_get_rules(compiler, &g_rules);
        if (ret != ERROR_SUCCESS) {
            if (ret == ERROR_INSUFICIENT_MEMORY) {
                SCLogWarning(SC_ERR_MEM_ALLOC, "insuficent memory for storing yara rules!");
            }
        }
    }

#ifdef DEBUG
    YR_RULE *rule = NULL;

    yr_rules_foreach(g_rules, rule)
    {
        SCLogInfo("yara rule identifier=>[%s]", rule->identifier);
    }
#endif

    yr_compiler_destroy(compiler);

    SCReturnInt(0);
}

/**
 * \brief Registration function for keyword: yara
 */
void DetectYaraRulesRegister(void)
{
    sigmatch_table[DETECT_YARA_RULES].name = "yara";
    sigmatch_table[DETECT_YARA_RULES].desc = "match on a yara rule";
    sigmatch_table[DETECT_YARA_RULES].url = "<NEED ONE>"; /*FIXME*/
    sigmatch_table[DETECT_YARA_RULES].FileMatch = DetectYaraRulesMatch;
    sigmatch_table[DETECT_YARA_RULES].Setup = DetectYaraRulesSetup;
    sigmatch_table[DETECT_YARA_RULES].Free  = DetectYaraRulesFree;
    sigmatch_table[DETECT_YARA_RULES].flags = SIGMATCH_NOOPT;

    SCLogInfo("yara library initialized successfully.");
	SCLogInfo("registering yara rule option");

    return;
}

/**
 * \brief DetectYaraRuleThreadFree() clears yara thread state
 *
 * \param ctx - (DetectYaraRuleThreadData *)
 *
 */
static void DetectYaraRuleThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectYaraRuleThreadData *t = (DetectYaraRuleThreadData *)ctx;
        SCFree(t);
    }

    yr_finalize_thread();
}

/**
 * \brief DetectYaraRuleThreadInit()  initis yara thread state. It holds nothing for now.
 *
 * \param data (DetectYaraRuleThreadData *)
 *
 * \retval pointer on Success
 * \retval NULL on Failure
 */
static void *DetectYaraRuleThreadInit(void *data)
{
    DetectYaraRuleThreadData *yr = SCMalloc(sizeof(DetectYaraRuleThreadData));
    if (unlikely(yr == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "couldn't alloc ctx memory");
        return NULL;
    }
    memset(yr, 0x00, sizeof(DetectYaraRuleThreadData));

    return yr;
}

/**
 * \brief DetectYaraRulesSetup this function is used to add the parsed "yara" option
 *        into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "yara" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectYaraRulesSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();

    SigMatch *sm = NULL;
    DetectYaraRulesData *yr= NULL;

    yr = SCMalloc(sizeof(DetectYaraRulesData));
    if (unlikely(yr == NULL))
        goto error;

    yr->rule = NULL; /* FIXME: Not supported option value yet */

    yr->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "yara",
            DetectYaraRuleThreadInit, (void *)yr,
            DetectYaraRuleThreadFree, 1);

   /* Okay so far so good, lets get this into a SigMatch
    * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_YARA_RULES;
    sm->ctx = (void *)yr;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_USE_DETECT);
    SCReturnInt(0);

error:
    if (yr != NULL)
        DetectYaraRulesFree(yr);
    if (sm != NULL)
        SCFree(sm);

    SCReturnInt(-1);
}


/**
 * \brief YaraRuleScanCallback()  when yara scan emits a message
 *
 * \param message - the message type. We just care about rule matching - CALLBACK_MSG_RULE_MATCHING
 * \param user_data - opaque data to report with a boolean if matches happens:w
 *
 * \retval CALLBACK_CONTINUE if we want keep waiting for a match
 * \retval CALLBACK_ABORT if we found a rule match
 */
int YaraRuleScanCallback(int message, void* message_data, void* user_data)
{

    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    YR_RULE *rule = message_data;

    if (!rule)
        return CALLBACK_CONTINUE;

    int *matched = user_data;

    if (! matched) /* This should never happen */
        return CALLBACK_ABORT;

    *matched = 1;

#ifdef DEBUG
    const char *identifier = rule->identifier;
    const char* tag = NULL;

    yr_rule_tags_foreach(rule, tag) {
        SCLogDebug("Tag rule:[%s] tag:[%s]",identifier, tag);
    }

    SCLogDebug("Matched rule [%s]", rule->identifier);
#endif /* DEBUG */

    return CALLBACK_ABORT;
}

/**
 * \brief DetectYaraRulesMatch matchs a loaded yara rule. No keyword options yet.
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileextData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectYaraRulesMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();

    uint64_t file_size = FileSize(file);

    if (file == NULL || file_size == 0)
        SCReturnInt(0);

    DetectYaraRulesData *yr = (DetectYaraRulesData *)m->ctx;

    if (yr == NULL)
        SCReturnInt(0);

    if (yr->thread_ctx_id == -1)
        SCReturnInt(0);

    DetectYaraRuleThreadData *tyara = (DetectYaraRuleThreadData *)
        DetectThreadCtxGetKeywordThreadCtx(det_ctx, yr->thread_ctx_id);

    if (tyara == NULL) {
        SCReturnInt(0);
    }

    const uint8_t *buffer = NULL;
    uint32_t buffer_size = 0;
    uint64_t offset = 0;
    int timeout = 1; /* seconds */

    StreamingBufferGetData(file->sb, &buffer, &buffer_size, &offset);

	int matched = 0;
    int scan_ret = yr_rules_scan_mem(g_rules,
			(uint8_t *) buffer, file_size, SCAN_FLAGS_FAST_MODE,
			YaraRuleScanCallback, &matched, timeout);

    if (scan_ret != ERROR_SUCCESS) {
        switch (scan_ret) {
            case ERROR_INSUFICIENT_MEMORY:
                SCLogWarning(SC_ERR_MEM_ALLOC, "Insuficient memory to complete the operation.");
                break;
            case ERROR_TOO_MANY_SCAN_THREADS:
                SCLogNotice("Too many threads trying to use the same YR_RULES object simultaneosly."
                            "The limit is defined by MAX_THREADS in ./include/yara/limits.h.");
                break;
            case ERROR_SCAN_TIMEOUT:
                SCLogNotice("Scan timed out.");
                break;
            case ERROR_CALLBACK_ERROR:
                SCLogNotice("Callback returned an error.");
                break;
            case ERROR_TOO_MANY_MATCHES:
                SCLogNotice("Too many matches for some string in your rules. "
                            "This usually happens when your rules contains very short or very common strings like 01 02 or FF FF FF FF."
                            "The limit is defined by MAX_STRING_MATCHES in ./include/yara/limits.h");
                break;
            default:
                break;
        }
    }

    SCReturnInt(matched);
}

/**
 * \brief DetectYaraRulesFree this function will free memory associated with DetectYaraRulesData
 *
 * \param ptr pointer to DetectYaraRulesData
 */
static void DetectYaraRulesFree(void *ptr)
{
    if (ptr != NULL) {
        DetectYaraRulesData *yr = (DetectYaraRulesData *)ptr;
        if (yr->rule != NULL)
            SCFree(yr->rule);
        SCFree(yr);
    }
}

#else

/**
 * \brief Registration function for keyword: yara
 * FIXME: without yara support. what should we do in this case?
 */
void DetectYaraRulesRegister(void)
{
    sigmatch_table[DETECT_YARA_RULES].name = "yara";
    sigmatch_table[DETECT_YARA_RULES].desc = "match on a yara rule - not enabled";
    sigmatch_table[DETECT_YARA_RULES].url = "<NEED ONE>"; /*FIXME*/

    return;
}

#endif /* HAVE_LIBYARA */
