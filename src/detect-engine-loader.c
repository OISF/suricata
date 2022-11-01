/* Copyright (C) 2021 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect-parse.h"

#include "tm-threads.h"

#include "detect-engine-loader.h"
#include "detect-engine-build.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"

#include "util-detect.h"
#include "util-threshold-config.h"
#include "util-path.h"

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

extern int rule_reload;
extern int engine_analysis;
static int fp_engine_analysis_set = 0;
int rule_engine_analysis_set = 0;

/**
 *  \brief Create the path if default-rule-path was specified
 *  \param sig_file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */
char *DetectLoadCompleteSigPath(const DetectEngineCtx *de_ctx, const char *sig_file)
{
    const char *defaultpath = NULL;
    char *path = NULL;
    char varname[128];

    if (sig_file == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS,"invalid sig_file argument - NULL");
        return NULL;
    }

    /* If we have a configuration prefix, only use it if the primary configuration node
     * is not marked as final, as that means it was provided on the command line with
     * a --set. */
    ConfNode *default_rule_path = ConfGetNode("default-rule-path");
    if ((!default_rule_path || !default_rule_path->final) && strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.default-rule-path",
                de_ctx->config_prefix);
        default_rule_path = ConfGetNode(varname);
    }
    if (default_rule_path) {
        defaultpath = default_rule_path->val;
    }

    /* Path not specified */
    if (PathIsRelative(sig_file)) {
        if (defaultpath) {
            SCLogDebug("Default path: %s", defaultpath);
            size_t path_len = sizeof(char) * (strlen(defaultpath) +
                          strlen(sig_file) + 2);
            path = SCMalloc(path_len);
            if (unlikely(path == NULL))
                return NULL;
            strlcpy(path, defaultpath, path_len);
#if defined OS_WIN32 || defined __CYGWIN__
            if (path[strlen(path) - 1] != '\\')
                strlcat(path, "\\\\", path_len);
#else
            if (path[strlen(path) - 1] != '/')
                strlcat(path, "/", path_len);
#endif
            strlcat(path, sig_file, path_len);
        } else {
            path = SCStrdup(sig_file);
            if (unlikely(path == NULL))
                return NULL;
        }
    } else {
        path = SCStrdup(sig_file);
        if (unlikely(path == NULL))
            return NULL;
    }
    return path;
}

/**
 *  \brief Load a file with signatures
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename to load signatures from
 *  \param goodsigs_tot Will store number of valid signatures in the file
 *  \param badsigs_tot Will store number of invalid signatures in the file
 *  \retval 0 on success, -1 on error
 */
static int DetectLoadSigFile(DetectEngineCtx *de_ctx, char *sig_file,
        int *goodsigs, int *badsigs)
{
    Signature *sig = NULL;
    int good = 0, bad = 0;
    char line[DETECT_MAX_RULE_SIZE] = "";
    size_t offset = 0;
    int lineno = 0, multiline = 0;

    (*goodsigs) = 0;
    (*badsigs) = 0;

    FILE *fp = fopen(sig_file, "r");
    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening rule file %s:"
                   " %s.", sig_file, strerror(errno));
        return -1;
    }

    while(fgets(line + offset, (int)sizeof(line) - offset, fp) != NULL) {
        lineno++;
        size_t len = strlen(line);

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line [0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        /* Check for multiline rules. */
        while (len > 0 && isspace((unsigned char)line[--len]));
        if (line[len] == '\\') {
            multiline++;
            offset = len;
            if (offset < sizeof(line) - 1) {
                /* We have room for more. */
                continue;
            }
            /* No more room in line buffer, continue, rule will fail
             * to parse. */
        }

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
        }

        /* Reset offset. */
        offset = 0;

        de_ctx->rule_file = sig_file;
        de_ctx->rule_line = lineno - multiline;

        sig = DetectEngineAppendSig(de_ctx, line);
        if (sig != NULL) {
            if (rule_engine_analysis_set || fp_engine_analysis_set) {
                RetrieveFPForSig(de_ctx, sig);
                if (fp_engine_analysis_set) {
                    EngineAnalysisFP(de_ctx, sig, line);
                }
                if (rule_engine_analysis_set) {
                    EngineAnalysisRules(de_ctx, sig, line);
                }
            }
            SCLogDebug("signature %"PRIu32" loaded", sig->id);
            good++;
        } else {
            if (!de_ctx->sigerror_silent) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "error parsing signature \"%s\" from "
                        "file %s at line %"PRId32"", line, sig_file, lineno - multiline);

                if (!SigStringAppend(&de_ctx->sig_stat, sig_file, line, de_ctx->sigerror, (lineno - multiline))) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error adding sig \"%s\" from "
                            "file %s at line %"PRId32"", line, sig_file, lineno - multiline);
                }
                if (de_ctx->sigerror) {
                    de_ctx->sigerror = NULL;
                }
            }
            if (rule_engine_analysis_set) {
                EngineAnalysisRulesFailure(line, sig_file, lineno - multiline);
            }
            if (!de_ctx->sigerror_ok) {
                bad++;
            }
        }
        multiline = 0;
    }
    fclose(fp);

    *goodsigs = good;
    *badsigs = bad;
    return 0;
}

/**
 *  \brief Expands wildcards and reads signatures from each matching file
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename (or pattern) holding signatures
 *  \retval -1 on error
 */
static int ProcessSigFiles(DetectEngineCtx *de_ctx, char *pattern,
        SigFileLoaderStat *st, int *good_sigs, int *bad_sigs)
{
    int r = 0;

    if (pattern == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "opening rule file null");
        return -1;
    }

#ifdef HAVE_GLOB_H
    glob_t files;
    r = glob(pattern, 0, NULL, &files);

    if (r == GLOB_NOMATCH) {
        SCLogWarning(SC_ERR_NO_RULES, "No rule files match the pattern %s", pattern);
        ++(st->bad_files);
        ++(st->total_files);
        return -1;
    } else if (r != 0) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "error expanding template %s: %s",
                 pattern, strerror(errno));
        return -1;
    }

    for (size_t i = 0; i < (size_t)files.gl_pathc; i++) {
        char *fname = files.gl_pathv[i];
        if (strcmp("/dev/null", fname) == 0)
            continue;
#else
        char *fname = pattern;
        if (strcmp("/dev/null", fname) == 0)
            return 0;
#endif
        SCLogConfig("Loading rule file: %s", fname);
        r = DetectLoadSigFile(de_ctx, fname, good_sigs, bad_sigs);
        if (r < 0) {
            ++(st->bad_files);
        }

        ++(st->total_files);

        st->good_sigs_total += *good_sigs;
        st->bad_sigs_total += *bad_sigs;

#ifdef HAVE_GLOB_H
    }
    globfree(&files);
#endif
    return r;
}

/**
 *  \brief Load signatures
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename (or pattern) holding signatures
 *  \param sig_file_exclusive File passed in 'sig_file' should be loaded exclusively.
 *  \retval -1 on error
 */
int SigLoadSignatures(DetectEngineCtx *de_ctx, char *sig_file, int sig_file_exclusive)
{
    SCEnter();

    ConfNode *rule_files;
    ConfNode *file = NULL;
    SigFileLoaderStat *sig_stat = &de_ctx->sig_stat;
    int ret = 0;
    char *sfile = NULL;
    char varname[128] = "rule-files";
    int good_sigs = 0;
    int bad_sigs = 0;

    if (strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.rule-files",
                de_ctx->config_prefix);
    }

    if (RunmodeGetCurrent() == RUNMODE_ENGINE_ANALYSIS) {
        fp_engine_analysis_set = SetupFPAnalyzer();
        rule_engine_analysis_set = SetupRuleAnalyzer();
    }

    /* ok, let's load signature files from the general config */
    if (!(sig_file != NULL && sig_file_exclusive == TRUE)) {
        rule_files = ConfGetNode(varname);
        if (rule_files != NULL) {
            if (!ConfNodeIsSequence(rule_files)) {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid rule-files configuration section: "
                    "expected a list of filenames.");
            }
            else {
                TAILQ_FOREACH(file, &rule_files->head, next) {
                    sfile = DetectLoadCompleteSigPath(de_ctx, file->val);
                    good_sigs = bad_sigs = 0;
                    ret = ProcessSigFiles(de_ctx, sfile, sig_stat, &good_sigs, &bad_sigs);
                    SCFree(sfile);

                    if (de_ctx->failure_fatal && ret != 0) {
                        /* Some rules failed to load, just exit as
                         * errors would have already been logged. */
                        exit(EXIT_FAILURE);
                    }

                    if (good_sigs == 0) {
                        SCLogConfig("No rules loaded from %s.", file->val);
                    }
                }
            }
        }
    }

    /* If a Signature file is specified from commandline, parse it too */
    if (sig_file != NULL) {
        ret = ProcessSigFiles(de_ctx, sig_file, sig_stat, &good_sigs, &bad_sigs);

        if (ret != 0) {
            if (de_ctx->failure_fatal == 1) {
                exit(EXIT_FAILURE);
            }
        }

        if (good_sigs == 0) {
            SCLogConfig("No rules loaded from %s", sig_file);
        }
    }

    /* now we should have signatures to work with */
    if (sig_stat->good_sigs_total <= 0) {
        if (sig_stat->total_files > 0) {
           SCLogWarning(SC_ERR_NO_RULES_LOADED, "%d rule files specified, but no rules were loaded!", sig_stat->total_files);
        } else {
            SCLogInfo("No signatures supplied.");
            goto end;
        }
    } else {
        /* we report the total of files and rules successfully loaded and failed */
        SCLogInfo("%" PRId32 " rule files processed. %" PRId32 " rules successfully loaded, %" PRId32 " rules failed",
            sig_stat->total_files, sig_stat->good_sigs_total, sig_stat->bad_sigs_total);
    }

    if ((sig_stat->bad_sigs_total || sig_stat->bad_files) && de_ctx->failure_fatal) {
        ret = -1;
        goto end;
    }

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);

    if (SCThresholdConfInitContext(de_ctx) < 0) {
        ret = -1;
        goto end;
    }

    /* Setup the signature group lookup structure and pattern matchers */
    if (SigGroupBuild(de_ctx) < 0)
        goto end;

    ret = 0;

 end:
    gettimeofday(&de_ctx->last_reload, NULL);
    if (RunmodeGetCurrent() == RUNMODE_ENGINE_ANALYSIS) {
        if (rule_engine_analysis_set) {
            CleanupRuleAnalyzer();
        }
        if (fp_engine_analysis_set) {
            CleanupFPAnalyzer();
        }
    }

    DetectParseDupSigHashFree(de_ctx);
    SCReturnInt(ret);
}

#define NLOADERS 4
static DetectLoaderControl *loaders = NULL;
static int cur_loader = 0;
void TmThreadWakeupDetectLoaderThreads(void);
static int num_loaders = NLOADERS;

/** \param loader -1 for auto select
 *  \retval loader_id or negative in case of error */
int DetectLoaderQueueTask(int loader_id, LoaderFunc Func, void *func_ctx)
{
    if (loader_id == -1) {
        loader_id = cur_loader;
        cur_loader++;
        if (cur_loader >= num_loaders)
            cur_loader = 0;
    }
    if (loader_id >= num_loaders || loader_id < 0) {
        return -ERANGE;
    }

    DetectLoaderControl *loader = &loaders[loader_id];

    DetectLoaderTask *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->Func = Func;
    t->ctx = func_ctx;

    SCMutexLock(&loader->m);
    TAILQ_INSERT_TAIL(&loader->task_list, t, next);
    SCMutexUnlock(&loader->m);

    TmThreadWakeupDetectLoaderThreads();

    SCLogDebug("%d %p %p", loader_id, Func, func_ctx);
    return loader_id;
}

/** \brief wait for loader tasks to complete
 *  \retval result 0 for ok, -1 for errors */
int DetectLoadersSync(void)
{
    SCLogDebug("waiting");
    int errors = 0;
    int i;
    for (i = 0; i < num_loaders; i++) {
        int done = 0;
        DetectLoaderControl *loader = &loaders[i];
        while (!done) {
            SCMutexLock(&loader->m);
            if (TAILQ_EMPTY(&loader->task_list)) {
                done = 1;
            }
            SCMutexUnlock(&loader->m);
        }
        SCMutexLock(&loader->m);
        if (loader->result != 0) {
            errors++;
            loader->result = 0;
        }
        SCMutexUnlock(&loader->m);

    }
    if (errors) {
        SCLogError(SC_ERR_INITIALIZATION, "%d loaders reported errors", errors);
        return -1;
    }
    SCLogDebug("done");
    return 0;
}

static void DetectLoaderInit(DetectLoaderControl *loader)
{
    memset(loader, 0x00, sizeof(*loader));
    SCMutexInit(&loader->m, NULL);
    TAILQ_INIT(&loader->task_list);
}

void DetectLoadersInit(void)
{
    intmax_t setting = NLOADERS;
    (void)ConfGetInt("multi-detect.loaders", &setting);

    if (setting < 1 || setting > 1024) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS,
                "invalid multi-detect.loaders setting %"PRIdMAX, setting);
        exit(EXIT_FAILURE);
    }
    num_loaders = (int32_t)setting;

    SCLogInfo("using %d detect loader threads", num_loaders);

    BUG_ON(loaders != NULL);
    loaders = SCCalloc(num_loaders, sizeof(DetectLoaderControl));
    BUG_ON(loaders == NULL);

    int i;
    for (i = 0; i < num_loaders; i++) {
        DetectLoaderInit(&loaders[i]);
    }
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadWakeupDetectLoaderThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            if (strncmp(tv->name,"DL#",3) == 0) {
                BUG_ON(tv->ctrl_cond == NULL);
                pthread_cond_broadcast(tv->ctrl_cond);
            }
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    return;
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadContinueDetectLoaderThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            if (strncmp(tv->name,"DL#",3) == 0)
                TmThreadContinue(tv);

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    return;
}


SC_ATOMIC_DECLARE(int, detect_loader_cnt);

typedef struct DetectLoaderThreadData_ {
    uint32_t instance;
} DetectLoaderThreadData;

static TmEcode DetectLoaderThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    DetectLoaderThreadData *ftd = SCCalloc(1, sizeof(DetectLoaderThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;

    ftd->instance = SC_ATOMIC_ADD(detect_loader_cnt, 1); /* id's start at 0 */
    SCLogDebug("detect loader instance %u", ftd->instance);

    /* pass thread data back to caller */
    *data = ftd;

    return TM_ECODE_OK;
}

static TmEcode DetectLoaderThreadDeinit(ThreadVars *t, void *data)
{
    SCFree(data);
    return TM_ECODE_OK;
}


static TmEcode DetectLoader(ThreadVars *th_v, void *thread_data)
{
    DetectLoaderThreadData *ftd = (DetectLoaderThreadData *)thread_data;
    BUG_ON(ftd == NULL);

    SCLogDebug("loader thread started");
    while (1)
    {
        if (TmThreadsCheckFlag(th_v, THV_PAUSE)) {
            TmThreadsSetFlag(th_v, THV_PAUSED);
            TmThreadTestThreadUnPaused(th_v);
            TmThreadsUnsetFlag(th_v, THV_PAUSED);
        }

        /* see if we have tasks */

        DetectLoaderControl *loader = &loaders[ftd->instance];
        SCMutexLock(&loader->m);

        DetectLoaderTask *task = NULL, *tmptask = NULL;
        TAILQ_FOREACH_SAFE(task, &loader->task_list, next, tmptask) {
            int r = task->Func(task->ctx, ftd->instance);
            loader->result |= r;
            TAILQ_REMOVE(&loader->task_list, task, next);
            SCFree(task->ctx);
            SCFree(task);
        }

        SCMutexUnlock(&loader->m);

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            break;
        }

        /* just wait until someone wakes us up */
        SCCtrlMutexLock(th_v->ctrl_mutex);
        SCCtrlCondWait(th_v->ctrl_cond, th_v->ctrl_mutex);
        SCCtrlMutexUnlock(th_v->ctrl_mutex);

        SCLogDebug("woke up...");
    }

    return TM_ECODE_OK;
}

/** \brief spawn the detect loader manager thread */
void DetectLoaderThreadSpawn(void)
{
    int i;
    for (i = 0; i < num_loaders; i++) {
        ThreadVars *tv_loader = NULL;

        char name[TM_THREAD_NAME_MAX];
        snprintf(name, sizeof(name), "%s#%02d", thread_name_detect_loader, i+1);

        tv_loader = TmThreadCreateCmdThreadByName(name,
                "DetectLoader", 1);
        BUG_ON(tv_loader == NULL);

        if (tv_loader == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(1);
        }
        if (TmThreadSpawn(tv_loader) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(1);
        }
    }
    return;
}

void TmModuleDetectLoaderRegister (void)
{
    tmm_modules[TMM_DETECTLOADER].name = "DetectLoader";
    tmm_modules[TMM_DETECTLOADER].ThreadInit = DetectLoaderThreadInit;
    tmm_modules[TMM_DETECTLOADER].ThreadDeinit = DetectLoaderThreadDeinit;
    tmm_modules[TMM_DETECTLOADER].Management = DetectLoader;
    tmm_modules[TMM_DETECTLOADER].cap_flags = 0;
    tmm_modules[TMM_DETECTLOADER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_DETECTLOADER].name);

    SC_ATOMIC_INIT(detect_loader_cnt);
}
