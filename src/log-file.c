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
 * Log files we track.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "app-layer-parser.h"

#include "detect-filemagic.h"

#include "stream.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-atomic.h"
#include "util-file.h"
#include "util-time.h"

#include "output.h"

#include "log-file-common.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#define MODULE_NAME_FILELOG "LogFileLog"

#define DEFAULT_LOG_FILENAME_FILELOG "files-json.log"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>
#include "output-json.h"
#endif

typedef struct LogFileLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFileLogThread;

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void LogFileWriteJsonRecord(LogFileLogThread *aft, const Packet *p, const File *ff) {
    SCMutexLock(&aft->file_ctx->fp_mutex);

    /* As writes are done via the LogFileCtx, check for rotation here. */
    if (aft->file_ctx->rotation_flag) {
        aft->file_ctx->rotation_flag = 0;
        if (SCConfLogReopen(aft->file_ctx) != 0) {
            SCLogWarning(SC_ERR_FOPEN, "Failed to re-open log file. "
                "Logging for this module will be disabled.");
        }
    }

    /* Bail early if no file pointer to write to (in the unlikely
     * event file rotation failed. */
    if (aft->file_ctx->fp == NULL) {
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
        return;
    }

    FILE *fp = aft->file_ctx->fp;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "file-log");
    json_t *file_json;
    file_json = LogFileLogFileJson(p, ff);
    json_object_set_new(js, "file-log", file_json);

    LogFileLogPrintJsonObj(fp, js);

    fflush(fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);
}

static int LogFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff)
{
    SCEnter();
    LogFileLogThread *aft = (LogFileLogThread *)thread_data;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    LogFileWriteJsonRecord(aft, p, ff);

    aft->file_cnt++;
    return 0;
}

static TmEcode LogFileLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFileLogThread *aft = SCMalloc(sizeof(LogFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFileLogThread));

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogFile. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogFileLogThreadDeinit(ThreadVars *t, void *data)
{
    LogFileLogThread *aft = (LogFileLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogFileLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogFileLogExitPrintStats(ThreadVars *tv, void *data) {
    LogFileLogThread *aft = (LogFileLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files logged: %" PRIu32 "", tv->name, aft->file_cnt);
}

/**
 *  \internal
 *
 *  \brief deinit the log ctx and write out the waldo
 *
 *  \param output_ctx output context to deinit
 */
static void LogFileLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    OutputUnregisterFileRotationFlag(&logfile_ctx->rotation_flag);
    LogFileFreeCtx(logfile_ctx);
    free(output_ctx);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogFileLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME_FILELOG) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }
    OutputRegisterFileRotationFlag(&logfile_ctx->rotation_flag);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = LogFileLogDeInitCtx;

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogInfo("forcing magic lookup for logged files");
    }

    const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
    if (force_md5 != NULL && ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
        FileForceMd5Enable();
        SCLogInfo("forcing md5 calculation for logged files");
#else
        SCLogInfo("md5 calculation requires linking against libnss");
#endif
    }

    FileForceTrackingEnable();
    SCReturnPtr(output_ctx, "OutputCtx");
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param config_file for loading separate configs
 *  \return -1 if failure, 0 if succesful
 * */
int LogFileLogOpenFileCtx(LogFileCtx *file_ctx, const char *filename, const
                            char *mode)
{
    return 0;
}

void TmModuleLogFileLogRegister (void) {
    tmm_modules[TMM_FILELOG].name = MODULE_NAME_FILELOG;
    tmm_modules[TMM_FILELOG].ThreadInit = LogFileLogThreadInit;
    tmm_modules[TMM_FILELOG].Func = NULL;
    tmm_modules[TMM_FILELOG].ThreadExitPrintStats = LogFileLogExitPrintStats;
    tmm_modules[TMM_FILELOG].ThreadDeinit = LogFileLogThreadDeinit;
    tmm_modules[TMM_FILELOG].RegisterTests = NULL;
    tmm_modules[TMM_FILELOG].cap_flags = 0;
    tmm_modules[TMM_FILELOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterFileModule(MODULE_NAME_FILELOG, "file-log", LogFileLogInitCtx,
            LogFileLogger);

    SCLogDebug("registered");
}
