/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"

#include "output.h"

#include "log-file.h"

#define MODULE_NAME "LogFileLog"

TmEcode LogFileLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogFileLogThreadDeinit(ThreadVars *, void *);
void LogFileLogExitPrintStats(ThreadVars *, void *);
int LogFileLogOpenFileCtx(LogFileCtx* , const char *, const char *);
static void LogFileLogDeInitCtx(OutputCtx *);

void TmModuleLogFileLogRegister (void) {
    tmm_modules[TMM_FILELOG].name = MODULE_NAME;
    tmm_modules[TMM_FILELOG].ThreadInit = LogFileLogThreadInit;
    tmm_modules[TMM_FILELOG].Func = LogFileLog;
    tmm_modules[TMM_FILELOG].ThreadExitPrintStats = LogFileLogExitPrintStats;
    tmm_modules[TMM_FILELOG].ThreadDeinit = LogFileLogThreadDeinit;
    tmm_modules[TMM_FILELOG].RegisterTests = NULL;
    tmm_modules[TMM_FILELOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "file", LogFileLogInitCtx);

    SCLogDebug("registered");
}

typedef struct LogFileLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;
} LogFileLogThread;
/*
static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}
*/
TmEcode LogFileLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    //LogFileLogThread *aft = (LogFileLogThread *)data;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    SCMutexLock(&p->flow->files_m);

    FlowFileContainer *ffc = p->flow->files;
    if (ffc != NULL) {
        FlowFile *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            if (ff->state == FLOWFILE_STATE_STORED)
                continue;

            FlowFileData *ffd;
            for (ffd = ff->chunks_head; ffd != NULL; ffd = ffd->next) {
                if (ffd->stored == 1)
                    continue;

                /* store */
                if (ff->fd == -1) {
                    SCLogDebug("trying to open file");

                    char filename[PATH_MAX] = "/tmp/file.";
                    snprintf(filename, sizeof(filename), "/tmp/file.%p", ff);
                    ff->fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
                    if (ff->fd == -1) {
                        SCLogDebug("failed to open file");
                        continue;
                    }
                } else {
                    SCLogDebug("already open file %d", ff->fd);
                }

                ssize_t r = write(ff->fd, (const void *)ffd->data, (size_t)ffd->len);
                if (r == -1) {
                    SCLogDebug("write failed: %s", strerror(errno));
                    continue;
                }

                if (ff->state == FLOWFILE_STATE_CLOSED ||
                        ff->state == FLOWFILE_STATE_TRUNCATED ||
                        ff->state == FLOWFILE_STATE_ERROR)
                {
                    if (ffd->next == NULL) {
                        ff->state = FLOWFILE_STATE_STORED;
                        close(ff->fd);
                        ff->fd = -1;
                    }
                }

                ffd->stored = 1;
            }
        }
    }
    SCMutexUnlock(&p->flow->files_m);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFileLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    //LogFileLogThread *aft = (LogFileLogThread *)data;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFileLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogFileLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogFileLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFileLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFileLogThread *aft = SCMalloc(sizeof(LogFileLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFileLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /* Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx= ((OutputCtx *)initdata)->data;

    /* enable the logger for the app layer */
    //AppLayerRegisterLogger(ALPROTO_HTTP);

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

    SCLogInfo("(%s) HTTP requests %" PRIu32 "", tv->name, aft->uri_cnt);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogFileLogInitCtx(ConfNode *conf)
{
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = NULL;
    output_ctx->DeInit = LogFileLogDeInitCtx;

    SCReturnPtr(output_ctx, "OutputCtx");
}

static void LogFileLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    free(output_ctx);
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
