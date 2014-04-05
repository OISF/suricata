/* Copyright (C) 2014 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-tcp-data.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "tcp-data.log"

#define MODULE_NAME "LogTcpDataLog"

#define OUTPUT_BUFFER_SIZE 65535

TmEcode LogTcpDataLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogTcpDataLogThreadDeinit(ThreadVars *, void *);
void LogTcpDataLogExitPrintStats(ThreadVars *, void *);
static void LogTcpDataLogDeInitCtx(OutputCtx *);

int LogTcpDataLogger(ThreadVars *tv, void *thread_data, const Flow *f, const uint8_t *data, uint32_t data_len, uint8_t flags);

void TmModuleLogTcpDataLogRegister (void) {
    tmm_modules[TMM_LOGTCPDATALOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTCPDATALOG].ThreadInit = LogTcpDataLogThreadInit;
    tmm_modules[TMM_LOGTCPDATALOG].ThreadExitPrintStats = LogTcpDataLogExitPrintStats;
    tmm_modules[TMM_LOGTCPDATALOG].ThreadDeinit = LogTcpDataLogThreadDeinit;
    tmm_modules[TMM_LOGTCPDATALOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTCPDATALOG].cap_flags = 0;
    tmm_modules[TMM_LOGTCPDATALOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterStreamingModule(MODULE_NAME, "tcp-data", LogTcpDataLogInitCtx,
            LogTcpDataLogger, STREAMING_TCP_DATA);
    OutputRegisterStreamingModule(MODULE_NAME, "http-body-data", LogTcpDataLogInitCtx,
            LogTcpDataLogger, STREAMING_HTTP_BODIES);
}

typedef struct LogTcpDataFileCtx_ {
    LogFileCtx *file_ctx;
    enum OutputStreamingType type;
    const char *log_dir;
} LogTcpDataFileCtx;

typedef struct LogTcpDataLogThread_ {
    LogTcpDataFileCtx *tcpdatalog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    MemBuffer *buffer;
} LogTcpDataLogThread;

int LogTcpDataLogger(ThreadVars *tv, void *thread_data, const Flow *f, const uint8_t *data, uint32_t data_len, uint8_t flags)
{
    SCEnter();
    LogTcpDataLogThread *aft = thread_data;
    LogTcpDataFileCtx *td = aft->tcpdatalog_ctx;
    char *mode = "a";

    if (flags & OUTPUT_STREAMING_FLAG_OPEN)
        mode = "w";

    if (data && data_len) {
        char srcip[46] = "", dstip[46] = "";
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)f->src.addr_data32, srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)f->dst.addr_data32, dstip, sizeof(dstip));
        }

        char name[PATH_MAX];
        snprintf(name, sizeof(name), "%s/%s/%s_%u-%s_%u-%s.data",
                td->log_dir,
                td->type == STREAMING_HTTP_BODIES ? "http" : "tcp",
                srcip, f->sp, dstip, f->dp,
                flags & OUTPUT_STREAMING_FLAG_TOSERVER ? "ts" : "tc");

        FILE *fp = fopen(name, mode);
        BUG_ON(fp == NULL);

        // PrintRawDataFp(stdout, (uint8_t *)data, data_len);
        fwrite(data, data_len, 1, fp);

        fclose(fp);
    }
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTcpDataLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogTcpDataLogThread *aft = SCMalloc(sizeof(LogTcpDataLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTcpDataLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tcpdatalog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogTcpDataLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTcpDataLogThread *aft = (LogTcpDataLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogTcpDataLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogTcpDataLogExitPrintStats(ThreadVars *tv, void *data) {
    LogTcpDataLogThread *aft = (LogTcpDataLogThread *)data;
    if (aft == NULL) {
        return;
    }
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogTcpDataLogInitCtx(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogTcpDataFileCtx *tcpdatalog_ctx = SCMalloc(sizeof(LogTcpDataFileCtx));
    if (unlikely(tcpdatalog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(tcpdatalog_ctx, 0x00, sizeof(LogTcpDataFileCtx));

    tcpdatalog_ctx->file_ctx = file_ctx;

    if (conf && conf->name) {
        if (strcmp(conf->name, "tcp-data") == 0) {
            tcpdatalog_ctx->type = STREAMING_TCP_DATA;
        } else if (strcmp(conf->name, "http-body-data") == 0) {
            tcpdatalog_ctx->type = STREAMING_HTTP_BODIES;
        }
    }

    tcpdatalog_ctx->log_dir = ConfigGetLogDirectory();

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto parsererror;
    }

    output_ctx->data = tcpdatalog_ctx;
    output_ctx->DeInit = LogTcpDataLogDeInitCtx;

    SCLogDebug("Streaming log output initialized");
    return output_ctx;

parsererror:
    LogFileFreeCtx(file_ctx);
    SCFree(tcpdatalog_ctx);
    SCLogError(SC_ERR_INVALID_ARGUMENT,"Syntax error in custom http log format string.");
    return NULL;

}

static void LogTcpDataLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTcpDataFileCtx *tcpdatalog_ctx = (LogTcpDataFileCtx *)output_ctx->data;
    LogFileFreeCtx(tcpdatalog_ctx->file_ctx);
    SCFree(tcpdatalog_ctx);
    SCFree(output_ctx);
}
