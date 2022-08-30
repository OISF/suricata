/* Copyright (C) 2014-2022 Open Information Security Foundation
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

TmEcode LogTcpDataLogThreadInit(ThreadVars *, const void *, void **);
TmEcode LogTcpDataLogThreadDeinit(ThreadVars *, void *);
static void LogTcpDataLogDeInitCtx(OutputCtx *);

int LogTcpDataLogger(ThreadVars *tv, void *thread_data, const Flow *f, const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags);

void LogTcpDataLogRegister (void) {
    OutputRegisterStreamingModule(LOGGER_TCP_DATA, MODULE_NAME, "tcp-data",
        LogTcpDataLogInitCtx, LogTcpDataLogger, STREAMING_TCP_DATA,
        LogTcpDataLogThreadInit, LogTcpDataLogThreadDeinit, NULL);
    OutputRegisterStreamingModule(LOGGER_TCP_DATA, MODULE_NAME, "http-body-data",
        LogTcpDataLogInitCtx, LogTcpDataLogger, STREAMING_HTTP_BODIES,
        LogTcpDataLogThreadInit, LogTcpDataLogThreadDeinit, NULL);
}

typedef struct LogTcpDataFileCtx_ {
    LogFileCtx *file_ctx;
    enum OutputStreamingType type;
    const char *log_dir;
    int file;
    int dir;
} LogTcpDataFileCtx;

typedef struct LogTcpDataLogThread_ {
    LogTcpDataFileCtx *tcpdatalog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    MemBuffer *buffer;
} LogTcpDataLogThread;

static int LogTcpDataLoggerDir(ThreadVars *tv, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    SCEnter();
    LogTcpDataLogThread *aft = thread_data;
    LogTcpDataFileCtx *td = aft->tcpdatalog_ctx;
    const char *mode = "a";

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

        char tx[64] = { 0 };
        if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION) {
            snprintf(tx, sizeof(tx), "%"PRIu64, tx_id);
        }

        snprintf(name, sizeof(name), "%s/%s/%s_%u-%s_%u-%s-%s.data",
                td->log_dir,
                td->type == STREAMING_HTTP_BODIES ? "http" : "tcp",
                srcip, f->sp, dstip, f->dp, tx,
                flags & OUTPUT_STREAMING_FLAG_TOSERVER ? "ts" : "tc");

        FILE *fp = fopen(name, mode);
        BUG_ON(fp == NULL);

        // PrintRawDataFp(stdout, (uint8_t *)data, data_len);
        fwrite(data, data_len, 1, fp);

        fclose(fp);
    }
    SCReturnInt(TM_ECODE_OK);
}

static int LogTcpDataLoggerFile(ThreadVars *tv, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    SCEnter();
    LogTcpDataLogThread *aft = thread_data;
    LogTcpDataFileCtx *td = aft->tcpdatalog_ctx;

    if (data && data_len) {
        MemBufferReset(aft->buffer);

        char srcip[46] = "", dstip[46] = "";
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)f->src.addr_data32, srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)f->dst.addr_data32, dstip, sizeof(dstip));
        }

        char name[PATH_MAX];
        snprintf(name, sizeof(name), "%s_%u-%s_%u-%s:",
                srcip, f->sp, dstip, f->dp,
                flags & OUTPUT_STREAMING_FLAG_TOSERVER ? "ts" : "tc");

        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                aft->buffer->size, (uint8_t *)name,strlen(name));
        MemBufferWriteString(aft->buffer, "\n");

        PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset,
                aft->buffer->size, (uint8_t *)data,data_len);

        td->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
                MEMBUFFER_OFFSET(aft->buffer), td->file_ctx);
    }
    SCReturnInt(TM_ECODE_OK);
}

int LogTcpDataLogger(ThreadVars *tv, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    SCEnter();
    LogTcpDataLogThread *aft = thread_data;
    LogTcpDataFileCtx *td = aft->tcpdatalog_ctx;

    if (td->dir == 1)
        LogTcpDataLoggerDir(tv, thread_data, f, data, data_len, tx_id, flags);
    if (td->file == 1)
        LogTcpDataLoggerFile(tv, thread_data, f, data, data_len, tx_id, flags);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTcpDataLogThreadInit(ThreadVars *t, const void *initdata, void **data)
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

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputInitResult LogTcpDataLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    char filename[PATH_MAX] = "";
    char dirname[32] = "";
    strlcpy(filename, DEFAULT_LOG_FILENAME, sizeof(filename));

    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_TCPDATA_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    LogTcpDataFileCtx *tcpdatalog_ctx = SCMalloc(sizeof(LogTcpDataFileCtx));
    if (unlikely(tcpdatalog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }
    memset(tcpdatalog_ctx, 0x00, sizeof(LogTcpDataFileCtx));

    tcpdatalog_ctx->file_ctx = file_ctx;

    if (conf) {
        if (conf->name) {
            if (strcmp(conf->name, "tcp-data") == 0) {
                tcpdatalog_ctx->type = STREAMING_TCP_DATA;
                snprintf(filename, sizeof(filename), "%s.log", conf->name);
                strlcpy(dirname, "tcp", sizeof(dirname));
            } else if (strcmp(conf->name, "http-body-data") == 0) {
                tcpdatalog_ctx->type = STREAMING_HTTP_BODIES;
                snprintf(filename, sizeof(filename), "%s.log", conf->name);
                strlcpy(dirname, "http", sizeof(dirname));
            }
        }

        const char *logtype = ConfNodeLookupChildValue(conf, "type");
        if (logtype == NULL)
            logtype = "file";

        if (strcmp(logtype, "file") == 0) {
            tcpdatalog_ctx->file = 1;
        } else if (strcmp(logtype, "dir") == 0) {
            tcpdatalog_ctx->dir = 1;
        } else if (strcmp(logtype, "both") == 0) {
            tcpdatalog_ctx->file = 1;
            tcpdatalog_ctx->dir = 1;
        }
    } else {
        tcpdatalog_ctx->file = 1;
        tcpdatalog_ctx->dir = 0;
    }

    if (tcpdatalog_ctx->file == 1) {
        SCLogInfo("opening logfile");
        if (SCConfLogOpenGeneric(conf, file_ctx, filename, 1) < 0) {
            LogFileFreeCtx(file_ctx);
            SCFree(tcpdatalog_ctx);
            return result;
        }
    }

    if (tcpdatalog_ctx->dir == 1) {
        tcpdatalog_ctx->log_dir = ConfigGetLogDirectory();
        char dirfull[PATH_MAX];

        /* create the filename to use */
        snprintf(dirfull, PATH_MAX, "%s/%s", tcpdatalog_ctx->log_dir, dirname);

        SCLogInfo("using directory %s", dirfull);

        /* if mkdir fails file open will fail, so deal with errors there */
        (void)SCMkDir(dirfull, 0700);
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto parsererror;
    }

    output_ctx->data = tcpdatalog_ctx;
    output_ctx->DeInit = LogTcpDataLogDeInitCtx;

    SCLogDebug("Streaming log output initialized");
    result.ctx = output_ctx;
    result.ok = true;
    return result;

parsererror:
    LogFileFreeCtx(file_ctx);
    SCFree(tcpdatalog_ctx);
    SCLogError(SC_ERR_INVALID_ARGUMENT,"Syntax error in custom http log format string.");
    return result;

}

static void LogTcpDataLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTcpDataFileCtx *tcpdatalog_ctx = (LogTcpDataFileCtx *)output_ctx->data;
    LogFileFreeCtx(tcpdatalog_ctx->file_ctx);
    SCFree(tcpdatalog_ctx);
    SCFree(output_ctx);
}
