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
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 * \author Eric Leblond <eric@regit.org>
 *
 * Implements tls logging portion of the engine.
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
#include "log-tlslog.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "tls.log"

#define MODULE_NAME "LogTlsLog"

#define OUTPUT_BUFFER_SIZE 65535

TmEcode LogTlsLog(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogTlsLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogTlsLogThreadDeinit(ThreadVars *, void *);
void LogTlsLogExitPrintStats(ThreadVars *, void *);
static void LogTlsLogDeInitCtx(OutputCtx *);

void TmModuleLogTlsLogRegister(void)
{
    tmm_modules[TMM_LOGTLSLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSLOG].ThreadInit = LogTlsLogThreadInit;
    tmm_modules[TMM_LOGTLSLOG].Func = LogTlsLog;
    tmm_modules[TMM_LOGTLSLOG].ThreadExitPrintStats = LogTlsLogExitPrintStats;
    tmm_modules[TMM_LOGTLSLOG].ThreadDeinit = LogTlsLogThreadDeinit;
    tmm_modules[TMM_LOGTLSLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "tls-log", LogTlsLogInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_TLS);
}

void TmModuleLogTlsLogIPv4Register(void)
{
    tmm_modules[TMM_LOGTLSLOG4].name = "LogTlsLogIPv4";
    tmm_modules[TMM_LOGTLSLOG4].ThreadInit = LogTlsLogThreadInit;
    tmm_modules[TMM_LOGTLSLOG4].Func = LogTlsLogIPv4;
    tmm_modules[TMM_LOGTLSLOG4].ThreadExitPrintStats = LogTlsLogExitPrintStats;
    tmm_modules[TMM_LOGTLSLOG4].ThreadDeinit = LogTlsLogThreadDeinit;
    tmm_modules[TMM_LOGTLSLOG4].RegisterTests = NULL;
}

void TmModuleLogTlsLogIPv6Register(void)
{
    tmm_modules[TMM_LOGTLSLOG6].name = "LogTlsLogIPv6";
    tmm_modules[TMM_LOGTLSLOG6].ThreadInit = LogTlsLogThreadInit;
    tmm_modules[TMM_LOGTLSLOG6].Func = LogTlsLogIPv6;
    tmm_modules[TMM_LOGTLSLOG6].ThreadExitPrintStats = LogTlsLogExitPrintStats;
    tmm_modules[TMM_LOGTLSLOG6].ThreadDeinit = LogTlsLogThreadDeinit;
    tmm_modules[TMM_LOGTLSLOG6].RegisterTests = NULL;
}

typedef struct LogTlsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogTlsFileCtx;


typedef struct LogTlsLogThread_ {
    LogTlsFileCtx *tlslog_ctx;
    /** LogTlsFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t tls_cnt;

    MemBuffer *buffer;
} LogTlsLogThread;

static void CreateTimeString(const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *) localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u", t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour, t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static TmEcode LogTlsLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto)
{

    SCEnter();
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    LogTlsFileCtx *hlog = aft->tlslog_ctx;

    char timebuf[64];

    /* no flow, no tls state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TLS)
        goto end;

    int r = AppLayerTransactionGetLoggedId(p->flow);

    if (r != 0) {
        goto end;
    }

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
        case AF_INET:
            PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
            break;
        case AF_INET6:
            PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
            break;
        default:
            goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
        case AF_INET:
            PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
            break;
        case AF_INET6:
            PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
            break;
        default:
            goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    MemBufferWriteString(aft->buffer,
                         "%s %s:%d -> %s:%d  TLS: Subject='%s' Issuerdn='%s'\n",
                         timebuf, srcip, sp, dstip, dp,
                         ssl_state->server_connp.cert0_subject, ssl_state->server_connp.cert0_issuerdn);

    AppLayerTransactionUpdateLoggedId(p->flow);

    aft->tls_cnt ++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
    MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
    fflush(hlog->file_ctx->fp);
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode LogTlsLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogTlsLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogTlsLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogTlsLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        SCReturnInt(LogTlsLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogTlsLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogTlsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogTlsLogThread *aft = SCMalloc(sizeof(LogTlsLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTlsLogThread));

    if (initdata == NULL) {
        SCLogDebug( "Error getting context for TLSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *) initdata)->data;

    *data = (void *) aft;
    return TM_ECODE_OK;
}

TmEcode LogTlsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogTlsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("TLS logger logged %" PRIu32 " requests", aft->tls_cnt);
}

/** \brief Create a new tls log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogTlsLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsLogInitCtx: Couldn't "
        "create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogTlsFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsFileCtx));
    if (tlslog_ctx == NULL)
        return NULL;
    tlslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsLogDeInitCtx;

    SCLogDebug("TLS log output initialized");

    return output_ctx;
}

static void LogTlsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}
