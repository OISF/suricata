/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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
 * Implements http logging portion of the engine.
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

#include "util-debug.h"

#include "output.h"
#include "log-httplog.h"
#include "app-layer-htp.h"
#include <htp/dslib.h>
#include "app-layer.h"
#include "util-privs.h"

#define DEFAULT_LOG_FILENAME "http.log"

#define MODULE_NAME "LogHttpLog"

TmEcode LogHttpLog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttpLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttpLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttpLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogHttpLogThreadDeinit(ThreadVars *, void *);
void LogHttpLogExitPrintStats(ThreadVars *, void *);
int LogHttpLogOpenFileCtx(LogFileCtx* , const char *);
static void LogHttpLogDeInitCtx(OutputCtx *);

void TmModuleLogHttpLogRegister (void) {
    tmm_modules[TMM_LOGHTTPLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGHTTPLOG].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG].Func = LogHttpLog;
    tmm_modules[TMM_LOGHTTPLOG].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGHTTPLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "http-log", LogHttpLogInitCtx);
}

void TmModuleLogHttpLogIPv4Register (void) {
    tmm_modules[TMM_LOGHTTPLOG4].name = "LogHttpLogIPv4";
    tmm_modules[TMM_LOGHTTPLOG4].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG4].Func = LogHttpLogIPv4;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG4].RegisterTests = NULL;
}

void TmModuleLogHttpLogIPv6Register (void) {
    tmm_modules[TMM_LOGHTTPLOG6].name = "LogHttpLogIPv6";
    tmm_modules[TMM_LOGHTTPLOG6].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG6].Func = LogHttpLogIPv6;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG6].RegisterTests = NULL;
}

typedef struct LogHttpLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;
} LogHttpLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = gmtime_r(&time, &local_tm);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

TmEcode LogHttpLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    SCEnter();
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    char timebuf[64];
    size_t idx = 0;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have HTTP state or not */
    SCMutexLock(&p->flow->m);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_HTTP)
        goto end;

    HtpState *htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    if (htp_state->connp == NULL)
        goto end;

    if (!(htp_state->flags & HTP_FLAG_NEW_REQUEST)) {
        SCLogDebug("no new http request , so no request logging");
        goto end;
    }
    htp_tx_t *tx = NULL;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[16], dstip[16];
    Port sp;
    Port dp;
    if ((PKT_IS_TOSERVER(p))) {
        inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
        sp = p->sp;
        dp = p->dp;
    } else {
        inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
        sp = p->dp;
        dp = p->sp;
    }

    SCMutexLock(&aft->file_ctx->fp_mutex);
    for (idx = htp_state->new_in_tx_index;
         idx < list_size(htp_state->connp->conn->transactions); idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        SCLogDebug("got a HTTP request and now logging !!");
        /* time */
        fprintf(aft->file_ctx->fp, "%s ", timebuf);

        /* hostname */
        if (tx->parsed_uri != NULL &&
                tx->parsed_uri->hostname != NULL)
        {
            PrintRawUriFp(aft->file_ctx->fp,
                    (uint8_t *)bstr_ptr(tx->parsed_uri->hostname),
                    bstr_len(tx->parsed_uri->hostname));
        } else {
            fprintf(aft->file_ctx->fp, "<hostname unknown>");
        }
        fprintf(aft->file_ctx->fp, " [**] ");

        /* uri */
        if (tx->request_uri != NULL) {
            PrintRawUriFp(aft->file_ctx->fp,
                            (uint8_t *)bstr_ptr(tx->request_uri),
                            bstr_len(tx->request_uri));
        }
        fprintf(aft->file_ctx->fp, " [**] ");

        /* user agent */
        htp_header_t *h_user_agent = table_getc(tx->request_headers, "user-agent");
        if (h_user_agent != NULL) {
            PrintRawUriFp(aft->file_ctx->fp,
                            (uint8_t *)bstr_ptr(h_user_agent->value),
                            bstr_len(h_user_agent->value));
        } else {
            fprintf(aft->file_ctx->fp, "<useragent unknown>");
        }

        /* ip/tcp header info */
        fprintf(aft->file_ctx->fp, " [**] %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
                srcip, sp, dstip, dp);

        aft->uri_cnt ++;
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    htp_state->flags &= ~HTP_FLAG_NEW_REQUEST;
end:
    SCMutexUnlock(&p->flow->m);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    SCEnter();
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    char timebuf[64];
    size_t idx = 0;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have HTTP state or not */
    SCMutexLock(&p->flow->m);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_HTTP)
        goto end;

    HtpState *htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    if (htp_state->connp == NULL)
        goto end;

    if (!(htp_state->flags & HTP_FLAG_NEW_REQUEST)) {
        SCLogDebug("no new http request , so no request logging");
        goto end;
    }
    htp_tx_t *tx = NULL;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp;
    Port dp;

    if ((PKT_IS_TOSERVER(p))) {
        inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
        sp = p->sp;
        dp = p->dp;
    } else {
        inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
        sp = p->dp;
        dp = p->sp;
    }
    SCMutexLock(&aft->file_ctx->fp_mutex);
    for (idx = htp_state->new_in_tx_index;
         idx < list_size(htp_state->connp->conn->transactions); idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        SCLogDebug("got a HTTP request and now logging !!");
        /* time */
        fprintf(aft->file_ctx->fp, "%s ", timebuf);

        /* hostname */
        if (tx->parsed_uri != NULL &&
                tx->parsed_uri->hostname != NULL)
        {
            PrintRawUriFp(aft->file_ctx->fp,
                    (uint8_t *)bstr_ptr(tx->parsed_uri->hostname),
                    bstr_len(tx->parsed_uri->hostname));
        } else {
            fprintf(aft->file_ctx->fp, "<hostname unknown>");
        }
        fprintf(aft->file_ctx->fp, " [**] ");

        /* uri */
        if (tx->request_uri != NULL) {
            PrintRawUriFp(aft->file_ctx->fp,
                            (uint8_t *)bstr_ptr(tx->request_uri),
                            bstr_len(tx->request_uri));
        }
        fprintf(aft->file_ctx->fp, " [**] ");

        /* user agent */
        htp_header_t *h_user_agent = table_getc(tx->request_headers, "user-agent");
        if (h_user_agent != NULL) {
            PrintRawUriFp(aft->file_ctx->fp,
                            (uint8_t *)bstr_ptr(h_user_agent->value),
                            bstr_len(h_user_agent->value));
        } else {
            fprintf(aft->file_ctx->fp, "<useragent unknown>");
        }

        /* ip/tcp header info */
        fprintf(aft->file_ctx->fp, " [**] %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
                srcip, sp, dstip, dp);

        aft->uri_cnt++;
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    htp_state->flags &= ~HTP_FLAG_NEW_REQUEST;
end:
    SCMutexUnlock(&p->flow->m);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
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
        SCReturnInt(LogHttpLogIPv4(tv, p, data, pq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogHttpLogIPv6(tv, p, data, pq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogHttpLogThread *aft = SCMalloc(sizeof(LogHttpLogThread));
    if (aft == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aft, 0, sizeof(LogHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogHttpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogHttpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogHttpLogExitPrintStats(ThreadVars *tv, void *data) {
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) HTTP requests %" PRIu32 "", tv->name, aft->uri_cnt);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogHttpLogInitCtx(ConfNode *conf)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "LogHttpLogInitCtx: Couldn't "
                   "create new file_ctx");
        return NULL;
    }

    const char *filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;

    /** fill the new LogFileCtx with the specific LogHttpLog configuration */
    ret=LogHttpLogOpenFileCtx(file_ctx, filename);

    if(ret < 0)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate OutputCtx for LogHttpLog");
        exit(EXIT_FAILURE);
    }
    output_ctx->data = file_ctx;
    output_ctx->DeInit = LogHttpLogDeInitCtx;

    return output_ctx;
}

static void LogHttpLogDeInitCtx(OutputCtx *output_ctx)
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
int LogHttpLogOpenFileCtx(LogFileCtx *file_ctx, const char *filename)
{
    char log_path[PATH_MAX], *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);

    file_ctx->fp = fopen(log_path, "w");

    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", log_path,
            strerror(errno));
        return -1;
    }

    return 0;
}


