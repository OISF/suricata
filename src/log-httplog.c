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
 * Implements http logging portion of the engine.
 */

#include <htp/dslib.h>

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
#include "log-httplog.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "util-privs.h"

#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "http.log"

#define MODULE_NAME "LogHttpLog"

TmEcode LogHttpLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogHttpLogThreadDeinit(ThreadVars *, void *);
void LogHttpLogExitPrintStats(ThreadVars *, void *);
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

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_HTTP);
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

typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogHttpFileCtx;

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1

typedef struct LogHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;
} LogHttpLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogHttpLogExtended(LogHttpFileCtx * hlog, htp_tx_t *tx)
{
    fprintf(hlog->file_ctx->fp, " [**] ");

    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = table_getc(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        PrintRawUriFp(hlog->file_ctx->fp,
                (uint8_t *)bstr_ptr(h_referer->value),
                bstr_len(h_referer->value));
    } else {
        fprintf(hlog->file_ctx->fp, "<no referer>");
    }
    fprintf(hlog->file_ctx->fp, " [**] ");

    /* method */
    if (tx->request_method != NULL) {
        PrintRawUriFp(hlog->file_ctx->fp,
                (uint8_t *)bstr_ptr(tx->request_method),
                bstr_len(tx->request_method));
    }
    fprintf(hlog->file_ctx->fp, " [**] ");

    /* protocol */
    if (tx->request_protocol != NULL) {
        PrintRawUriFp(hlog->file_ctx->fp,
                (uint8_t *)bstr_ptr(tx->request_protocol),
                bstr_len(tx->request_protocol));
    } else {
        fprintf(hlog->file_ctx->fp, "<no protocol>");
    }
    fprintf(hlog->file_ctx->fp, " [**] ");

    /* response status */
    if (tx->response_status != NULL) {
        PrintRawUriFp(hlog->file_ctx->fp,
                (uint8_t *)bstr_ptr(tx->response_status),
                bstr_len(tx->response_status));
        /* Redirect? */
        if ((tx->response_status_number > 300) && ((tx->response_status_number) < 303)) {
            htp_header_t *h_location = table_getc(tx->response_headers, "location");
            if (h_location != NULL) {
                fprintf(hlog->file_ctx->fp, " => ");
                PrintRawUriFp(hlog->file_ctx->fp,
                        (uint8_t *)bstr_ptr(h_location->value),
                        bstr_len(h_location->value));
            }
        }
    } else {
        fprintf(hlog->file_ctx->fp, "<no status>");
    }

    /* length */
    fprintf(hlog->file_ctx->fp, " [**] %"PRIuMAX" bytes", (uintmax_t)tx->response_message_len);
}

static TmEcode LogHttpLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    LogHttpFileCtx *hlog = aft->httplog_ctx;
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

    int r = AppLayerTransactionGetLoggedId(p->flow);
    if (r < 0) {
        goto end;
    }
    size_t logged = (size_t)r;

    r = HtpTransactionGetLoggableId(p->flow);
    if (r < 0) {
        goto end;
    }
    size_t loggable = (size_t)r;

    /* nothing to do */
    if (logged >= loggable) {
        goto end;
    }

    HtpState *htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    if (htp_state->connp == NULL || htp_state->connp->conn == NULL)
        goto end;

    htp_tx_t *tx = NULL;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    for (idx = logged; idx < loggable; idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        /* output now starting, so get output lock */
        SCMutexLock(&hlog->file_ctx->fp_mutex);

        SCLogDebug("got a HTTP request and now logging !!");
        /* time */
        fprintf(hlog->file_ctx->fp, "%s ", timebuf);

        /* hostname */
        if (tx->parsed_uri != NULL &&
                tx->parsed_uri->hostname != NULL)
        {
            PrintRawUriFp(hlog->file_ctx->fp,
                    (uint8_t *)bstr_ptr(tx->parsed_uri->hostname),
                    bstr_len(tx->parsed_uri->hostname));
        } else {
            fprintf(hlog->file_ctx->fp, "<hostname unknown>");
        }
        fprintf(hlog->file_ctx->fp, " [**] ");

        /* uri */
        if (tx->request_uri != NULL) {
            PrintRawUriFp(hlog->file_ctx->fp,
                            (uint8_t *)bstr_ptr(tx->request_uri),
                            bstr_len(tx->request_uri));
        }
        fprintf(hlog->file_ctx->fp, " [**] ");

        /* user agent */
        htp_header_t *h_user_agent = NULL;
        if (tx->request_headers != NULL) {
            h_user_agent = table_getc(tx->request_headers, "user-agent");
        }
        if (h_user_agent != NULL) {
            PrintRawUriFp(hlog->file_ctx->fp,
                            (uint8_t *)bstr_ptr(h_user_agent->value),
                            bstr_len(h_user_agent->value));
        } else {
            fprintf(hlog->file_ctx->fp, "<useragent unknown>");
        }
        if (hlog->flags & LOG_HTTP_EXTENDED) {
            LogHttpLogExtended(hlog, tx);
        }

        /* ip/tcp header info */
        fprintf(hlog->file_ctx->fp, " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
                srcip, sp, dstip, dp);

        aft->uri_cnt ++;
        fflush(hlog->file_ctx->fp);
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);

        AppLayerTransactionUpdateLoggedId(p->flow);
    }

end:
    SCMutexUnlock(&p->flow->m);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode LogHttpLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogHttpLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogHttpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        SCReturnInt(LogHttpLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogHttpLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogHttpLogThread *aft = SCMalloc(sizeof(LogHttpLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /* Use the Ouptut Context (file pointer and mutex) */
    aft->httplog_ctx= ((OutputCtx *)initdata)->data;

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

    SCLogInfo("HTTP logger logged %" PRIu32 " requests", aft->uri_cnt);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogHttpLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogHttpFileCtx *httplog_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (httplog_ctx == NULL) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(httplog_ctx, 0x00, sizeof(LogHttpFileCtx));

    httplog_ctx->file_ctx = file_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended == NULL) {
        httplog_ctx->flags |= LOG_HTTP_DEFAULT;
    } else {
        if (ConfValIsTrue(extended)) {
            httplog_ctx->flags |= LOG_HTTP_EXTENDED;
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL) {
        LogFileFreeCtx(file_ctx);
        SCFree(httplog_ctx);
        return NULL;
    }

    output_ctx->data = httplog_ctx;
    output_ctx->DeInit = LogHttpLogDeInitCtx;

    SCLogDebug("HTTP log output initialized");

    return output_ctx;
}

static void LogHttpLogDeInitCtx(OutputCtx *output_ctx)
{
    LogHttpFileCtx *httplog_ctx = (LogHttpFileCtx *)output_ctx->data;
    LogFileFreeCtx(httplog_ctx->file_ctx);
    SCFree(httplog_ctx);
    SCFree(output_ctx);
}
