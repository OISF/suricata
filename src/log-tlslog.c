/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Implements TLS logging portion of the engine.
 */

#include "suricata-common.h"
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
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"
#include "log-cf-common.h"

#define DEFAULT_LOG_FILENAME "tls.log"

#define MODULE_NAME "LogTlsLog"

#define PRINT_BUF_LEN 46

#define OUTPUT_BUFFER_SIZE   65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT  0
#define LOG_TLS_EXTENDED 1
#define LOG_TLS_CUSTOM   2

#define LOG_TLS_SESSION_RESUMPTION 4

#define LOG_TLS_CF_VERSION         'v'
#define LOG_TLS_CF_DATE_NOT_BEFORE 'd'
#define LOG_TLS_CF_DATE_NOT_AFTER  'D'
#define LOG_TLS_CF_SHA1            'f'
#define LOG_TLS_CF_SNI             'n'
#define LOG_TLS_CF_SUBJECT         's'
#define LOG_TLS_CF_ISSUER          'i'
#define LOG_TLS_CF_EXTENDED        'E'

typedef struct LogTlsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;  /** Store mode */
    LogCustomFormat *cf;
} LogTlsFileCtx;

typedef struct LogTlsLogThread_ {
    LogTlsFileCtx *tlslog_ctx;

    /* LogTlsFileCtx has the pointer to the file and a mutex to allow
       multithreading. */
    uint32_t tls_cnt;

    MemBuffer *buffer;
} LogTlsLogThread;

int TLSGetIPInformations(const Packet *p, char* srcip, size_t srcip_len,
                         Port* sp, char* dstip, size_t dstip_len, Port* dp,
                         int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p),
                          srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p),
                          dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip,
                          srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip,
                          dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->sp;
        *dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p),
                          srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p),
                          dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip,
                          srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip,
                          dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->dp;
        *dp = p->sp;
    }
    return 1;
}

static TmEcode LogTlsLogThreadInit(ThreadVars *t, const void *initdata,
                                   void **data)
{
    LogTlsLogThread *aft = SCMalloc(sizeof(LogTlsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    memset(aft, 0, sizeof(LogTlsLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for TLSLog. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *) initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogTlsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    memset(aft, 0, sizeof(LogTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogTlsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    LogCustomFormatFree(tlslog_ctx->cf);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}

static void LogTlsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("TLS logger logged %" PRIu32 " requests", aft->tls_cnt);
}

/** \brief Create a new tls log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputInitResult LogTlsLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsLogInitCtx: Couldn't "
                   "create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        goto filectx_error;
    }

    LogTlsFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsFileCtx));
    if (unlikely(tlslog_ctx == NULL)) {
        goto filectx_error;
    }
    tlslog_ctx->file_ctx = file_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    const char *custom = ConfNodeLookupChildValue(conf, "custom");
    const char *customformat = ConfNodeLookupChildValue(conf, "customformat");

    /* If custom logging format is selected, lets parse it */
    if (custom != NULL && customformat != NULL && ConfValIsTrue(custom)) {
        tlslog_ctx->cf = LogCustomFormatAlloc();
        if (!tlslog_ctx->cf) {
            goto tlslog_error;
        }

        tlslog_ctx->flags |= LOG_TLS_CUSTOM;

        if (!LogCustomFormatParse(tlslog_ctx->cf, customformat)) {
            goto parser_error;
        }
    } else {
        if (extended == NULL) {
            tlslog_ctx->flags |= LOG_TLS_DEFAULT;
        } else {
            if (ConfValIsTrue(extended)) {
                tlslog_ctx->flags |= LOG_TLS_EXTENDED;
            }
        }
    }

    const char *resumption = ConfNodeLookupChildValue(conf,
                                                      "session-resumption");
    if (resumption == NULL || ConfValIsTrue(resumption)) {
        tlslog_ctx->flags |= LOG_TLS_SESSION_RESUMPTION;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto tlslog_error;
    }
    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsLogDeInitCtx;

    SCLogDebug("TLS log output initialized");

    /* Enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;

parser_error:
    SCLogError(SC_ERR_INVALID_ARGUMENT, "Syntax error in custom tls log "
               "format string.");
tlslog_error:
    LogCustomFormatFree(tlslog_ctx->cf);
    SCFree(tlslog_ctx);
filectx_error:
    LogFileFreeCtx(file_ctx);
    return result;
}

static void LogTlsLogVersion(MemBuffer *buffer, uint16_t version)
{
    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(version, ssl_version);
    MemBufferWriteString(buffer, "VERSION='%s'", ssl_version);
}

static void LogTlsLogDate(MemBuffer *buffer, const char *title, time_t *date)
{
    char timebuf[64] = {0};
    struct timeval tv;
    tv.tv_sec = *date;
    tv.tv_usec = 0;
    CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
    MemBufferWriteString(buffer, "%s='%s'", title, timebuf);
}

static void LogTlsLogString(MemBuffer *buffer, const char *title,
                            const char *value)
{
    MemBufferWriteString(buffer, "%s='%s'", title, value);
}

static void LogTlsLogBasic(LogTlsLogThread *aft, SSLState *ssl_state,
                           const struct timeval *ts, char *srcip, Port sp,
                           char *dstip, Port dp)
{
    char timebuf[64];
    CreateTimeString(ts, timebuf, sizeof(timebuf));
    MemBufferWriteString(aft->buffer,
                         "%s %s:%d -> %s:%d  TLS:",
                         timebuf, srcip, sp, dstip, dp);

    if (ssl_state->server_connp.cert0_subject != NULL) {
        MemBufferWriteString(aft->buffer, " Subject='%s'",
        ssl_state->server_connp.cert0_subject);
    }

    if (ssl_state->server_connp.cert0_issuerdn != NULL) {
        MemBufferWriteString(aft->buffer, " Issuerdn='%s'",
                             ssl_state->server_connp.cert0_issuerdn);
    }

    if (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) {
        /* Only log a session as 'resumed' if a certificate has not
           been seen. */
        if ((ssl_state->server_connp.cert0_issuerdn == NULL) &&
                (ssl_state->server_connp.cert0_subject == NULL) &&
                (ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
                ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
            MemBufferWriteString(aft->buffer, " Session='resumed'");
        }
    }
}

static void LogTlsLogExtended(LogTlsLogThread *aft, SSLState *ssl_state,
                              const struct timeval *ts, char *srcip, Port sp,
                              char *dstip, Port dp)
{
    if (ssl_state->server_connp.cert0_fingerprint != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SHA1",
                        ssl_state->server_connp.cert0_fingerprint);
    }
    if (ssl_state->client_connp.sni != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SNI", ssl_state->client_connp.sni);
    }
    if (ssl_state->server_connp.cert0_serial != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SERIAL",
                        ssl_state->server_connp.cert0_serial);
    }

    LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
    LogTlsLogVersion(aft->buffer, ssl_state->server_connp.version);

    if (ssl_state->server_connp.cert0_not_before != 0) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogDate(aft->buffer, "NOTBEFORE",
                      &ssl_state->server_connp.cert0_not_before);
    }
    if (ssl_state->server_connp.cert0_not_after != 0) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogDate(aft->buffer, "NOTAFTER",
                      &ssl_state->server_connp.cert0_not_after);
    }
}

/* Custom format logging */
static void LogTlsLogCustom(LogTlsLogThread *aft, SSLState *ssl_state,
                            const struct timeval *ts, char *srcip, Port sp,
                            char *dstip, Port dp)
{
    LogTlsFileCtx *tlslog_ctx = aft->tlslog_ctx;
    uint32_t i;
    char buf[64];

    for (i = 0; i < tlslog_ctx->cf->cf_n; i++)
    {
        LogCustomFormatNode *node = tlslog_ctx->cf->cf_nodes[i];
        if (!node) /* Should never happen */
            continue;

        switch (node->type) {
            case LOG_CF_LITERAL:
            /* LITERAL */
                MemBufferWriteString(aft->buffer, "%s", node->data);
                break;
            case LOG_CF_TIMESTAMP:
            /* TIMESTAMP */
                LogCustomFormatWriteTimestamp(aft->buffer, node->data, ts);
                break;
            case LOG_CF_TIMESTAMP_U:
            /* TIMESTAMP USECONDS */
                snprintf(buf, sizeof(buf), "%06u", (unsigned int) ts->tv_usec);
                PrintRawUriBuf((char *)aft->buffer->buffer,
                               &aft->buffer->offset,
                               aft->buffer->size, (uint8_t *)buf,
                               MIN(strlen(buf),6));
                break;
            case LOG_CF_CLIENT_IP:
            /* CLIENT IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer,
                               &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)srcip,strlen(srcip));
                break;
            case LOG_CF_SERVER_IP:
            /* SERVER IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer,
                               &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)dstip, strlen(dstip));
                break;
            case LOG_CF_CLIENT_PORT:
            /* CLIENT PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", sp);
                break;
            case LOG_CF_SERVER_PORT:
            /* SERVER PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", dp);
                break;
            case LOG_TLS_CF_VERSION:
                LogTlsLogVersion(aft->buffer, ssl_state->server_connp.version);
                break;
            case LOG_TLS_CF_DATE_NOT_BEFORE:
                LogTlsLogDate(aft->buffer, "NOTBEFORE",
                              &ssl_state->server_connp.cert0_not_before);
                break;
            case LOG_TLS_CF_DATE_NOT_AFTER:
                LogTlsLogDate(aft->buffer, "NOTAFTER",
                              &ssl_state->server_connp.cert0_not_after);
                break;
            case LOG_TLS_CF_SHA1:
                if (ssl_state->server_connp.cert0_fingerprint != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                            ssl_state->server_connp.cert0_fingerprint);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_SNI:
                if (ssl_state->client_connp.sni != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                                         ssl_state->client_connp.sni);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_SUBJECT:
                if (ssl_state->server_connp.cert0_subject != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                            ssl_state->server_connp.cert0_subject);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_ISSUER:
                if (ssl_state->server_connp.cert0_issuerdn != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                            ssl_state->server_connp.cert0_issuerdn);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_EXTENDED:
            /* Extended format  */
                LogTlsLogExtended(aft, ssl_state, ts, srcip, sp, dstip, dp);
                break;
            default:
            /* NO MATCH */
                MemBufferWriteString(aft->buffer, LOG_CF_NONE);
                SCLogDebug("No matching parameter %%%c for custom tls log.",
                           node->type);
                break;
        }
    }
}


static int LogTlsLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                        Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogTlsLogThread *aft = (LogTlsLogThread *)thread_data;
    LogTlsFileCtx *hlog = aft->tlslog_ctx;
    int ipproto = (PKT_IS_IPV4(p)) ? AF_INET : AF_INET6;

    SSLState *ssl_state = (SSLState *)state;
    if (unlikely(ssl_state == NULL)) {
        return 0;
    }

    if (((hlog->flags & LOG_TLS_SESSION_RESUMPTION) == 0 ||
            (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) == 0) &&
            (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
        return 0;
    }

    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];

    Port sp, dp;
    if (!TLSGetIPInformations(p, srcip, PRINT_BUF_LEN, &sp, dstip,
                              PRINT_BUF_LEN, &dp, ipproto)) {
        return 0;
    }

    MemBufferReset(aft->buffer);

    if (hlog->flags & LOG_TLS_CUSTOM) {
        LogTlsLogCustom(aft, ssl_state, &p->ts, srcip, sp, dstip, dp);
    } else if (hlog->flags & LOG_TLS_EXTENDED) {
        LogTlsLogBasic(aft, ssl_state, &p->ts, srcip, sp, dstip, dp);
        LogTlsLogExtended(aft, ssl_state, &p->ts, srcip, sp, dstip, dp);
    } else {
        LogTlsLogBasic(aft, ssl_state, &p->ts, srcip, sp, dstip, dp);
    }

    MemBufferWriteString(aft->buffer, "\n");

    aft->tls_cnt++;

    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);

    return 0;
}

void LogTlsLogRegister(void)
{
    OutputRegisterTxModuleWithProgress(LOGGER_TLS, MODULE_NAME, "tls-log",
        LogTlsLogInitCtx, ALPROTO_TLS, LogTlsLogger, TLS_HANDSHAKE_DONE,
        TLS_HANDSHAKE_DONE, LogTlsLogThreadInit, LogTlsLogThreadDeinit,
        LogTlsLogExitPrintStats);
}
