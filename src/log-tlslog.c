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
 *
 * Implements TLS logging portion of the engine. The TLS logger is
 * implemented as a packet logger, as the TLS parser is not transaction
 * aware.
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
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "tls.log"

#define MODULE_NAME "LogTlsLog"

#define OUTPUT_BUFFER_SIZE 65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    1

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

static void LogTlsLogExtended(LogTlsLogThread *aft, SSLState * state)
{
    if (state->server_connp.cert0_fingerprint != NULL) {
        MemBufferWriteString(aft->buffer, " SHA1='%s'", state->server_connp.cert0_fingerprint);
    }
    if (state->client_connp.sni != NULL) {
        MemBufferWriteString(aft->buffer, " SNI='%s'", state->client_connp.sni);
    }
    switch (state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
            MemBufferWriteString(aft->buffer, " VERSION='UNDETERMINED'");
            break;
        case SSL_VERSION_2:
            MemBufferWriteString(aft->buffer, " VERSION='SSLv2'");
            break;
        case SSL_VERSION_3:
            MemBufferWriteString(aft->buffer, " VERSION='SSLv3'");
            break;
        case TLS_VERSION_10:
            MemBufferWriteString(aft->buffer, " VERSION='TLSv1'");
            break;
        case TLS_VERSION_11:
            MemBufferWriteString(aft->buffer, " VERSION='TLS 1.1'");
            break;
        case TLS_VERSION_12:
            MemBufferWriteString(aft->buffer, " VERSION='TLS 1.2'");
            break;
        default:
            MemBufferWriteString(aft->buffer, " VERSION='0x%04x'",
                                 state->server_connp.version);
            break;
    }
    MemBufferWriteString(aft->buffer, "\n");
}

int TLSGetIPInformations(const Packet *p, char* srcip, size_t srcip_len,
                             Port* sp, char* dstip, size_t dstip_len,
                             Port* dp, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->sp;
        *dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->dp;
        *dp = p->sp;
    }
    return 1;
}

static TmEcode LogTlsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogTlsLogThread *aft = SCMalloc(sizeof(LogTlsLogThread));
    if (unlikely(aft == NULL))
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

static TmEcode LogTlsLogThreadDeinit(ThreadVars *t, void *data)
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

static void LogTlsLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputTlsLoggerDisable();

    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}

static void LogTlsLogExitPrintStats(ThreadVars *tv, void *data)
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
static OutputCtx *LogTlsLogInitCtx(ConfNode *conf)
{
    if (OutputTlsLoggerEnable() != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "only one 'tls' logger "
            "can be enabled");
        return NULL;
    }

    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsLogInitCtx: Couldn't "
        "create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        goto filectx_error;
    }

    LogTlsFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsFileCtx));
    if (unlikely(tlslog_ctx == NULL))
        goto filectx_error;
    tlslog_ctx->file_ctx = file_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended == NULL) {
        tlslog_ctx->flags |= LOG_TLS_DEFAULT;
    } else {
        if (ConfValIsTrue(extended)) {
            tlslog_ctx->flags |= LOG_TLS_EXTENDED;
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto tlslog_error;
    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsLogDeInitCtx;

    SCLogDebug("TLS log output initialized");

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    return output_ctx;

tlslog_error:
    SCFree(tlslog_ctx);
filectx_error:
    LogFileFreeCtx(file_ctx);
    return NULL;
}

/** \internal
 *  \brief Condition function for TLS logger
 *  \retval bool true or false -- log now?
 */
static int LogTlsCondition(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL) {
        return FALSE;
    }

    if (!(PKT_IS_TCP(p))) {
        return FALSE;
    }

    FLOWLOCK_RDLOCK(p->flow);
    uint16_t proto = FlowGetAppProtocol(p->flow);
    if (proto != ALPROTO_TLS)
        goto dontlog;

    SSLState *ssl_state = (SSLState *)FlowGetAppState(p->flow);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto dontlog;
    }

    /* we only log the state once if we don't have to write
     * the cert due to tls.store keyword. */
    if (!(ssl_state->server_connp.cert_log_flag & SSL_TLS_LOG_PEM) &&
        (ssl_state->flags & SSL_AL_FLAG_STATE_LOGGED))
        goto dontlog;

    if (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL)
        goto dontlog;

    /* todo: logic to log once */

    FLOWLOCK_UNLOCK(p->flow);
    return TRUE;
dontlog:
    FLOWLOCK_UNLOCK(p->flow);
    return FALSE;
}

static int LogTlsLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    LogTlsLogThread *aft = (LogTlsLogThread *)thread_data;
    LogTlsFileCtx *hlog = aft->tlslog_ctx;
    char timebuf[64];
    int ipproto = (PKT_IS_IPV4(p)) ? AF_INET : AF_INET6;

    if (unlikely(p->flow == NULL)) {
        return 0;
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = FlowGetAppProtocol(p->flow);
    if (proto != ALPROTO_TLS)
        goto end;

    SSLState *ssl_state = (SSLState *)FlowGetAppState(p->flow);
    if (unlikely(ssl_state == NULL)) {
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    /* Don't log again the state. If we are here it was because we had
     * to store the cert. */
    if (ssl_state->flags & SSL_AL_FLAG_STATE_LOGGED)
        goto end;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
#define PRINT_BUF_LEN 46
    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
    Port sp, dp;
    if (!TLSGetIPInformations(p, srcip, PRINT_BUF_LEN,
                              &sp, dstip, PRINT_BUF_LEN, &dp, ipproto)) {
        goto end;
    }

    MemBufferReset(aft->buffer);
    MemBufferWriteString(aft->buffer,
                         "%s %s:%d -> %s:%d  TLS: Subject='%s' Issuerdn='%s'",
                         timebuf, srcip, sp, dstip, dp,
                         ssl_state->server_connp.cert0_subject,
                         ssl_state->server_connp.cert0_issuerdn);

    if (hlog->flags & LOG_TLS_EXTENDED) {
        LogTlsLogExtended(aft, ssl_state);
    } else {
        MemBufferWriteString(aft->buffer, "\n");
    }

    aft->tls_cnt++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);

    /* we only log the state once */
    ssl_state->flags |= SSL_AL_FLAG_STATE_LOGGED;
end:
    FLOWLOCK_UNLOCK(p->flow);
    return 0;
}

void TmModuleLogTlsLogRegister(void)
{
    tmm_modules[TMM_LOGTLSLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGTLSLOG].ThreadInit = LogTlsLogThreadInit;
    tmm_modules[TMM_LOGTLSLOG].Func = NULL;
    tmm_modules[TMM_LOGTLSLOG].ThreadExitPrintStats = LogTlsLogExitPrintStats;
    tmm_modules[TMM_LOGTLSLOG].ThreadDeinit = LogTlsLogThreadDeinit;
    tmm_modules[TMM_LOGTLSLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTLSLOG].cap_flags = 0;
    tmm_modules[TMM_LOGTLSLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "tls-log", LogTlsLogInitCtx,
            LogTlsLogger, LogTlsCondition);
}
