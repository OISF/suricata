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
#include "util-crypt.h"

#define DEFAULT_LOG_FILENAME "tls.log"

static char tls_logfile_base_dir[PATH_MAX] = "/tmp";
SC_ATOMIC_DECLARE(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLog"

#define OUTPUT_BUFFER_SIZE 65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    1

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

    SC_ATOMIC_INIT(cert_id);
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
    uint8_t*   enc_buf;
    size_t     enc_buf_len;
} LogTlsLogThread;

static void CreateTimeString(const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *) localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogTlsLogExtended(LogTlsLogThread *aft, SSLState * state)
{
    if (state->server_connp.cert0_fingerprint != NULL) {
        MemBufferWriteString(aft->buffer, " SHA1='%s'", state->server_connp.cert0_fingerprint);
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

static int GetIPInformations(Packet *p, char* srcip, size_t srcip_len,
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

static int CreateFileName(LogTlsFileCtx *log, Packet *p, SSLState *state, char *filename)
{
#define FILELEN 64  //filename len + extention + ending path / + some space

    int filenamelen = FILELEN + strlen(tls_logfile_base_dir);
    int file_id = SC_ATOMIC_ADD(cert_id, 1);

    if (filenamelen + 1 > PATH_MAX) {
        return 0;
    }

    /* Use format : packet time + incremental ID
     * When running on same pcap it will overwrite
     * On a live device, we will not be able to overwrite */
    snprintf(filename, filenamelen, "%s/%ld.%ld-%d.pem",
             tls_logfile_base_dir,
             p->ts.tv_sec,
             (long int)p->ts.tv_usec,
             file_id);
    return 1;
}


static void LogTlsLogPem(LogTlsLogThread *aft, Packet *p, SSLState *state, LogTlsFileCtx *log, int ipproto)
{
#define PEMHEADER "-----BEGIN CERTIFICATE-----\n"
#define PEMFOOTER "-----END CERTIFICATE-----\n"
    //Logging pem certificate
    char filename[PATH_MAX] = "";
    FILE* fp = NULL;
    FILE* fpmeta = NULL;
    unsigned long pemlen;
    unsigned char* pembase64ptr = NULL;
    int ret;
    SSLCertsChain *cert;

    if ((state->server_connp.cert_input == NULL) || (state->server_connp.cert_input_len == 0))
        SCReturn;

    CreateFileName(log, p, state, filename);
    if (strlen(filename) == 0) {
        SCLogWarning(SC_ERR_FOPEN, "Can't create PEM filename");
        SCReturn;
    }

    fp = fopen(filename, "w");
    if (fp == NULL) {
        SCLogWarning(SC_ERR_FOPEN, "Can't create PEM file: %s", filename);
        SCReturn;
    }

    TAILQ_FOREACH(cert, &state->server_connp.certs, next) {
        pemlen = (4 * (cert->cert_len + 2) / 3) +1;
        if (pemlen > aft->enc_buf_len) {
            aft->enc_buf = (uint8_t*) SCRealloc(aft->enc_buf, sizeof(uint8_t) * pemlen);
            if (aft->enc_buf == NULL) {
                SCLogWarning(SC_ERR_MEM_ALLOC, "Can't allocate data for base64 encoding");
                goto end_fp;
            }
            aft->enc_buf_len = pemlen;
        }

        memset(aft->enc_buf, 0, aft->enc_buf_len);

        ret = Base64Encode((unsigned char*) cert->cert_data, cert->cert_len, aft->enc_buf, &pemlen);
        if (ret != SC_BASE64_OK) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "Invalid return of Base64Encode function");
            goto end_fwrite_fp;
        }

        if (fprintf(fp, PEMHEADER)  < 0)
            goto end_fwrite_fp;

        pembase64ptr = aft->enc_buf;
        while (pemlen > 0) {
            size_t loffset = pemlen >= 64 ? 64 : pemlen;
            if (fwrite(pembase64ptr, 1, loffset, fp) != loffset)
                goto end_fwrite_fp;
            if (fwrite("\n", 1, 1, fp) != 1)
                goto end_fwrite_fp;
            pembase64ptr += 64;
            if (pemlen < 64)
                break;
            pemlen -= 64;
        }

        if (fprintf(fp, PEMFOOTER) < 0)
            goto end_fwrite_fp;
    }
    fclose(fp);

    //Logging certificate informations
    memcpy(filename + (strlen(filename) - 3), "meta", 4);
    fpmeta = fopen(filename, "w");
    if (fpmeta != NULL) {
        #define PRINT_BUF_LEN 46
        char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
        char timebuf[64];
        Port sp, dp;
        CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
        if (!GetIPInformations(p, srcip, PRINT_BUF_LEN, &sp, dstip, PRINT_BUF_LEN, &dp, ipproto))
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "TIME:              %s\n", timebuf) < 0)
            goto end_fwrite_fpmeta;
        if (p->pcap_cnt > 0) {
            if (fprintf(fpmeta, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt) < 0)
                goto end_fwrite_fpmeta;
        }
        if (fprintf(fpmeta, "SRC IP:            %s\n", srcip) < 0)
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "DST IP:            %s\n", dstip) < 0)
            goto end_fwrite_fpmeta;
        if (fprintf(fpmeta, "PROTO:             %" PRIu32 "\n", p->proto) < 0)
            goto end_fwrite_fpmeta;
        if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
            if (fprintf(fpmeta, "SRC PORT:          %" PRIu16 "\n", sp) < 0)
                goto end_fwrite_fpmeta;
            if (fprintf(fpmeta, "DST PORT:          %" PRIu16 "\n", dp) < 0)
                goto end_fwrite_fpmeta;
        }

        if (fprintf(fpmeta, "TLS SUBJECT:       %s\n"
                    "TLS ISSUERDN:      %s\n"
                    "TLS FINGERPRINT:   %s\n",
                state->server_connp.cert0_subject,
                state->server_connp.cert0_issuerdn,
                state->server_connp.cert0_fingerprint) < 0)
            goto end_fwrite_fpmeta;

        fclose(fpmeta);
    } else {
        SCLogWarning(SC_ERR_FOPEN, "Can't open meta file: %s",
                     filename); 
        SCReturn;
    }

    /* Reset the store flag */
    state->server_connp.cert_log_flag &= ~SSL_TLS_LOG_PEM;
    SCReturn;

end_fwrite_fp:
    fclose(fp);
    SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate");
end_fwrite_fpmeta:
    if (fpmeta) {
        fclose(fpmeta);
        SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate metafile");
    }
    SCReturn;
end_fp:
    fclose(fp);
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

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    if (ssl_state->server_connp.cert_log_flag & SSL_TLS_LOG_PEM) {
        LogTlsLogPem(aft, p, ssl_state, hlog, ipproto);
    }

    int r = AppLayerTransactionGetLoggedId(p->flow);

    if (r != 0) {
        goto end;
    }

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    #define PRINT_BUF_LEN 46
    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
    Port sp, dp;
    if (!GetIPInformations(p, srcip, PRINT_BUF_LEN,
                           &sp, dstip, PRINT_BUF_LEN, &dp, ipproto)) {
        goto end;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    MemBufferWriteString(aft->buffer,
                         "%s %s:%d -> %s:%d  TLS: Subject='%s' Issuerdn='%s'",
                         timebuf, srcip, sp, dstip, dp,
                         ssl_state->server_connp.cert0_subject, ssl_state->server_connp.cert0_issuerdn);

    AppLayerTransactionUpdateLoggedId(p->flow);

    if (hlog->flags & LOG_TLS_EXTENDED) {
        LogTlsLogExtended(aft, ssl_state);
    } else {
        MemBufferWriteString(aft->buffer, "\n");
    }

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

    aft->enc_buf = SCMalloc(CERT_ENC_BUFFER_SIZE);
    if (aft->enc_buf == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    aft->enc_buf_len = CERT_ENC_BUFFER_SIZE;
    memset(aft->enc_buf, 0, aft->enc_buf_len);

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

    char *s_default_log_dir = NULL;
    if (ConfGet("default-log-dir", &s_default_log_dir) != 1)
        s_default_log_dir = DEFAULT_LOG_DIR;

    const char *s_base_dir = NULL;
    s_base_dir = ConfNodeLookupChildValue(conf, "certs-log-dir");
    if (s_base_dir == NULL || strlen(s_base_dir) == 0) {
        strlcpy(tls_logfile_base_dir,
                s_default_log_dir, sizeof(tls_logfile_base_dir));
    } else {
        if (PathIsAbsolute(s_base_dir)) {
            strlcpy(tls_logfile_base_dir,
                    s_base_dir, sizeof(tls_logfile_base_dir));
        } else {
            snprintf(tls_logfile_base_dir, sizeof(tls_logfile_base_dir),
                    "%s/%s", s_default_log_dir, s_base_dir);
        }
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
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

    return output_ctx;

tlslog_error:
    if (tlslog_ctx != NULL)
        SCFree(tlslog_ctx);
filectx_error:
    LogFileFreeCtx(file_ctx);
    return NULL;
}

static void LogTlsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}
