/* Copyright (C) 2022 Open Information Security Foundation
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
 * Implements TLS store portion of the engine.
 *
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
#include "log-tlsstore.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

#define MODULE_NAME "LogTlsStoreLog"

static char tls_logfile_base_dir[PATH_MAX] = "/tmp";
SC_ATOMIC_DECLARE(unsigned int, cert_id);
static char logging_dir_not_writable;

#define LOGGING_WRITE_ISSUE_LIMIT 6

typedef struct LogTlsStoreLogThread_ {
    uint32_t tls_cnt;

    uint8_t*   enc_buf;
    size_t     enc_buf_len;
} LogTlsStoreLogThread;

static int CreateFileName(const Packet *p, SSLState *state, char *filename, size_t filename_size)
{
    char path[PATH_MAX];
    int file_id = SC_ATOMIC_ADD(cert_id, 1);

    /* Use format : packet time + incremental ID
     * When running on same pcap it will overwrite
     * On a live device, we will not be able to overwrite */
    if (snprintf(path, sizeof(path), "%s/%ld.%ld-%d.pem",
             tls_logfile_base_dir,
             (long int)p->ts.tv_sec,
             (long int)p->ts.tv_usec,
             file_id) == sizeof(path))
        return 0;

    strlcpy(filename, path, filename_size);
    return 1;
}

static void LogTlsLogPem(LogTlsStoreLogThread *aft, const Packet *p, SSLState *state, int ipproto)
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
    uint8_t *ptmp;
    SSLCertsChain *cert;

    if (TAILQ_EMPTY(&state->server_connp.certs))
        SCReturn;

    CreateFileName(p, state, filename, sizeof(filename));
    if (strlen(filename) == 0) {
        SCLogWarning(SC_ERR_FOPEN, "Can't create PEM filename");
        SCReturn;
    }

    fp = fopen(filename, "w");
    if (fp == NULL) {
        if (logging_dir_not_writable < LOGGING_WRITE_ISSUE_LIMIT) {
            SCLogWarning(SC_ERR_FOPEN,
                         "Can't create PEM file '%s' in '%s' directory",
                         filename, tls_logfile_base_dir);
            logging_dir_not_writable++;
        }
        SCReturn;
    }

    TAILQ_FOREACH(cert, &state->server_connp.certs, next) {
        pemlen = Base64EncodeBufferSize(cert->cert_len);
        if (pemlen > aft->enc_buf_len) {
            ptmp = (uint8_t*) SCRealloc(aft->enc_buf, sizeof(uint8_t) * pemlen);
            if (ptmp == NULL) {
                SCFree(aft->enc_buf);
                aft->enc_buf = NULL;
                aft->enc_buf_len = 0;
                SCLogWarning(SC_ERR_MEM_ALLOC, "Can't allocate data for base64 encoding");
                goto end_fp;
            }
            aft->enc_buf = ptmp;
            aft->enc_buf_len = pemlen;
        }

        memset(aft->enc_buf, 0, aft->enc_buf_len);

        ret = Base64Encode((unsigned char*) cert->cert_data, cert->cert_len, aft->enc_buf, &pemlen);
        if (ret != SC_BASE64_OK) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "Invalid return of Base64Encode function");
            goto end_fwrite_fp;
        }

        if (fprintf(fp, PEMHEADER) < 0)
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
        if (!TLSGetIPInformations(p, srcip, PRINT_BUF_LEN, &sp, dstip, PRINT_BUF_LEN, &dp, ipproto))
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
        if (logging_dir_not_writable < LOGGING_WRITE_ISSUE_LIMIT) {
            SCLogWarning(SC_ERR_FOPEN,
                         "Can't create meta file '%s' in '%s' directory",
                         filename, tls_logfile_base_dir);
            logging_dir_not_writable++;
        }
        SCReturn;
    }

    /* Reset the store flag */
    state->server_connp.cert_log_flag &= ~SSL_TLS_LOG_PEM;
    SCReturn;

end_fwrite_fp:
    fclose(fp);
    if (logging_dir_not_writable < LOGGING_WRITE_ISSUE_LIMIT) {
        SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate");
        logging_dir_not_writable++;
    }
end_fwrite_fpmeta:
    if (fpmeta) {
        fclose(fpmeta);
        if (logging_dir_not_writable < LOGGING_WRITE_ISSUE_LIMIT) {
            SCLogWarning(SC_ERR_FWRITE, "Unable to write certificate metafile");
            logging_dir_not_writable++;
        }
    }
    SCReturn;
end_fp:
    fclose(fp);
    SCReturn;
}

/** \internal
 *  \brief Condition function for TLS logger
 *  \retval bool true or false -- log now?
 */
static int LogTlsStoreCondition(ThreadVars *tv, const Packet *p, void *state,
                                void *tx, uint64_t tx_id)
{
    if (p->flow == NULL) {
        return FALSE;
    }

    if (!(PKT_IS_TCP(p))) {
        return FALSE;
    }

    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto dontlog;
    }

    if ((ssl_state->server_connp.cert_log_flag & SSL_TLS_LOG_PEM) == 0)
        goto dontlog;

    if (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL)
        goto dontlog;

    return TRUE;
dontlog:
    return FALSE;
}

static int LogTlsStoreLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                             Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogTlsStoreLogThread *aft = (LogTlsStoreLogThread *)thread_data;
    int ipproto = (PKT_IS_IPV4(p)) ? AF_INET : AF_INET6;

    SSLState *ssl_state = (SSLState *)state;
    if (unlikely(ssl_state == NULL)) {
        return 0;
    }

    if (ssl_state->server_connp.cert_log_flag & SSL_TLS_LOG_PEM) {
        LogTlsLogPem(aft, p, ssl_state, ipproto);
    }

    return 0;
}

static TmEcode LogTlsStoreLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTlsStoreLogThread *aft = SCMalloc(sizeof(LogTlsStoreLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTlsStoreLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for LogTLSStore. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    struct stat stat_buf;
    /* coverity[toctou] */
    if (stat(tls_logfile_base_dir, &stat_buf) != 0) {
        int ret;
        /* coverity[toctou] */
        ret = SCMkDir(tls_logfile_base_dir, S_IRWXU|S_IXGRP|S_IRGRP);
        if (ret != 0) {
            int err = errno;
            if (err != EEXIST) {
                SCLogError(SC_ERR_LOGDIR_CONFIG,
                        "Cannot create certs drop directory %s: %s",
                        tls_logfile_base_dir, strerror(err));
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Created certs drop directory %s",
                    tls_logfile_base_dir);
        }

    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogTlsStoreLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsStoreLogThread *aft = (LogTlsStoreLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    if (aft->enc_buf != NULL)
        SCFree(aft->enc_buf);

    /* clear memory */
    memset(aft, 0, sizeof(LogTlsStoreLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogTlsStoreLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsStoreLogThread *aft = (LogTlsStoreLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) certificates extracted %" PRIu32 "", tv->name, aft->tls_cnt);
}

/**
 *  \internal
 *
 *  \brief deinit the log ctx and write out the waldo
 *
 *  \param output_ctx output context to deinit
 */
static void LogTlsStoreLogDeInitCtx(OutputCtx *output_ctx)
{
    SCFree(output_ctx);
}

/** \brief Create a new http log LogFilestoreCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFilestoreCtx* to the file_ctx if succesful
 * */
static OutputInitResult LogTlsStoreLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    output_ctx->data = NULL;
    output_ctx->DeInit = LogTlsStoreLogDeInitCtx;

    /* FIXME we need to implement backward compability here */
    const char *s_default_log_dir = NULL;
    s_default_log_dir = ConfigGetLogDirectory();

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

    SCLogInfo("storing certs in %s", tls_logfile_base_dir);

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    SCReturnCT(result, "OutputInitResult");
}

void LogTlsStoreRegister (void)
{
    OutputRegisterTxModuleWithCondition(LOGGER_TLS_STORE, MODULE_NAME,
        "tls-store", LogTlsStoreLogInitCtx, ALPROTO_TLS, LogTlsStoreLogger,
        LogTlsStoreCondition, LogTlsStoreLogThreadInit,
        LogTlsStoreLogThreadDeinit, LogTlsStoreLogExitPrintStats);

    SC_ATOMIC_INIT(cert_id);
    SC_ATOMIC_SET(cert_id, 1);

    SCLogDebug("registered");
}
