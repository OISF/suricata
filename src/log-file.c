/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Log files we track.
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

#include "app-layer-parser.h"

#include "detect-filemagic.h"

#include "stream.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-atomic.h"
#include "util-file.h"
#include "util-time.h"

#include "output.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "util-decode-mime.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#define MODULE_NAME "LogFileLog"

#define DEFAULT_LOG_FILENAME "files-json.log"

typedef struct LogFileLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFileLogThread;

static void LogFileMetaGetUri(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud != NULL) {
                if (tx_ud->request_uri_normalized != NULL) {
                    PrintRawJsonFp(fp,
                                   bstr_ptr(tx_ud->request_uri_normalized),
                                   bstr_len(tx_ud->request_uri_normalized));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetHost(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(tx->request_hostname),
                           bstr_len(tx->request_hostname));
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetReferer(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "Referer");
            if (h != NULL) {
                PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(h->value),
                               bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetUserAgent(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "User-Agent");
            if (h != NULL) {
                PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(h->value),
                               bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetSmtp(FILE *fp, const Packet *p, const File *ff)
{
    SMTPState *state = (SMTPState *) p->flow->alstate;
    if (state != NULL) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, state, ff->txid);
        if (tx == NULL || tx->msg_tail == NULL)
            return;

        /* Message Id */
        if (tx->msg_tail->msg_id != NULL) {

            fprintf(fp, "\"message-id\": \"");
            PrintRawJsonFp(fp, (uint8_t *) tx->msg_tail->msg_id,
                    (int) tx->msg_tail->msg_id_len);
            fprintf(fp, "\", ");
        }

        /* Sender */
        MimeDecField *field = MimeDecFindField(tx->msg_tail, "from");
        if (field != NULL) {
            fprintf(fp, "\"sender\": \"");
            PrintRawJsonFp(fp, (uint8_t *) field->value,
                    (int) field->value_len);
            fprintf(fp, "\", ");
        }
    }
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void LogFileWriteJsonRecord(LogFileLogThread *aft, const Packet *p, const File *ff, int ipver)
{
    SCMutexLock(&aft->file_ctx->fp_mutex);

    /* As writes are done via the LogFileCtx, check for rotation here. */
    if (aft->file_ctx->rotation_flag) {
        aft->file_ctx->rotation_flag = 0;
        if (SCConfLogReopen(aft->file_ctx) != 0) {
            SCLogWarning(SC_ERR_FOPEN, "Failed to re-open log file. "
                "Logging for this module will be disabled.");
        }
    }

    /* Bail early if no file pointer to write to (in the unlikely
     * event file rotation failed. */
    if (aft->file_ctx->fp == NULL) {
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
        return;
    }

    FILE *fp = aft->file_ctx->fp;
    char timebuf[64];
    AppProto alproto = FlowGetAppProtocol(p->flow);

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    fprintf(fp, "{ ");

    if (ff->file_store_id > 0)
        fprintf(fp, "\"id\": %u, ", ff->file_store_id);

    fprintf(fp, "\"timestamp\": \"");
    PrintRawJsonFp(fp, (uint8_t *)timebuf, strlen(timebuf));
    fprintf(fp, "\", ");
    if (p->pcap_cnt > 0) {
        fprintf(fp, "\"pcap_pkt_num\": %"PRIu64", ", p->pcap_cnt);
    }

    fprintf(fp, "\"ipver\": %d, ", ipver == AF_INET ? 4 : 6);

    char srcip[46], dstip[46];
    Port sp, dp;
    switch (ipver) {
        case AF_INET:
            PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
            break;
        case AF_INET6:
            PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
            break;
        default:
            strlcpy(srcip, "<unknown>", sizeof(srcip));
            strlcpy(dstip, "<unknown>", sizeof(dstip));
            break;
    }
    sp = p->sp;
    dp = p->dp;

    fprintf(fp, "\"srcip\": \"%s\", ", srcip);
    fprintf(fp, "\"dstip\": \"%s\", ", dstip);
    fprintf(fp, "\"protocol\": %" PRIu32 ", ", p->proto);
    if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
        fprintf(fp, "\"sp\": %" PRIu16 ", ", sp);
        fprintf(fp, "\"dp\": %" PRIu16 ", ", dp);
    }

    if (alproto == ALPROTO_HTTP) {
        fprintf(fp, "\"http_uri\": \"");
        LogFileMetaGetUri(fp, p, ff);
        fprintf(fp, "\", ");

        fprintf(fp, "\"http_host\": \"");
        LogFileMetaGetHost(fp, p, ff);
        fprintf(fp, "\", ");

        fprintf(fp, "\"http_referer\": \"");
        LogFileMetaGetReferer(fp, p, ff);
        fprintf(fp, "\", ");

        fprintf(fp, "\"http_user_agent\": \"");
        LogFileMetaGetUserAgent(fp, p, ff);
        fprintf(fp, "\", ");
    } else if (p->flow->alproto == ALPROTO_SMTP) {
        /* Only applicable to SMTP */
        LogFileMetaGetSmtp(fp, p, ff);
    }

    fprintf(fp, "\"filename\": \"");
    PrintRawJsonFp(fp, ff->name, ff->name_len);
    fprintf(fp, "\", ");
#ifdef HAVE_MAGIC
    fprintf(fp, "\"magic\": \"");
    if (ff->magic) {
        PrintRawJsonFp(fp, (uint8_t *)ff->magic, strlen(ff->magic));
    } else {
        fprintf(fp, "unknown");
    }
    fprintf(fp, "\", ");
#endif
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            fprintf(fp, "\"state\": \"CLOSED\", ");
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                fprintf(fp, "\"md5\": \"");
                size_t x;
                for (x = 0; x < sizeof(ff->md5); x++) {
                    fprintf(fp, "%02x", ff->md5[x]);
                }
                fprintf(fp, "\", ");
            }
            if (ff->flags & FILE_SHA1) {
                fprintf(fp, "\"sha1\": \"");
                size_t x;
                for (x = 0; x < sizeof(ff->sha1); x++) {
                    fprintf(fp, "%02x", ff->sha1[x]);
                }
                fprintf(fp, "\", ");
            }
            if (ff->flags & FILE_SHA256) {
                fprintf(fp, "\"sha256\": \"");
                size_t x;
                for (x = 0; x < sizeof(ff->sha256); x++) {
                    fprintf(fp, "%02x", ff->sha256[x]);
                }
                fprintf(fp, "\", ");
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            fprintf(fp, "\"state\": \"TRUNCATED\", ");
            break;
        case FILE_STATE_ERROR:
            fprintf(fp, "\"state\": \"ERROR\", ");
            break;
        default:
            fprintf(fp, "\"state\": \"UNKNOWN\", ");
            break;
    }
    fprintf(fp, "\"stored\": %s, ", ff->flags & FILE_STORED ? "true" : "false");
    fprintf(fp, "\"size\": %"PRIu64" ", FileTrackedSize(ff));
    fprintf(fp, "}\n");
    fflush(fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);
}

static int LogFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff)
{
    SCEnter();
    LogFileLogThread *aft = (LogFileLogThread *)thread_data;
    int ipver = -1;

    if (PKT_IS_IPV4(p)) {
        ipver = AF_INET;
    } else if (PKT_IS_IPV6(p)) {
        ipver = AF_INET6;
    } else {
        return 0;
    }

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    LogFileWriteJsonRecord(aft, p, ff, ipver);

    aft->file_cnt++;
    return 0;
}

static TmEcode LogFileLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogFileLogThread *aft = SCMalloc(sizeof(LogFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFileLogThread));

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogFile. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogFileLogThreadDeinit(ThreadVars *t, void *data)
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

static void LogFileLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogFileLogThread *aft = (LogFileLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files logged: %" PRIu32 "", tv->name, aft->file_cnt);
}

/**
 *  \internal
 *
 *  \brief deinit the log ctx and write out the waldo
 *
 *  \param output_ctx output context to deinit
 */
static void LogFileLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    free(output_ctx);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogFileLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = LogFileLogDeInitCtx;

    const char *force_filestore = ConfNodeLookupChildValue(conf, "force-filestore");
    if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
        FileForceFilestoreEnable();
        SCLogInfo("forcing filestore of all files");
    }

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogInfo("forcing magic lookup for logged files");
    }

    FileForceHashParseCfg(conf);
    FileForceTrackingEnable();
    SCReturnPtr(output_ctx, "OutputCtx");
}

void LogFileLogRegister (void)
{
    OutputRegisterFileModule(LOGGER_FILE, MODULE_NAME, "file-log",
        LogFileLogInitCtx, LogFileLogger, LogFileLogThreadInit,
        LogFileLogThreadDeinit, LogFileLogExitPrintStats);

    SCLogDebug("registered");
}
