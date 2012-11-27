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

#include "output.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#define MODULE_NAME "LogFileLog"

#define DEFAULT_LOG_FILENAME "files-json.log"

TmEcode LogFileLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogFileLogThreadDeinit(ThreadVars *, void *);
void LogFileLogExitPrintStats(ThreadVars *, void *);
int LogFileLogOpenFileCtx(LogFileCtx* , const char *, const char *);
static OutputCtx *LogFileLogInitCtx(ConfNode *);
static void LogFileLogDeInitCtx(OutputCtx *);

void TmModuleLogFileLogRegister (void) {
    tmm_modules[TMM_FILELOG].name = MODULE_NAME;
    tmm_modules[TMM_FILELOG].ThreadInit = LogFileLogThreadInit;
    tmm_modules[TMM_FILELOG].Func = LogFileLog;
    tmm_modules[TMM_FILELOG].ThreadExitPrintStats = LogFileLogExitPrintStats;
    tmm_modules[TMM_FILELOG].ThreadDeinit = LogFileLogThreadDeinit;
    tmm_modules[TMM_FILELOG].RegisterTests = NULL;
    tmm_modules[TMM_FILELOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "file-log", LogFileLogInitCtx);

    SCLogDebug("registered");
}

typedef struct LogFileLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFileLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogFileMetaGetUri(FILE *fp, Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, ff->txid);
        if (tx != NULL && tx->request_uri_normalized != NULL) {
            PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(tx->request_uri_normalized),
                    bstr_len(tx->request_uri_normalized));
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetHost(FILE *fp, Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, ff->txid);
        if (tx != NULL) {
            table_t *headers;
            headers = tx->request_headers;
            htp_header_t *h = NULL;

            table_iterator_reset(headers);
            while (table_iterator_next(headers, (void **)&h) != NULL) {
                if (bstr_len(h->name) >= 4 &&
                        SCMemcmpLowercase((uint8_t *)"host", (uint8_t *)bstr_ptr(h->name), bstr_len(h->name)) == 0) {
                    PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetReferer(FILE *fp, Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, ff->txid);
        if (tx != NULL) {
            table_t *headers;
            headers = tx->request_headers;
            htp_header_t *h = NULL;

            table_iterator_reset(headers);
            while (table_iterator_next(headers, (void **)&h) != NULL) {
                if (bstr_len(h->name) >= 7 &&
                        SCMemcmpLowercase((uint8_t *)"referer", (uint8_t *)bstr_ptr(h->name), bstr_len(h->name)) == 0) {
                    PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFileMetaGetUserAgent(FILE *fp, Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, ff->txid);
        if (tx != NULL) {
            table_t *headers;
            headers = tx->request_headers;
            htp_header_t *h = NULL;

            table_iterator_reset(headers);
            while (table_iterator_next(headers, (void **)&h) != NULL) {
                if (bstr_len(h->name) >= 10 &&
                        SCMemcmpLowercase((uint8_t *)"user-agent", (uint8_t *)bstr_ptr(h->name), bstr_len(h->name)) == 0) {
                    PrintRawJsonFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void LogFileWriteJsonRecord(LogFileLogThread *aft, Packet *p, File *ff, int ipver) {
    SCMutexLock(&aft->file_ctx->fp_mutex);

    FILE *fp = aft->file_ctx->fp;
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    fprintf(fp, "{ ");

    if (ff->file_id > 0)
        fprintf(fp, "\"id\": %u, ", ff->file_id);

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

    fprintf(fp, "\"filename\": \"");
    PrintRawJsonFp(fp, ff->name, ff->name_len);
    fprintf(fp, "\", ");

    fprintf(fp, "\"magic\": \"");
    if (ff->magic) {
        PrintRawJsonFp(fp, (uint8_t *)ff->magic, strlen(ff->magic));
    } else {
        fprintf(fp, "unknown");
    }
    fprintf(fp, "\", ");

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
    fprintf(fp, "\"size\": %"PRIu64" ", ff->size);
    fprintf(fp, "}\n");
    fflush(fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);
}

static TmEcode LogFileLogWrap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipver)
{
    SCEnter();
    LogFileLogThread *aft = (LogFileLogThread *)data;
    uint8_t flags = 0;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= STREAM_TOCLIENT;
    else
        flags |= STREAM_TOSERVER;

    int file_close = (p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0;
    int file_trunc = 0;

    FLOWLOCK_WRLOCK(p->flow);
    file_trunc = StreamTcpReassembleDepthReached(p);

    FileContainer *ffc = AppLayerGetFilesFromFlow(p->flow, flags);
    SCLogDebug("ffc %p", ffc);
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            if (ff->flags & FILE_LOGGED)
                continue;

            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicGlobalLookup(ff);
            }

            SCLogDebug("ff %p", ff);

            if (file_trunc && ff->state < FILE_STATE_CLOSED)
                ff->state = FILE_STATE_TRUNCATED;

            if (ff->state == FILE_STATE_CLOSED ||
                    ff->state == FILE_STATE_TRUNCATED || ff->state == FILE_STATE_ERROR ||
                    (file_close == 1 && ff->state < FILE_STATE_CLOSED))
            {
                LogFileWriteJsonRecord(aft, p, ff, ipver);

                ff->flags |= FILE_LOGGED;
                aft->file_cnt++;
            }
        }

        FilePrune(ffc);
    }

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFileLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogFileLogWrap(tv, p, data, NULL, NULL, AF_INET);
}

TmEcode LogFileLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogFileLogWrap(tv, p, data, NULL, NULL, AF_INET6);
}

TmEcode LogFileLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    int r = TM_ECODE_OK;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    if (PKT_IS_IPV4(p)) {
        r = LogFileLogIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        r = LogFileLogIPv6(tv, p, data, pq, postpq);
    }

    SCReturnInt(r);
}

TmEcode LogFileLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

TmEcode LogFileLogThreadDeinit(ThreadVars *t, void *data)
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

void LogFileLogExitPrintStats(ThreadVars *tv, void *data) {
    LogFileLogThread *aft = (LogFileLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files logged: %" PRIu32 "", tv->name, aft->file_cnt);
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

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = LogFileLogDeInitCtx;

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogInfo("forcing magic lookup for logged files");
    }

    const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
    if (force_md5 != NULL && ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
        FileForceMd5Enable();
        SCLogInfo("forcing md5 calculation for logged files");
#else
        SCLogInfo("md5 calculation requires linking against libnss");
#endif
    }

    FileForceTrackingEnable();
    SCReturnPtr(output_ctx, "OutputCtx");
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

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param config_file for loading separate configs
 *  \return -1 if failure, 0 if succesful
 * */
int LogFileLogOpenFileCtx(LogFileCtx *file_ctx, const char *filename, const
                            char *mode)
{
    return 0;
}
