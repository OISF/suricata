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

#define MODULE_NAME "LogFilestoreLog"

static char g_logfile_base_dir[PATH_MAX] = "/tmp";

typedef struct LogFilestoreLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFilestoreCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFilestoreLogThread;

static void LogFilestoreMetaGetUri(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud->request_uri_normalized != NULL) {
                PrintRawUriFp(fp, bstr_ptr(tx_ud->request_uri_normalized),
                              bstr_len(tx_ud->request_uri_normalized));
            }
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetHost(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            PrintRawUriFp(fp, (uint8_t *)bstr_ptr(tx->request_hostname),
                          bstr_len(tx->request_hostname));
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetReferer(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "Referer");
            if (h != NULL) {
                PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                              bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetUserAgent(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "User-Agent");
            if (h != NULL) {
                PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                              bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetSmtp(FILE *fp, const Packet *p, const File *ff)
{
    SMTPState *state = (SMTPState *) p->flow->alstate;
    if (state != NULL) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, state, ff->txid);
        if (tx == NULL || tx->msg_tail == NULL)
            return;

        /* Message Id */
        if (tx->msg_tail->msg_id != NULL) {
            fprintf(fp, "MESSAGE-ID:        ");
            PrintRawUriFp(fp, (uint8_t *) tx->msg_tail->msg_id, tx->msg_tail->msg_id_len);
            fprintf(fp, "\n");
        }

        /* Sender */
        MimeDecField *field = MimeDecFindField(tx->msg_tail, "from");
        if (field != NULL) {
            fprintf(fp, "SENDER:            ");
            PrintRawUriFp(fp, (uint8_t *) field->value, field->value_len);
            fprintf(fp, "\n");
        }
    }
}

static void LogFilestoreLogCreateMetaFile(const Packet *p, const File *ff, char *filename, int ipver) {
    char metafilename[PATH_MAX] = "";
    snprintf(metafilename, sizeof(metafilename), "%s.meta", filename);
    FILE *fp = fopen(metafilename, "w+");
    if (fp != NULL) {
        char timebuf[64];

        CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

        fprintf(fp, "TIME:              %s\n", timebuf);
        if (p->pcap_cnt > 0) {
            fprintf(fp, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
        }

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

        fprintf(fp, "SRC IP:            %s\n", srcip);
        fprintf(fp, "DST IP:            %s\n", dstip);
        fprintf(fp, "PROTO:             %" PRIu32 "\n", p->proto);
        if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
            fprintf(fp, "SRC PORT:          %" PRIu16 "\n", sp);
            fprintf(fp, "DST PORT:          %" PRIu16 "\n", dp);
        }

        fprintf(fp, "APP PROTO:         %s\n",
                AppProtoToString(p->flow->alproto));

        /* Only applicable to HTTP traffic */
        if (p->flow->alproto == ALPROTO_HTTP) {
            fprintf(fp, "HTTP URI:          ");
            LogFilestoreMetaGetUri(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP HOST:         ");
            LogFilestoreMetaGetHost(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP REFERER:      ");
            LogFilestoreMetaGetReferer(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP USER AGENT:   ");
            LogFilestoreMetaGetUserAgent(fp, p, ff);
            fprintf(fp, "\n");
        } else if (p->flow->alproto == ALPROTO_SMTP) {
            /* Only applicable to SMTP */
            LogFilestoreMetaGetSmtp(fp, p, ff);
        }

        fprintf(fp, "FILENAME:          ");
        PrintRawUriFp(fp, ff->name, ff->name_len);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

static void LogFilestoreLogCloseMetaFile(const File *ff)
{
    char filename[PATH_MAX] = "";
    snprintf(filename, sizeof(filename), "%s/file.%u",
            g_logfile_base_dir, ff->file_id);
    char metafilename[PATH_MAX] = "";
    snprintf(metafilename, sizeof(metafilename), "%s.meta", filename);
    FILE *fp = fopen(metafilename, "a");
    if (fp != NULL) {
        fprintf(fp, "MAGIC:             %s\n",
                ff->magic ? ff->magic : "<unknown>");

        switch (ff->state) {
            case FILE_STATE_CLOSED:
                fprintf(fp, "STATE:             CLOSED\n");
#ifdef HAVE_NSS
                if (ff->flags & FILE_MD5) {
                    fprintf(fp, "MD5:               ");
                    size_t x;
                    for (x = 0; x < sizeof(ff->md5); x++) {
                        fprintf(fp, "%02x", ff->md5[x]);
                    }
                    fprintf(fp, "\n");
                }
#endif
                break;
            case FILE_STATE_TRUNCATED:
                fprintf(fp, "STATE:             TRUNCATED\n");
                break;
            case FILE_STATE_ERROR:
                fprintf(fp, "STATE:             ERROR\n");
                break;
            default:
                fprintf(fp, "STATE:             UNKNOWN\n");
                break;
        }
        fprintf(fp, "SIZE:              %"PRIu64"\n", ff->size);

        fclose(fp);
    } else {
        SCLogInfo("opening %s failed: %s", metafilename, strerror(errno));
    }
}

static int LogFilestoreLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff, const FileData *ffd, uint8_t flags)
{
    SCEnter();
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)thread_data;
    char filename[PATH_MAX] = "";
    int file_fd = -1;
    int ipver = -1;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        ipver = AF_INET;
    } else if (PKT_IS_IPV6(p)) {
        ipver = AF_INET6;
    } else {
        return 0;
    }

    SCLogDebug("ff %p, ffd %p", ff, ffd);

    snprintf(filename, sizeof(filename), "%s/file.%u",
            g_logfile_base_dir, ff->file_id);

    if (flags & OUTPUT_FILEDATA_FLAG_OPEN) {
        aft->file_cnt++;

        /* create a .meta file that contains time, src/dst/sp/dp/proto */
        LogFilestoreLogCreateMetaFile(p, ff, filename, ipver);

        file_fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
        if (file_fd == -1) {
            SCLogDebug("failed to create file");
            return -1;
        }
    /* we can get called with a NULL ffd when we need to close */
    } else if (ffd != NULL) {
        file_fd = open(filename, O_APPEND | O_NOFOLLOW | O_WRONLY);
        if (file_fd == -1) {
            SCLogDebug("failed to open file %s: %s", filename, strerror(errno));
            return -1;
        }
    }

    if (file_fd != -1) {
        ssize_t r = write(file_fd, (const void *)ffd->data, (size_t)ffd->len);
        if (r == -1) {
            SCLogDebug("write failed: %s", strerror(errno));
        }
        close(file_fd);
    }

    if (flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
        LogFilestoreLogCloseMetaFile(ff);
    }

    return 0;
}

static TmEcode LogFilestoreLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFilestoreLogThread *aft = SCMalloc(sizeof(LogFilestoreLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFilestoreLogThread));

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogFilestore. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    struct stat stat_buf;
    if (stat(g_logfile_base_dir, &stat_buf) != 0) {
        int ret;
        ret = mkdir(g_logfile_base_dir, S_IRWXU|S_IXGRP|S_IRGRP);
        if (ret != 0) {
            int err = errno;
            if (err != EEXIST) {
                SCLogError(SC_ERR_LOGDIR_CONFIG,
                        "Cannot create file drop directory %s: %s",
                        g_logfile_base_dir, strerror(err));
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Created file drop directory %s",
                    g_logfile_base_dir);
        }

    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogFilestoreLogThreadDeinit(ThreadVars *t, void *data)
{
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogFilestoreLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogFilestoreLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files extracted %" PRIu32 "", tv->name, aft->file_cnt);
}

/**
 *  \internal
 *
 *  \brief deinit the log ctx and write out the waldo
 *
 *  \param output_ctx output context to deinit
 */
static void LogFilestoreLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);

}

/** \brief Create a new http log LogFilestoreCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFilestoreCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogFilestoreLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("Could not create new LogFilestoreCtx");
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = NULL;
    output_ctx->DeInit = LogFilestoreLogDeInitCtx;

    char *s_default_log_dir = NULL;
    s_default_log_dir = ConfigGetLogDirectory();

    const char *s_base_dir = NULL;
    s_base_dir = ConfNodeLookupChildValue(conf, "log-dir");
    if (s_base_dir == NULL || strlen(s_base_dir) == 0) {
        strlcpy(g_logfile_base_dir,
                s_default_log_dir, sizeof(g_logfile_base_dir));
    } else {
        if (PathIsAbsolute(s_base_dir)) {
            strlcpy(g_logfile_base_dir,
                    s_base_dir, sizeof(g_logfile_base_dir));
        } else {
            snprintf(g_logfile_base_dir, sizeof(g_logfile_base_dir),
                    "%s/%s", s_default_log_dir, s_base_dir);
        }
    }

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogInfo("forcing magic lookup for stored files");
    }

    const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
    if (force_md5 != NULL && ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
        FileForceMd5Enable();
        SCLogInfo("forcing md5 calculation for stored files");
#else
        SCLogInfo("md5 calculation requires linking against libnss");
#endif
    }
    SCLogInfo("storing files in %s", g_logfile_base_dir);

    SCReturnPtr(output_ctx, "OutputCtx");
}

void TmModuleLogFilestoreRegister (void)
{
    tmm_modules[TMM_FILESTORE].name = MODULE_NAME;
    tmm_modules[TMM_FILESTORE].ThreadInit = LogFilestoreLogThreadInit;
    tmm_modules[TMM_FILESTORE].Func = NULL;
    tmm_modules[TMM_FILESTORE].ThreadExitPrintStats = LogFilestoreLogExitPrintStats;
    tmm_modules[TMM_FILESTORE].ThreadDeinit = LogFilestoreLogThreadDeinit;
    tmm_modules[TMM_FILESTORE].RegisterTests = NULL;
    tmm_modules[TMM_FILESTORE].cap_flags = 0;
    tmm_modules[TMM_FILESTORE].flags = TM_FLAG_LOGAPI_TM;
    tmm_modules[TMM_FILESTORE].priority = 10;

    OutputRegisterFiledataModule(MODULE_NAME, "file", LogFilestoreLogInitCtx,
            LogFilestoreLogger);
    OutputRegisterFiledataModule(MODULE_NAME, "file-store", LogFilestoreLogInitCtx,
            LogFilestoreLogger);

    SCLogDebug("registered");
}
