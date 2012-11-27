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

#define MODULE_NAME "LogFilestoreLog"

TmEcode LogFilestoreLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFilestoreLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFilestoreLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFilestoreLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogFilestoreLogThreadDeinit(ThreadVars *, void *);
void LogFilestoreLogExitPrintStats(ThreadVars *, void *);
int LogFilestoreLogOpenFileCtx(LogFileCtx* , const char *, const char *);
static OutputCtx *LogFilestoreLogInitCtx(ConfNode *);
static void LogFilestoreLogDeInitCtx(OutputCtx *);

SC_ATOMIC_DECLARE(unsigned int, file_id);
static char g_logfile_base_dir[PATH_MAX] = "/tmp";
static char g_waldo[PATH_MAX] = "";

void TmModuleLogFilestoreRegister (void) {
    tmm_modules[TMM_FILESTORE].name = MODULE_NAME;
    tmm_modules[TMM_FILESTORE].ThreadInit = LogFilestoreLogThreadInit;
    tmm_modules[TMM_FILESTORE].Func = LogFilestoreLog;
    tmm_modules[TMM_FILESTORE].ThreadExitPrintStats = LogFilestoreLogExitPrintStats;
    tmm_modules[TMM_FILESTORE].ThreadDeinit = LogFilestoreLogThreadDeinit;
    tmm_modules[TMM_FILESTORE].RegisterTests = NULL;
    tmm_modules[TMM_FILESTORE].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "file", LogFilestoreLogInitCtx);
    OutputRegisterModule(MODULE_NAME, "file-store", LogFilestoreLogInitCtx);

    SCLogDebug("registered");

    SC_ATOMIC_INIT(file_id);
}

typedef struct LogFilestoreLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFilestoreCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFilestoreLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogFilestoreMetaGetUri(FILE *fp, Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, ff->txid);
        if (tx != NULL && tx->request_uri_normalized != NULL) {
            PrintRawUriFp(fp, (uint8_t *)bstr_ptr(tx->request_uri_normalized),
                    bstr_len(tx->request_uri_normalized));
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetHost(FILE *fp, Packet *p, File *ff) {
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
                    PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetReferer(FILE *fp, Packet *p, File *ff) {
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
                    PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreMetaGetUserAgent(FILE *fp, Packet *p, File *ff) {
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
                    PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                        bstr_len(h->value));
                    return;
                }
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void LogFilestoreLogCreateMetaFile(Packet *p, File *ff, char *filename, int ipver) {
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
        fprintf(fp, "FILENAME:          ");
        PrintRawUriFp(fp, ff->name, ff->name_len);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

static void LogFilestoreLogCloseMetaFile(File *ff) {
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

static TmEcode LogFilestoreLogWrap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipver)
{
    SCEnter();
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
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
            int file_fd = -1;

            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicGlobalLookup(ff);
            }

            SCLogDebug("ff %p", ff);
            if (ff->flags & FILE_STORED) {
                SCLogDebug("stored flag set");
                continue;
            }

            if (!(ff->flags & FILE_STORE)) {
                SCLogDebug("ff FILE_STORE not set");
                continue;
            }

            FileData *ffd;
            for (ffd = ff->chunks_head; ffd != NULL; ffd = ffd->next) {
                SCLogDebug("ffd %p", ffd);
                if (ffd->stored == 1) {
                    if (file_close == 1 && ffd->next == NULL) {
                        LogFilestoreLogCloseMetaFile(ff);
                        ff->flags |= FILE_STORED;
                    }
                    continue;
                }

                /* store */
                SCLogDebug("trying to open file");

                char filename[PATH_MAX] = "";

                if (ff->file_id == 0) {
                    ff->file_id = SC_ATOMIC_ADD(file_id, 1);

                    snprintf(filename, sizeof(filename), "%s/file.%u",
                            g_logfile_base_dir, ff->file_id);

                    file_fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
                    if (file_fd == -1) {
                        SCLogDebug("failed to open file");
                        continue;
                    }

                    /* create a .meta file that contains time, src/dst/sp/dp/proto */
                    LogFilestoreLogCreateMetaFile(p, ff, filename, ipver);
                    aft->file_cnt++;
                } else {
                    snprintf(filename, sizeof(filename), "%s/file.%u",
                            g_logfile_base_dir, ff->file_id);

                    file_fd = open(filename, O_APPEND | O_NOFOLLOW | O_WRONLY);
                    if (file_fd == -1) {
                        SCLogDebug("failed to open file %s: %s", filename, strerror(errno));
                        continue;
                    }
                }

                ssize_t r = write(file_fd, (const void *)ffd->data, (size_t)ffd->len);
                if (r == -1) {
                    SCLogDebug("write failed: %s", strerror(errno));

                    close(file_fd);
                    continue;
                }

                close(file_fd);

                if (file_trunc && ff->state < FILE_STATE_CLOSED)
                    ff->state = FILE_STATE_TRUNCATED;

                if (ff->state == FILE_STATE_CLOSED ||
                    ff->state == FILE_STATE_TRUNCATED ||
                    ff->state == FILE_STATE_ERROR ||
                    (file_close == 1 && ff->state < FILE_STATE_CLOSED))
                {
                    if (ffd->next == NULL) {
                        LogFilestoreLogCloseMetaFile(ff);

                        ff->flags |= FILE_STORED;
                    }
                }

                ffd->stored = 1;
            }
        }

        FilePrune(ffc);
    }

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFilestoreLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogFilestoreLogWrap(tv, p, data, NULL, NULL, AF_INET);
}

TmEcode LogFilestoreLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogFilestoreLogWrap(tv, p, data, NULL, NULL, AF_INET6);
}

TmEcode LogFilestoreLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        r = LogFilestoreLogIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        r = LogFilestoreLogIPv6(tv, p, data, pq, postpq);
    }

    SCReturnInt(r);
}

TmEcode LogFilestoreLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

TmEcode LogFilestoreLogThreadDeinit(ThreadVars *t, void *data)
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

void LogFilestoreLogExitPrintStats(ThreadVars *tv, void *data) {
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files extracted %" PRIu32 "", tv->name, aft->file_cnt);
}

/**
 *  \internal
 *
 *  \brief Open the waldo file (if available) and load the file_id
 *
 *  \param path full path for the waldo file
 */
static void LogFilestoreLogLoadWaldo(const char *path) {
    char line[16] = "";
    unsigned int id = 0;

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        SCLogInfo("couldn't open waldo: %s", strerror(errno));
        SCReturn;
    }

    if (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (sscanf(line, "%10u", &id) == 1) {
            SCLogInfo("id %u", id);
            (void) SC_ATOMIC_CAS(&file_id, 0, id);
        }
    }
    fclose(fp);
}

/**
 *  \internal
 *
 *  \brief Store the waldo file based on the file_id
 *
 *  \param path full path for the waldo file
 */
static void LogFilestoreLogStoreWaldo(const char *path) {
    char line[16] = "";

    if (SC_ATOMIC_GET(file_id) == 0) {
        SCReturn;
    }

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        SCLogInfo("couldn't open waldo: %s", strerror(errno));
        SCReturn;
    }

    snprintf(line, sizeof(line), "%u\n", SC_ATOMIC_GET(file_id));
    if (fwrite(line, strlen(line), 1, fp) != 1) {
        SCLogError(SC_ERR_FWRITE, "fwrite failed: %s", strerror(errno));
    }
    fclose(fp);
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
    if (ConfGet("default-log-dir", &s_default_log_dir) != 1)
        s_default_log_dir = DEFAULT_LOG_DIR;

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

    const char *waldo = ConfNodeLookupChildValue(conf, "waldo");
    if (waldo != NULL && strlen(waldo) > 0) {
        if (PathIsAbsolute(waldo)) {
            snprintf(g_waldo, sizeof(g_waldo), "%s", waldo);
        } else {
            snprintf(g_waldo, sizeof(g_waldo), "%s/%s", s_default_log_dir, waldo);
        }

        SCLogInfo("loading waldo file %s", g_waldo);
        LogFilestoreLogLoadWaldo(g_waldo);
    }
    SCLogInfo("storing files in %s", g_logfile_base_dir);

    SCReturnPtr(output_ctx, "OutputCtx");
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
    free(output_ctx);

    if (strlen(g_waldo) > 0) {
        LogFilestoreLogStoreWaldo(g_waldo);
    }
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFilestoreCtx using LogFilestoreNewCtx()
 *  \param config_file for loading separate configs
 *  \return -1 if failure, 0 if succesful
 * */
int LogFilestoreLogOpenFileCtx(LogFileCtx *file_ctx, const char *filename, const
                            char *mode)
{
    return 0;
}
