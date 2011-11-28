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

#define MODULE_NAME "LogFileLog"

TmEcode LogFileLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFileLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogFileLogThreadDeinit(ThreadVars *, void *);
void LogFileLogExitPrintStats(ThreadVars *, void *);
int LogFileLogOpenFileCtx(LogFileCtx* , const char *, const char *);
static void LogFileLogDeInitCtx(OutputCtx *);

SC_ATOMIC_DECLARE(unsigned int, file_id);
static char g_logfile_base_dir[PATH_MAX] = "/tmp";

void TmModuleLogFileLogRegister (void) {
    tmm_modules[TMM_FILELOG].name = MODULE_NAME;
    tmm_modules[TMM_FILELOG].ThreadInit = LogFileLogThreadInit;
    tmm_modules[TMM_FILELOG].Func = LogFileLog;
    tmm_modules[TMM_FILELOG].ThreadExitPrintStats = LogFileLogExitPrintStats;
    tmm_modules[TMM_FILELOG].ThreadDeinit = LogFileLogThreadDeinit;
    tmm_modules[TMM_FILELOG].RegisterTests = NULL;
    tmm_modules[TMM_FILELOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "file", LogFileLogInitCtx);

    SCLogDebug("registered");

    SC_ATOMIC_INIT(file_id);
}

typedef struct LogFileLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
} LogFileLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogFileLogCreateMetaFile(Packet *p, File *ff, char *filename, int ipver) {
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
        fprintf(fp, "FILENAME:          ");
        PrintRawUriFp(fp, ff->name, ff->name_len);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

static void LogFileLogCloseMetaFile(File *ff) {
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

    SCMutexLock(&p->flow->m);

    FileContainer *ffc = AppLayerGetFilesFromFlow(p->flow, flags);
    SCLogDebug("ffc %p", ffc);
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            int file_fd = -1;

            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicLookup(ff);
            }

            SCLogDebug("ff %p", ff);
            if (ff->state == FILE_STATE_STORED) {
                SCLogDebug("ff->state == FILE_STATE_STORED");
                continue;
            }

            if (ff->store != 1) {
                SCLogDebug("ff->store %d, so not 1", ff->store);
                continue;
            }

            FileData *ffd;
            for (ffd = ff->chunks_head; ffd != NULL; ffd = ffd->next) {
                SCLogDebug("ffd %p", ffd);
                if (ffd->stored == 1) {
                    if (file_close == 1 && ffd->next == NULL) {
                        LogFileLogCloseMetaFile(ff);
                        ff->state = FILE_STATE_STORED;
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
                    LogFileLogCreateMetaFile(p, ff, filename, ipver);
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
                    file_fd = -1;
                    continue;
                }

                close(file_fd);
                file_fd = -1;

                if (ff->state == FILE_STATE_CLOSED ||
                    ff->state == FILE_STATE_TRUNCATED ||
                    ff->state == FILE_STATE_ERROR ||
                    (file_close == 1 && ff->state < FILE_STATE_CLOSED))
                {
                    if (ffd->next == NULL) {
                        LogFileLogCloseMetaFile(ff);

                        ff->state = FILE_STATE_STORED;
                    }
                }

                ffd->stored = 1;
            }
        }

        FilePrune(ffc);
    }

    SCMutexUnlock(&p->flow->m);
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
    if (aft == NULL)
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

    struct stat stat_buf;
    if (stat(g_logfile_base_dir, &stat_buf) != 0) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The file drop directory \"%s\" "
                "supplied doesn't exist. Shutting down the engine",
                g_logfile_base_dir);
        exit(EXIT_FAILURE);
    }

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

    SCLogInfo("(%s) Files extracted %" PRIu32 "", tv->name, aft->file_cnt);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogFileLogInitCtx(ConfNode *conf)
{
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;

    output_ctx->data = NULL;
    output_ctx->DeInit = LogFileLogDeInitCtx;

    char *s_default_log_dir = NULL;
    if (ConfGet("default-log-dir", &s_default_log_dir) != 1)
        s_default_log_dir = DEFAULT_LOG_DIR;

    const char *s_base_dir = NULL;
    s_base_dir = ConfNodeLookupChildValue(conf, "log-dir");
    if (s_base_dir == NULL) {
        strlcpy(g_logfile_base_dir,
                s_default_log_dir, sizeof(g_logfile_base_dir));
    } else {
        if (s_base_dir[0] == '/') {
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

    SCLogInfo("storing files in %s", g_logfile_base_dir);

    SCReturnPtr(output_ctx, "OutputCtx");
}

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
