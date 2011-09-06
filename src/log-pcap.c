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


/** \file
 *
 *  \author William Metcalf <William.Metcalf@gmail.com>
 *
 *  Pcap packet logging module.
 */

#if LIBPCAP_VERSION_MAJOR == 1
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "log-pcap.h"
#include "decode-ipv4.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"

#include "source-pcap.h"

#include "output.h"

#define DEFAULT_LOG_FILENAME "pcaplog"
#define MODULE_NAME "PcapLog"
#define MIN_LIMIT 1
#define DEFAULT_LIMIT 100

#define LOGMODE_NORMAL  0
#define LOGMODE_SGUIL   1

static int g_logpcap_mode = LOGMODE_NORMAL;
static char g_logpcap_sguil_base_dir[PATH_MAX] = "";

/*prototypes*/
TmEcode PcapLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode PcapLogThreadInit(ThreadVars *, void *, void **);
TmEcode PcapLogThreadDeinit(ThreadVars *, void *);
int PcapLogOpenFileCtx(LogFileCtx *, const char *);
static void PcapLogFileDeInitCtx(OutputCtx *);

/**
 * PcapLog thread vars
 *
 * Used for storing file options.
 */
typedef struct PcapLogThread_ {
    LogFileCtx *file_ctx;       /**< LogFileCtx pointer */
    uint32_t size_current;      /**< file current size */
    pcap_t *pcap_dead_handle;   /**< pcap_dumper_t needs a handle */
    pcap_dumper_t *pcap_dumper; /**< actually writes the packets */
    struct pcap_pkthdr *h;      /**< pcap header struct */
    int prev_day;               /**< last day, for finding out when
                                     to rotate in sguil mode */
} PcapLogThread;

void TmModulePcapLogRegister (void) {
    tmm_modules[TMM_PCAPLOG].name = MODULE_NAME;
    tmm_modules[TMM_PCAPLOG].ThreadInit = PcapLogThreadInit;
    tmm_modules[TMM_PCAPLOG].Func = PcapLog;
    tmm_modules[TMM_PCAPLOG].ThreadDeinit = PcapLogThreadDeinit;
    tmm_modules[TMM_PCAPLOG].RegisterTests = NULL;

    OutputRegisterModule(MODULE_NAME, "pcap-log", PcapLogInitCtx);
}

/**
 *  \brief Function to close pcaplog file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param pl PcapLog thread variable.
 */
int PcapLogCloseFile(ThreadVars *t, PcapLogThread *pl) {
    if (pl != NULL) {
        if (pl->pcap_dumper != NULL)
            pcap_dump_close(pl->pcap_dumper);
        pl->size_current = 0;
        pl->pcap_dumper = NULL;

        if (pl->pcap_dead_handle != NULL)
            pcap_close(pl->pcap_dead_handle);
        pl->pcap_dead_handle = NULL;
    }
    return 0;
}

/**
 *  \brief Function to rotate pcaplog file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param pl PcapLog thread variable.
 *
 *  \retval 0 on succces
 *  \retval -1 on failure
 */
int PcapLogRotateFile(ThreadVars *t, PcapLogThread *pl) {
    if (PcapLogCloseFile(t,pl) < 0) {
        SCLogDebug("PcapLogCloseFile failed");
        return -1;
    }
    if (PcapLogOpenFileCtx(pl->file_ctx,pl->file_ctx->prefix) < 0) {
        SCLogError(SC_ERR_FOPEN, "opening new pcap log file failed");
        return -1;
    }
    return 0;
}

/**
 *  \brief Pcap logging main function
 *
 *  \param t threadvar
 *  \param p packet
 *  \param data thread module specific data
 *  \param pq pre-packet-queue
 *  \param postpq post-packet-queue
 *
 *  \retval TM_ECODE_OK on succes
 *  \retval TM_ECODE_FAILED on serious error
 */
TmEcode PcapLog (ThreadVars *t, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    size_t len;
    PcapLogThread *pl = (PcapLogThread *)data;
    int rotate = 0;

    if (pl == NULL) {
        return TM_ECODE_FAILED;
    }

    if (p->flags & PKT_PSEUDO_STREAM_END || p->flags & PKT_STREAM_NOPCAPLOG ||
            (IS_TUNNEL_PKT(p) && !IS_TUNNEL_ROOT_PKT(p)))
    {
        return TM_ECODE_OK;
    }

    pl->h->ts.tv_sec = p->ts.tv_sec;
    pl->h->ts.tv_usec = p->ts.tv_usec;
    pl->h->caplen = GET_PKT_LEN(p);
    pl->h->len = GET_PKT_LEN(p);
    len = sizeof(*pl->h) + GET_PKT_LEN(p);

    if (g_logpcap_mode == LOGMODE_SGUIL) {
        struct tm local_tm;
        struct tm *tms = (struct tm *)localtime_r(&p->ts.tv_sec, &local_tm);
        if (tms->tm_mday != pl->prev_day) {
            rotate = 1;
            pl->prev_day = tms->tm_mday;
        }
    }

    SCMutexLock(&pl->file_ctx->fp_mutex);
    if ((pl->size_current + len) > pl->file_ctx->size_limit || rotate) {
        if (PcapLogRotateFile(t,pl) < 0)
        {
            SCMutexUnlock(&pl->file_ctx->fp_mutex);
            SCLogDebug("rotation of pcap failed");
            return TM_ECODE_FAILED;
        }
    }
    SCMutexUnlock(&pl->file_ctx->fp_mutex);

    /* XXX pcap handles, nfq, pfring, can only have one link type ipfw? we do
     * this here as we don't know the link type until we get our first packet */
    if (pl->pcap_dead_handle == NULL) {
        SCLogDebug("Setting pcap-log link type to %u", p->datalink);

        if ((pl->pcap_dead_handle = pcap_open_dead(p->datalink,
                        LIBPCAP_SNAPLEN)) == NULL)
        {
            SCLogDebug("Error opening dead pcap handle");
            return TM_ECODE_FAILED;
        }
    }
    /* XXX LogfileCtx setup currently doesn't allow thread vars so we open the
     * handle here */
    if (pl->pcap_dumper == NULL) {
        if ((pl->pcap_dumper = pcap_dump_open(pl->pcap_dead_handle,
                        pl->file_ctx->filename)) == NULL)
        {
            SCLogInfo("Error opening dump file %s",pcap_geterr(pl->pcap_dead_handle));
            return TM_ECODE_FAILED;
        }
    }

    pcap_dump((u_char *)pl->pcap_dumper, pl->h, GET_PKT_DATA(p));
    pl->size_current += len;
    SCLogDebug("%u %u",pl->size_current,pl->file_ctx->size_limit);

    return TM_ECODE_OK;
}

TmEcode PcapLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    PcapLogThread *pl = SCMalloc(sizeof(PcapLogThread));
    if (pl == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(pl, 0, sizeof(PcapLogThread));

    pl->h = SCMalloc(sizeof(*pl->h));
    if (pl->h == NULL) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for PcapLog.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    pl->file_ctx = ((OutputCtx*)initdata)->data;

    pl->pcap_dead_handle = NULL;
    pl->pcap_dumper = NULL;

    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));
    TimeGet(&ts);
    struct tm local_tm;
    struct tm *tms = (struct tm *)localtime_r(&ts.tv_sec, &local_tm);
    pl->prev_day = tms->tm_mday;

    *data = (void *)pl;
    return TM_ECODE_OK;
}

/**
 *  \brief Thread deinit function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param data PcapLog thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */

TmEcode PcapLogThreadDeinit(ThreadVars *t, void *data)
{
    PcapLogThread *pl = (PcapLogThread *)data;
    if (pl == NULL) {
        goto error;
    }

    /* clear memory */
    memset(pl, 0, sizeof(PcapLogThread));
    free(pl);
    return TM_ECODE_OK;

error:
    /* clear memory */
    if (pl != NULL) {
        memset(pl, 0, sizeof(PcapLogThread));
        free(pl);
    }
    return TM_ECODE_FAILED;
}

/** \brief Create a new LogFileCtx from the provided ConfNode.
 *  \param conf The configuration node for this output.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *PcapLogInitCtx(ConfNode *conf)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogDebug( "PcapLogInitCtx: "
                "Couldn't create new file_ctx");
        return NULL;
    }

    const char *filename = NULL;
    if (conf != NULL) { /* To faciliate unit tests. */
        filename = ConfNodeLookupChildValue(conf, "filename");
    }
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;

    file_ctx->prefix = SCStrdup(filename);

    uint32_t limit = DEFAULT_LIMIT;
    if (conf != NULL) {
        const char *s_limit = NULL;
        s_limit = ConfNodeLookupChildValue(conf, "limit");
        if (s_limit != NULL) {
            if (ByteExtractStringUint32(&limit, 10, 0, s_limit) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize pcap-log output, invalid limit: %s",
                    s_limit);
                exit(EXIT_FAILURE);
            }
            if (limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize pcap-log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }
        }
    }
    file_ctx->size_limit = limit * 1024 * 1024;

    if (conf != NULL) {
        const char *s_mode = NULL;
        s_mode = ConfNodeLookupChildValue(conf, "mode");
        if (s_mode != NULL) {
            if (strcasecmp(s_mode, "sguil") == 0) {
                g_logpcap_mode = LOGMODE_SGUIL;
            }
        }

        if (g_logpcap_mode == LOGMODE_SGUIL) {
            const char *s_sguil_base = NULL;
            s_sguil_base = ConfNodeLookupChildValue(conf, "sguil_base_dir");
            if (s_sguil_base == NULL) {
                SCLogError(SC_ERR_LOGPCAP_SGUIL_BASE_DIR_MISSING,
                    "log-pcap \"sguil\" mode requires \"sguil_base_dir\" "
                    "option to be set.");
                exit(EXIT_FAILURE);
            }

            strlcpy(g_logpcap_sguil_base_dir,
                    s_sguil_base, sizeof(g_logpcap_sguil_base_dir));
        }
    }

    SCLogInfo("using %s logging", g_logpcap_mode == LOGMODE_SGUIL ?
            "Sguil compatible" : "normal");

    ret = PcapLogOpenFileCtx(file_ctx, filename);
    if (ret < 0)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for OutputCtx.");
        exit(EXIT_FAILURE);
    }
    output_ctx->data = file_ctx;
    output_ctx->DeInit = PcapLogFileDeInitCtx;

    return output_ctx;
}

static void PcapLogFileDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx != NULL) {
        LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
        if (logfile_ctx != NULL) {
            LogFileFreeCtx(logfile_ctx);
        }
        free(output_ctx);
    }
}

/**
 *  \brief Read the config set the file pointer, open the file
 *
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param prefix Prefix of the log file.
 *
 *  \retval -1 if failure
 *  \retval 0 if succesful
 */
int PcapLogOpenFileCtx(LogFileCtx *file_ctx, const char *prefix)
{
    char *filename = NULL;

    if (file_ctx->filename != NULL)
        filename = file_ctx->filename;
    else {
        filename = file_ctx->filename = SCMalloc(PATH_MAX);
        if (filename == NULL) {
            return -1;
        }
    }

    /** get the time so we can have a filename with seconds since epoch */
    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));
    TimeGet(&ts);

    char *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;

    if (g_logpcap_mode == LOGMODE_SGUIL) {
        struct tm local_tm;
        struct tm *tms = (struct tm *)localtime_r(&ts.tv_sec, &local_tm);

        char dirname[32], dirfull[PATH_MAX] = "";

        snprintf(dirname, sizeof(dirname), "%04d-%02d-%02d",
                tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday);

        /* create the filename to use */
        snprintf(dirfull, PATH_MAX, "%s/%s", g_logpcap_sguil_base_dir, dirname);

        /* if mkdir fails file open will fail, so deal with errors there */
#ifndef OS_WIN32
        (void)mkdir(dirfull, 0700);
#else
        (void)mkdir(dirfull);
#endif

        snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, dirfull, prefix, (uint32_t)ts.tv_sec);
    } else {
        /* create the filename to use */
        if (prefix[0] == '/') {
            snprintf(filename, PATH_MAX, "%s.%" PRIu32, prefix, (uint32_t)ts.tv_sec);
        } else {
            snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, log_dir, prefix, (uint32_t)ts.tv_sec);
        }
    }

    return 0;
}
