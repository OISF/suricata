/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Logs alerts in a format compatible to Snort's unified1 format, so it should
 * be readable by Barnyard.
 *
 * \todo inspect error messages for threadsafety
 * \todo inspect gettimeofday for threadsafely
 * \todo implement configuration
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-unittest.h"
#include "util-time.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "alert-unified-alert.h"
#include "util-privs.h"

#define DEFAULT_LOG_FILENAME "unified.alert"

/**< Default log file limit in MB. */
#define DEFAULT_LIMIT 32

/**< Minimum log file limit in MB. */
#define MIN_LIMIT 1

#define MODULE_NAME "AlertUnifiedAlert"

TmEcode AlertUnifiedAlert (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertUnifiedAlertThreadInit(ThreadVars *, void *, void **);
TmEcode AlertUnifiedAlertThreadDeinit(ThreadVars *, void *);
int AlertUnifiedAlertOpenFileCtx(LogFileCtx *, const char *);
void AlertUnifiedAlertRegisterTests (void);
static void AlertUnifiedAlertDeInitCtx(OutputCtx *);

void TmModuleAlertUnifiedAlertRegister (void) {
    tmm_modules[TMM_ALERTUNIFIEDALERT].name = MODULE_NAME;
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadInit = AlertUnifiedAlertThreadInit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].Func = AlertUnifiedAlert;
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadDeinit = AlertUnifiedAlertThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].RegisterTests = AlertUnifiedAlertRegisterTests;
    tmm_modules[TMM_ALERTUNIFIEDALERT].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "unified-alert", AlertUnifiedAlertInitCtx);
}

typedef struct AlertUnifiedAlertThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertUnifiedAlertThread;

#define ALERTUNIFIEDALERT_ALERTMAGIC 0xDEAD4137 /* taken from Snort */
#define ALERTUNIFIEDALERT_VERMAJOR 1            /* taken from Snort */
#define ALERTUNIFIEDALERT_VERMINOR 81           /* taken from Snort */

typedef struct AlertUnifiedAlertFileHeader_ {
    uint32_t magic;
    uint32_t ver_major;
    uint32_t ver_minor;
    uint32_t timezone;
} AlertUnifiedAlertFileHeader;

typedef struct AlertUnifiedAlertPacketHeader_ {
    /* Snort's 'Event' structure */
    uint32_t sig_gen;
    uint32_t sig_sid;
    uint32_t sig_rev;
    uint32_t sig_class;

    uint32_t sig_prio;
    uint32_t pad1; /* Snort's event_id */
    uint32_t pad2; /* Snort's event_reference */
#ifdef UNIFIED_NATIVE_TIMEVAL
    struct timeval ref_ts; /* Reference timestamp. */
    struct timeval ts; /* Timestamp. */
#else
    SCTimeval32 ref_ts; /* Reference timestamp. */
    SCTimeval32 ts; /* Timestamp. */
#endif /* UNIFIED_NATIVE_TIMEVAL */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sp;
    uint16_t dp;
    uint32_t protocol;

    uint32_t flags;
} AlertUnifiedAlertPacketHeader;

int AlertUnifiedAlertWriteFileHeader(LogFileCtx *file_ctx) {
    int ret;
    if (file_ctx->flags & LOGFILE_HEADER_WRITTEN)
        return 0;

    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "file pointer is NULL");
        return -1;
    }

    /** write the fileheader to the file so the reader can recognize it */
    AlertUnifiedAlertFileHeader hdr;
    hdr.magic = ALERTUNIFIEDALERT_ALERTMAGIC;
    hdr.ver_major = ALERTUNIFIEDALERT_VERMAJOR;
    hdr.ver_minor = ALERTUNIFIEDALERT_VERMINOR;
    hdr.timezone = 0; /* XXX */

    ret = fwrite(&hdr, sizeof(AlertUnifiedAlertFileHeader), 1, file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: ret = %" PRId32 ", %s",
                   ret, strerror(errno));
        return -1;
    }
    fflush(file_ctx->fp);

    file_ctx->size_current = sizeof(hdr);

    file_ctx->flags |= LOGFILE_HEADER_WRITTEN;
    return 0;
}

int AlertUnifiedAlertCloseFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (aun->file_ctx->fp != NULL) {
        fclose(aun->file_ctx->fp);
    }
    aun->file_ctx->size_current = 0;
    aun->file_ctx->flags = 0;

    return 0;
}

int AlertUnifiedAlertRotateFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (AlertUnifiedAlertCloseFile(t,aun) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC,
                   "Error: AlertUnifiedAlertCloseFile failed");
        return -1;
    }
    if (AlertUnifiedAlertOpenFileCtx(aun->file_ctx,aun->file_ctx->prefix) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC,
                   "Error: AlertUnifiedLogOpenFileCtx, open new log file failed");
        return -1;
    }
    if (AlertUnifiedAlertWriteFileHeader(aun->file_ctx) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC, "Error: "
                   "AlertUnifiedLogAppendFile, write unified header failed");
        return -1;
    }

    return 0;
}

TmEcode AlertUnifiedAlert (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertUnifiedAlertThread *aun = (AlertUnifiedAlertThread *)data;
    AlertUnifiedAlertPacketHeader hdr;

    int ret;
    uint8_t ethh_offset = 0;

    /* the unified1 format only supports IPv4. */
    if (p->alerts.cnt == 0 || !PKT_IS_IPV4(p))
        return TM_ECODE_OK;

    /* if we have no ethernet header (e.g. when using nfq), we have to create
     * one ourselves. */
    if (p->ethh == NULL) {
        ethh_offset = sizeof(EthernetHdr);
    }

    /* fill the hdr structure with the data of the packet */
    hdr.pad1 = 0;
    hdr.pad2 = 0;
    hdr.ts.tv_sec = hdr.ref_ts.tv_sec = p->ts.tv_sec;
    hdr.ts.tv_usec = hdr.ref_ts.tv_usec = p->ts.tv_sec;
    hdr.src_ip = ntohl(GET_IPV4_SRC_ADDR_U32(p)); /* addr is host order */
    hdr.dst_ip = ntohl(GET_IPV4_DST_ADDR_U32(p)); /* addr is host order */
    hdr.sp = p->sp;
    hdr.dp = p->dp;
    hdr.protocol = IPV4_GET_RAW_IPPROTO(p->ip4h);
    hdr.flags = 0;

    uint16_t i = 0;
    for (; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];

        /* fill the rest of the hdr structure with the data of the alert */
        hdr.sig_gen = pa->gid;
        hdr.sig_sid = pa->sid;
        hdr.sig_rev = pa->rev;
        hdr.sig_class = pa->class;
        hdr.sig_prio = pa->prio;

        SCMutexLock(&aun->file_ctx->fp_mutex);
        /** check and enforce the filesize limit, thread safe */
        if ((aun->file_ctx->size_current + sizeof(hdr)) > aun->file_ctx->size_limit) {
            if (AlertUnifiedAlertRotateFile(tv,aun) < 0) {
                SCMutexUnlock(&aun->file_ctx->fp_mutex);
                aun->file_ctx->alerts += i;
                return TM_ECODE_FAILED;
            }
        }
        /* Then the unified header */
        ret = fwrite(&hdr, sizeof(AlertUnifiedAlertPacketHeader), 1, aun->file_ctx->fp);
        if (ret != 1) {
            SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            aun->file_ctx->alerts += i;
            return TM_ECODE_FAILED;
        }
        /* force writing to disk so barnyard will not read half
         * written records and choke. */
        fflush(aun->file_ctx->fp);

        aun->file_ctx->size_current += sizeof(hdr);
        aun->file_ctx->alerts++;
        SCMutexUnlock(&aun->file_ctx->fp_mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertUnifiedAlertThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertUnifiedAlertThread *aun = SCMalloc(sizeof(AlertUnifiedAlertThread));
    if (aun == NULL)
        return TM_ECODE_FAILED;
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for UnifiedAlert.  \"initdata\" argument NULL");
        SCFree(aun);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aun;
    return TM_ECODE_OK;
}

TmEcode AlertUnifiedAlertThreadDeinit(ThreadVars *t, void *data)
{
    AlertUnifiedAlertThread *aun = (AlertUnifiedAlertThread *)data;
    if (aun == NULL) {
        goto error;
    }

    if (!(aun->file_ctx->flags & LOGFILE_ALERTS_PRINTED)) {
        SCLogInfo("Alert unified1 alert module wrote %"PRIu64" alerts",
                aun->file_ctx->alerts);

        /* Do not print it for each thread */
        aun->file_ctx->flags |= LOGFILE_ALERTS_PRINTED;
    }
    /* clear memory */
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));
    SCFree(aun);
    return TM_ECODE_OK;

error:
    return TM_ECODE_FAILED;
}


/** \brief Create a new LogFileCtx for unified alert logging.
 *  \param conf The ConfNode for this output.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *AlertUnifiedAlertInitCtx(ConfNode *conf)
{
    int ret = 0;
    LogFileCtx *file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC,
                   "AlertUnifiedAlertInitCtx: Couldn't create new file_ctx");
        return NULL;
    }

    const char *filename = NULL;
    if (conf != NULL)
        filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;
    file_ctx->prefix = SCStrdup(filename);

    const char *s_limit = NULL;
    uint32_t limit = DEFAULT_LIMIT;
    if (conf != NULL) {
        s_limit = ConfNodeLookupChildValue(conf, "limit");
        if (s_limit != NULL) {
            if (ByteExtractStringUint32(&limit, 10, 0, s_limit) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize unified alert output, invalid limit: %s",
                    s_limit);
                exit(EXIT_FAILURE);
            }
            if (limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize unified alert output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }
        }
    }
    file_ctx->size_limit = limit * 1024 * 1024;

    ret = AlertUnifiedAlertOpenFileCtx(file_ctx, filename);
    if (ret < 0)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = file_ctx;
    output_ctx->DeInit = AlertUnifiedAlertDeInitCtx;

    SCLogInfo("Unified-alert initialized: filename %s, limit %"PRIu32" MB",
       filename, limit);

    return output_ctx;
}

static void AlertUnifiedAlertDeInitCtx(OutputCtx *output_ctx)
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
int AlertUnifiedAlertOpenFileCtx(LogFileCtx *file_ctx, const char *prefix)
{
    int ret = 0;
    char *filename = NULL;
    if (file_ctx->filename != NULL)
        filename = file_ctx->filename;
    else {
        filename = file_ctx->filename = SCMalloc(PATH_MAX); /* XXX some sane default? */
        if (filename == NULL)
            return -1;
    }

    /* get the time so we can have a filename with seconds since epoch */
    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));

    extern int run_mode;
    if (run_mode == MODE_UNITTEST)
        TimeGet(&ts);
    else
        gettimeofday(&ts, NULL);

    /* create the filename to use */
    char *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;

    snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, log_dir, prefix, (uint32_t)ts.tv_sec);

    /* XXX filename & location */
    file_ctx->fp = fopen(filename, "wb");
    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", filename,
            strerror(errno));
        return TM_ECODE_FAILED;
    }
    file_ctx->flags = 0;

    /** Write Unified header */
    ret = AlertUnifiedAlertWriteFileHeader(file_ctx);
    if (ret != 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC,
                   "Error: AlertUnifiedLogWriteFileHeader failed");
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/**
 *  \test Test the Rotate process
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int AlertUnifiedAlertTestRotate01(void)
{
    int ret = 0;
    int r = 0;
    ThreadVars tv;
    OutputCtx *oc;
    LogFileCtx *lf;
    void *data = NULL;

    oc = AlertUnifiedAlertInitCtx(NULL);
    if (oc == NULL)
        return 0;
    lf = (LogFileCtx *)oc->data;
    if (lf == NULL)
        return 0;
    char *filename = SCStrdup(lf->filename);

    memset(&tv, 0, sizeof(ThreadVars));

    ret = AlertUnifiedAlertThreadInit(&tv, oc, &data);
    if (ret == TM_ECODE_FAILED) {
        LogFileFreeCtx(lf);
        if (filename != NULL)
            free(filename);
        return 0;
    }

    TimeSetIncrementTime(1);

    ret = AlertUnifiedAlertRotateFile(&tv, data);
    if (ret == -1)
        goto error;

    if (strcmp(filename, lf->filename) == 0)
        goto error;

    r = 1;

error:
    AlertUnifiedAlertThreadDeinit(&tv, data);
    if (oc != NULL) AlertUnifiedAlertDeInitCtx(oc);
    if (filename != NULL) free(filename);
    return r;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for Unified2
 */
void AlertUnifiedAlertRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("UnifiedAlertTestRotate01 -- Rotate File",
                   AlertUnifiedAlertTestRotate01, 1);
#endif /* UNITTESTS */
}
