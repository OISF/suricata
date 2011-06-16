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

#include <string.h>

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
#include "util-debug.h"
#include "util-error.h"
#include "util-byte.h"

#include "output.h"
#include "alert-unified-log.h"
#include "util-privs.h"

#define DEFAULT_LOG_FILENAME "unified.log"

/**< Default log file limit in MB. */
#define DEFAULT_LIMIT 32

/**< Minimum log file limit in MB. */
#define MIN_LIMIT 1

#define MODULE_NAME "AlertUnifiedLog"

TmEcode AlertUnifiedLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertUnifiedLogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertUnifiedLogThreadDeinit(ThreadVars *, void *);
int AlertUnifiedLogOpenFileCtx(LogFileCtx *, const char *);
void AlertUnifiedLogRegisterTests(void);
static void AlertUnifiedLogDeInitCtx(OutputCtx *);

void TmModuleAlertUnifiedLogRegister (void) {
    tmm_modules[TMM_ALERTUNIFIEDLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTUNIFIEDLOG].ThreadInit = AlertUnifiedLogThreadInit;
    tmm_modules[TMM_ALERTUNIFIEDLOG].Func = AlertUnifiedLog;
    tmm_modules[TMM_ALERTUNIFIEDLOG].ThreadDeinit = AlertUnifiedLogThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIEDLOG].RegisterTests = AlertUnifiedLogRegisterTests;
    tmm_modules[TMM_ALERTUNIFIEDLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "unified-log", AlertUnifiedLogInitCtx);

#if __WORDSIZE == 64
    SCLogInfo("The Unified1 module detected a 64-bit system. For Barnyard "
            "0.2.0 to work correctly, it needs to be patched. Patch can be "
            "found here: https://redmine.openinfosecfoundation.org/attachments/download/184/barnyard.64bit.diff");
#endif
}

typedef struct AlertUnifiedLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */
} AlertUnifiedLogThread;

#define ALERTUNIFIEDLOG_LOGMAGIC 0xDEAD1080 /* taken from Snort */
#define ALERTUNIFIEDLOG_VERMAJOR 1          /* taken from Snort */
#define ALERTUNIFIEDLOG_VERMINOR 2          /* taken from Snort */

typedef struct AlertUnifiedLogFileHeader_ {
    uint32_t magic;
    uint16_t ver_major;
    uint16_t ver_minor;
    uint32_t timezone;
    uint32_t pad1; /* Snort has something called sigfigs, dunno what it is. I do know it's always 0. */
    uint32_t snaplen;
    uint32_t linktype;
} AlertUnifiedLogFileHeader;

typedef struct AlertUnifiedLogPacketHeader_ {
    /* Snort's 'Event' structure */
    uint32_t sig_gen;
    uint32_t sig_sid;
    uint32_t sig_rev;
    uint32_t sig_class;
    uint32_t sig_prio;
    uint32_t pad1; /* Snort's event_id */
    uint32_t pad2; /* Snort's event_reference */
#ifdef UNIFIED_NATIVE_TIMEVAL
    struct timeval ref_tv;
#else
    SCTimeval32 ref_tv;
#endif /* UNIFIED_NATIVE_TIMEVAL */

    /* 32 bit unsigned flags */
    uint32_t pktflags;

    /* Snort's 'SnortPktHeader' structure */
#ifdef UNIFIED_NATIVE_TIMEVAL
    struct timeval tv;
#else
    SCTimeval32 tv;
#endif /* UNIFIED_NATIVE_TIMEVAL */
    uint32_t caplen;
    uint32_t pktlen;
} AlertUnifiedLogPacketHeader;

int AlertUnifiedLogWriteFileHeader(LogFileCtx *file_ctx) {
    int ret;

    if (file_ctx->flags & LOGFILE_HEADER_WRITTEN)
        return 0;

    /* write the fileheader to the file so the reader can recognize it */

    AlertUnifiedLogFileHeader hdr;
    hdr.magic = ALERTUNIFIEDLOG_LOGMAGIC;
    hdr.ver_major = ALERTUNIFIEDLOG_VERMAJOR;
    hdr.ver_minor = ALERTUNIFIEDLOG_VERMINOR;
    hdr.timezone = 0; /* XXX */
    hdr.pad1 = 0; /* XXX */
    hdr.snaplen = 65536; /* XXX */
    hdr.linktype = DLT_EN10MB; /* XXX */

    ret = fwrite(&hdr, sizeof(hdr), 1, file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "fwrite failed: ret = %" PRId32 ", %s", ret,
                strerror(errno));
        return -1;
    }

    file_ctx->size_current = sizeof(hdr);
    return 0;
}

int AlertUnifiedLogCloseFile(ThreadVars *t, AlertUnifiedLogThread *aun) {
    if (aun->file_ctx->fp != NULL) {
        fclose(aun->file_ctx->fp);
    }
    aun->file_ctx->size_current = 0;
    aun->file_ctx->flags = 0;
    return 0;
}

int AlertUnifiedLogRotateFile(ThreadVars *t, AlertUnifiedLogThread *aun) {
    if (AlertUnifiedLogCloseFile(t,aun) < 0) {
        printf("Error: AlertUnifiedLogCloseFile failed\n");
        return -1;
    }

    if (AlertUnifiedLogOpenFileCtx(aun->file_ctx,aun->file_ctx->prefix) < 0) {
        printf("Error: AlertUnifiedLogOpenFileCtx, open new log file failed\n");
        return -1;
    }

    return 0;
}

TmEcode AlertUnifiedLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *post_pq)
{
    AlertUnifiedLogThread *aun = (AlertUnifiedLogThread *)data;
    AlertUnifiedLogPacketHeader hdr;
    PacketAlert pa_tag;
    PacketAlert *pa;
    int ret;
    uint8_t ethh_offset = 0;
    uint32_t buflen = 0;
    int pkt_has_tag = 0;

    if (p->flags & PKT_HAS_TAG) {
        PacketAlertAppendTag(p, &pa_tag);
        pkt_has_tag = 1;
    }

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
    hdr.tv.tv_sec = hdr.ref_tv.tv_sec = p->ts.tv_sec;
    hdr.tv.tv_usec = hdr.ref_tv.tv_usec = p->ts.tv_usec;
    hdr.pktflags = 0; /* XXX */
    hdr.pktlen = hdr.caplen = p->pktlen + ethh_offset;


    uint16_t i = 0;
    for (; i < p->alerts.cnt + 1; i++) {
        if (i < p->alerts.cnt)
            pa = &p->alerts.alerts[i];
        else
            if (pkt_has_tag == 1)
                pa = &pa_tag;
            else
                break;

        /* fill the hdr structure with the data of the alert */
        hdr.sig_gen = pa->gid;
        hdr.sig_sid = pa->sid;
        hdr.sig_rev = pa->rev;
        hdr.sig_class = pa->class;
        hdr.sig_prio = pa->prio;

        memcpy(aun->data,&hdr,sizeof(hdr));
        buflen = sizeof(hdr);

        if (p->ethh == NULL) {
            EthernetHdr ethh;
            memset(&ethh, 0, sizeof(EthernetHdr));
            ethh.eth_type = htons(ETHERNET_TYPE_IP);

            memcpy(aun->data+buflen,&ethh,sizeof(ethh));
            buflen += sizeof(ethh);
        }

        memcpy(aun->data+buflen,&p->pkt,p->pktlen);
        buflen += p->pktlen;

        /** Wait for the mutex. We dont want all the threads rotating the file
         * at the same time :) */
        SCMutexLock(&aun->file_ctx->fp_mutex);
        if ((aun->file_ctx->size_current + sizeof(hdr) + p->pktlen + ethh_offset) > aun->file_ctx->size_limit) {
            if (AlertUnifiedLogRotateFile(tv,aun) < 0) {
                SCMutexUnlock(&aun->file_ctx->fp_mutex);
                aun->file_ctx->alerts += i;
                return TM_ECODE_FAILED;
            }
        }

        ret = fwrite(aun->data, buflen, 1, aun->file_ctx->fp);
        if (ret != 1) {
            SCLogError(SC_ERR_FWRITE, "fwrite failed: %s", strerror(errno));
            aun->file_ctx->alerts += i;
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return TM_ECODE_FAILED;
        }
        /* force writing to disk so barnyard will not read half
         * written records and choke. */
        fflush(aun->file_ctx->fp);

        aun->file_ctx->alerts++;
        aun->file_ctx->size_current += buflen;
        SCMutexUnlock(&aun->file_ctx->fp_mutex);
    }

    return TM_ECODE_OK;
}

TmEcode AlertUnifiedLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertUnifiedLogThread *aun = SCMalloc(sizeof(AlertUnifiedLogThread));
    if (aun == NULL)
        return TM_ECODE_FAILED;
    memset(aun, 0, sizeof(AlertUnifiedLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for UnifiedLog. \"initdata\" argument NULL");
        SCFree(aun);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = ((OutputCtx *)initdata)->data;

    if (aun->file_ctx->fp == NULL) {
        SCLogError (SC_ERR_OPENING_FILE, "Target file has not been opened, check"
                " the write permission");
        SCFree(aun);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aun;

#define T_DATA_SIZE 80000
    aun->data = SCMalloc(T_DATA_SIZE);
    if (aun->data == NULL) {
        SCFree(aun);
        return TM_ECODE_FAILED;
    }
    aun->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    return TM_ECODE_OK;
}

TmEcode AlertUnifiedLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertUnifiedLogThread *aun = (AlertUnifiedLogThread *)data;
    if (aun == NULL) {
        goto error;
    }

    if (!(aun->file_ctx->flags & LOGFILE_ALERTS_PRINTED)) {
        SCLogInfo("Alert unified1 log module wrote %"PRIu64" alerts",
                aun->file_ctx->alerts);

        /* Do not print it for each thread */
        aun->file_ctx->flags |= LOGFILE_ALERTS_PRINTED;
    }

    if (aun->data != NULL) {
        SCFree(aun->data);
        aun->data = NULL;
    }
    aun->datalen = 0;
    /* clear memory */
    memset(aun, 0, sizeof(AlertUnifiedLogThread));
    SCFree(aun);
    return TM_ECODE_OK;

error:

    return TM_ECODE_FAILED;
}


/** \brief Create a new LogFileCtx for unified alert logging.
 *  \param ConfNode pointer to the configuration node for this logger.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *AlertUnifiedLogInitCtx(ConfNode *conf)
{
    int ret = 0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Couldn't create new file_ctx");
        return NULL;
    }

    const char *filename = NULL;
    if (conf != NULL) { /* \todo Maybe test should setup a ConfNode */
        filename = ConfNodeLookupChildValue(conf, "filename");
    }
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
                    "Fail to initialize unified log output, invalid limit: %s",
                    s_limit);
                exit(EXIT_FAILURE);
            }
            if (limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize unified log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }
            SCLogDebug("limit set to %"PRIu32, limit);
        }
    }
    file_ctx->size_limit = limit * 1024 * 1024;

    ret = AlertUnifiedLogOpenFileCtx(file_ctx, filename);
    if (ret < 0)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = file_ctx;
    output_ctx->DeInit = AlertUnifiedLogDeInitCtx;

    SCLogInfo("Unified-log initialized: filename %s, limit %"PRIu32" MB",
       filename, limit);

    return output_ctx;
}

static void AlertUnifiedLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    free(output_ctx);
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param prefix Prefix for log filenames.
 *  \return -1 if failure, 0 if succesful
 * */
int AlertUnifiedLogOpenFileCtx(LogFileCtx *file_ctx, const char *prefix)
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

    /** Write Unified header */
    ret = AlertUnifiedLogWriteFileHeader(file_ctx);
    if (ret != 0) {
        printf("Error: AlertUnifiedLogWriteFileHeader failed.\n");
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
static int AlertUnifiedLogTestRotate01(void)
{
    int ret = 0;
    int r = 0;
    ThreadVars tv;
    OutputCtx *oc;
    LogFileCtx *lf;
    void *data = NULL;

    oc = AlertUnifiedLogInitCtx(NULL);
    if (oc == NULL)
        return 0;
    lf = (LogFileCtx *)oc->data;
    if (lf == NULL)
        return 0;
    char *filename = SCStrdup(lf->filename);

    memset(&tv, 0, sizeof(ThreadVars));

    ret = AlertUnifiedLogThreadInit(&tv, oc, &data);
    if (ret == TM_ECODE_FAILED) {
        LogFileFreeCtx(lf);
        if (filename != NULL)
            free(filename);
        return 0;
    }

    TimeSetIncrementTime(1);

    ret = AlertUnifiedLogRotateFile(&tv, data);
    if (ret == -1)
        goto error;

    if (strcmp(filename, lf->filename) == 0)
        goto error;

    r = 1;

error:
    AlertUnifiedLogThreadDeinit(&tv, data);
    if (oc != NULL) AlertUnifiedLogDeInitCtx(oc);
    if (filename != NULL) free(filename);
    return r;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for Unified2
 */
void AlertUnifiedLogRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("UnifiedAlertTestRotate01 -- Rotate File",
                   AlertUnifiedLogTestRotate01, 1);
#endif /* UNITTESTS */
}

