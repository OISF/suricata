/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* alert unified
 *
 * Logs alerts in a format compatible to Snort's unified1 format, so it should
 * be readable by Barnyard.
 *
 * TODO
 * - inspect error messages for threadsafety
 * - inspect gettimeofday for threadsafely
 * - implement configuration
 *
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

#define DEFAULT_LOG_FILENAME "unified.alert"

TmEcode AlertUnifiedAlert (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertUnifiedAlertThreadInit(ThreadVars *, void *, void **);
TmEcode AlertUnifiedAlertThreadDeinit(ThreadVars *, void *);
int AlertUnifiedAlertOpenFileCtx(LogFileCtx *, char *);
void AlertUnifiedAlertRegisterTests (void);

void TmModuleAlertUnifiedAlertRegister (void) {
    tmm_modules[TMM_ALERTUNIFIEDALERT].name = "AlertUnifiedAlert";
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadInit = AlertUnifiedAlertThreadInit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].Func = AlertUnifiedAlert;
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadDeinit = AlertUnifiedAlertThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].RegisterTests = AlertUnifiedAlertRegisterTests;
}

typedef struct AlertUnifiedAlertThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    uint32_t size_limit;
    uint32_t size_current;
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
    uint32_t tv_sec1; /* from Snort's struct pcap_timeval in Event */
    uint32_t tv_usec1; /* from Snort's struct pcap_timeval in Event */

    uint32_t tv_sec2; /* from Snort's struct pcap_timeval */
    uint32_t tv_usec2; /* from Snort's struct pcap_timeval */

    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sp;
    uint16_t dp;
    uint32_t protocol;
    uint32_t flags;
} AlertUnifiedAlertPacketHeader;

int AlertUnifiedAlertWriteFileHeader(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    int ret;

    /** write the fileheader to the file so the reader can recognize it */
    AlertUnifiedAlertFileHeader hdr;
    hdr.magic = ALERTUNIFIEDALERT_ALERTMAGIC;
    hdr.ver_major = ALERTUNIFIEDALERT_VERMAJOR;
    hdr.ver_minor = ALERTUNIFIEDALERT_VERMINOR;
    hdr.timezone = 0; /* XXX */

    ret = fwrite(&hdr, sizeof(hdr), 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: ret = %" PRId32 ", %s",
                   ret, strerror(errno));
        return -1;
    }
    fflush(aun->file_ctx->fp);

    aun->size_current = sizeof(hdr);
    return 0;
}

int AlertUnifiedAlertCloseFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (aun->file_ctx->fp != NULL) {
        fclose(aun->file_ctx->fp);
    }
    aun->size_current = 0;

    return 0;
}

int AlertUnifiedAlertRotateFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (AlertUnifiedAlertCloseFile(t,aun) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR,
                   "Error: AlertUnifiedAlertCloseFile failed");
        return -1;
    }
    if (AlertUnifiedAlertOpenFileCtx(aun->file_ctx,aun->file_ctx->config_file) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR,
                   "Error: AlertUnifiedLogOpenFileCtx, open new log file failed");
        return -1;
    }
    if (AlertUnifiedAlertWriteFileHeader(t, aun) < 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR, "Error: "
                   "AlertUnifiedLogAppendFile, write unified header failed");
        return -1;
    }

    return 0;
}

TmEcode AlertUnifiedAlert (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
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

    /** check and enforce the filesize limit, thread safe */
    SCMutexLock(&aun->file_ctx->fp_mutex);
    if ((aun->size_current + sizeof(hdr)) > aun->size_limit) {
        if (AlertUnifiedAlertRotateFile(tv,aun) < 0)
        {
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return TM_ECODE_FAILED;
        }
    }
    SCMutexUnlock(&aun->file_ctx->fp_mutex);

    /* XXX which one to add to this alert? Lets see how Snort solves this.
     * For now just take last alert. */
    PacketAlert *pa = &p->alerts.alerts[p->alerts.cnt-1];

    /* fill the hdr structure */
    hdr.sig_gen = pa->gid;
    hdr.sig_sid = pa->sid;
    hdr.sig_rev = pa->rev;
    hdr.sig_class = pa->class;
    hdr.sig_prio = pa->prio;
    hdr.pad1 = 0;
    hdr.pad2 = 0;
    hdr.tv_sec1 = hdr.tv_sec2 = p->ts.tv_sec;
    hdr.tv_usec1 = hdr.tv_usec2 = p->ts.tv_usec;
    hdr.src_ip = GET_IPV4_SRC_ADDR_U32(p);
    hdr.dst_ip = GET_IPV4_DST_ADDR_U32(p);
    hdr.sp = p->sp;
    hdr.dp = p->dp;
    hdr.protocol = IPV4_GET_RAW_IPPROTO(p->ip4h);
    hdr.flags = 0;

    /* write and flush so it's written immediately */
    ret = fwrite(&hdr, sizeof(hdr), 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
        return TM_ECODE_FAILED;
    }
    /* force writing to disk so barnyard will not read half
     * written records and choke. */
    fflush(aun->file_ctx->fp);

    aun->size_current += sizeof(hdr);
    return TM_ECODE_OK;
}

TmEcode AlertUnifiedAlertThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertUnifiedAlertThread *aun = malloc(sizeof(AlertUnifiedAlertThread));
    if (aun == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));

    if(initdata == NULL)
    {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR, "Error getting context for "
                   "UnifiedAlert.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = (LogFileCtx*) initdata;
    aun->size_limit = 30;

    /** Write Unified header */
    int ret = AlertUnifiedAlertWriteFileHeader(t, aun);
    if (ret != 0) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR,
                   "Error: AlertUnifiedLogWriteFileHeader failed");
        return TM_ECODE_FAILED;
    }

    /* XXX make configurable */
    aun->size_limit = 10 * 1024 * 1024;

    *data = (void *)aun;
    return TM_ECODE_OK;
}

TmEcode AlertUnifiedAlertThreadDeinit(ThreadVars *t, void *data)
{
    AlertUnifiedAlertThread *aun = (AlertUnifiedAlertThread *)data;
    if (aun == NULL) {
        goto error;
    }

    /* clear memory */
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));
    free(aun);
    return TM_ECODE_OK;

error:
    /* clear memory */
    if (aun != NULL) {
        memset(aun, 0, sizeof(AlertUnifiedAlertThread));
        free(aun);
    }
    return TM_ECODE_FAILED;
}


/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *AlertUnifiedAlertInitCtx(char *config_file)
{
    int ret = 0;
    LogFileCtx *file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_UNIFIED_ALERT_GENERIC_ERROR,
                   "AlertUnifiedAlertInitCtx: Couldn't create new file_ctx");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific AlertUnifiedAlert configuration */
    ret = AlertUnifiedAlertOpenFileCtx(file_ctx, config_file);

    if (ret < 0)
        return NULL;

    /** In AlertUnifiedAlertOpenFileCtx the second parameter should be
    * the configuration file to use but it's not implemented yet, so
    * passing NULL to load the default configuration
    */

    return file_ctx;
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param config_file for loading separate configs
 *  \return -1 if failure, 0 if succesful
 * */
int AlertUnifiedAlertOpenFileCtx(LogFileCtx *file_ctx, char *config_file)
{
    char *filename = NULL;
    if (file_ctx->filename != NULL)
        filename = file_ctx->filename;
    else
        filename = file_ctx->filename = malloc(PATH_MAX); /* XXX some sane default? */

    if (config_file == NULL) {
        /** Separate config files not implemented at the moment,
        * but it must be able to load from separate config file.
        * Load the default configuration.
        */

        /* get the time so we can have a filename with seconds since epoch */
        struct timeval ts;
        memset (&ts, 0, sizeof(struct timeval));
        TimeGet(&ts);

        /* create the filename to use */
        char *log_dir;
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;

        snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, log_dir, "unified.alert", (uint32_t)ts.tv_sec);

        /* XXX filename & location */
        file_ctx->fp = fopen(filename, "wb");
        if (file_ctx->fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", filename,
                       strerror(errno));
            return -1;
        }
    }

    return 0;
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
    LogFileCtx *lf;
    void *data = NULL;

    lf = AlertUnifiedAlertInitCtx(NULL);
    if (lf == NULL)
        return 0;
    char *filename = strdup(lf->filename);

    memset(&tv, 0, sizeof(ThreadVars));

    if (lf == NULL)
        return 0;

    ret = AlertUnifiedAlertThreadInit(&tv, lf, &data);
    if (ret == TM_ECODE_FAILED) {
        LogFileFreeCtx(lf);
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
    if (lf != NULL) LogFileFreeCtx(lf);
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
