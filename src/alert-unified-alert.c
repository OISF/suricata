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

#include "eidps-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-unittest.h"

#define DEFAULT_LOG_FILENAME "unified.alert"

int AlertUnifiedAlert (ThreadVars *, Packet *, void *, PacketQueue *);
int AlertUnifiedAlertThreadInit(ThreadVars *, void *, void **);
int AlertUnifiedAlertThreadDeinit(ThreadVars *, void *);
int AlertUnifiedAlertOpenFileCtx(LogFileCtx *, char *);

void TmModuleAlertUnifiedAlertRegister (void) {
    tmm_modules[TMM_ALERTUNIFIEDALERT].name = "AlertUnifiedAlert";
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadInit = AlertUnifiedAlertThreadInit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].Func = AlertUnifiedAlert;
    tmm_modules[TMM_ALERTUNIFIEDALERT].ThreadDeinit = AlertUnifiedAlertThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIEDALERT].RegisterTests = NULL;
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
        printf("Error: fwrite failed: ret = %" PRId32 ", %s\n", ret, strerror(errno));
        return -1;
    }
    fflush(aun->file_ctx->fp);

    aun->size_current = sizeof(hdr);
    return 0;
}

int AlertUnifiedAlertCloseFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (aun->file_ctx->fp != NULL)
        fclose(aun->file_ctx->fp);

    return 0;
}

int AlertUnifiedAlertRotateFile(ThreadVars *t, AlertUnifiedAlertThread *aun) {
    if (AlertUnifiedAlertCloseFile(t,aun) < 0) {
        printf("Error: AlertUnifiedAlertCloseFile failed\n");
        return -1;
    }
    if (AlertUnifiedAlertOpenFileCtx(aun->file_ctx,aun->file_ctx->config_file) < 0) {
        printf("Error: AlertUnifiedLogOpenFileCtx, open new log file failed\n");
        return -1;
    }
    if (AlertUnifiedAlertWriteFileHeader(t, aun) < 0) {
        printf("Error: AlertUnifiedLogAppendFile, write unified header failed\n");
        return -1;
    }

    return 0;
}

int AlertUnifiedAlert (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertUnifiedAlertThread *aun = (AlertUnifiedAlertThread *)data;
    AlertUnifiedAlertPacketHeader hdr;
    int ret;
    uint8_t ethh_offset = 0;

    /* the unified1 format only supports IPv4. */
    if (p->alerts.cnt == 0 || !PKT_IS_IPV4(p))
        return 0;

    /* if we have no ethernet header (e.g. when using nfq), we have to create
     * one ourselves. */
    if (p->ethh == NULL) {
        ethh_offset = sizeof(EthernetHdr);
    }

    /** check and enforce the filesize limit, thread safe */
    mutex_lock(&aun->file_ctx->fp_mutex);
    if ((aun->size_current + sizeof(hdr)) > aun->size_limit) {
        if (AlertUnifiedAlertRotateFile(tv,aun) < 0)
        {
            mutex_unlock(&aun->file_ctx->fp_mutex);
            return -1;
        }
    }
    mutex_unlock(&aun->file_ctx->fp_mutex);

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
        printf("Error: fwrite failed: %s\n", strerror(errno));
        return -1;
    }
    /* force writing to disk so barnyard will not read half
     * written records and choke. */
    fflush(aun->file_ctx->fp);

    aun->size_current += sizeof(hdr);
    return 0;
}

int AlertUnifiedAlertThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertUnifiedAlertThread *aun = malloc(sizeof(AlertUnifiedAlertThread));
    if (aun == NULL) {
        return -1;
    }
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));

    if(initdata == NULL)
    {
        printf("Error getting context for the file\n");
        return -1;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = (LogFileCtx*) initdata;

    /** Write Unified header */
    int ret = AlertUnifiedAlertWriteFileHeader(t, aun);
    if (ret != 0) {
        printf("Error: AlertUnifiedLogWriteFileHeader failed.\n");
        return -1;
    }

    /* XXX make configurable */
    aun->size_limit = 10 * 1024 * 1024;

    *data = (void *)aun;
    return 0;
}

int AlertUnifiedAlertThreadDeinit(ThreadVars *t, void *data)
{
    AlertUnifiedAlertThread *aun = (AlertUnifiedAlertThread *)data;
    if (aun == NULL) {
        goto error;
    }

    /* clear memory */
    memset(aun, 0, sizeof(AlertUnifiedAlertThread));
    free(aun);
    return 0;

error:
    /* clear memory */
    if (aun != NULL) {
        memset(aun, 0, sizeof(AlertUnifiedAlertThread));
        free(aun);
    }
    return -1;
}


/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *AlertUnifiedAlertInitCtx(char *config_file)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        printf("AlertUnifiedAlertInitCtx: Couldn't create new file_ctx\n");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific AlertUnifiedAlert configuration */
    ret=AlertUnifiedAlertOpenFileCtx(file_ctx, config_file);

    if(ret < 0)
        return NULL;

    /** In AlertUnifiedAlertOpenFileCtx the second parameter should be the configuration file to use
    * but it's not implemented yet, so passing NULL to load the default
    * configuration
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
    char filename[PATH_MAX]; /* XXX some sane default? */

    if(config_file == NULL)
    {
        /** Separate config files not implemented at the moment,
        * but it must be able to load from separate config file.
        * Load the default configuration.
        */

        /* get the time so we can have a filename with seconds since epoch
         * in it. XXX review if we can take this info from somewhere else.
         * This is used both during init and runtime, so it must be thread
         * safe. */
        struct timeval ts;
        memset (&ts, 0, sizeof(struct timeval));
        gettimeofday(&ts, NULL);

        /* create the filename to use */
        char *log_dir;
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;
        snprintf(filename, sizeof(filename), "%s/%s.%" PRIu32, log_dir, "unified.alert", (uint32_t)ts.tv_sec);

        /* XXX filename & location */
        file_ctx->fp = fopen(filename, "wb");
        if (file_ctx->fp == NULL) {
            printf("Error: fopen %s failed: %s\n", filename, strerror(errno)); /* XXX errno threadsafety? */
            return -1;
        }

        if(file_ctx->config_file == NULL)
            file_ctx->config_file = strdup("configfile.aua");
            /** Remember the config file (or NULL if not indicated) */

    }

    return 0;
}


