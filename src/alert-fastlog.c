/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* alert fastlog
 *
 * Logs alerts in a line based text format compatible to Snort's
 * alert_fast format.
 *
 * TODO
 * - Print the protocol as a string
 * - Support classifications
 * - Support more than just IPv4/IPv4 TCP/UDP.
 * - Print [drop] as well if appropriate
 */

#include "eidps-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "util-debug.h"
#include "util-unittest.h"

#define DEFAULT_LOG_FILENAME "fast.log"

TmEcode AlertFastlog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertFastlogThreadDeinit(ThreadVars *, void *);
void AlertFastlogExitPrintStats(ThreadVars *, void *);
int AlertFastlogOpenFileCtx(LogFileCtx *, char *);

void TmModuleAlertFastlogRegister (void) {
    tmm_modules[TMM_ALERTFASTLOG].name = "AlertFastlog";
    tmm_modules[TMM_ALERTFASTLOG].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG].Func = AlertFastlog;
    tmm_modules[TMM_ALERTFASTLOG].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG].RegisterTests = NULL;
}

void TmModuleAlertFastlogIPv4Register (void) {
    tmm_modules[TMM_ALERTFASTLOG4].name = "AlertFastlogIPv4";
    tmm_modules[TMM_ALERTFASTLOG4].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG4].Func = AlertFastlogIPv4;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG4].RegisterTests = NULL;
}

void TmModuleAlertFastlogIPv6Register (void) {
    tmm_modules[TMM_ALERTFASTLOG6].name = "AlertFastlogIPv6";
    tmm_modules[TMM_ALERTFASTLOG6].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG6].Func = AlertFastlogIPv6;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG6].RegisterTests = NULL;
}

typedef struct AlertFastlogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    uint32_t alerts;
} AlertFastlogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

TmEcode AlertFastlogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    aft->alerts += p->alerts.cnt;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        char srcip[16], dstip[16];

        inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

        fprintf(aft->file_ctx->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: fixme] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV4_GET_IPPROTO(p), srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertFastlogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    aft->alerts += p->alerts.cnt;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        char srcip[46], dstip[46];

        inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

        fprintf(aft->file_ctx->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: fixme] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
        fflush(aft->file_ctx->fp);
    }

    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertFastlog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertFastlogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertFastlogIPv6(tv, p, data, pq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertFastlogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertFastlogThread *aft = malloc(sizeof(AlertFastlogThread));
    if (aft == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aft, 0, sizeof(AlertFastlogThread));
    if(initdata == NULL)
    {
        printf("Error getting context for the file\n");
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = (LogFileCtx*) initdata;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertFastlogThreadDeinit(ThreadVars *t, void *data)
{
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertFastlogThread));

    free(aft);
    return TM_ECODE_OK;
}

void AlertFastlogExitPrintStats(ThreadVars *tv, void *data) {
    AlertFastlogThread *aft = (AlertFastlogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu32 "", tv->name, aft->alerts);
}

/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *AlertFastlogInitCtx(char *config_file)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        printf("AlertFastlogInitCtx: Couldn't create new file_ctx\n");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific AlertFastlog configuration */
    ret=AlertFastlogOpenFileCtx(file_ctx, config_file);

    if(ret < 0)
        return NULL;

    /** In AlertFastlogOpenFileCtx the second parameter should be the configuration file to use
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
int AlertFastlogOpenFileCtx(LogFileCtx *file_ctx, char *config_file)
{
    if(config_file == NULL)
    {
        /** Separate config files not implemented at the moment,
        * but it must be able to load from separate config file.
        * Load the default configuration.
        */

        char log_path[PATH_MAX], *log_dir;
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, DEFAULT_LOG_FILENAME);

        file_ctx->fp = fopen(log_path, "w");

        if (file_ctx->fp == NULL) {
            printf("ERROR: failed to open %s: %s\n", log_path, strerror(errno));
            return -1;
        }
    }

    return 0;
}


