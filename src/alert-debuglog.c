/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* alert debuglog
 *
 * TODO
 * - figure out a way to (thread) safely print detection engine info
 *   - maybe by having a log queue in the packet
 *   - maybe by accessing it just and hoping threading doesn't hurt
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-print.h"

#include "pkt-var.h"

#include "util-unittest.h"

#include "util-debug.h"

#define DEFAULT_LOG_FILENAME "alert-debug.log"

TmEcode AlertDebuglog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebuglogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebuglogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebuglogThreadInit(ThreadVars *, void*, void **);
TmEcode AlertDebuglogThreadDeinit(ThreadVars *, void *);
void AlertDebuglogExitPrintStats(ThreadVars *, void *);
int AlertDebuglogOpenFileCtx(LogFileCtx* , char *);

void TmModuleAlertDebuglogRegister (void) {
    tmm_modules[TMM_ALERTDEBUGLOG].name = "AlertDebuglog";
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadInit = AlertDebuglogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG].Func = AlertDebuglog;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadExitPrintStats = AlertDebuglogExitPrintStats;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadDeinit = AlertDebuglogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG].RegisterTests = NULL;
}

typedef struct AlertDebuglogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t alerts;
} AlertDebuglogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

TmEcode AlertDebuglogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    fprintf(aft->file_ctx->fp, "+================\n");
    fprintf(aft->file_ctx->fp, "TIME:              %s\n", timebuf);
    fprintf(aft->file_ctx->fp, "ALERT CNT:         %" PRIu32 "\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];

        fprintf(aft->file_ctx->fp, "ALERT MSG [%02d]:    %s\n", i, pa->msg);
        fprintf(aft->file_ctx->fp, "ALERT GID [%02d]:    %" PRIu32 "\n", i, pa->gid);
        fprintf(aft->file_ctx->fp, "ALERT SID [%02d]:    %" PRIu32 "\n", i, pa->sid);
        fprintf(aft->file_ctx->fp, "ALERT REV [%02d]:    %" PRIu32 "\n", i, pa->rev);
        fprintf(aft->file_ctx->fp, "ALERT CLASS [%02d]:  %s\n", i, pa->class_msg);
        fprintf(aft->file_ctx->fp, "ALERT PRIO [%02d]:   %" PRIu32 "\n", i, pa->prio);
    }

    char srcip[16], dstip[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    fprintf(aft->file_ctx->fp, "SRC IP:            %s\n", srcip);
    fprintf(aft->file_ctx->fp, "DST IP:            %s\n", dstip);
    fprintf(aft->file_ctx->fp, "PROTO:             %" PRIu32 "\n", IPV4_GET_IPPROTO(p));
    if (IPV4_GET_IPPROTO(p) == IPPROTO_TCP || IPV4_GET_IPPROTO(p) == IPPROTO_UDP) {
        fprintf(aft->file_ctx->fp, "SRC PORT:          %" PRIu32 "\n", p->sp);
        fprintf(aft->file_ctx->fp, "DST PORT:          %" PRIu32 "\n", p->dp);
    }

    /* flow stuff */
    fprintf(aft->file_ctx->fp, "FLOW:              to_server: %s, to_client %s\n",
        p->flowflags & FLOW_PKT_TOSERVER ? "TRUE" : "FALSE",
        p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE" : "FALSE");

    PktVar *pv = PktVarGet(p,"http_host");
    if (pv) {
        fprintf(aft->file_ctx->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->file_ctx->fp, pv->value, pv->value_len);
    }

    pv = PktVarGet(p,"http_ua");
    if (pv) {
        fprintf(aft->file_ctx->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->file_ctx->fp, pv->value, pv->value_len);
    }

    for (i = 0; i < p->http_uri.cnt; i++) {
        fprintf(aft->file_ctx->fp, "RAW URI [%2d]:      ", i);
        PrintRawUriFp(aft->file_ctx->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->file_ctx->fp, "\n");
        PrintRawDataFp(aft->file_ctx->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
    }

/* any stuff */
/* Sig details? */
/* pkt vars */
/* flowvars */

    aft->alerts += p->alerts.cnt;

    fprintf(aft->file_ctx->fp, "PACKET LEN:        %" PRIu32 "\n", p->pktlen);
    fprintf(aft->file_ctx->fp, "PACKET:\n");
    PrintRawDataFp(aft->file_ctx->fp, p->pkt, p->pktlen);

    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebuglogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
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
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebuglog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertDebuglogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertDebuglogIPv6(tv, p, data, pq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertDebuglogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertDebuglogThread *aft = malloc(sizeof(AlertDebuglogThread));
    if (aft == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aft, 0, sizeof(AlertDebuglogThread));

    if(initdata == NULL)
    {
        SCLogError(SC_ERR_DEBUG_LOG_GENERIC_ERROR, "Error getting context for "
                   "DebugLog.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx=(LogFileCtx *) initdata;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertDebuglogThreadDeinit(ThreadVars *t, void *data)
{
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertDebuglogThread));

    free(aft);
    return TM_ECODE_OK;
}

void AlertDebuglogExitPrintStats(ThreadVars *tv, void *data) {
    AlertDebuglogThread *aft = (AlertDebuglogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu32 "", tv->name, aft->alerts);
}


/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *AlertDebuglogInitCtx(char *config_file)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogError(SC_ERR_DEBUG_LOG_GENERIC_ERROR, "AlertDebuglogInitCtx: Couldn't "
                   "create new file_ctx");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific AlertDebuglog configuration */
    ret=AlertDebuglogOpenFileCtx(file_ctx, config_file);

    if(ret < 0)
        return NULL;

    /** In AlertDebuglogOpenFileCtx the second parameter should be the configuration file to use
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
int AlertDebuglogOpenFileCtx(LogFileCtx *file_ctx, char *config_file)
{
    int ret=0;
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
            SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", log_path,
                       strerror(errno));
            return -1;
        }
    }

    return ret;
}


