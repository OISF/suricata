/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* httplog
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

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#define DEFAULT_LOG_FILENAME "http.log"

TmEcode LogHttplog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttplogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttplogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode LogHttplogThreadInit(ThreadVars *, void *, void **);
TmEcode LogHttplogThreadDeinit(ThreadVars *, void *);
void LogHttplogExitPrintStats(ThreadVars *, void *);
int LogHttplogOpenFileCtx(LogFileCtx* , char *);

void TmModuleLogHttplogRegister (void) {
    tmm_modules[TMM_LOGHTTPLOG].name = "LogHttplog";
    tmm_modules[TMM_LOGHTTPLOG].ThreadInit = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG].Func = LogHttplog;
    tmm_modules[TMM_LOGHTTPLOG].ThreadExitPrintStats = LogHttplogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG].ThreadDeinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG].RegisterTests = NULL;
}

void TmModuleLogHttplogIPv4Register (void) {
    tmm_modules[TMM_LOGHTTPLOG4].name = "LogHttplogIPv4";
    tmm_modules[TMM_LOGHTTPLOG4].ThreadInit = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG4].Func = LogHttplogIPv4;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadExitPrintStats = LogHttplogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadDeinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG4].RegisterTests = NULL;
}

void TmModuleLogHttplogIPv6Register (void) {
    tmm_modules[TMM_LOGHTTPLOG6].name = "LogHttplogIPv6";
    tmm_modules[TMM_LOGHTTPLOG6].ThreadInit = LogHttplogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG6].Func = LogHttplogIPv6;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadExitPrintStats = LogHttplogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadDeinit = LogHttplogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG6].RegisterTests = NULL;
}

typedef struct LogHttplogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;
} LogHttplogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm *t = gmtime(&time);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

TmEcode LogHttplogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    int i;
    char timebuf[64];

    /* XXX add a better check for this */
    if (p->http_uri.cnt == 0)
        return TM_ECODE_OK;

    PktVar *pv_hn = PktVarGet(p, "http_host");
    PktVar *pv_ua = PktVarGet(p, "http_ua");

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[16], dstip[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    SCMutexLock(&aft->file_ctx->fp_mutex);
    for (i = 0; i < p->http_uri.cnt; i++) {
        /* time */
        fprintf(aft->file_ctx->fp, "%s ", timebuf);
        /* hostname */
        if (pv_hn != NULL) PrintRawUriFp(aft->file_ctx->fp, pv_hn->value, pv_hn->value_len);
        else fprintf(aft->file_ctx->fp, "<hostname unknown>");
        fprintf(aft->file_ctx->fp, " [**] ");
        /* uri */
        PrintRawUriFp(aft->file_ctx->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->file_ctx->fp, " [**] ");
        /* user agent */
        if (pv_ua != NULL) PrintRawUriFp(aft->file_ctx->fp, pv_ua->value, pv_ua->value_len);
        else fprintf(aft->file_ctx->fp, "<useragent unknown>");
        /* ip/tcp header info */
        fprintf(aft->file_ctx->fp, " [**] %s:%" PRIu32 " -> %s:%" PRIu32 "\n", srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    aft->uri_cnt += p->http_uri.cnt;
    return TM_ECODE_OK;
}

TmEcode LogHttplogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    int i;
    char timebuf[64];

    /* XXX add a better check for this */
    if (p->http_uri.cnt == 0)
        return TM_ECODE_OK;

    PktVar *pv_hn = PktVarGet(p, "http_host");
    PktVar *pv_ua = PktVarGet(p, "http_ua");

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

    SCMutexLock(&aft->file_ctx->fp_mutex);
    for (i = 0; i < p->http_uri.cnt; i++) {
        /* time */
        fprintf(aft->file_ctx->fp, "%s ", timebuf);
        /* hostname */
        if (pv_hn != NULL) PrintRawUriFp(aft->file_ctx->fp, pv_hn->value, pv_hn->value_len);
        else fprintf(aft->file_ctx->fp, "<hostname unknown>");
        fprintf(aft->file_ctx->fp, " [**] ");
        /* uri */
        PrintRawUriFp(aft->file_ctx->fp, p->http_uri.raw[i], p->http_uri.raw_size[i]);
        fprintf(aft->file_ctx->fp, " [**] ");
        /* user agent */
        if (pv_ua != NULL) PrintRawUriFp(aft->file_ctx->fp, pv_ua->value, pv_ua->value_len);
        else fprintf(aft->file_ctx->fp, "<useragent unknown>");
        /* ip/tcp header info */
        fprintf(aft->file_ctx->fp, " [**] %s:%" PRIu32 " -> %s:%" PRIu32 "\n", srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    aft->uri_cnt += p->http_uri.cnt;
    return TM_ECODE_OK;
}

TmEcode LogHttplog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (!(PKT_IS_TCP(p)))
        return TM_ECODE_OK;

    if (PKT_IS_IPV4(p)) {
        return LogHttplogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return LogHttplogIPv6(tv, p, data, pq);
    }

    return TM_ECODE_OK;
}

TmEcode LogHttplogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogHttplogThread *aft = malloc(sizeof(LogHttplogThread));
    if (aft == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(aft, 0, sizeof(LogHttplogThread));

    if(initdata == NULL)
    {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC_ERROR, "Error getting context for "
                   "HTTPLog.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx=(LogFileCtx*) initdata;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogHttplogThreadDeinit(ThreadVars *t, void *data)
{
    LogHttplogThread *aft = (LogHttplogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogHttplogThread));

    free(aft);
    return TM_ECODE_OK;
}

void LogHttplogExitPrintStats(ThreadVars *tv, void *data) {
    LogHttplogThread *aft = (LogHttplogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) HTTP requests %" PRIu32 "", tv->name, aft->uri_cnt);
}

/** \brief Create a new file_ctx from config_file (if specified)
 *  \param config_file for loading separate configs
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
LogFileCtx *LogHttplogInitCtx(char *config_file)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC_ERROR, "LogHttplogInitCtx: Couldn't "
                   "create new file_ctx");
        return NULL;
    }

    /** fill the new LogFileCtx with the specific LogHttplog configuration */
    ret=LogHttplogOpenFileCtx(file_ctx, config_file);

    if(ret < 0)
        return NULL;

    /** In LogHttplogOpenFileCtx the second parameter should be the configuration file to use
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
int LogHttplogOpenFileCtx(LogFileCtx *file_ctx, char *config_file)
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
            SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", log_path,
                       strerror(errno));
            return -1;
        }
        if(file_ctx->config_file == NULL)
            file_ctx->config_file = strdup("configfile.lh");
            /** Remember the config file (or NULL if not indicated) */
    }

    return 0;
}


