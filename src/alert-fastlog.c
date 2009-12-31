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

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-classification-config.h"

#define DEFAULT_LOG_FILENAME "fast.log"

TmEcode AlertFastlog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertFastlogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertFastlogThreadDeinit(ThreadVars *, void *);
void AlertFastlogExitPrintStats(ThreadVars *, void *);
int AlertFastlogOpenFileCtx(LogFileCtx *, char *);
void AlertFastLogRegisterTests(void);

void TmModuleAlertFastlogRegister (void) {
    tmm_modules[TMM_ALERTFASTLOG].name = "AlertFastlog";
    tmm_modules[TMM_ALERTFASTLOG].ThreadInit = AlertFastlogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG].Func = AlertFastlog;
    tmm_modules[TMM_ALERTFASTLOG].ThreadExitPrintStats = AlertFastlogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG].ThreadDeinit = AlertFastlogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG].RegisterTests = AlertFastLogRegisterTests;
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

        fprintf(aft->file_ctx->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->class_msg, pa->prio, IPV4_GET_IPPROTO(p), srcip, p->sp, dstip, p->dp);
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

        fprintf(aft->file_ctx->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
                timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->class_msg, pa->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->file_ctx->fp);
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
        SCLogError(SC_ERR_FAST_LOG_GENERIC_ERROR, "Error getting context for "
                   "AlertFastLog.  \"initdata\" argument NULL");
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
        SCLogError(SC_ERR_FAST_LOG_GENERIC_ERROR, "AlertFastlogInitCtx: Couldn't "
                   "create new file_ctx");
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
            SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", log_path,
                       strerror(errno));
            return -1;
        }
    }

    return 0;
}


/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int AlertFastLogTest01()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Fastlog test\"; content:GET; "
                               "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (p.alerts.cnt == 1)
        result = (strcmp(p.alerts.alerts[0].class_msg, "Unknown are we") == 0);
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

int AlertFastLogTest02()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Fastlog test\"; content:GET; "
                               "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);
    if (result == 0) printf("sig parse failed: ");

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (p.alerts.cnt == 1) {
        result = (strcmp(p.alerts.alerts[0].class_msg, "Unknown Traffic") != 0);
        if (result == 0) printf("p.alerts.alerts[0].class_msg %s: ", p.alerts.alerts[0].class_msg);
        result = (strcmp(p.alerts.alerts[0].class_msg,
                         "Unknown are we") == 0);
        if (result == 0) printf("p.alerts.alerts[0].class_msg %s: ", p.alerts.alerts[0].class_msg);
    } else {
        result = 0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void AlertFastLogRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("AlertFastLogTest01", AlertFastLogTest01, 1);
    UtRegisterTest("AlertFastLogTest02", AlertFastLogTest02, 1);

#endif /* UNITTESTS */

}
