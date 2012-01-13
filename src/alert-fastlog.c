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
 * Logs alerts in a line based text format compatible to Snort's
 * alert_fast format.
 *
 * \todo Support classifications
 * \todo Support more than just IPv4/IPv6 TCP/UDP.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "util-classification-config.h"

#include "output.h"
#include "alert-fastlog.h"

#include "util-mpm-b2g-cuda.h"
#include "util-cuda-handlers.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "fast.log"

#define MODULE_NAME "AlertFastLog"

TmEcode AlertFastLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertFastLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertFastLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertFastLogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertFastLogThreadDeinit(ThreadVars *, void *);
void AlertFastLogExitPrintStats(ThreadVars *, void *);
void AlertFastLogRegisterTests(void);
static void AlertFastLogDeInitCtx(OutputCtx *);

void TmModuleAlertFastLogRegister (void) {
    tmm_modules[TMM_ALERTFASTLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTFASTLOG].ThreadInit = AlertFastLogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG].Func = AlertFastLog;
    tmm_modules[TMM_ALERTFASTLOG].ThreadExitPrintStats = AlertFastLogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG].ThreadDeinit = AlertFastLogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG].RegisterTests = AlertFastLogRegisterTests;
    tmm_modules[TMM_ALERTFASTLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "fast", AlertFastLogInitCtx);
}

void TmModuleAlertFastLogIPv4Register (void) {
    tmm_modules[TMM_ALERTFASTLOG4].name = "AlertFastLogIPv4";
    tmm_modules[TMM_ALERTFASTLOG4].ThreadInit = AlertFastLogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG4].Func = AlertFastLogIPv4;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadExitPrintStats = AlertFastLogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG4].ThreadDeinit = AlertFastLogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG4].RegisterTests = NULL;
}

void TmModuleAlertFastLogIPv6Register (void) {
    tmm_modules[TMM_ALERTFASTLOG6].name = "AlertFastLogIPv6";
    tmm_modules[TMM_ALERTFASTLOG6].ThreadInit = AlertFastLogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG6].Func = AlertFastLogIPv6;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadExitPrintStats = AlertFastLogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG6].ThreadDeinit = AlertFastLogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG6].RegisterTests = NULL;
}

typedef struct AlertFastLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertFastLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

TmEcode AlertFastLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    int i;
    char timebuf[64];
    char *action = "";
    extern uint8_t engine_mode;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    aft->file_ctx->alerts += p->alerts.cnt;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char srcip[16], dstip[16];

        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

        if (pa->action & ACTION_DROP && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        if (SCProtoNameValid(IPV4_GET_IPPROTO(p)) == TRUE) {
            fprintf(aft->file_ctx->fp, "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                    PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                    " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf, action,
                    pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                    known_proto[IPV4_GET_IPPROTO(p)], srcip, p->sp, dstip, p->dp);
        } else {
            fprintf(aft->file_ctx->fp, "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                    PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                    " {PROTO:%03" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf,
                    action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                    IPV4_GET_IPPROTO(p), srcip, p->sp, dstip, p->dp);
        }
        fflush(aft->file_ctx->fp);
    }
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertFastLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    int i;
    char timebuf[64];
    char *action = "";
    extern uint8_t engine_mode;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    aft->file_ctx->alerts += p->alerts.cnt;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char srcip[46], dstip[46];

        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

        if (pa->action & ACTION_DROP && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        if (SCProtoNameValid(IPV6_GET_L4PROTO(p)) == TRUE) {
            fprintf(aft->file_ctx->fp, "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                    "" PRIu32 "] %s [**] [Classification: %s] [Priority: %"
                    "" PRIu32 "] {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf,
                    action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                    pa->s->prio, known_proto[IPV6_GET_L4PROTO(p)], srcip, p->sp,
                    dstip, p->dp);

        } else {
            fprintf(aft->file_ctx->fp, "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                    "" PRIu32 "] %s [**] [Classification: %s] [Priority: %"
                    "" PRIu32 "] {PROTO:%03" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
                    timebuf, action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                    pa->s->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
        }

        fflush(aft->file_ctx->fp);
    }
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertFastLogDecoderEvent(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    int i;
    char timebuf[64];
    char *action = "";
    extern uint8_t engine_mode;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    aft->file_ctx->alerts += p->alerts.cnt;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if (pa->action & ACTION_DROP && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        fprintf(aft->file_ctx->fp, "%s  %s[**] [%" PRIu32 ":%" PRIu32
                ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: "
                "%" PRIu32 "] [**] [Raw pkt: ", timebuf, action, pa->s->gid,
                pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio);

        PrintRawLineHexFp(aft->file_ctx->fp, GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
        if (p->pcap_cnt != 0) {
            fprintf(aft->file_ctx->fp, "] [pcap file packet: %"PRIu64"]", p->pcap_cnt);
        }

        fprintf(aft->file_ctx->fp,"\n");

        fflush(aft->file_ctx->fp);
    }
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertFastLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertFastLogIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertFastLogIPv6(tv, p, data, pq, postpq);
    } else if (p->events.cnt > 0) {
        return AlertFastLogDecoderEvent(tv, p, data, pq, postpq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertFastLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertFastLogThread *aft = SCMalloc(sizeof(AlertFastLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertFastLogThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertFastLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertFastLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertFastLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertFastLogExitPrintStats(ThreadVars *tv, void *data) {
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("Fast log output wrote %" PRIu64 " alerts", aft->file_ctx->alerts);
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertFastLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertFastLogInitCtx2: Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertFastLogDeInitCtx;

    return output_ctx;
}

static void AlertFastLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int AlertFastLogTest01()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1)
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    else
        result = 0;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

int AlertFastLogTest02()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);
    if (result == 0)
        printf("sig parse failed: ");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown Traffic") != 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);

        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    } else {
        result = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void AlertFastLogRegisterTests(void)
{

#ifdef UNITTESTS

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextInit",
            SCCudaHlTestEnvCudaContextInit, 1);
#endif

    UtRegisterTest("AlertFastLogTest01", AlertFastLogTest01, 1);
    UtRegisterTest("AlertFastLogTest02", AlertFastLogTest02, 1);

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextDeInit",
            SCCudaHlTestEnvCudaContextDeInit, 1);
#endif

#endif /* UNITTESTS */

}
