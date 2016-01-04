/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "fast.log"

#define MODULE_NAME "AlertFastLog"

/* The largest that size allowed for one alert string. */
#define MAX_FASTLOG_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_FASTLOG_BUFFER_SIZE (2 * MAX_FASTLOG_ALERT_SIZE)

TmEcode AlertFastLogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertFastLogThreadDeinit(ThreadVars *, void *);
void AlertFastLogExitPrintStats(ThreadVars *, void *);
void AlertFastLogRegisterTests(void);
static void AlertFastLogDeInitCtx(OutputCtx *);

int AlertFastLogCondition(ThreadVars *tv, const Packet *p);
int AlertFastLogger(ThreadVars *tv, void *data, const Packet *p);

void TmModuleAlertFastLogRegister (void)
{
    tmm_modules[TMM_ALERTFASTLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTFASTLOG].ThreadInit = AlertFastLogThreadInit;
    tmm_modules[TMM_ALERTFASTLOG].ThreadExitPrintStats = AlertFastLogExitPrintStats;
    tmm_modules[TMM_ALERTFASTLOG].ThreadDeinit = AlertFastLogThreadDeinit;
    tmm_modules[TMM_ALERTFASTLOG].RegisterTests = AlertFastLogRegisterTests;
    tmm_modules[TMM_ALERTFASTLOG].cap_flags = 0;
    tmm_modules[TMM_ALERTFASTLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "fast",
            AlertFastLogInitCtx, AlertFastLogger, AlertFastLogCondition);
}

typedef struct AlertFastLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertFastLogThread;

int AlertFastLogCondition(ThreadVars *tv, const Packet *p)
{
    return (p->alerts.cnt ? TRUE : FALSE);
}

static inline void AlertFastLogOutputAlert(AlertFastLogThread *aft, char *buffer,
                                           int alert_size)
{
    SCMutex *file_lock = &aft->file_ctx->fp_mutex;
    /* Output the alert string and count alerts. Only need to lock here. */
    SCMutexLock(file_lock);
    aft->file_ctx->alerts++;
    aft->file_ctx->Write(buffer, alert_size, aft->file_ctx);
    SCMutexUnlock(file_lock);
}

int AlertFastLogger(ThreadVars *tv, void *data, const Packet *p)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    int i;
    char timebuf[64];
    int decoder_event = 0;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    } else {
        decoder_event = 1;
    }

    /* Buffer to store the generated alert strings. The buffer is
     * filled with alert strings until it doesn't have room to store
     * another full alert, only then is the buffer written.  This is
     * more efficient for multiple alerts and only slightly slower for
     * single alerts.
     */
    char alert_buffer[MAX_FASTLOG_BUFFER_SIZE];

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char *action = "";
        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        char proto[16] = "";
        if (likely(decoder_event == 0)) {
            if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
                strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
            } else {
                snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
            }
        }

        /* Create the alert string without locking. */
        int size = 0;
        if (likely(decoder_event == 0)) {
            PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE, 
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                            PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                            " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf, action,
                            pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                            proto, srcip, p->sp, dstip, p->dp);
        } else {
            PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE, 
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32
                            ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: "
                            "%" PRIu32 "] [**] [Raw pkt: ", timebuf, action, pa->s->gid,
                            pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio);
            PrintBufferRawLineHex(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                                  GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
            if (p->pcap_cnt != 0) {
                PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE, 
                                "] [pcap file packet: %"PRIu64"]\n", p->pcap_cnt);
            } else {
                PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE, "]\n");
            }
        }

        /* Write the alert to output file */
        AlertFastLogOutputAlert(aft, alert_buffer, size);
    }

    return TM_ECODE_OK;
}

TmEcode AlertFastLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertFastLogThread *aft = SCMalloc(sizeof(AlertFastLogThread));
    if (unlikely(aft == NULL))
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

void AlertFastLogExitPrintStats(ThreadVars *tv, void *data)
{
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

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
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

static int AlertFastLogTest01()
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

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

static int AlertFastLogTest02()
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

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    }

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

    UtRegisterTest("AlertFastLogTest01", AlertFastLogTest01, 1);
    UtRegisterTest("AlertFastLogTest02", AlertFastLogTest02, 1);

#endif /* UNITTESTS */

}
