/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 */

#include "suricata-common.h"

#include "detect-engine.h"

#include "output.h"
#include "alert-fastlog.h"

#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#ifdef UNITTESTS
#include "util-classification-config.h"
#include "detect-engine-build.h"
#include "detect-parse.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#endif
#define DEFAULT_LOG_FILENAME "fast.log"

#define MODULE_NAME "AlertFastLog"

/* The largest that size allowed for one alert string. */
#define MAX_FASTLOG_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_FASTLOG_BUFFER_SIZE (2 * MAX_FASTLOG_ALERT_SIZE)

TmEcode AlertFastLogThreadInit(ThreadVars *, const void *, void **);
TmEcode AlertFastLogThreadDeinit(ThreadVars *, void *);
void AlertFastLogRegisterTests(void);
static void AlertFastLogDeInitCtx(OutputCtx *);

int AlertFastLogCondition(ThreadVars *tv, void *thread_data, const Packet *p);
int AlertFastLogger(ThreadVars *tv, void *data, const Packet *p);

void AlertFastLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_ALERT_FAST, MODULE_NAME, "fast",
        AlertFastLogInitCtx, AlertFastLogger, AlertFastLogCondition,
        AlertFastLogThreadInit, AlertFastLogThreadDeinit, NULL);
    AlertFastLogRegisterTests();
}

typedef struct AlertFastLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertFastLogThread;

int AlertFastLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return (p->alerts.cnt ? TRUE : FALSE);
}

static inline void AlertFastLogOutputAlert(AlertFastLogThread *aft, char *buffer,
                                           int alert_size)
{
    /* Output the alert string and count alerts. Only need to lock here. */
    aft->file_ctx->Write(buffer, alert_size, aft->file_ctx);
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

    char proto[16] = "";
    const char *protoptr;
    if (SCProtoNameValid(IP_GET_IPPROTO(p))) {
        protoptr = known_proto[IP_GET_IPPROTO(p)];
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
        protoptr = proto;
    }
    uint16_t src_port_or_icmp = p->sp;
    uint16_t dst_port_or_icmp = p->dp;
    if (IP_GET_IPPROTO(p) == IPPROTO_ICMP || IP_GET_IPPROTO(p) == IPPROTO_ICMPV6) {
        src_port_or_icmp = p->icmp_s.type;
        dst_port_or_icmp = p->icmp_s.code;
    }
    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        const char *action = "";
        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        /* Create the alert string without locking. */
        int size = 0;
        if (likely(decoder_event == 0)) {
            PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                            PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                            " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf, action,
                            pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                            protoptr, srcip, src_port_or_icmp, dstip, dst_port_or_icmp);
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

TmEcode AlertFastLogThreadInit(ThreadVars *t, const void *initdata, void **data)
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

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputInitResult AlertFastLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertFastLogInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertFastLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void AlertFastLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

static int AlertFastLogTest01(void)
{
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(p->alerts.cnt == 1);
    FAIL_IF_NOT(strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    PASS;
}

static int AlertFastLogTest02(void)
{
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(p->alerts.cnt == 1);
    FAIL_IF_NOT(strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void AlertFastLogRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("AlertFastLogTest01", AlertFastLogTest01);
    UtRegisterTest("AlertFastLogTest02", AlertFastLogTest02);

#endif /* UNITTESTS */

}
