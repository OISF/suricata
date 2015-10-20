/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Drop log module to log the dropped packet information in a format
 * compatible to Linux' Netfilter.
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

#include "decode-ipv4.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"

#include "output.h"
#include "log-droplog.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "drop.log"

#define MODULE_NAME "LogDropLog"

typedef struct LogDropLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    uint64_t drop_cnt;
} LogDropLogThread;

/**
 * \brief   Initialize the droplog thread
 * \param t Pointer the current thread variable
 * \param initdata pointer to the output context
 * \param data  Pointer to the pointer to droplog thread to be initialized
 *
 * \return TM_ECODE_OK on success
 */
static TmEcode LogDropLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    if(initdata == NULL) {
        SCLogDebug("Error getting context for LogDropLog. \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    LogDropLogThread *dlt = SCMalloc(sizeof(LogDropLogThread));
    if (unlikely(dlt == NULL))
        return TM_ECODE_FAILED;
    memset(dlt, 0, sizeof(LogDropLogThread));

    /** Use the Ouptut Context (file pointer and mutex) */
    dlt->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)dlt;
    return TM_ECODE_OK;
}

/**
 * \brief   Deinitialize the droplog thread
 * \param t Pointer the current thread variable
 * \param data  Pointer to the droplog thread to be cleared
 *
 * \return TM_ECODE_OK on success
 */
static TmEcode LogDropLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDropLogThread *dlt = (LogDropLogThread *)data;
    if (dlt == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(dlt, 0, sizeof(LogDropLogThread));

    SCFree(dlt);
    return TM_ECODE_OK;
}

/**
 * \brief Destroy the LogFileCtx and cleared "drop" output module
 *
 * \param output_ctx pointer the output context to be cleared
 */
static void LogDropLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputDropLoggerDisable();

    if (output_ctx != NULL) {
        LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
        if (logfile_ctx != NULL) {
            LogFileFreeCtx(logfile_ctx);
        }
        SCFree(output_ctx);
    }
}

/**
 * \brief Create a new LogFileCtx for "drop" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputCtx *LogDropLogInitCtx(ConfNode *conf)
{
    if (OutputDropLoggerEnable() != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "only one 'drop' logger "
            "can be enabled");
        return NULL;
    }

    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("LogDropLogInitCtx: Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }
    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = LogDropLogDeInitCtx;

    return output_ctx;
}

/**
 * \brief   Log the dropped packets in netfilter format when engine is running
 *          in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is being logged
 * \param data  Pointer to the droplog struct
 *
 * \return return TM_EODE_OK on success
 */
static int LogDropLogNetFilter (ThreadVars *tv, const Packet *p, void *data)
{
    LogDropLogThread *dlt = (LogDropLogThread *)data;
    uint16_t proto = 0;
    char timebuf[64];

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&dlt->file_ctx->fp_mutex);

    if (dlt->file_ctx->rotation_flag) {
        dlt->file_ctx->rotation_flag  = 0;
        if (SCConfLogReopen(dlt->file_ctx) != 0) {
            /* Rotation failed, error already logged. */
            SCMutexUnlock(&dlt->file_ctx->fp_mutex);
            return TM_ECODE_FAILED;
        }
    }

    char srcip[46] = "";
    char dstip[46] = "";

    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, 16);
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, 16);
        fprintf(dlt->file_ctx->fp, "%s: IN= OUT= SRC=%s DST=%s LEN=%"PRIu16" "
                "TOS=0x%02"PRIu8" TTL=%"PRIu8" ID=%"PRIu16"", timebuf,
                srcip, dstip, IPV4_GET_IPLEN(p), IPV4_GET_IPTOS(p),
                IPV4_GET_IPTTL(p), IPV4_GET_IPID(p));
        proto = IPV4_GET_IPPROTO(p);
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
        fprintf(dlt->file_ctx->fp, "%s: IN= OUT= SRC=%s DST=%s LEN=%"PRIu16""
                " TC=%"PRIu32" HOPLIMIT=%"PRIu8" FLOWLBL=%"PRIu32"", timebuf,
                srcip, dstip, IPV6_GET_PLEN(p), IPV6_GET_CLASS(p),
                IPV6_GET_HLIM(p), IPV6_GET_FLOW(p));
        proto = IPV6_GET_L4PROTO(p);
    }

    if (SCProtoNameValid(proto) == TRUE) {
        fprintf(dlt->file_ctx->fp, " PROTO=%s",known_proto[proto]);
    } else {
        fprintf(dlt->file_ctx->fp, " PROTO=%03"PRIu16"",proto);
    }

    switch (proto) {
        case IPPROTO_TCP:
            fprintf(dlt->file_ctx->fp, " SPT=%"PRIu16" DPT=%"PRIu16" "
                    "SEQ=%"PRIu32" ACK=%"PRIu32" WINDOW=%"PRIu32"",
                    GET_TCP_SRC_PORT(p), GET_TCP_DST_PORT(p), TCP_GET_SEQ(p),
                    TCP_GET_ACK(p), TCP_GET_WINDOW(p));
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_SYN(p) ? " SYN" : "");
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_ACK(p) ? " ACK" : "");
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_PUSH(p) ? " PSH" : "");
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_RST(p) ? " RST" : "");
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_URG(p) ? " URG" : "");
            fprintf(dlt->file_ctx->fp, TCP_ISSET_FLAG_FIN(p) ? " FIN" : "");
            fprintf(dlt->file_ctx->fp, " RES=0x%02"PRIu8" URGP=%"PRIu16"",
                    TCP_GET_RAW_X2(p->tcph), TCP_GET_URG_POINTER(p));
            break;
        case IPPROTO_UDP:
            fprintf(dlt->file_ctx->fp, " SPT=%"PRIu16" DPT=%"PRIu16""
                    " LEN=%"PRIu16"", UDP_GET_SRC_PORT(p),
                    UDP_GET_DST_PORT(p), UDP_GET_LEN(p));
            break;
        case IPPROTO_ICMP:
            if (PKT_IS_ICMPV4(p)) {
                fprintf(dlt->file_ctx->fp, " TYPE=%"PRIu8" CODE=%"PRIu8""
                        " ID=%"PRIu16" SEQ=%"PRIu16"", ICMPV4_GET_TYPE(p),
                        ICMPV4_GET_CODE(p), ICMPV4_GET_ID(p), ICMPV4_GET_SEQ(p));
            } else if(PKT_IS_ICMPV6(p)) {
                fprintf(dlt->file_ctx->fp, " TYPE=%"PRIu8" CODE=%"PRIu8""
                        " ID=%"PRIu16" SEQ=%"PRIu16"", ICMPV6_GET_TYPE(p),
                        ICMPV6_GET_CODE(p), ICMPV6_GET_ID(p), ICMPV6_GET_SEQ(p));
            }
            break;
        default:
            fprintf(dlt->file_ctx->fp," Unknown protocol");
    }

    fprintf(dlt->file_ctx->fp,"\n");

    fflush(dlt->file_ctx->fp);

    dlt->drop_cnt++;
    SCMutexUnlock(&dlt->file_ctx->fp_mutex);

    return TM_ECODE_OK;

}

/**
 * \brief Check if we need to drop-log this packet
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is tested
 *
 * \retval bool TRUE or FALSE
 */
static int LogDropCondition(ThreadVars *tv, const Packet *p)
{
    if (!EngineModeIsIPS()) {
        SCLogDebug("engine is not running in inline mode, so returning");
        return FALSE;
    }
    if (PKT_IS_PSEUDOPKT(p)) {
        SCLogDebug("drop log doesn't log pseudo packets");
        return FALSE;
    }

    if (p->flow != NULL) {
        int ret = FALSE;
        FLOWLOCK_RDLOCK(p->flow);
        if (p->flow->flags & FLOW_ACTION_DROP) {
            if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED))
                ret = TRUE;
            else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED))
                ret = TRUE;
        }
        FLOWLOCK_UNLOCK(p->flow);
        return ret;
    } else if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
        return TRUE;
    }

    return FALSE;
}

/**
 * \brief   Log the dropped packets when engine is running in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the droplog struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on succes
 */
static int LogDropLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{

    int r = LogDropLogNetFilter(tv, p, thread_data);
    if (r < 0)
        return -1;

    if (p->flow) {
        FLOWLOCK_RDLOCK(p->flow);
        if (p->flow->flags & FLOW_ACTION_DROP) {
            if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED))
                p->flow->flags |= FLOW_TOSERVER_DROP_LOGGED;
            else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED))
                p->flow->flags |= FLOW_TOCLIENT_DROP_LOGGED;
        }
        FLOWLOCK_UNLOCK(p->flow);
    }
    return 0;
}

static void LogDropLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogDropLogThread *dlt = (LogDropLogThread *)data;
    if (dlt == NULL) {
        return;
    }

    SCLogInfo("(%s) Dropped Packets %" PRIu64 "", tv->name, dlt->drop_cnt);
}

/***************************** Unittests ****************************/

#ifdef UNITTESTS

/** \brief test if the action is drop then packet should be logged */
int LogDropLogTest01()
{
    int result = 0;
    EngineModeSetIPS();

    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    LogDropLogThread dlt;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        printf("Could not create new LogFileCtx\n");
        return 0;
    }

    memset (&dlt, 0, sizeof(LogDropLogThread));
    dlt.file_ctx = logfile_ctx;
    dlt.file_ctx->fp = stdout;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any any "
            "(msg:\"LogDropLog test\"; content:\"GET\"; Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1 && (PACKET_TEST_ACTION(p, ACTION_DROP)))
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);

    if (LogDropCondition(NULL, p) == TRUE)
        LogDropLogger(NULL, &dlt, p);

    if (dlt.drop_cnt == 0) {
        printf("Packet should be logged but its not\n");
        result = 0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    EngineModeSetIDS();
    return result;
}

/** \brief test if the action is alert then packet shouldn't be logged */
int LogDropLogTest02()
{
    int result = 0;
    EngineModeSetIPS();

    uint8_t *buf = (uint8_t *) "GET";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    LogDropLogThread dlt;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        printf("Could not create new LogFileCtx\n");
        return 0;
    }

    memset (&dlt, 0, sizeof(LogDropLogThread));
    dlt.file_ctx = logfile_ctx;
    dlt.file_ctx->fp = stdout;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_UDP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert udp any any -> any any "
            "(msg:\"LogDropLog test\"; content:\"GET\"; Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1 && p->alerts.alerts[0].action != ACTION_DROP)
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);

    if (LogDropCondition(NULL, p) == TRUE)
        LogDropLogger(NULL, &dlt, p);

    if (dlt.drop_cnt != 0) {
        printf("Packet shouldn't be logged but it is\n");
        result = 0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);

    EngineModeSetIDS();
    return result;
}

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
static void LogDropLogRegisterTests(void)
{
    UtRegisterTest("LogDropLogTest01", LogDropLogTest01, 1);
    UtRegisterTest("LogDropLogTest02", LogDropLogTest02, 1);
}
#endif

/** \brief function to register the drop log module */
void TmModuleLogDropLogRegister (void)
{

    tmm_modules[TMM_LOGDROPLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGDROPLOG].ThreadInit = LogDropLogThreadInit;
    tmm_modules[TMM_LOGDROPLOG].ThreadExitPrintStats = LogDropLogExitPrintStats;
    tmm_modules[TMM_LOGDROPLOG].ThreadDeinit = LogDropLogThreadDeinit;
#ifdef UNITTESTS
    tmm_modules[TMM_LOGDROPLOG].RegisterTests = LogDropLogRegisterTests;
#endif
    tmm_modules[TMM_LOGDROPLOG].cap_flags = 0;
    tmm_modules[TMM_LOGDROPLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "drop", LogDropLogInitCtx,
            LogDropLogger, LogDropCondition);
}
