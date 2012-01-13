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
 * \todo figure out a way to (thread) safely print detection engine info
 * \todo maybe by having a log queue in the packet
 * \todo maybe by accessing it just and hoping threading doesn't hurt
 */

#include "suricata-common.h"
#include "suricata.h"

#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "stream.h"
#include "app-layer-protos.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"

#include "pkt-var.h"

#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "alert-debuglog.h"
#include "util-privs.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "util-var-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "alert-debug.log"

#define MODULE_NAME "AlertDebugLog"

TmEcode AlertDebugLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertDebugLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertDebugLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertDebugLogThreadInit(ThreadVars *, void*, void **);
TmEcode AlertDebugLogThreadDeinit(ThreadVars *, void *);
void AlertDebugLogExitPrintStats(ThreadVars *, void *);

void TmModuleAlertDebugLogRegister (void) {
    tmm_modules[TMM_ALERTDEBUGLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadInit = AlertDebugLogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG].Func = AlertDebugLog;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadExitPrintStats = AlertDebugLogExitPrintStats;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadDeinit = AlertDebugLogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG].RegisterTests = NULL;
    tmm_modules[TMM_ALERTDEBUGLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "alert-debug", AlertDebugLogInitCtx);
}

typedef struct AlertDebugLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
} AlertDebugLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)localtime_r(&time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

/**
 *  \brief Function to log the FlowVars in to alert-debug.log
 *
 *  \param aft Pointer to AltertDebugLog Thread
 *  \param p Pointer to the packet
 *
 */
static void AlertDebugLogFlowVars(AlertDebugLogThread *aft, Packet *p)
{
    GenericVar *gv = p->flow->flowvar;
    uint16_t i;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *) gv;

            if (fv->datatype == FLOWVAR_TYPE_STR) {
                fprintf(aft->file_ctx->fp, "FLOWVAR idx(%"PRIu32"):    "
                        ,fv->idx);
                for (i = 0; i < fv->data.fv_str.value_len; i++) {
                    if (isprint(fv->data.fv_str.value[i]))
                        fprintf(aft->file_ctx->fp, "%c", fv->data.fv_str.value[i]);
                    else
                        fprintf(aft->file_ctx->fp, "\\%02X", fv->data.fv_str.value[i]);
                }
            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                fprintf(aft->file_ctx->fp, "FLOWVAR idx(%"PRIu32"):   "
                        " %" PRIu32 "\"", fv->idx, fv->data.fv_int.value);
            }
        }
        gv = gv->next;
    }
}

/**
 *  \brief Function to log the FlowBits in to alert-debug.log
 *
 *  \param aft Pointer to AltertDebugLog Thread
 *  \param p Pointer to the packet
 *
 */
static void AlertDebugLogFlowBits(AlertDebugLogThread *aft, Packet *p)
{
    GenericVar *gv = p->flow->flowvar;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *) gv;
            char *name = VariableIdxGetName(fb->idx, fb->type);
            if (name != NULL) {
                fprintf(aft->file_ctx->fp, "FLOWBIT:           %s\n",name);
                SCFree(name);
            }
        }
        gv = gv->next;
    }
}

/**
 *  \brief Function to log the PktVars in to alert-debug.log
 *
 *  \param aft Pointer to AltertDebugLog Thread
 *  \param p Pointer to the packet
 *
 */
static void AlertDebugLogPktVars(AlertDebugLogThread *aft, Packet *p)
{
    PktVar *pv = p->pktvar;

    while(pv != NULL) {
        fprintf(aft->file_ctx->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->file_ctx->fp, pv->value, pv->value_len);
        pv = pv->next;
    }
}

/** \todo doc
 * assume we have aft lock */
static int AlertDebugPrintStreamSegmentCallback(Packet *p, void *data, uint8_t *buf, uint32_t buflen)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;

    fprintf(aft->file_ctx->fp, "STREAM DATA:\n");
    PrintRawDataFp(aft->file_ctx->fp, buf, buflen);

    return 1;
}



TmEcode AlertDebugLogger(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    fprintf(aft->file_ctx->fp, "+================\n");
    fprintf(aft->file_ctx->fp, "TIME:              %s\n", timebuf);
    if (p->pcap_cnt > 0) {
        fprintf(aft->file_ctx->fp, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
    }

    char srcip[46], dstip[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }

    fprintf(aft->file_ctx->fp, "SRC IP:            %s\n", srcip);
    fprintf(aft->file_ctx->fp, "DST IP:            %s\n", dstip);
    fprintf(aft->file_ctx->fp, "PROTO:             %" PRIu32 "\n", p->proto);
    if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
        fprintf(aft->file_ctx->fp, "SRC PORT:          %" PRIu32 "\n", p->sp);
        fprintf(aft->file_ctx->fp, "DST PORT:          %" PRIu32 "\n", p->dp);
        if (PKT_IS_TCP(p)) {
            fprintf(aft->file_ctx->fp, "TCP SEQ:           %"PRIu32"\n", TCP_GET_SEQ(p));
            fprintf(aft->file_ctx->fp, "TCP ACK:           %"PRIu32"\n", TCP_GET_ACK(p));
        }
    }

    /* flow stuff */
    fprintf(aft->file_ctx->fp, "FLOW:              to_server: %s, to_client: %s\n",
        p->flowflags & FLOW_PKT_TOSERVER ? "TRUE" : "FALSE",
        p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE" : "FALSE");

    if (p->flow != NULL) {
        SCMutexLock(&p->flow->m);
        CreateTimeString(&p->flow->startts, timebuf, sizeof(timebuf));
        fprintf(aft->file_ctx->fp, "FLOW Start TS:     %s\n",timebuf);
#ifdef DEBUG
        fprintf(aft->file_ctx->fp, "FLOW PKTS TODST:   %"PRIu32"\n",p->flow->todstpktcnt);
        fprintf(aft->file_ctx->fp, "FLOW PKTS TOSRC:   %"PRIu32"\n",p->flow->tosrcpktcnt);
        fprintf(aft->file_ctx->fp, "FLOW Total Bytes:  %"PRIu64"\n",p->flow->bytecnt);
#endif
        fprintf(aft->file_ctx->fp, "FLOW IPONLY SET:   TOSERVER: %s, TOCLIENT: %s\n",
                p->flow->flags & FLOW_TOSERVER_IPONLY_SET ? "TRUE" : "FALSE",
                p->flow->flags & FLOW_TOCLIENT_IPONLY_SET ? "TRUE" : "FALSE");
        fprintf(aft->file_ctx->fp, "FLOW ACTION:       DROP: %s, PASS %s\n",
                p->flow->flags & FLOW_ACTION_DROP ? "TRUE" : "FALSE",
                p->flow->flags & FLOW_ACTION_PASS ? "TRUE" : "FALSE");
        fprintf(aft->file_ctx->fp, "FLOW NOINSPECTION: PACKET: %s, PAYLOAD: %s, APP_LAYER: %s\n",
                p->flow->flags & FLOW_NOPACKET_INSPECTION ? "TRUE" : "FALSE",
                p->flow->flags & FLOW_NOPAYLOAD_INSPECTION ? "TRUE" : "FALSE",
                p->flow->flags & FLOW_NO_APPLAYER_INSPECTION ? "TRUE" : "FALSE");
        fprintf(aft->file_ctx->fp, "FLOW APP_LAYER:    DETECTED: %s, PROTO %"PRIu16"\n",
                (p->flow->alproto != ALPROTO_UNKNOWN) ? "TRUE" : "FALSE", p->flow->alproto);
        AlertDebugLogFlowVars(aft, p);
        AlertDebugLogFlowBits(aft, p);
        SCMutexUnlock(&p->flow->m);
    }

    AlertDebugLogPktVars(aft, p);

/* any stuff */
/* Sig details? */

    fprintf(aft->file_ctx->fp, "PACKET LEN:        %" PRIu32 "\n", GET_PKT_LEN(p));
    fprintf(aft->file_ctx->fp, "PACKET:\n");
    PrintRawDataFp(aft->file_ctx->fp, GET_PKT_DATA(p), GET_PKT_LEN(p));

    fprintf(aft->file_ctx->fp, "ALERT CNT:           %" PRIu32 "\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        fprintf(aft->file_ctx->fp, "ALERT MSG [%02d]:      %s\n", i, pa->s->msg);
        fprintf(aft->file_ctx->fp, "ALERT GID [%02d]:      %" PRIu32 "\n", i, pa->s->gid);
        fprintf(aft->file_ctx->fp, "ALERT SID [%02d]:      %" PRIu32 "\n", i, pa->s->id);
        fprintf(aft->file_ctx->fp, "ALERT REV [%02d]:      %" PRIu32 "\n", i, pa->s->rev);
        fprintf(aft->file_ctx->fp, "ALERT CLASS [%02d]:    %s\n", i, pa->s->class_msg ? pa->s->class_msg : "<none>");
        fprintf(aft->file_ctx->fp, "ALERT PRIO [%02d]:     %" PRIu32 "\n", i, pa->s->prio);
        fprintf(aft->file_ctx->fp, "ALERT FOUND IN [%02d]: %s\n", i, pa->alert_msg ? "STREAM" : "OTHER");
        if (pa->alert_msg != NULL) {
            fprintf(aft->file_ctx->fp, "ALERT STREAM LEN[%02d]:%"PRIu16"\n", i, ((StreamMsg *)pa->alert_msg)->data.data_len);
            fprintf(aft->file_ctx->fp, "ALERT STREAM [%02d]:\n", i);
            PrintRawDataFp(aft->file_ctx->fp, ((StreamMsg *)pa->alert_msg)->data.data,
                    ((StreamMsg *)pa->alert_msg)->data.data_len);
        } else if (p->payload_len > 0) {
            fprintf(aft->file_ctx->fp, "PAYLOAD LEN:       %" PRIu32 "\n", p->payload_len);
            fprintf(aft->file_ctx->fp, "PAYLOAD:\n");
            PrintRawDataFp(aft->file_ctx->fp, p->payload, p->payload_len);
        }
        if (pa->flags & PACKET_ALERT_FLAG_STATE_MATCH) {
            /* This is an app layer alert */
            int ret;
            uint8_t flag;
            if ((! PKT_IS_TCP(p)) || p->flow == NULL ||
                    p->flow->protoctx == NULL) {
                SCMutexUnlock(&aft->file_ctx->fp_mutex);
                return TM_ECODE_OK;
            }
            /* IDS mode reverse the data */
            /** \todo improve the order selection policy */
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                flag = FLOW_PKT_TOCLIENT;
            } else {
                flag = FLOW_PKT_TOSERVER;
            }
            ret = StreamSegmentForEach(p, flag,
                                 AlertDebugPrintStreamSegmentCallback,
                                 (void *)aft);
            if (ret < 0) {
                SCMutexUnlock(&aft->file_ctx->fp_mutex);
                return TM_ECODE_FAILED;
            }
        }
    }

    aft->file_ctx->alerts += p->alerts.cnt;

    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebugLogDecoderEvent(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    fprintf(aft->file_ctx->fp, "+================\n");
    fprintf(aft->file_ctx->fp, "TIME:              %s\n", timebuf);
    if (p->pcap_cnt > 0) {
        fprintf(aft->file_ctx->fp, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
    }
    fprintf(aft->file_ctx->fp, "ALERT CNT:         %" PRIu32 "\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        fprintf(aft->file_ctx->fp, "ALERT MSG [%02d]:    %s\n", i, pa->s->msg);
        fprintf(aft->file_ctx->fp, "ALERT GID [%02d]:    %" PRIu32 "\n", i, pa->s->gid);
        fprintf(aft->file_ctx->fp, "ALERT SID [%02d]:    %" PRIu32 "\n", i, pa->s->id);
        fprintf(aft->file_ctx->fp, "ALERT REV [%02d]:    %" PRIu32 "\n", i, pa->s->rev);
        fprintf(aft->file_ctx->fp, "ALERT CLASS [%02d]:  %s\n", i, pa->s->class_msg);
        fprintf(aft->file_ctx->fp, "ALERT PRIO [%02d]:   %" PRIu32 "\n", i, pa->s->prio);
    }

    aft->file_ctx->alerts += p->alerts.cnt;

    fprintf(aft->file_ctx->fp, "PACKET LEN:        %" PRIu32 "\n", GET_PKT_LEN(p));
    fprintf(aft->file_ctx->fp, "PACKET:\n");
    PrintRawDataFp(aft->file_ctx->fp, GET_PKT_DATA(p), GET_PKT_LEN(p));

    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebugLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertDebugLogger(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertDebugLogger(tv, p, data, pq, postpq);
    } else if (p->events.cnt > 0) {
        return AlertDebugLogDecoderEvent(tv, p, data, pq, postpq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertDebugLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertDebugLogThread *aft = SCMalloc(sizeof(AlertDebugLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertDebugLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for DebugLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertDebugLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertDebugLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertDebugLogExitPrintStats(ThreadVars *tv, void *data) {
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu64 "", tv->name, aft->file_ctx->alerts);
}

static void AlertDebugLogDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx != NULL) {
        LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
        if (logfile_ctx != NULL) {
            LogFileFreeCtx(logfile_ctx);
        }
        SCFree(output_ctx);
    }
}

/**
 *  \brief Create a new LogFileCtx for alert debug logging.
 *
 *  \param ConfNode containing configuration for this logger.
 *
 *  \return output_ctx if succesful, NULL otherwise
 */
OutputCtx *AlertDebugLogInitCtx(ConfNode *conf)
{
    LogFileCtx *file_ctx = NULL;

    file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogDebug("couldn't create new file_ctx");
        goto error;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        goto error;
    }

    OutputCtx *output_ctx = SCMalloc(sizeof(OutputCtx));
    if (output_ctx == NULL)
        goto error;

    memset(output_ctx, 0x00, sizeof(OutputCtx));
    output_ctx->data = file_ctx;
    output_ctx->DeInit = AlertDebugLogDeInitCtx;

    SCLogDebug("Alert debug log output initialized");
    return output_ctx;

error:
    if (file_ctx != NULL) {
        LogFileFreeCtx(file_ctx);
    }

    return NULL;
}
