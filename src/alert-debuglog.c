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
#include "util-validate.h"
#include "util-buffer.h"

#include "output.h"
#include "alert-debuglog.h"
#include "util-privs.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "util-var-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "stream-tcp-reassemble.h"

#define DEFAULT_LOG_FILENAME "alert-debug.log"

#define MODULE_NAME "AlertDebugLog"

typedef struct AlertDebugLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    MemBuffer *buffer;
} AlertDebugLogThread;

/**
 *  \brief Function to log the FlowVars in to alert-debug.log
 *
 *  \param aft Pointer to AltertDebugLog Thread
 *  \param p Pointer to the packet
 *
 */
static void AlertDebugLogFlowVars(AlertDebugLogThread *aft, const Packet *p)
{
    const GenericVar *gv = p->flow->flowvar;
    uint16_t i;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *)gv;
            const char *fbname = VarNameStoreLookupById(fb->idx, VAR_TYPE_FLOW_BIT);
            if (fbname) {
                MemBufferWriteString(aft->buffer, "FLOWBIT:           %s\n",
                        fbname);
            }
        } else if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *) gv;

            if (fv->datatype == FLOWVAR_TYPE_STR) {
                const char *fvname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_VAR);
                MemBufferWriteString(aft->buffer, "FLOWVAR:           \"%s\" => \"",
                                     fvname);
                for (i = 0; i < fv->data.fv_str.value_len; i++) {
                    if (isprint(fv->data.fv_str.value[i])) {
                        MemBufferWriteString(aft->buffer, "%c",
                                             fv->data.fv_str.value[i]);
                    } else {
                        MemBufferWriteString(aft->buffer, "\\%02X",
                                             fv->data.fv_str.value[i]);
                    }
                }
                MemBufferWriteString(aft->buffer, "\"\n");
            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                const char *fvname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_INT);
                MemBufferWriteString(aft->buffer, "FLOWINT:           \"%s\" =>"
                        " %"PRIu32"\n", fvname, fv->data.fv_int.value);
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
static void AlertDebugLogPktVars(AlertDebugLogThread *aft, const Packet *p)
{
    const PktVar *pv = p->pktvar;

    while (pv != NULL) {
        const char *varname = VarNameStoreLookupById(pv->id, VAR_TYPE_PKT_VAR);
        MemBufferWriteString(aft->buffer, "PKTVAR:            %s\n", varname);
        PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                             pv->value, pv->value_len);
        pv = pv->next;
    }
}

/** \todo doc
 * assume we have aft lock */
static int AlertDebugPrintStreamSegmentCallback(
        const Packet *p, TcpSegment *seg, void *data, const uint8_t *buf, uint32_t buflen)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;

    MemBufferWriteString(aft->buffer, "STREAM DATA LEN:     %"PRIu32"\n", buflen);
    MemBufferWriteString(aft->buffer, "STREAM DATA:\n");

    PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                         buf, buflen);

    return 1;
}

static TmEcode AlertDebugLogger(ThreadVars *tv, const Packet *p, void *thread_data)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)thread_data;
    int i;
    char timebuf[64];
    const char *pkt_src_str = NULL;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(aft->buffer);

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    MemBufferWriteString(aft->buffer, "+================\n"
                         "TIME:              %s\n", timebuf);
    if (p->pcap_cnt > 0) {
        MemBufferWriteString(aft->buffer, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
    }
    pkt_src_str = PktSrcToString(p->pkt_src);
    MemBufferWriteString(aft->buffer, "PKT SRC:           %s\n", pkt_src_str);

    char srcip[46], dstip[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else {
        DEBUG_VALIDATE_BUG_ON(!(PKT_IS_IPV6(p)));
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }

    MemBufferWriteString(aft->buffer, "SRC IP:            %s\n"
                         "DST IP:            %s\n"
                         "PROTO:             %" PRIu32 "\n",
                         srcip, dstip, p->proto);
    if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
        MemBufferWriteString(aft->buffer, "SRC PORT:          %" PRIu32 "\n"
                             "DST PORT:          %" PRIu32 "\n",
                             p->sp, p->dp);
        if (PKT_IS_TCP(p)) {
            MemBufferWriteString(aft->buffer, "TCP SEQ:           %"PRIu32"\n"
                                 "TCP ACK:           %"PRIu32"\n",
                                 TCP_GET_SEQ(p), TCP_GET_ACK(p));
        }
    }

    /* flow stuff */
    MemBufferWriteString(aft->buffer, "FLOW:              to_server: %s, "
                         "to_client: %s\n",
                         p->flowflags & FLOW_PKT_TOSERVER ? "TRUE" : "FALSE",
                         p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE" : "FALSE");

    if (p->flow != NULL) {
        int applayer = 0;
        applayer = StreamTcpAppLayerIsDisabled(p->flow);
        CreateTimeString(&p->flow->startts, timebuf, sizeof(timebuf));
        MemBufferWriteString(aft->buffer, "FLOW Start TS:     %s\n", timebuf);
        MemBufferWriteString(aft->buffer, "FLOW PKTS TODST:   %"PRIu32"\n"
                             "FLOW PKTS TOSRC:   %"PRIu32"\n"
                             "FLOW Total Bytes:  %"PRIu64"\n",
                             p->flow->todstpktcnt, p->flow->tosrcpktcnt,
                             p->flow->todstbytecnt + p->flow->tosrcbytecnt);
        MemBufferWriteString(aft->buffer,
                             "FLOW IPONLY SET:   TOSERVER: %s, TOCLIENT: %s\n"
                             "FLOW ACTION:       DROP: %s\n"
                             "FLOW NOINSPECTION: PACKET: %s, PAYLOAD: %s, APP_LAYER: %s\n"
                             "FLOW APP_LAYER:    DETECTED: %s, PROTO %"PRIu16"\n",
                             p->flow->flags & FLOW_TOSERVER_IPONLY_SET ? "TRUE" : "FALSE",
                             p->flow->flags & FLOW_TOCLIENT_IPONLY_SET ? "TRUE" : "FALSE",
                             p->flow->flags & FLOW_ACTION_DROP ? "TRUE" : "FALSE",
                             p->flow->flags & FLOW_NOPACKET_INSPECTION ? "TRUE" : "FALSE",
                             p->flow->flags & FLOW_NOPAYLOAD_INSPECTION ? "TRUE" : "FALSE",
                             applayer ? "TRUE" : "FALSE",
                             (p->flow->alproto != ALPROTO_UNKNOWN) ? "TRUE" : "FALSE", p->flow->alproto);
        AlertDebugLogFlowVars(aft, p);
    }

    AlertDebugLogPktVars(aft, p);

/* any stuff */
/* Sig details? */

    MemBufferWriteString(aft->buffer,
                         "PACKET LEN:        %" PRIu32 "\n"
                         "PACKET:\n",
                         GET_PKT_LEN(p));
    PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                         GET_PKT_DATA(p), GET_PKT_LEN(p));

    MemBufferWriteString(aft->buffer, "ALERT CNT:           %" PRIu32 "\n",
                         p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        MemBufferWriteString(aft->buffer,
                             "ALERT MSG [%02d]:      %s\n"
                             "ALERT GID [%02d]:      %" PRIu32 "\n"
                             "ALERT SID [%02d]:      %" PRIu32 "\n"
                             "ALERT REV [%02d]:      %" PRIu32 "\n"
                             "ALERT CLASS [%02d]:    %s\n"
                             "ALERT PRIO [%02d]:     %" PRIu32 "\n"
                             "ALERT FOUND IN [%02d]: %s\n",
                             i, pa->s->msg,
                             i, pa->s->gid,
                             i, pa->s->id,
                             i, pa->s->rev,
                             i, pa->s->class_msg ? pa->s->class_msg : "<none>",
                             i, pa->s->prio,
                             i,
                             pa->flags & PACKET_ALERT_FLAG_STREAM_MATCH  ? "STREAM" :
                             (pa->flags & PACKET_ALERT_FLAG_STATE_MATCH ? "STATE" : "PACKET"));
        if (pa->flags & PACKET_ALERT_FLAG_TX) {
            MemBufferWriteString(aft->buffer,
                    "ALERT IN TX [%02d]:    %"PRIu64"\n", i, pa->tx_id);
        } else {
            MemBufferWriteString(aft->buffer,
                    "ALERT IN TX [%02d]:    N/A\n", i);
        }
        if (p->payload_len > 0) {
            MemBufferWriteString(aft->buffer,
                                 "PAYLOAD LEN:         %" PRIu32 "\n"
                                 "PAYLOAD:\n",
                                 p->payload_len);
            PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                                 p->payload, p->payload_len);
        }
        if ((pa->flags & PACKET_ALERT_FLAG_STATE_MATCH) ||
            (pa->flags & PACKET_ALERT_FLAG_STREAM_MATCH)) {
            /* This is an app layer or stream alert */
            int ret;
            uint8_t flag;
            if (!(PKT_IS_TCP(p)) || p->flow == NULL ||
                    p->flow->protoctx == NULL) {
                return TM_ECODE_OK;
            }
            /* IDS mode reverse the data */
            /** \todo improve the order selection policy */
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                flag = STREAM_DUMP_TOCLIENT;
            } else {
                flag = STREAM_DUMP_TOSERVER;
            }
            ret = StreamSegmentForEach((const Packet *)p, flag,
                                 AlertDebugPrintStreamSegmentCallback,
                                 (void *)aft);
            if (ret < 0) {
                return TM_ECODE_FAILED;
            }
        }
    }

    aft->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), aft->file_ctx);

    return TM_ECODE_OK;
}

static TmEcode AlertDebugLogDecoderEvent(ThreadVars *tv, const Packet *p, void *thread_data)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)thread_data;
    int i;
    char timebuf[64];
    const char *pkt_src_str = NULL;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(aft->buffer);

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    MemBufferWriteString(aft->buffer,
                         "+================\n"
                         "TIME:              %s\n", timebuf);
    if (p->pcap_cnt > 0) {
        MemBufferWriteString(aft->buffer,
                             "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
    }
    pkt_src_str = PktSrcToString(p->pkt_src);
    MemBufferWriteString(aft->buffer, "PKT SRC:           %s\n", pkt_src_str);
    MemBufferWriteString(aft->buffer,
                         "ALERT CNT:         %" PRIu32 "\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        MemBufferWriteString(aft->buffer,
                             "ALERT MSG [%02d]:    %s\n"
                             "ALERT GID [%02d]:    %" PRIu32 "\n"
                             "ALERT SID [%02d]:    %" PRIu32 "\n"
                             "ALERT REV [%02d]:    %" PRIu32 "\n"
                             "ALERT CLASS [%02d]:  %s\n"
                             "ALERT PRIO [%02d]:   %" PRIu32 "\n",
                             i, pa->s->msg,
                             i, pa->s->gid,
                             i, pa->s->id,
                             i, pa->s->rev,
                             i, pa->s->class_msg,
                             i, pa->s->prio);
    }

    MemBufferWriteString(aft->buffer,
                         "PACKET LEN:        %" PRIu32 "\n"
                         "PACKET:\n",
                         GET_PKT_LEN(p));
    PrintRawDataToBuffer(aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                         GET_PKT_DATA(p), GET_PKT_LEN(p));

    aft->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), aft->file_ctx);

    return TM_ECODE_OK;
}

static TmEcode AlertDebugLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    AlertDebugLogThread *aft = SCMalloc(sizeof(AlertDebugLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertDebugLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertDebugLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    /* 1 mb seems sufficient enough */
    aft->buffer = MemBufferCreateNew(1 * 1024 * 1024);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode AlertDebugLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(AlertDebugLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
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
static OutputInitResult AlertDebugLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = NULL;

    file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogDebug("couldn't create new file_ctx");
        goto error;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        goto error;
    }

    OutputCtx *output_ctx = SCMalloc(sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto error;

    memset(output_ctx, 0x00, sizeof(OutputCtx));
    output_ctx->data = file_ctx;
    output_ctx->DeInit = AlertDebugLogDeInitCtx;

    SCLogDebug("Alert debug log output initialized");
    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    if (file_ctx != NULL) {
        LogFileFreeCtx(file_ctx);
    }

    return result;
}

static int AlertDebugLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return (p->alerts.cnt ? TRUE : FALSE);
}

static int AlertDebugLogLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        return AlertDebugLogger(tv, p, thread_data);
    } else if (p->events.cnt > 0) {
        return AlertDebugLogDecoderEvent(tv, p, thread_data);
    }
    return TM_ECODE_OK;
}

void AlertDebugLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_ALERT_DEBUG, MODULE_NAME, "alert-debug",
        AlertDebugLogInitCtx, AlertDebugLogLogger, AlertDebugLogCondition,
        AlertDebugLogThreadInit, AlertDebugLogThreadDeinit, NULL);
}
