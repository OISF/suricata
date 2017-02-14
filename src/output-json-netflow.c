/* Copyright (C) 2014 Open Information Security Foundation
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
 * Implements Unidirectiontal NetFlow JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"

#include "stream-tcp-private.h"

typedef struct LogJsonFileCtx_ {
    LogFileCtx *file_ctx;
} LogJsonFileCtx;

typedef struct JsonNetFlowLogThread_ {
    LogJsonFileCtx *flowlog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */

    MemBuffer *buffer;
    SCJson *js;
} JsonNetFlowLogThread;


static SCJson *CreateJSONHeaderFromFlow(SCJson *js, Flow *f, char *event_type,
    int dir)
{
    char timebuf[64];
    char srcip[46], dstip[46];
    Port sp, dp;

    SCJsonReset(js);
    SCJsonOpenObject(js);

    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    CreateIsoTimeString(&tv, timebuf, sizeof(timebuf));

    srcip[0] = '\0';
    dstip[0] = '\0';
    if (FLOW_IS_IPV4(f)) {
        if (dir == 0) {
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dstip, sizeof(dstip));
        } else {
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), dstip, sizeof(dstip));
        }
    } else if (FLOW_IS_IPV6(f)) {
        if (dir == 0) {
            PrintInet(AF_INET6, (const void *)&(f->src.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->dst.address), dstip, sizeof(dstip));
        } else {
            PrintInet(AF_INET6, (const void *)&(f->dst.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->src.address), dstip, sizeof(dstip));
        }
    }

    if (dir == 0) {
        sp = f->sp;
        dp = f->dp;
    } else {
        sp = f->dp;
        dp = f->sp;
    }

    char proto[16];
    if (SCProtoNameValid(f->proto) == TRUE) {
        strlcpy(proto, known_proto[f->proto], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "%03" PRIu32, f->proto);
    }

    /* time */
    SCJsonSetString(js, "timestamp", timebuf);

    CreateJSONFlowId(js, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif
    if (event_type) {
        SCJsonSetString(js, "event_type", event_type);
    }
#if 0
    /* vlan */
    if (f->vlan_id[0] > 0) {
        json_t *js_vlan;
        switch (f->vlan_idx) {
            case 1:
                json_object_set_new(js, "vlan",
                                    json_integer(f->vlan_id[0]));
                break;
            case 2:
                js_vlan = json_array();
                if (unlikely(js != NULL)) {
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID1(p)));
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID2(p)));
                    json_object_set_new(js, "vlan", js_vlan);
                }
                break;
            default:
                /* shouldn't get here */
                break;
        }
    }
#endif
    /* tuple */
    SCJsonSetString(js, "src_ip", srcip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            SCJsonSetInt(js, "src_port", sp);
            break;
    }
    SCJsonSetString(js, "dest_ip", dstip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            SCJsonSetInt(js, "dest_port", dp);
            break;
    }
    SCJsonSetString(js, "proto", proto);
    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            SCJsonSetInt(js, "icmp_type", f->type);
            SCJsonSetInt(js, "icmp_code", f->code);
            break;
    }
    return js;
}

/* JSON format logging */
static void JsonNetFlowLogJSONToServer(JsonNetFlowLogThread *aft, SCJson *js, Flow *f)
{
    SCJsonSetString(js, "app_proto",
        AppProtoToString(f->alproto_ts ? f->alproto_ts : f->alproto));
        
    SCJsonStartObject(js, "netflow");

    SCJsonSetInt(js, "pkts", f->todstpktcnt);
    SCJsonSetInt(js, "bytes", f->todstbytecnt);

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    SCJsonSetString(js, "start", timebuf1);
    SCJsonSetString(js, "end", timebuf2);

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    SCJsonSetInt(js, "age", age);

    SCJsonCloseObject(js);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        SCJsonStartObject(js, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        SCJsonSetString(js, "tcp_flags", hexflags);

        JsonTcpFlags(ssn ? ssn->client.tcp_flags : 0, js);

        SCJsonCloseObject(js);
    }
}

static void JsonNetFlowLogJSONToClient(JsonNetFlowLogThread *aft, SCJson *js, Flow *f)
{

    SCJsonSetString(js, "app_proto",
        AppProtoToString(f->alproto_tc ? f->alproto_tc : f->alproto));

    SCJsonStartObject(js, "netflow");

    SCJsonSetInt(js, "pkts", f->tosrcpktcnt);
    SCJsonSetInt(js, "bytes", f->tosrcbytecnt);

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    SCJsonSetString(js, "start", timebuf1);
    SCJsonSetString(js, "end", timebuf2);

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    SCJsonSetInt(js, "age", age);

    SCJsonCloseObject(js);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        SCJsonStartObject(js, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        SCJsonSetString(js, "tcp_flags", hexflags);

        JsonTcpFlags(ssn ? ssn->server.tcp_flags : 0, js);

        SCJsonCloseObject(js);
    }
}

static int JsonNetFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    JsonNetFlowLogThread *jhl = (JsonNetFlowLogThread *)thread_data;
    SCJson *js = jhl->js;

    /* reset */
    MemBufferReset(jhl->buffer);
    CreateJSONHeaderFromFlow(js, f, "netflow", 0); //TODO const
    JsonNetFlowLogJSONToServer(jhl, js, f);
    SCJsonCloseObject(js);
    OutputJSONBuffer(js, jhl->flowlog_ctx->file_ctx, &jhl->buffer);
    SCJsonReset(js);

    /* reset */
    MemBufferReset(jhl->buffer);
    CreateJSONHeaderFromFlow(js, f, "netflow", 1); //TODO const
    JsonNetFlowLogJSONToClient(jhl, js, f);
    SCJsonCloseObject(js);
    OutputJSONBuffer(js, jhl->flowlog_ctx->file_ctx, &jhl->buffer);
    SCJsonReset(js);

    SCReturnInt(TM_ECODE_OK);
}

static void OutputNetFlowLogDeinit(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = flow_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "netflow.json"
OutputCtx *OutputNetFlowLogInit(ConfNode *conf)
{
    SCLogInfo("hi");
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_NETFLOW_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(flow_ctx);
        return NULL;
    }

    flow_ctx->file_ctx = file_ctx;
    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputNetFlowLogDeinit;

    return output_ctx;
}

static void OutputNetFlowLogDeinitSub(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

OutputCtx *OutputNetFlowLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return NULL;
    }

    flow_ctx->file_ctx = ojc->file_ctx;

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputNetFlowLogDeinitSub;

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonNetFlowLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonNetFlowLogThread *aft = SCMalloc(sizeof(JsonNetFlowLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonNetFlowLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogNetflow.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->flowlog_ctx = ((OutputCtx *)initdata)->data; //TODO

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->js = SCJsonNew();
    if (aft->js == NULL) {
        MemBufferFree(aft->buffer);
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonNetFlowLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonNetFlowLogThread *aft = (JsonNetFlowLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonNetFlowLogThread));

    SCJsonFree(aft->js);

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonNetFlowLogRegister(void)
{
    /* register as separate module */
    OutputRegisterFlowModule(LOGGER_JSON_NETFLOW, "JsonNetFlowLog",
        "netflow-json-log", OutputNetFlowLogInit, JsonNetFlowLogger,
        JsonNetFlowLogThreadInit, JsonNetFlowLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_NETFLOW, "eve-log", "JsonNetFlowLog",
        "eve-log.netflow", OutputNetFlowLogInitSub, JsonNetFlowLogger,
        JsonNetFlowLogThreadInit, JsonNetFlowLogThreadDeinit, NULL);
}
