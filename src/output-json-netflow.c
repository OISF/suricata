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
#include "output-json-netflow.h"

#include "stream-tcp-private.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogJsonFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogJsonFileCtx;

typedef struct JsonNetFlowLogThread_ {
    LogJsonFileCtx *flowlog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */

    MemBuffer *buffer;
} JsonNetFlowLogThread;


static json_t *CreateJSONHeaderFromFlow(const Flow *f, const char *event_type, int dir)
{
    char timebuf[64];
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    CreateIsoTimeString(&tv, timebuf, sizeof(timebuf));

    /* reverse header direction if the flow started out wrong */
    dir ^= ((f->flags & FLOW_DIR_REVERSED) != 0);

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
    json_object_set_new(js, "timestamp", json_string(timebuf));

    CreateJSONFlowId(js, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif

    /* input interface */
    if (f->livedev) {
        json_object_set_new(js, "in_iface", json_string(f->livedev->dev));
    }

    if (event_type) {
        json_object_set_new(js, "event_type", json_string(event_type));
    }

    /* vlan */
    if (f->vlan_idx > 0) {
        json_t *js_vlan = json_array();
        json_array_append_new(js_vlan, json_integer(f->vlan_id[0]));
        if (f->vlan_idx > 1) {
            json_array_append_new(js_vlan, json_integer(f->vlan_id[1]));
        }
        json_object_set_new(js, "vlan", js_vlan);
    }

    /* tuple */
    json_object_set_new(js, "src_ip", json_string(srcip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "src_port", json_integer(sp));
            break;
    }
    json_object_set_new(js, "dest_ip", json_string(dstip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "dest_port", json_integer(dp));
            break;
    }
    json_object_set_new(js, "proto", json_string(proto));
    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6: {
            uint8_t type = f->icmp_s.type;
            uint8_t code = f->icmp_s.code;
            if (dir == 1) {
                type = f->icmp_d.type;
                code = f->icmp_d.code;

            }
            json_object_set_new(js, "icmp_type", json_integer(type));
            json_object_set_new(js, "icmp_code", json_integer(code));
            break;
        }
    }
    return js;
}

/* JSON format logging */
static void JsonNetFlowLogJSONToServer(JsonNetFlowLogThread *aft, json_t *js, Flow *f)
{
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    json_object_set_new(js, "app_proto",
            json_string(AppProtoToString(f->alproto_ts ? f->alproto_ts : f->alproto)));

    json_object_set_new(hjs, "pkts",
            json_integer(f->todstpktcnt));
    json_object_set_new(hjs, "bytes",
            json_integer(f->todstbytecnt));

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    json_object_set_new(hjs, "start", json_string(timebuf1));
    json_object_set_new(hjs, "end", json_string(timebuf2));

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    json_object_set_new(hjs, "age",
            json_integer(age));

    json_object_set_new(hjs, "min_ttl", json_integer(f->min_ttl_toserver));
    json_object_set_new(hjs, "max_ttl", json_integer(f->max_ttl_toserver));

    json_object_set_new(js, "netflow", hjs);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        json_t *tjs = json_object();
        if (tjs == NULL) {
            return;
        }

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        json_object_set_new(tjs, "tcp_flags", json_string(hexflags));

        JsonTcpFlags(ssn ? ssn->client.tcp_flags : 0, tjs);

        json_object_set_new(js, "tcp", tjs);
    }
}

static void JsonNetFlowLogJSONToClient(JsonNetFlowLogThread *aft, json_t *js, Flow *f)
{
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    json_object_set_new(js, "app_proto",
            json_string(AppProtoToString(f->alproto_tc ? f->alproto_tc : f->alproto)));

    json_object_set_new(hjs, "pkts",
            json_integer(f->tosrcpktcnt));
    json_object_set_new(hjs, "bytes",
            json_integer(f->tosrcbytecnt));

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    json_object_set_new(hjs, "start", json_string(timebuf1));
    json_object_set_new(hjs, "end", json_string(timebuf2));

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    json_object_set_new(hjs, "age",
            json_integer(age));

    /* To client is zero if we did not see any packet */
    if (f->tosrcpktcnt) {
        json_object_set_new(hjs, "min_ttl", json_integer(f->min_ttl_toclient));
        json_object_set_new(hjs, "max_ttl", json_integer(f->max_ttl_toclient));
    }

    json_object_set_new(js, "netflow", hjs);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        json_t *tjs = json_object();
        if (tjs == NULL) {
            return;
        }

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        json_object_set_new(tjs, "tcp_flags", json_string(hexflags));

        JsonTcpFlags(ssn ? ssn->server.tcp_flags : 0, tjs);

        json_object_set_new(js, "tcp", tjs);
    }
}

static int JsonNetFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    JsonNetFlowLogThread *jhl = (JsonNetFlowLogThread *)thread_data;
    LogJsonFileCtx *netflow_ctx = jhl->flowlog_ctx;

    /* reset */
    MemBufferReset(jhl->buffer);
    json_t *js = CreateJSONHeaderFromFlow(f, "netflow", 0);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;
    JsonNetFlowLogJSONToServer(jhl, js, f);
    JsonAddCommonOptions(&netflow_ctx->cfg, NULL, f, js);
    OutputJSONBuffer(js, jhl->flowlog_ctx->file_ctx, &jhl->buffer);
    json_object_del(js, "netflow");
    json_object_clear(js);
    json_decref(js);

    /* only log a response record if we actually have seen response packets */
    if (f->tosrcpktcnt) {
        /* reset */
        MemBufferReset(jhl->buffer);
        js = CreateJSONHeaderFromFlow(f, "netflow", 1);
        if (unlikely(js == NULL))
            return TM_ECODE_OK;
        JsonNetFlowLogJSONToClient(jhl, js, f);
        JsonAddCommonOptions(&netflow_ctx->cfg, NULL, f, js);
        OutputJSONBuffer(js, jhl->flowlog_ctx->file_ctx, &jhl->buffer);
        json_object_del(js, "netflow");
        json_object_clear(js);
        json_decref(js);
    }
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
static OutputInitResult OutputNetFlowLogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_NETFLOW_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(flow_ctx);
        return result;
    }

    flow_ctx->file_ctx = file_ctx;
    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputNetFlowLogDeinit;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void OutputNetFlowLogDeinitSub(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputNetFlowLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return result;
    }

    flow_ctx->file_ctx = ojc->file_ctx;
    flow_ctx->cfg = ojc->cfg;

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputNetFlowLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonNetFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data)
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

#else

void JsonNetFlowLogRegister (void)
{
}

#endif
