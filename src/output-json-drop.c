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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * JSON Drop log module to log the dropped packet information
 *
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
#include "output-json.h"
#include "output-json-alert.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#define MODULE_NAME "JsonDropLog"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define LOG_DROP_ALERTS 1

typedef struct JsonDropOutputCtx_ {
    LogFileCtx *file_ctx;
    uint8_t flags;
} JsonDropOutputCtx;

typedef struct JsonDropLogThread_ {
    JsonDropOutputCtx *drop_ctx;
    MemBuffer *buffer;
} JsonDropLogThread;

/**
 * \brief   Log the dropped packets in netfilter format when engine is running
 *          in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is being logged
 *
 * \return return TM_EODE_OK on success
 */
static int DropLogJSON (JsonDropLogThread *aft, const Packet *p)
{
    uint16_t proto = 0;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    json_t *js = CreateJSONHeader((Packet *)p, 0, "drop");//TODO const
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    json_t *djs = json_object();
    if (unlikely(djs == NULL)) {
        json_decref(js);
        return TM_ECODE_OK;
    }

    /* reset */
    MemBufferReset(buffer);

    if (PKT_IS_IPV4(p)) {
        json_object_set_new(djs, "len", json_integer(IPV4_GET_IPLEN(p)));
        json_object_set_new(djs, "tos", json_integer(IPV4_GET_IPTOS(p)));
        json_object_set_new(djs, "ttl", json_integer(IPV4_GET_IPTTL(p)));
        json_object_set_new(djs, "ipid", json_integer(IPV4_GET_IPID(p)));
        proto = IPV4_GET_IPPROTO(p);
    } else if (PKT_IS_IPV6(p)) {
        json_object_set_new(djs, "len", json_integer(IPV6_GET_PLEN(p)));
        json_object_set_new(djs, "tc", json_integer(IPV6_GET_CLASS(p)));
        json_object_set_new(djs, "hoplimit", json_integer(IPV6_GET_HLIM(p)));
        json_object_set_new(djs, "flowlbl", json_integer(IPV6_GET_FLOW(p)));
        proto = IPV6_GET_L4PROTO(p);
    }
    switch (proto) {
        case IPPROTO_TCP:
            json_object_set_new(djs, "tcpseq", json_integer(TCP_GET_SEQ(p)));
            json_object_set_new(djs, "tcpack", json_integer(TCP_GET_ACK(p)));
            json_object_set_new(djs, "tcpwin", json_integer(TCP_GET_WINDOW(p)));
            json_object_set_new(djs, "syn", TCP_ISSET_FLAG_SYN(p) ? json_true() : json_false());
            json_object_set_new(djs, "ack", TCP_ISSET_FLAG_ACK(p) ? json_true() : json_false());
            json_object_set_new(djs, "psh", TCP_ISSET_FLAG_PUSH(p) ? json_true() : json_false());
            json_object_set_new(djs, "rst", TCP_ISSET_FLAG_RST(p) ? json_true() : json_false());
            json_object_set_new(djs, "urg", TCP_ISSET_FLAG_URG(p) ? json_true() : json_false());
            json_object_set_new(djs, "fin", TCP_ISSET_FLAG_FIN(p) ? json_true() : json_false());
            json_object_set_new(djs, "tcpres", json_integer(TCP_GET_RAW_X2(p->tcph)));
            json_object_set_new(djs, "tcpurgp", json_integer(TCP_GET_URG_POINTER(p)));
            break;
        case IPPROTO_UDP:
            json_object_set_new(djs, "udplen", json_integer(UDP_GET_LEN(p)));
            break;
        case IPPROTO_ICMP:
            if (PKT_IS_ICMPV4(p)) {
                json_object_set_new(djs, "icmp_id", json_integer(ICMPV4_GET_ID(p)));
                json_object_set_new(djs, "icmp_seq", json_integer(ICMPV4_GET_SEQ(p)));
            } else if(PKT_IS_ICMPV6(p)) {
                json_object_set_new(djs, "icmp_id", json_integer(ICMPV6_GET_ID(p)));
                json_object_set_new(djs, "icmp_seq", json_integer(ICMPV6_GET_SEQ(p)));
            }
            break;
    }
    json_object_set_new(js, "drop", djs);

    if (aft->drop_ctx->flags & LOG_DROP_ALERTS) {
        int logged = 0;
        int i;
        for (i = 0; i < p->alerts.cnt; i++) {
            const PacketAlert *pa = &p->alerts.alerts[i];
            if (unlikely(pa->s == NULL)) {
                continue;
            }
            if ((pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) ||
               ((pa->action & ACTION_DROP) && EngineModeIsIPS()))
            {
                AlertJsonHeader(p, pa, js);
                logged = 1;
            }
        }
        if (logged == 0) {
            if (p->alerts.drop.action != 0) {
                const PacketAlert *pa = &p->alerts.drop;
                AlertJsonHeader(p, pa, js);
            }
        }
    }

    OutputJSONBuffer(js, aft->drop_ctx->file_ctx, buffer);
    json_object_del(js, "drop");
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonDropLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonDropLogThread *aft = SCMalloc(sizeof(JsonDropLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(*aft));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertFastLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    aft->drop_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonDropLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonDropLogThread *aft = (JsonDropLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonDropLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputDropLoggerDisable();

    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

static void JsonDropLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputDropLoggerDisable();

    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

static void JsonDropOutputCtxFree(JsonDropOutputCtx *drop_ctx)
{
    if (drop_ctx != NULL) {
        if (drop_ctx->file_ctx != NULL)
            LogFileFreeCtx(drop_ctx->file_ctx);
        SCFree(drop_ctx);
    }
}

#define DEFAULT_LOG_FILENAME "drop.json"
static OutputCtx *JsonDropLogInitCtx(ConfNode *conf)
{
    if (OutputDropLoggerEnable() != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "only one 'drop' logger "
            "can be enabled");
        return NULL;
    }

    JsonDropOutputCtx *drop_ctx = SCCalloc(1, sizeof(*drop_ctx));
    if (drop_ctx == NULL)
        return NULL;

    drop_ctx->file_ctx = LogFileNewCtx();
    if (drop_ctx->file_ctx == NULL) {
        JsonDropOutputCtxFree(drop_ctx);
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, drop_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        JsonDropOutputCtxFree(drop_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonDropOutputCtxFree(drop_ctx);
        return NULL;
    }

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "alerts");
        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                drop_ctx->flags = LOG_DROP_ALERTS;
            }
        }
    }

    output_ctx->data = drop_ctx;
    output_ctx->DeInit = JsonDropLogDeInitCtx;
    return output_ctx;
}

static OutputCtx *JsonDropLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    if (OutputDropLoggerEnable() != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "only one 'drop' logger "
            "can be enabled");
        return NULL;
    }

    AlertJsonThread *ajt = parent_ctx->data;

    JsonDropOutputCtx *drop_ctx = SCCalloc(1, sizeof(*drop_ctx));
    if (drop_ctx == NULL)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonDropOutputCtxFree(drop_ctx);
        return NULL;
    }

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "alerts");
        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                drop_ctx->flags = LOG_DROP_ALERTS;
            }
        }
    }

    drop_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = drop_ctx;
    output_ctx->DeInit = JsonDropLogDeInitCtxSub;
    return output_ctx;
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
static int JsonDropLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonDropLogThread *td = thread_data;
    int r = DropLogJSON(td, p);
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


/**
 * \brief Check if we need to drop-log this packet
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is tested
 *
 * \retval bool TRUE or FALSE
 */
static int JsonDropLogCondition(ThreadVars *tv, const Packet *p)
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

        /* for a flow that will be dropped fully, log just once per direction */
        FLOWLOCK_RDLOCK(p->flow);
        if (p->flow->flags & FLOW_ACTION_DROP) {
            if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED))
                ret = TRUE;
            else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED))
                ret = TRUE;
        }
        FLOWLOCK_UNLOCK(p->flow);

        /* if drop is caused by signature, log anyway */
        if (p->alerts.drop.action != 0)
            ret = TRUE;

        return ret;
    } else if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
        return TRUE;
    }

    return FALSE;
}

void TmModuleJsonDropLogRegister (void)
{
    tmm_modules[TMM_JSONDROPLOG].name = MODULE_NAME;
    tmm_modules[TMM_JSONDROPLOG].ThreadInit = JsonDropLogThreadInit;
    tmm_modules[TMM_JSONDROPLOG].ThreadDeinit = JsonDropLogThreadDeinit;
    tmm_modules[TMM_JSONDROPLOG].cap_flags = 0;
    tmm_modules[TMM_JSONDROPLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "drop-json-log",
            JsonDropLogInitCtx, JsonDropLogger, JsonDropLogCondition);
    OutputRegisterPacketSubModule("eve-log", MODULE_NAME, "eve-log.drop",
            JsonDropLogInitCtxSub, JsonDropLogger, JsonDropLogCondition);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonDropLogRegister (void)
{
    tmm_modules[TMM_JSONDROPLOG].name = MODULE_NAME;
    tmm_modules[TMM_JSONDROPLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
