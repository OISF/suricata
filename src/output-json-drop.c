/* Copyright (C) 2007-2023 Open Information Security Foundation
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
#include "packet.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "decode-ipv4.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-drop.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#include "action-globals.h"

#define MODULE_NAME "JsonDropLog"

#define LOG_DROP_ALERTS  BIT_U8(1)
#define LOG_DROP_VERDICT BIT_U8(2)

typedef struct JsonDropOutputCtx_ {
    uint8_t flags;
    OutputJsonCtx *eve_ctx;
} JsonDropOutputCtx;

typedef struct JsonDropLogThread_ {
    JsonDropOutputCtx *drop_ctx;
    OutputJsonThreadCtx *ctx;
} JsonDropLogThread;

/* default to true as this has been the default behavior for a long time */
static int g_droplog_flows_start = 1;

/**
 * \brief   Log the dropped packets in netfilter format when engine is running
 *          in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is being logged
 *
 * \return return TM_ECODE_OK on success
 */
static int DropLogJSON(ThreadVars *tv, JsonDropLogThread *aft, const Packet *p)
{
    JsonDropOutputCtx *drop_ctx = aft->drop_ctx;

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

    SCJsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "drop", &addr, drop_ctx->eve_ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    if (p->flow != NULL) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            SCJbSetString(js, "direction", "to_server");
        } else {
            SCJbSetString(js, "direction", "to_client");
        }
    }

    SCJbOpenObject(js, "drop");

    uint16_t proto = 0;
    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        SCJbSetUint(js, "len", IPV4_GET_RAW_IPLEN(ip4h));
        SCJbSetUint(js, "tos", IPV4_GET_RAW_IPTOS(ip4h));
        SCJbSetUint(js, "ttl", IPV4_GET_RAW_IPTTL(ip4h));
        SCJbSetUint(js, "ipid", IPV4_GET_RAW_IPID(ip4h));
        proto = IPV4_GET_RAW_IPPROTO(ip4h);
    } else if (PacketIsIPv6(p)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        SCJbSetUint(js, "len", IPV6_GET_RAW_PLEN(ip6h));
        SCJbSetUint(js, "tc", IPV6_GET_RAW_CLASS(ip6h));
        SCJbSetUint(js, "hoplimit", IPV6_GET_RAW_HLIM(ip6h));
        SCJbSetUint(js, "flowlbl", IPV6_GET_RAW_FLOW(ip6h));
        proto = IPV6_GET_L4PROTO(p);
    }
    switch (proto) {
        case IPPROTO_TCP:
            if (PacketIsTCP(p)) {
                const TCPHdr *tcph = PacketGetTCP(p);
                SCJbSetUint(js, "tcpseq", TCP_GET_RAW_SEQ(tcph));
                SCJbSetUint(js, "tcpack", TCP_GET_RAW_ACK(tcph));
                SCJbSetUint(js, "tcpwin", TCP_GET_RAW_WINDOW(tcph));
                SCJbSetBool(js, "syn", TCP_ISSET_FLAG_RAW_SYN(tcph) ? true : false);
                SCJbSetBool(js, "ack", TCP_ISSET_FLAG_RAW_ACK(tcph) ? true : false);
                SCJbSetBool(js, "psh", TCP_ISSET_FLAG_RAW_PUSH(tcph) ? true : false);
                SCJbSetBool(js, "rst", TCP_ISSET_FLAG_RAW_RST(tcph) ? true : false);
                SCJbSetBool(js, "urg", TCP_ISSET_FLAG_RAW_URG(tcph) ? true : false);
                SCJbSetBool(js, "fin", TCP_ISSET_FLAG_RAW_FIN(tcph) ? true : false);
                SCJbSetUint(js, "tcpres", TCP_GET_RAW_X2(tcph));
                SCJbSetUint(js, "tcpurgp", TCP_GET_RAW_URG_POINTER(tcph));
            }
            break;
        case IPPROTO_UDP:
            if (PacketIsUDP(p)) {
                const UDPHdr *udph = PacketGetUDP(p);
                SCJbSetUint(js, "udplen", UDP_GET_RAW_LEN(udph));
            }
            break;
        case IPPROTO_ICMP:
            if (PacketIsICMPv4(p)) {
                SCJbSetUint(js, "icmp_id", ICMPV4_GET_ID(p));
                SCJbSetUint(js, "icmp_seq", ICMPV4_GET_SEQ(p));
            } else if (PacketIsICMPv6(p)) {
                SCJbSetUint(js, "icmp_id", ICMPV6_GET_ID(p));
                SCJbSetUint(js, "icmp_seq", ICMPV6_GET_SEQ(p));
            }
            break;
    }
    if (p->drop_reason != 0) {
        const char *str = PacketDropReasonToString(p->drop_reason);
        SCJbSetString(js, "reason", str);
    }

    /* Close drop. */
    SCJbClose(js);

    if (aft->drop_ctx->flags & LOG_DROP_VERDICT) {
        EveAddVerdict(js, p, 0);
    }

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
                AlertJsonHeader(p, pa, js, 0, &addr, NULL);
                logged = 1;
                break;
            }
        }
        if (logged == 0) {
            if (p->alerts.drop.action != 0) {
                const PacketAlert *pa = &p->alerts.drop;
                AlertJsonHeader(p, pa, js, 0, &addr, NULL);
            }
        }
    }

    OutputJsonBuilderBuffer(tv, p, p->flow, js, aft->ctx);
    SCJbFree(js);

    return TM_ECODE_OK;
}

static TmEcode JsonDropLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonDropLogThread *aft = SCCalloc(1, sizeof(JsonDropLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogDrop.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    aft->drop_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->drop_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonDropLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonDropLogThread *aft = (JsonDropLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonDropOutputCtxFree(JsonDropOutputCtx *drop_ctx)
{
    if (drop_ctx != NULL) {
        SCFree(drop_ctx);
    }
}

static void JsonDropLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputDropLoggerDisable();

    JsonDropOutputCtx *drop_ctx = output_ctx->data;
    SCFree(drop_ctx);
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

static OutputInitResult JsonDropLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    if (OutputDropLoggerEnable() != 0) {
        SCLogError("only one 'drop' logger "
                   "can be enabled");
        return result;
    }

    OutputJsonCtx *ajt = parent_ctx->data;

    JsonDropOutputCtx *drop_ctx = SCCalloc(1, sizeof(*drop_ctx));
    if (drop_ctx == NULL)
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonDropOutputCtxFree(drop_ctx);
        return result;
    }

    if (conf) {
        const char *extended = SCConfNodeLookupChildValue(conf, "alerts");
        if (extended != NULL) {
            if (SCConfValIsTrue(extended)) {
                drop_ctx->flags |= LOG_DROP_ALERTS;
            }
        }
        extended = SCConfNodeLookupChildValue(conf, "flows");
        if (extended != NULL) {
            if (strcasecmp(extended, "start") == 0) {
                g_droplog_flows_start = 1;
            } else if (strcasecmp(extended, "all") == 0) {
                g_droplog_flows_start = 0;
            } else {
                SCLogWarning("valid options for "
                             "'flow' are 'start' and 'all'");
            }
        }
        extended = SCConfNodeLookupChildValue(conf, "verdict");
        if (extended != NULL) {
            if (SCConfValIsTrue(extended)) {
                drop_ctx->flags |= LOG_DROP_VERDICT;
            }
        }
    }

    drop_ctx->eve_ctx = ajt;

    output_ctx->data = drop_ctx;
    output_ctx->DeInit = JsonDropLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/**
 * \brief   Log the dropped packets when engine is running in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the droplog struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on success
 */
static int JsonDropLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonDropLogThread *td = thread_data;
    int r = DropLogJSON(tv, td, p);
    if (r < 0)
        return -1;

    if (!g_droplog_flows_start)
        return 0;

    if (p->flow) {
        if (p->flow->flags & FLOW_ACTION_DROP) {
            if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED))
                p->flow->flags |= FLOW_TOSERVER_DROP_LOGGED;
            else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED))
                p->flow->flags |= FLOW_TOCLIENT_DROP_LOGGED;
        }
    }
    return 0;
}

/**
 * \brief Check if we need to drop-log this packet
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is tested
 *
 * \retval bool true or false
 */
static bool JsonDropLogCondition(ThreadVars *tv, void *data, const Packet *p)
{
    if (!EngineModeIsIPS()) {
        SCLogDebug("engine is not running in inline mode, so returning");
        return false;
    }
    if (PKT_IS_PSEUDOPKT(p)) {
        SCLogDebug("drop log doesn't log pseudo packets");
        return false;
    }

    if (!(PacketCheckAction(p, ACTION_DROP))) {
        return false;
    }

    if (g_droplog_flows_start && p->flow != NULL) {
        bool ret = false;

        /* for a flow that will be dropped fully, log just once per direction */
        if (p->flow->flags & FLOW_ACTION_DROP) {
            if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED))
                ret = true;
            else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED))
                ret = true;
        }

        /* if drop is caused by signature, log anyway */
        if (p->alerts.drop.action != 0)
            ret = true;

        return ret;
    }

    return true;
}

void JsonDropLogRegister (void)
{
    OutputPacketLoggerFunctions output_logger_functions = {
        .LogFunc = JsonDropLogger,
        .FlushFunc = OutputJsonLogFlush,
        .ConditionFunc = JsonDropLogCondition,
        .ThreadInitFunc = JsonDropLogThreadInit,
        .ThreadDeinitFunc = JsonDropLogThreadDeinit,
        .ThreadExitPrintStatsFunc = NULL,
    };

    OutputRegisterPacketSubModule(LOGGER_JSON_DROP, "eve-log", MODULE_NAME, "eve-log.drop",
            JsonDropLogInitCtxSub, &output_logger_functions);
}
