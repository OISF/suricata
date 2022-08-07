/* Copyright (C) 2014-2020 Open Information Security Foundation
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
#include "util-device.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"
#include "output-json-netflow.h"

#include "stream-tcp-private.h"

static JsonBuilder *CreateEveHeaderFromNetFlow(const Flow *f, int dir)
{
    char timebuf[64];
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    JsonBuilder *js = jb_new_object();
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

    /* time */
    jb_set_string(js, "timestamp", timebuf);

    CreateEveFlowId(js, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif

    /* input interface */
    if (f->livedev) {
        jb_set_string(js, "in_iface", f->livedev->dev);
    }

    JB_SET_STRING(js, "event_type", "netflow");

    /* vlan */
    if (f->vlan_idx > 0) {
        jb_open_array(js, "vlan");
        jb_append_uint(js, f->vlan_id[0]);
        if (f->vlan_idx > 1) {
            jb_append_uint(js, f->vlan_id[1]);
        }
        if (f->vlan_idx > 2) {
            jb_append_uint(js, f->vlan_id[2]);
        }
        jb_close(js);
    }

    /* tuple */
    jb_set_string(js, "src_ip", srcip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            jb_set_uint(js, "src_port", sp);
            break;
    }
    jb_set_string(js, "dest_ip", dstip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            jb_set_uint(js, "dest_port", dp);
            break;
    }

    if (SCProtoNameValid(f->proto)) {
        jb_set_string(js, "proto", known_proto[f->proto]);
    } else {
        char proto[4];
        snprintf(proto, sizeof(proto), "%"PRIu8"", f->proto);
        jb_set_string(js, "proto", proto);
    }

    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6: {
            uint8_t type = f->icmp_s.type;
            uint8_t code = f->icmp_s.code;
            if (dir == 1) {
                type = f->icmp_d.type;
                code = f->icmp_d.code;

            }
            jb_set_uint(js, "icmp_type", type);
            jb_set_uint(js, "icmp_code", code);
            break;
        }
        case IPPROTO_ESP:
            jb_set_uint(js, "spi", f->esp.spi);
            break;
    }
    return js;
}

/* JSON format logging */
static void NetFlowLogEveToServer(JsonBuilder *js, Flow *f)
{
    jb_set_string(js, "app_proto",
            AppProtoToString(f->alproto_ts ? f->alproto_ts : f->alproto));

    jb_open_object(js, "netflow");

    jb_set_uint(js, "pkts", f->todstpktcnt);
    jb_set_uint(js, "bytes", f->todstbytecnt);

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    jb_set_string(js, "start", timebuf1);
    jb_set_string(js, "end", timebuf2);

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    jb_set_uint(js, "age", age);

    jb_set_uint(js, "min_ttl", f->min_ttl_toserver);
    jb_set_uint(js, "max_ttl", f->max_ttl_toserver);

    /* Close netflow. */
    jb_close(js);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        jb_open_object(js, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        jb_set_string(js, "tcp_flags", hexflags);

        EveTcpFlags(ssn ? ssn->client.tcp_flags : 0, js);

        jb_close(js);
    }
}

static void NetFlowLogEveToClient(JsonBuilder *js, Flow *f)
{
    jb_set_string(js, "app_proto",
            AppProtoToString(f->alproto_tc ? f->alproto_tc : f->alproto));

    jb_open_object(js, "netflow");

    jb_set_uint(js, "pkts", f->tosrcpktcnt);
    jb_set_uint(js, "bytes", f->tosrcbytecnt);

    char timebuf1[64], timebuf2[64];

    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));

    jb_set_string(js, "start", timebuf1);
    jb_set_string(js, "end", timebuf2);

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    jb_set_uint(js, "age", age);

    /* To client is zero if we did not see any packet */
    if (f->tosrcpktcnt) {
        jb_set_uint(js, "min_ttl", f->min_ttl_toclient);
        jb_set_uint(js, "max_ttl", f->max_ttl_toclient);
    }

    /* Close netflow. */
    jb_close(js);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        jb_open_object(js, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        jb_set_string(js, "tcp_flags", hexflags);

        EveTcpFlags(ssn ? ssn->server.tcp_flags : 0, js);

        jb_close(js);
    }
}

static int JsonNetFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    OutputJsonThreadCtx *jhl = thread_data;

    JsonBuilder *jb = CreateEveHeaderFromNetFlow(f, 0);
    if (unlikely(jb == NULL))
        return TM_ECODE_OK;
    NetFlowLogEveToServer(jb, f);
    EveAddCommonOptions(&jhl->ctx->cfg, NULL, f, jb);
    OutputJsonBuilderBuffer(jb, jhl);
    jb_free(jb);

    /* only log a response record if we actually have seen response packets */
    if (f->tosrcpktcnt) {
        jb = CreateEveHeaderFromNetFlow(f, 1);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;
        NetFlowLogEveToClient(jb, f);
        EveAddCommonOptions(&jhl->ctx->cfg, NULL, f, jb);
        OutputJsonBuilderBuffer(jb, jhl);
        jb_free(jb);
    }
    SCReturnInt(TM_ECODE_OK);
}

void JsonNetFlowLogRegister(void)
{
    /* register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_NETFLOW, "eve-log", "JsonNetFlowLog", "eve-log.netflow",
            OutputJsonLogInitSub, JsonNetFlowLogger, JsonLogThreadInit, JsonLogThreadDeinit, NULL);
}
