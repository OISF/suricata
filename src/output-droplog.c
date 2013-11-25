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

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

/**
 * \brief   Log the dropped packets in netfilter format when engine is running
 *          in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is being logged
 * \param data  Pointer to the droplog struct
 * \param pq    Pointer the packet queue
 * \param postpq Pointer the packet queue where this packet will be sent
 *
 * \return return TM_EODE_OK on success
 */
TmEcode OutputDropLogJSON (AlertJsonThread *aft, Packet *p, PacketQueue *pq,
                      PacketQueue *postpq)
{
    uint16_t proto = 0;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    json_t *js = CreateJSONHeader(p, 0);
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
    OutputJSON(js, aft, &aft->drop_cnt);
    json_object_del(js, "drop");
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

/**
 * \brief   Log the dropped packets when engine is running in inline mode
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is being logged
 * \param data  Pointer to the droplog struct
 * \param pq    Pointer the packet queue
 * \param postpq Pointer the packet queue where this packet will be sent
 *
 * \return return TM_EODE_OK on success
 */
TmEcode OutputDropLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                      PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;

    /* Check if we are in inline mode or not, if not then no need to log */
    extern uint8_t engine_mode;
    if (!IS_ENGINE_MODE_IPS(engine_mode)) {
        SCLogDebug("engine is not running in inline mode, so returning");
        return TM_ECODE_OK;
    }

    if ((p->flow != NULL) && (p->flow->flags & FLOW_ACTION_DROP)) {
        if (PKT_IS_TOSERVER(p) && !(p->flow->flags & FLOW_TOSERVER_DROP_LOGGED)) {
            p->flow->flags |= FLOW_TOSERVER_DROP_LOGGED;
            return OutputDropLogJSON(aft, p, pq, NULL);

        } else if (PKT_IS_TOCLIENT(p) && !(p->flow->flags & FLOW_TOCLIENT_DROP_LOGGED)) {
            p->flow->flags |= FLOW_TOCLIENT_DROP_LOGGED;
            return OutputDropLogJSON(aft, p, pq, NULL);
        }
    } else {
        return OutputDropLogJSON(aft, p, pq, postpq);
    }

    return TM_ECODE_OK;

}

OutputCtx *OutputDropLogInit(ConfNode *conf)
{
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return NULL;
    }

    return output_ctx;
}


#endif
