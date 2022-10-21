/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "packet.h"
#include "pkt-var.h"
#include "flow.h"
#include "host.h"
#include "util-profiling.h"
#include "util-validate.h"

/** \brief issue drop action
 *
 *  Set drop (+reject) flags in both current and root packet.
 *
 *  \param action action bit flags. Must be limited to ACTION_DROP_REJECT
 */
void PacketDrop(Packet *p, const uint8_t action, enum PacketDropReason r)
{
    DEBUG_VALIDATE_BUG_ON((action & ~ACTION_DROP_REJECT) != 0);

    if (p->drop_reason == PKT_DROP_REASON_NOT_SET)
        p->drop_reason = (uint8_t)r;

    if (p->root) {
        p->root->action |= action;
        if (p->root->drop_reason == PKT_DROP_REASON_NOT_SET) {
            p->root->drop_reason = PKT_DROP_REASON_INNER_PACKET;
        }
    }
    p->action |= action;
}

bool PacketCheckAction(const Packet *p, const uint8_t a)
{
    if (likely(p->root == NULL)) {
        return (p->action & a) != 0;
    } else {
        /* check against both */
        const uint8_t actions = p->action | p->root->action;
        return (actions & a) != 0;
    }
}

/**
 *  \brief Initialize a packet structure for use.
 */
void PacketInit(Packet *p)
{
    SCMutexInit(&p->tunnel_mutex, NULL);
    p->alerts.alerts = PacketAlertCreate();
    PACKET_RESET_CHECKSUMS(p);
    p->livedev = NULL;
}

void PacketReleaseRefs(Packet *p)
{
    FlowDeReference(&p->flow);
    HostDeReference(&p->host_src);
    HostDeReference(&p->host_dst);
}

/**
 *  \brief Recycle a packet structure for reuse.
 */
void PacketReinit(Packet *p)
{
/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a)                                                                              \
    do {                                                                                           \
        (a)->family = 0;                                                                           \
        (a)->addr_data32[0] = 0;                                                                   \
        (a)->addr_data32[1] = 0;                                                                   \
        (a)->addr_data32[2] = 0;                                                                   \
        (a)->addr_data32[3] = 0;                                                                   \
    } while (0)

    CLEAR_ADDR(&p->src);
    CLEAR_ADDR(&p->dst);
    p->sp = 0;
    p->dp = 0;
    p->proto = 0;
    p->recursion_level = 0;
    PACKET_FREE_EXTDATA(p);
    p->flags = 0;
    p->flowflags = 0;
    p->pkt_src = 0;
    p->vlan_id[0] = 0;
    p->vlan_id[1] = 0;
    p->vlan_idx = 0;
    p->ts.tv_sec = 0;
    p->ts.tv_usec = 0;
    p->datalink = 0;
    p->drop_reason = 0;
#define PACKET_RESET_ACTION(p) (p)->action = 0
    PACKET_RESET_ACTION(p);
    if (p->pktvar != NULL) {
        PktVarFree(p->pktvar);
        p->pktvar = NULL;
    }
    p->ethh = NULL;
    if (p->ip4h != NULL) {
        CLEAR_IPV4_PACKET(p);
    }
    if (p->ip6h != NULL) {
        CLEAR_IPV6_PACKET(p);
    }
    if (p->tcph != NULL) {
        CLEAR_TCP_PACKET(p);
    }
    if (p->udph != NULL) {
        CLEAR_UDP_PACKET(p);
    }
    if (p->sctph != NULL) {
        CLEAR_SCTP_PACKET(p);
    }
    if (p->esph != NULL) {
        CLEAR_ESP_PACKET(p);
    }
    if (p->icmpv4h != NULL) {
        CLEAR_ICMPV4_PACKET(p);
    }
    if (p->icmpv6h != NULL) {
        CLEAR_ICMPV6_PACKET(p);
    }
    p->ppph = NULL;
    p->pppoesh = NULL;
    p->pppoedh = NULL;
    p->greh = NULL;
    p->payload = NULL;
    p->payload_len = 0;
    p->BypassPacketsFlow = NULL;
#define RESET_PKT_LEN(p) ((p)->pktlen = 0)
    RESET_PKT_LEN(p);
    p->alerts.cnt = 0;
    p->alerts.discarded = 0;
    p->alerts.suppressed = 0;
    p->alerts.drop.action = 0;
    p->pcap_cnt = 0;
    p->tunnel_rtv_cnt = 0;
    p->tunnel_tpr_cnt = 0;
    p->events.cnt = 0;
    AppLayerDecoderEventsResetEvents(p->app_layer_events);
    p->next = NULL;
    p->prev = NULL;
    p->root = NULL;
    p->livedev = NULL;
    PACKET_RESET_CHECKSUMS(p);
    PACKET_PROFILING_RESET(p);
    p->tenant_id = 0;
    p->nb_decoded_layers = 0;
}

void PacketRecycle(Packet *p)
{
    PacketReleaseRefs(p);
    PacketReinit(p);
}

/**
 *  \brief Cleanup a packet so that we can free it. No memset needed..
 */
void PacketDestructor(Packet *p)
{
    PacketReleaseRefs(p);
    if (p->pktvar != NULL) {
        PktVarFree(p->pktvar);
    }
    PacketAlertFree(p->alerts.alerts);
    PACKET_FREE_EXTDATA(p);
    SCMutexDestroy(&p->tunnel_mutex);
    AppLayerDecoderEventsFreeEvents(&p->app_layer_events);
    PACKET_PROFILING_RESET(p);
}
