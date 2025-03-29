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
#include "action-globals.h"
#include "app-layer-events.h"

/** \brief issue drop action
 *
 *  Set drop (+reject) flags in both current and root packet.
 *
 *  \param action action bit flags. Must be limited to ACTION_DROP_REJECT|ACTION_ALERT
 */
void PacketDrop(Packet *p, const uint8_t action, enum PacketDropReason r)
{
    DEBUG_VALIDATE_BUG_ON((action & ~(ACTION_DROP_REJECT | ACTION_ALERT)) != 0);

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
    SCSpinInit(&p->persistent.tunnel_lock, 0);
    p->alerts.alerts = PacketAlertCreate();
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
    p->app_update_direction = 0;
    p->flags = 0;
    p->flowflags = 0;
    p->pkt_src = 0;
    p->vlan_id[0] = 0;
    p->vlan_id[1] = 0;
    p->vlan_idx = 0;
    p->ttype = PacketTunnelNone;
    SCTIME_INIT(p->ts);
    p->datalink = 0;
    p->drop_reason = 0;
#define PACKET_RESET_ACTION(p) (p)->action = 0
    PACKET_RESET_ACTION(p);
    if (p->pktvar != NULL) {
        PktVarFree(p->pktvar);
        p->pktvar = NULL;
    }
    PacketClearL2(p);
    PacketClearL3(p);
    PacketClearL4(p);
    p->payload = NULL;
    p->payload_len = 0;
    p->BypassPacketsFlow = NULL;
#define RESET_PKT_LEN(p) ((p)->pktlen = 0)
    RESET_PKT_LEN(p);
    p->alerts.cnt = 0;
    p->alerts.discarded = 0;
    p->alerts.suppressed = 0;
    p->alerts.drop.action = 0;
    PacketAlertRecycle(p->alerts.alerts);
    p->pcap_cnt = 0;
    p->tunnel_rtv_cnt = 0;
    p->tunnel_tpr_cnt = 0;
    p->events.cnt = 0;
    AppLayerDecoderEventsResetEvents(p->app_layer_events);
    p->next = NULL;
    p->prev = NULL;
    p->tunnel_verdicted = false;
    p->root = NULL;
    p->livedev = NULL;
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
    SCSpinDestroy(&p->persistent.tunnel_lock);
    AppLayerDecoderEventsFreeEvents(&p->app_layer_events);
    PACKET_PROFILING_RESET(p);
}
