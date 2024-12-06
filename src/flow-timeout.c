/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "conf.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "runmodes.h"

#include "util-random.h"
#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"
#include "flow-manager.h"
#include "flow-timeout.h"
#include "pkt-var.h"
#include "host.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

#include "util-debug.h"
#include "util-privs.h"
#include "util-datalink.h"

#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-frames.h"
#include "app-layer-parser.h"
#include "app-layer.h"

#include "util-profiling.h"

/**
 * \internal
 * \brief Pseudo packet setup to finish a flow when needed.
 *
 * \param p         a dummy pseudo packet from packet pool.  Not all pseudo
 *                  packets need to force reassembly, in which case we just
 *                  set dummy ack/seq values.
 * \param direction Direction of the packet.  0 indicates toserver and 1
 *                  indicates toclient.
 * \param f         Pointer to the flow.
 * \param ssn       Pointer to the tcp session.
 * \retval          pseudo packet with everything set up
 */
static inline Packet *FlowPseudoPacketSetup(
        Packet *p, int direction, Flow *f, const TcpSession *ssn)
{
    const int orig_dir = direction;
    p->tenant_id = f->tenant_id;
    p->datalink = DatalinkGetGlobalType();
    p->proto = IPPROTO_TCP;
    FlowReference(&p->flow, f);
    p->flags |= PKT_STREAM_EST;
    p->flags |= PKT_STREAM_EOF;
    p->flags |= PKT_HAS_FLOW;
    p->flags |= PKT_PSEUDO_STREAM_END;
    memcpy(&p->vlan_id[0], &f->vlan_id[0], sizeof(p->vlan_id));
    p->vlan_idx = f->vlan_idx;
    p->livedev = (struct LiveDevice_ *)f->livedev;

    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        DecodeSetNoPacketInspectionFlag(p);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        DecodeSetNoPayloadInspectionFlag(p);
    }

    if (direction == 0)
        p->flowflags |= FLOW_PKT_TOSERVER;
    else
        p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->payload = NULL;
    p->payload_len = 0;

    /* apply reversed flow logic after setting direction to the packet */
    direction ^= ((f->flags & FLOW_DIR_REVERSED) != 0);

    if (FLOW_IS_IPV4(f)) {
        if (direction == 0) {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &p->src);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &p->dst);
            p->sp = f->sp;
            p->dp = f->dp;
        } else {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &p->dst);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &p->src);
            p->sp = f->dp;
            p->dp = f->sp;
        }

        /* Check if we have enough room in direct data. We need ipv4 hdr + tcp hdr.
         * Force an allocation if it is not the case.
         */
        if (GET_PKT_DIRECT_MAX_SIZE(p) <  40) {
            if (PacketCallocExtPkt(p, 40) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        IPV4Hdr *ip4h = PacketSetIPV4(p, GET_PKT_DATA(p));
        /* version 4 and length 20 bytes for the tcp header */
        ip4h->ip_verhl = 0x45;
        ip4h->ip_tos = 0;
        ip4h->ip_len = htons(40);
        ip4h->ip_id = 0;
        ip4h->ip_off = 0;
        ip4h->ip_ttl = 64;
        ip4h->ip_proto = IPPROTO_TCP;
        //p->ip4h->ip_csum =
        if (direction == 0) {
            ip4h->s_ip_src.s_addr = f->src.addr_data32[0];
            ip4h->s_ip_dst.s_addr = f->dst.addr_data32[0];
        } else {
            ip4h->s_ip_src.s_addr = f->dst.addr_data32[0];
            ip4h->s_ip_dst.s_addr = f->src.addr_data32[0];
        }

        /* set the tcp header */
        PacketSetTCP(p, GET_PKT_DATA(p) + 20);

        SET_PKT_LEN(p, 40); /* ipv4 hdr + tcp hdr */

    } else if (FLOW_IS_IPV6(f)) {
        if (direction == 0) {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &p->src);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &p->dst);
            p->sp = f->sp;
            p->dp = f->dp;
        } else {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &p->dst);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &p->src);
            p->sp = f->dp;
            p->dp = f->sp;
        }

        /* Check if we have enough room in direct data. We need ipv6 hdr + tcp hdr.
         * Force an allocation if it is not the case.
         */
        if (GET_PKT_DIRECT_MAX_SIZE(p) <  60) {
            if (PacketCallocExtPkt(p, 60) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        IPV6Hdr *ip6h = PacketSetIPV6(p, GET_PKT_DATA(p));
        /* version 6 */
        ip6h->s_ip6_vfc = 0x60;
        ip6h->s_ip6_flow = 0;
        ip6h->s_ip6_nxt = IPPROTO_TCP;
        ip6h->s_ip6_plen = htons(20);
        ip6h->s_ip6_hlim = 64;
        if (direction == 0) {
            ip6h->s_ip6_src[0] = f->src.addr_data32[0];
            ip6h->s_ip6_src[1] = f->src.addr_data32[1];
            ip6h->s_ip6_src[2] = f->src.addr_data32[2];
            ip6h->s_ip6_src[3] = f->src.addr_data32[3];
            ip6h->s_ip6_dst[0] = f->dst.addr_data32[0];
            ip6h->s_ip6_dst[1] = f->dst.addr_data32[1];
            ip6h->s_ip6_dst[2] = f->dst.addr_data32[2];
            ip6h->s_ip6_dst[3] = f->dst.addr_data32[3];
        } else {
            ip6h->s_ip6_src[0] = f->dst.addr_data32[0];
            ip6h->s_ip6_src[1] = f->dst.addr_data32[1];
            ip6h->s_ip6_src[2] = f->dst.addr_data32[2];
            ip6h->s_ip6_src[3] = f->dst.addr_data32[3];
            ip6h->s_ip6_dst[0] = f->src.addr_data32[0];
            ip6h->s_ip6_dst[1] = f->src.addr_data32[1];
            ip6h->s_ip6_dst[2] = f->src.addr_data32[2];
            ip6h->s_ip6_dst[3] = f->src.addr_data32[3];
        }

        /* set the tcp header */
        PacketSetTCP(p, GET_PKT_DATA(p) + 40);

        SET_PKT_LEN(p, 60); /* ipv6 hdr + tcp hdr */
    }

    p->l4.hdrs.tcph->th_offx2 = 0x50;
    p->l4.hdrs.tcph->th_flags = 0;
    p->l4.hdrs.tcph->th_win = 10;
    p->l4.hdrs.tcph->th_urp = 0;

    /* to server */
    if (orig_dir == 0) {
        p->l4.hdrs.tcph->th_sport = htons(f->sp);
        p->l4.hdrs.tcph->th_dport = htons(f->dp);

        p->l4.hdrs.tcph->th_seq = htonl(ssn->client.next_seq);
        p->l4.hdrs.tcph->th_ack = 0;

        /* to client */
    } else {
        p->l4.hdrs.tcph->th_sport = htons(f->dp);
        p->l4.hdrs.tcph->th_dport = htons(f->sp);

        p->l4.hdrs.tcph->th_seq = htonl(ssn->server.next_seq);
        p->l4.hdrs.tcph->th_ack = 0;
    }

    if (FLOW_IS_IPV4(f)) {
        IPV4Hdr *ip4h = p->l3.hdrs.ip4h;
        p->l4.hdrs.tcph->th_sum = TCPChecksum(ip4h->s_ip_addrs, (uint16_t *)p->l4.hdrs.tcph, 20, 0);
        /* calc ipv4 csum as we may log it and barnyard might reject
         * a wrong checksum */
        ip4h->ip_csum = IPV4Checksum((uint16_t *)ip4h, IPV4_GET_RAW_HLEN(ip4h), 0);
    } else if (FLOW_IS_IPV6(f)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        p->l4.hdrs.tcph->th_sum =
                TCPChecksum(ip6h->s_ip6_addrs, (uint16_t *)p->l4.hdrs.tcph, 20, 0);
    }

    p->ts = TimeGet();

    if (direction == 0) {
        if (f->alparser && !STREAM_HAS_SEEN_DATA(&ssn->client)) {
            AppLayerParserStateSetFlag(f->alparser, APP_LAYER_PARSER_EOF_TS);
        }
    } else {
        if (f->alparser && !STREAM_HAS_SEEN_DATA(&ssn->server)) {
            AppLayerParserStateSetFlag(f->alparser, APP_LAYER_PARSER_EOF_TC);
        }
    }

    return p;

error:
    FlowDeReference(&p->flow);
    return NULL;
}

Packet *FlowPseudoPacketGet(int direction, Flow *f, const TcpSession *ssn)
{
    PacketPoolWait();
    Packet *p = PacketPoolGetPacket();
    if (p == NULL) {
        return NULL;
    }

    PACKET_PROFILING_START(p);

    return FlowPseudoPacketSetup(p, direction, f, ssn);
}

/**
 *  \brief Check if a flow needs forced reassembly, or any other processing
 *
 *  \param f *LOCKED* flow
 *
 *  \retval false no
 *  \retval true yes
 */
bool FlowNeedsReassembly(Flow *f)
{
    if (f == NULL || f->protoctx == NULL) {
        return false;
    }

    TcpSession *ssn = (TcpSession *)f->protoctx;
    uint8_t client = StreamNeedsReassembly(ssn, STREAM_TOSERVER);
    uint8_t server = StreamNeedsReassembly(ssn, STREAM_TOCLIENT);

    /* if state is not fully closed we assume that we haven't fully
     * inspected the app layer state yet */
    if (ssn->state >= TCP_ESTABLISHED && ssn->state != TCP_CLOSED)
    {
        client = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        server = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }

    /* if app layer still needs some love, push through */
    if (f->alproto != ALPROTO_UNKNOWN && f->alstate != NULL) {
        const uint64_t total_txs = AppLayerParserGetTxCnt(f, f->alstate);

        if (AppLayerParserGetTransactionActive(f, f->alparser, STREAM_TOCLIENT) < total_txs)
        {
            server = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
        if (AppLayerParserGetTransactionActive(f, f->alparser, STREAM_TOSERVER) < total_txs)
        {
            client = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
    }

    /* if any frame is present we assume it still needs work */
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container) {
        if (frames_container->toserver.cnt)
            client = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        if (frames_container->toclient.cnt)
            server = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }

    /* nothing to do */
    if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NONE &&
        server == STREAM_HAS_UNPROCESSED_SEGMENTS_NONE) {
        return false;
    }

    f->ffr_ts = client;
    f->ffr_tc = server;
    return true;
}

/**
 * \internal
 * \brief Sends the flow to its respective thread's flow queue.
 *
 *        The function requires flow to be locked beforehand.
 *
 * Normally, the first thread_id value should be used. This is when the flow is
 * created on seeing the first packet to the server; when the flow's reversed
 * flag is set, choose the second thread_id (to client/source).
 *
 * \param f Pointer to the flow.
 */
void FlowSendToLocalThread(Flow *f)
{
    // Choose the thread_id based on whether the flow has been
    // reversed.
    int idx = f->flags & FLOW_DIR_REVERSED ? 1 : 0;
    TmThreadsInjectFlowById(f, (const int)f->thread_id[idx]);
}

/**
 * \internal
 * \brief Remove flows from the hash bucket as they have more work to be done in
 *        in the detection engine.
 *
 * When this function is called we're running in virtually dead engine,
 * so locking the flows is not strictly required. The reasons it is still
 * done are:
 * - code consistency
 * - silence complaining profilers
 * - allow us to aggressively check using debug validation assertions
 * - be robust in case of future changes
 * - locking overhead is negligible when no other thread fights us
 */
static inline void FlowRemoveHash(void)
{
    for (uint32_t idx = 0; idx < flow_config.hash_size; idx++) {
        FlowBucket *fb = &flow_hash[idx];
        FBLOCK_LOCK(fb);

        Flow *f = fb->head;
        Flow *prev_f = NULL;

        /* we need to loop through all the flows in the queue */
        while (f != NULL) {
            Flow *next_f = f->next;

            FLOWLOCK_WRLOCK(f);

            /* Get the tcp session for the flow */
            TcpSession *ssn = (TcpSession *)f->protoctx;
            /* \todo Also skip flows that shouldn't be inspected */
            if (ssn == NULL) {
                FLOWLOCK_UNLOCK(f);
                prev_f = f;
                f = next_f;
                continue;
            }

            /* in case of additional work, we pull the flow out of the
             * hash and xfer ownership to the injected packet(s) */
            if (FlowNeedsReassembly(f)) {
                RemoveFromHash(f, prev_f);
                f->flow_end_flags |= FLOW_END_FLAG_SHUTDOWN;
                FlowSendToLocalThread(f);
                FLOWLOCK_UNLOCK(f);
                f = next_f;
                continue;
            }

            FLOWLOCK_UNLOCK(f);

            /* next flow in the queue */
            prev_f = f;
            f = f->next;
        }
        FBLOCK_UNLOCK(fb);
    }
}

/**
 * \brief Clean up all the flows that have unprocessed segments and have
 *        some work to do in the detection engine.
 */
void FlowWorkToDoCleanup(void)
{
    /* Carry out cleanup of unattended flows */
    FlowRemoveHash();
}
