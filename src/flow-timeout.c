/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-parser.h"
#include "app-layer.h"

#include "util-profiling.h"

static TmSlot *stream_pseudo_pkt_stream_tm_slot = NULL;
static ThreadVars *stream_pseudo_pkt_stream_TV = NULL;

static TmSlot *stream_pseudo_pkt_detect_tm_slot = NULL;
static ThreadVars *stream_pseudo_pkt_detect_TV = NULL;
static ThreadVars *stream_pseudo_pkt_detect_prev_TV = NULL;

static TmSlot *stream_pseudo_pkt_decode_tm_slot = NULL;
static ThreadVars *stream_pseudo_pkt_decode_TV = NULL;

/**
 * \internal
 * \brief Flush out if we have any unattended packets.
 */
static inline void FlowForceReassemblyFlushPendingPseudoPackets(void)
{
    /* we don't lock the queue, since flow manager is dead */
    if (stream_pseudo_pkt_decode_tm_slot->slot_post_pq.len == 0)
        return;

    SCMutexLock(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq.mutex_q);
    Packet *p = PacketDequeue(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq);
    SCMutexUnlock(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq.mutex_q);
    if (TmThreadsSlotProcessPkt(stream_pseudo_pkt_decode_TV,
                                stream_pseudo_pkt_decode_tm_slot,
                                p) != TM_ECODE_OK) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "Received error from FFR on "
                   "flushing packets through decode->.. TMs");
    }

    return;
}

/**
 * \internal
 * \brief Pseudo packet setup for flow forced reassembly.
 *
 * \param direction Direction of the packet.  0 indicates toserver and 1
 *                  indicates toclient.
 * \param f         Pointer to the flow.
 * \param ssn       Pointer to the tcp session.
 * \param dummy     Indicates to create a dummy pseudo packet.  Not all pseudo
 *                  packets need to force reassembly, in which case we just
 *                  set dummy ack/seq values.
 */
static inline Packet *FlowForceReassemblyPseudoPacketSetup(Packet *p,
                                                           int direction,
                                                           Flow *f,
                                                           TcpSession *ssn,
                                                           int dummy)
{
    p->datalink = DLT_RAW;
    p->proto = IPPROTO_TCP;
    FlowReference(&p->flow, f);
    p->flags |= PKT_STREAM_EST;
    p->flags |= PKT_STREAM_EOF;
    p->flags |= PKT_HAS_FLOW;
    p->flags |= PKT_PSEUDO_STREAM_END;
    if (direction == 0)
        p->flowflags |= FLOW_PKT_TOSERVER;
    else
        p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->payload = NULL;
    p->payload_len = 0;

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

        /* set the ip header */
        p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
        /* version 4 and length 20 bytes for the tcp header */
        p->ip4h->ip_verhl = 0x45;
        p->ip4h->ip_tos = 0;
        p->ip4h->ip_len = htons(40);
        p->ip4h->ip_id = 0;
        p->ip4h->ip_off = 0;
        p->ip4h->ip_ttl = 64;
        p->ip4h->ip_proto = IPPROTO_TCP;
        //p->ip4h->ip_csum =
        if (direction == 0) {
            p->ip4h->s_ip_src.s_addr = f->src.addr_data32[0];
            p->ip4h->s_ip_dst.s_addr = f->dst.addr_data32[0];
        } else {
            p->ip4h->s_ip_src.s_addr = f->dst.addr_data32[0];
            p->ip4h->s_ip_dst.s_addr = f->src.addr_data32[0];
        }

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 20);

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

        /* set the ip header */
        p->ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
        /* version 6 */
        p->ip6h->s_ip6_vfc = 0x60;
        p->ip6h->s_ip6_flow = 0;
        p->ip6h->s_ip6_nxt = IPPROTO_TCP;
        p->ip6h->s_ip6_plen = htons(20);
        p->ip6h->s_ip6_hlim = 64;
        if (direction == 0) {
            p->ip6h->s_ip6_src[0] = f->src.addr_data32[0];
            p->ip6h->s_ip6_src[1] = f->src.addr_data32[1];
            p->ip6h->s_ip6_src[2] = f->src.addr_data32[2];
            p->ip6h->s_ip6_src[3] = f->src.addr_data32[3];
            p->ip6h->s_ip6_dst[0] = f->dst.addr_data32[0];
            p->ip6h->s_ip6_dst[1] = f->dst.addr_data32[1];
            p->ip6h->s_ip6_dst[2] = f->dst.addr_data32[2];
            p->ip6h->s_ip6_dst[3] = f->dst.addr_data32[3];
        } else {
            p->ip6h->s_ip6_src[0] = f->dst.addr_data32[0];
            p->ip6h->s_ip6_src[1] = f->dst.addr_data32[1];
            p->ip6h->s_ip6_src[2] = f->dst.addr_data32[2];
            p->ip6h->s_ip6_src[3] = f->dst.addr_data32[3];
            p->ip6h->s_ip6_dst[0] = f->src.addr_data32[0];
            p->ip6h->s_ip6_dst[1] = f->src.addr_data32[1];
            p->ip6h->s_ip6_dst[2] = f->src.addr_data32[2];
            p->ip6h->s_ip6_dst[3] = f->src.addr_data32[3];
        }

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 40);

        SET_PKT_LEN(p, 60); /* ipv6 hdr + tcp hdr */
    }

    p->tcph->th_offx2 = 0x50;
    p->tcph->th_flags |= TH_ACK;
    p->tcph->th_win = 10;
    p->tcph->th_urp = 0;

    /* to server */
    if (direction == 0) {
        p->tcph->th_sport = htons(f->sp);
        p->tcph->th_dport = htons(f->dp);

        if (dummy) {
            p->tcph->th_seq = htonl(ssn->client.next_seq);
            p->tcph->th_ack = htonl(ssn->server.last_ack);
        } else {
            p->tcph->th_seq = htonl(ssn->client.next_seq);
            p->tcph->th_ack = htonl(ssn->server.seg_list_tail->seq +
                                    ssn->server.seg_list_tail->payload_len);
        }

        /* to client */
    } else {
        p->tcph->th_sport = htons(f->dp);
        p->tcph->th_dport = htons(f->sp);

        if (dummy) {
            p->tcph->th_seq = htonl(ssn->server.next_seq);
            p->tcph->th_ack = htonl(ssn->client.last_ack);
        } else {
            p->tcph->th_seq = htonl(ssn->server.next_seq);
            p->tcph->th_ack = htonl(ssn->client.seg_list_tail->seq +
                                    ssn->client.seg_list_tail->payload_len);
        }
    }

    if (FLOW_IS_IPV4(f)) {
        p->tcph->th_sum = TCPCalculateChecksum(p->ip4h->s_ip_addrs,
                                               (uint16_t *)p->tcph, 20);
        /* calc ipv4 csum as we may log it and barnyard might reject
         * a wrong checksum */
        p->ip4h->ip_csum = IPV4CalculateChecksum((uint16_t *)p->ip4h,
                IPV4_GET_RAW_HLEN(p->ip4h));
    } else if (FLOW_IS_IPV6(f)) {
        p->tcph->th_sum = TCPCalculateChecksum(p->ip6h->s_ip6_addrs,
                                               (uint16_t *)p->tcph, 20);
    }

    memset(&p->ts, 0, sizeof(struct timeval));
    TimeGet(&p->ts);

    AppLayerParserSetEOF(f->alparser);

    return p;
}

static inline Packet *FlowForceReassemblyPseudoPacketGet(int direction,
                                                         Flow *f,
                                                         TcpSession *ssn,
                                                         int dummy)
{
    Packet *p;

    p = PacketGetFromAlloc();
    if (p == NULL)
        return NULL;

    return FlowForceReassemblyPseudoPacketSetup(p, direction, f, ssn, dummy);
}

/**
 *  \brief Check if a flow needs forced reassembly, or any other processing
 *
 *  \param f *LOCKED* flow
 *  \param server ptr to int that should be set to 1 or 2 if we return 1
 *  \param client ptr to int that should be set to 1 or 2 if we return 1
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int FlowForceReassemblyNeedReassembly(Flow *f, int *server, int *client)
{
    TcpSession *ssn;

    if (f == NULL) {
        *server = *client = STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
        SCReturnInt(0);
    }

    /* Get the tcp session for the flow */
    ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL) {
        *server = *client = STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
        SCReturnInt(0);
    }

    *client = StreamNeedsReassembly(ssn, 0);
    *server = StreamNeedsReassembly(ssn, 1);

    /* if state is not fully closed we assume that we haven't fully
     * inspected the app layer state yet */
    if (ssn->state >= TCP_ESTABLISHED && ssn->state != TCP_CLOSED)
    {
        if (*client != STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY)
            *client = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;

        if (*server != STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY)
            *server = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }

    /* if app layer still needs some love, push through */
    if (f->alproto != ALPROTO_UNKNOWN && f->alstate != NULL &&
        AppLayerParserProtocolSupportsTxs(f->proto, f->alproto))
    {
        uint64_t total_txs = AppLayerParserGetTxCnt(f->proto, f->alproto, f->alstate);

        if (AppLayerParserGetTransactionActive(f->proto, f->alproto,
                                               f->alparser, STREAM_TOCLIENT) < total_txs)
        {
            if (*server != STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY)
                *server = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
        if (AppLayerParserGetTransactionActive(f->proto, f->alproto,
                                               f->alparser, STREAM_TOSERVER) < total_txs)
        {
            if (*client != STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY)
                *client = STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        }
    }

    /* nothing to do */
    if (*client == STREAM_HAS_UNPROCESSED_SEGMENTS_NONE &&
        *server == STREAM_HAS_UNPROCESSED_SEGMENTS_NONE) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

/**
 * \internal
 * \brief Forces reassembly for flow if it needs it.
 *
 *        The function requires flow to be locked beforehand.
 *
 * \param f Pointer to the flow.
 * \param server action required for server: 1 or 2
 * \param client action required for client: 1 or 2
 *
 * \retval 0 This flow doesn't need any reassembly processing; 1 otherwise.
 */
int FlowForceReassemblyForFlowV2(Flow *f, int server, int client)
{
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    TcpSession *ssn;

    /* looks like we have no flows in this queue */
    if (f == NULL) {
        return 0;
    }

    /* Get the tcp session for the flow */
    ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL) {
        return 0;
    }

    /* The packets we use are based on what segments in what direction are
     * unprocessed.
     * p1 if we have client segments for reassembly purpose only.  If we
     * have no server segments p2 can be a toserver packet with dummy
     * seq/ack, and if we have server segments p2 has to carry out reassembly
     * for server segment as well, in which case we will also need a p3 in the
     * toclient which is now dummy since all we need it for is detection */

    /* insert a pseudo packet in the toserver direction */
    if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
        p1 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 0);
        if (p1 == NULL) {
            goto done;
        }
        PKT_SET_SRC(p1, PKT_SRC_FFR_V2);

        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
            p2 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 0);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                goto done;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR_V2);

            p3 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
            if (p3 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                FlowDeReference(&p2->flow);
                TmqhOutputPacketpool(NULL, p2);
                goto done;
            }
            PKT_SET_SRC(p3, PKT_SRC_FFR_V2);
        } else {
            p2 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 1);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                goto done;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR_V2);
        }

    } else if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
            p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 0);
            if (p1 == NULL) {
                goto done;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR_V2);

            p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                goto done;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR_V2);
        } else {
            p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 1);
            if (p1 == NULL) {
                goto done;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR_V2);

            if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
                p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
                if (p2 == NULL) {
                    FlowDeReference(&p1->flow);
                    TmqhOutputPacketpool(NULL, p1);
                    goto done;
                }
                PKT_SET_SRC(p2, PKT_SRC_FFR_V2);
            }
        }

    } else {
        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
            p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 0);
            if (p1 == NULL) {
                goto done;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR_V2);

            p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                goto done;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR_V2);
        } else if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
            p1 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
            if (p1 == NULL) {
                goto done;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR_V2);
        } else {
            /* impossible */
            BUG_ON(1);
        }
    }

    /* inject the packet(s) into the appropriate thread */
    int thread_id = (int)f->thread_id;
    Packet *packets[4] = { p1, p2 ? p2 : p3, p2 ? p3 : NULL, NULL }; /**< null terminated array of packets */
    if (unlikely(!(TmThreadsInjectPacketsById(packets, thread_id)))) {
        FlowDeReference(&p1->flow);
        TmqhOutputPacketpool(NULL, p1);
        if (p2) {
            FlowDeReference(&p2->flow);
            TmqhOutputPacketpool(NULL, p2);
        }
        if (p3) {
            FlowDeReference(&p3->flow);
            TmqhOutputPacketpool(NULL, p3);
        }
    }

    /* done, in case of error (no packet) we still tag flow as complete
     * as we're probably resource stress if we couldn't get packets */
done:
    f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;
    return 1;
}

/**
 * \internal
 * \brief Forces reassembly for flows that need it.
 *
 * When this function is called we're running in virtually dead engine,
 * so locking the flows is not strictly required. The reasons it is still
 * done are:
 * - code consistency
 * - silence complaining profilers
 * - allow us to aggressively check using debug valdation assertions
 * - be robust in case of future changes
 * - locking overhead if neglectable when no other thread fights us
 *
 * \param q The queue to process flows from.
 */
static inline void FlowForceReassemblyForHash(void)
{
    Flow *f;
    TcpSession *ssn;
    int client_ok;
    int server_ok;

    uint32_t idx = 0;

    /* We use this packet just for reassembly purpose */
    Packet *reassemble_p = PacketGetFromAlloc();
    if (reassemble_p == NULL)
        return;

    for (idx = 0; idx < flow_config.hash_size; idx++) {
        FlowBucket *fb = &flow_hash[idx];

        FBLOCK_LOCK(fb);

        /* get the topmost flow from the QUEUE */
        f = fb->head;

        /* we need to loop through all the flows in the queue */
        while (f != NULL) {
            PACKET_RECYCLE(reassemble_p);

            FLOWLOCK_WRLOCK(f);

            /* Get the tcp session for the flow */
            ssn = (TcpSession *)f->protoctx;

            /* \todo Also skip flows that shouldn't be inspected */
            if (ssn == NULL) {
                FLOWLOCK_UNLOCK(f);
                f = f->hnext;
                continue;
            }

            (void)FlowForceReassemblyNeedReassembly(f, &server_ok, &client_ok);

            /* ah ah!  We have some unattended toserver segments */
            if (client_ok == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
                StreamTcpThread *stt = SC_ATOMIC_GET(stream_pseudo_pkt_stream_tm_slot->slot_data);

                ssn->client.last_ack = (ssn->client.seg_list_tail->seq +
                        ssn->client.seg_list_tail->payload_len);

                FlowForceReassemblyPseudoPacketSetup(reassemble_p, 1, f, ssn, 1);
                StreamTcpReassembleHandleSegment(stream_pseudo_pkt_stream_TV,
                        stt->ra_ctx, ssn, &ssn->server,
                        reassemble_p, NULL);
                FlowDeReference(&reassemble_p->flow);
            }
            /* oh oh!  We have some unattended toclient segments */
            if (server_ok == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY) {
                StreamTcpThread *stt = SC_ATOMIC_GET(stream_pseudo_pkt_stream_tm_slot->slot_data);

                ssn->server.last_ack = (ssn->server.seg_list_tail->seq +
                        ssn->server.seg_list_tail->payload_len);

                FlowForceReassemblyPseudoPacketSetup(reassemble_p, 0, f, ssn, 1);
                StreamTcpReassembleHandleSegment(stream_pseudo_pkt_stream_TV,
                        stt->ra_ctx, ssn, &ssn->client,
                        reassemble_p, NULL);
                FlowDeReference(&reassemble_p->flow);
            }

            FLOWLOCK_UNLOCK(f);

            /* insert a pseudo packet in the toserver direction */
            if (client_ok) {
                FLOWLOCK_WRLOCK(f);
                Packet *p = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 1);
                FLOWLOCK_UNLOCK(f);

                if (p == NULL) {
                    TmqhOutputPacketpool(NULL, reassemble_p);
                    FBLOCK_UNLOCK(fb);
                    return;
                }
                PKT_SET_SRC(p, PKT_SRC_FFR_SHUTDOWN);

                if (stream_pseudo_pkt_detect_prev_TV != NULL) {
                    stream_pseudo_pkt_detect_prev_TV->
                        tmqh_out(stream_pseudo_pkt_detect_prev_TV, p);
                } else {
                    TmSlot *s = stream_pseudo_pkt_detect_tm_slot;
                    while (s != NULL) {
                        TmSlotFunc SlotFunc = SC_ATOMIC_GET(s->SlotFunc);
                        SlotFunc(NULL, p, SC_ATOMIC_GET(s->slot_data), &s->slot_pre_pq,
                                    &s->slot_post_pq);
                        s = s->slot_next;
                    }

                    if (stream_pseudo_pkt_detect_TV != NULL) {
                        stream_pseudo_pkt_detect_TV->
                            tmqh_out(stream_pseudo_pkt_detect_TV, p);
                    } else {
                        TmqhOutputPacketpool(NULL, p);
                    }
                }
            }
            if (server_ok) {
                FLOWLOCK_WRLOCK(f);
                Packet *p = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
                FLOWLOCK_UNLOCK(f);

                if (p == NULL) {
                    TmqhOutputPacketpool(NULL, reassemble_p);
                    FBLOCK_UNLOCK(fb);
                    return;
                }
                PKT_SET_SRC(p, PKT_SRC_FFR_SHUTDOWN);

                if (stream_pseudo_pkt_detect_prev_TV != NULL) {
                    stream_pseudo_pkt_detect_prev_TV->
                        tmqh_out(stream_pseudo_pkt_detect_prev_TV, p);
                } else {
                    TmSlot *s = stream_pseudo_pkt_detect_tm_slot;
                    while (s != NULL) {
                        TmSlotFunc SlotFunc = SC_ATOMIC_GET(s->SlotFunc);
                        SlotFunc(NULL, p, SC_ATOMIC_GET(s->slot_data), &s->slot_pre_pq,
                                    &s->slot_post_pq);
                        s = s->slot_next;
                    }

                    if (stream_pseudo_pkt_detect_TV != NULL) {
                        stream_pseudo_pkt_detect_TV->
                            tmqh_out(stream_pseudo_pkt_detect_TV, p);
                    } else {
                        TmqhOutputPacketpool(NULL, p);
                    }
                }
            }

            /* next flow in the queue */
            f = f->hnext;
        }
        FBLOCK_UNLOCK(fb);
    }

    PKT_SET_SRC(reassemble_p, PKT_SRC_FFR_SHUTDOWN);
    TmqhOutputPacketpool(NULL, reassemble_p);
    return;
}

/**
 * \brief Force reassembly for all the flows that have unprocessed segments.
 */
void FlowForceReassembly(void)
{
    /* Do remember.  We need to have packet acquire disabled by now */

    /** ----- Part 1 ------*/
    /* Flush out unattended packets */
    FlowForceReassemblyFlushPendingPseudoPackets();

    /** ----- Part 2 ----- **/
    /* Check if all threads are idle.  We need this so that we have all
     * packets freeds.  As a consequence, no flows are in use */

    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    ThreadVars *tv = tv_root[TVT_PPT];

    /* we are doing this in order receive -> decode -> ... -> log */
    while (tv != NULL) {
        if (tv->inq != NULL) {
            /* we wait till we dry out all the inq packets, before we
             * kill this thread.  Do note that you should have disabled
             * packet acquire by now using TmThreadDisableReceiveThreads()*/
            if (!(strlen(tv->inq->name) == strlen("packetpool") &&
                  strcasecmp(tv->inq->name, "packetpool") == 0)) {
                PacketQueue *q = &trans_q[tv->inq->id];
                while (q->len != 0) {
                    usleep(100);
                }
                TmThreadsSetFlag(tv, THV_PAUSE);
                if (tv->inq->q_type == 0)
                    SCCondSignal(&trans_q[tv->inq->id].cond_q);
                else
                    SCCondSignal(&data_queues[tv->inq->id].cond_q);
                while (!TmThreadsCheckFlag(tv, THV_PAUSED)) {
                    if (tv->inq->q_type == 0)
                        SCCondSignal(&trans_q[tv->inq->id].cond_q);
                    else
                        SCCondSignal(&data_queues[tv->inq->id].cond_q);
                    usleep(100);
                }
                TmThreadsUnsetFlag(tv, THV_PAUSE);
            }
        }
        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);

    /** ----- Part 3 ----- **/
    /* Carry out flow reassembly for unattended flows */
    FlowForceReassemblyForHash();

    return;
}

/**
 *  \param detect_disabled bool, indicating if we use a detection engine (true)
 */
void FlowForceReassemblySetup(int detect_disabled)
{
    /* get StreamTCP TM's slot and TV containing this slot */
    stream_pseudo_pkt_stream_tm_slot = TmSlotGetSlotForTM(TMM_STREAMTCP);
    if (stream_pseudo_pkt_stream_tm_slot == NULL) {
        /* yes, this is fatal! */
        SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                   "retrieve the slot for STREAMTCP TM");
        exit(EXIT_FAILURE);
    }
    stream_pseudo_pkt_stream_TV =
        TmThreadsGetTVContainingSlot(stream_pseudo_pkt_stream_tm_slot);
    if (stream_pseudo_pkt_stream_TV == NULL) {
        /* yes, this is fatal! */
        SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                   "retrieve the TV containing STREAMTCP TM slot");
        exit(EXIT_FAILURE);
    }

    if (!detect_disabled) {
        /* get detect TM's slot and TV containing this slot */
        stream_pseudo_pkt_detect_tm_slot = TmSlotGetSlotForTM(TMM_DETECT);
        if (stream_pseudo_pkt_detect_tm_slot == NULL) {
            /* yes, this is fatal! */
            SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                    "retrieve a slot for DETECT TM");
            exit(EXIT_FAILURE);
        }
        stream_pseudo_pkt_detect_TV =
            TmThreadsGetTVContainingSlot(stream_pseudo_pkt_detect_tm_slot);
        if (stream_pseudo_pkt_detect_TV == NULL) {
            /* yes, this is fatal! */
            SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                    "retrieve the TV containing the Detect TM slot");
            exit(EXIT_FAILURE);
        }
        if (stream_pseudo_pkt_detect_TV->tm_slots == stream_pseudo_pkt_detect_tm_slot) {
            stream_pseudo_pkt_detect_prev_TV = stream_pseudo_pkt_detect_TV->prev;
        }
        if (strcasecmp(stream_pseudo_pkt_detect_TV->outqh_name, "packetpool") == 0) {
            stream_pseudo_pkt_detect_TV = NULL;
        }
    }

    SCMutexLock(&tv_root_lock);
    ThreadVars *tv = tv_root[TVT_PPT];
    int done = 0;
    while (tv) {
        TmSlot *slots = tv->tm_slots;
        while (slots) {
            TmModule *tm = TmModuleGetById(slots->tm_id);
            if (tm->flags & TM_FLAG_DECODE_TM) {
                done = 1;
                stream_pseudo_pkt_decode_tm_slot = slots;
                break;
            }
            slots = slots->slot_next;
        }
        if (done)
            break;
        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);

    if (stream_pseudo_pkt_decode_tm_slot == NULL) {
        /* yes, this is fatal! */
        SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                   "retrieve the slot for DECODE TM");
        exit(EXIT_FAILURE);
    }
    stream_pseudo_pkt_decode_TV =
        TmThreadsGetTVContainingSlot(stream_pseudo_pkt_decode_tm_slot);
    if (stream_pseudo_pkt_decode_TV == NULL) {
        /* yes, this is fatal! */
        SCLogError(SC_ERR_TM_MODULES_ERROR, "Looks like we have failed to "
                   "retrieve the TV containing the Decode TM slot");
        exit(EXIT_FAILURE);
    }

    return;
}
