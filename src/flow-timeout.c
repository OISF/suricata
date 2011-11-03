/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
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
    p->proto = IPPROTO_TCP;
    p->flow = f;
    FlowIncrUsecnt(f);
    p->flags |= PKT_STREAM_EST;
    p->flags |= PKT_STREAM_EOF;
    p->flags |= PKT_HAS_FLOW;
    p->flags |= PKT_PSEUDO_STREAM_END;
    if (direction == 0)
        p->flowflags |= FLOW_PKT_TOSERVER;
    else
        p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    if (direction == 0) {
        COPY_ADDRESS(&f->src, &p->src);
        COPY_ADDRESS(&f->dst, &p->dst);
        p->sp = f->sp;
        p->dp = f->dp;
    } else {
        COPY_ADDRESS(&f->src, &p->dst);
        COPY_ADDRESS(&f->dst, &p->src);
        p->sp = f->dp;
        p->dp = f->sp;
    }
    p->payload = NULL;
    p->payload_len = 0;
    if (f->src.family == AF_INET) {
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
            p->ip4h->ip_src.s_addr = f->src.addr_data32[0];
            p->ip4h->ip_dst.s_addr = f->dst.addr_data32[0];
        } else {
            p->ip4h->ip_src.s_addr = f->dst.addr_data32[0];
            p->ip4h->ip_dst.s_addr = f->src.addr_data32[0];
        }

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 20);

    } else {
        /* set the ip header */
        p->ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
        /* version 6 */
        p->ip6h->s_ip6_vfc = 0x60;
        p->ip6h->s_ip6_flow = 0;
        p->ip6h->s_ip6_nxt = IPPROTO_TCP;
        p->ip6h->s_ip6_plen = htons(20);
        p->ip6h->s_ip6_hlim = 64;
        if (direction == 0) {
            p->ip6h->ip6_src[0] = f->src.addr_data32[0];
            p->ip6h->ip6_src[1] = f->src.addr_data32[1];
            p->ip6h->ip6_src[2] = f->src.addr_data32[2];
            p->ip6h->ip6_src[3] = f->src.addr_data32[3];
            p->ip6h->ip6_dst[0] = f->dst.addr_data32[0];
            p->ip6h->ip6_dst[1] = f->dst.addr_data32[1];
            p->ip6h->ip6_dst[2] = f->dst.addr_data32[2];
            p->ip6h->ip6_dst[3] = f->dst.addr_data32[3];
        } else {
            p->ip6h->ip6_src[0] = f->dst.addr_data32[0];
            p->ip6h->ip6_src[1] = f->dst.addr_data32[1];
            p->ip6h->ip6_src[2] = f->dst.addr_data32[2];
            p->ip6h->ip6_src[3] = f->dst.addr_data32[3];
            p->ip6h->ip6_dst[0] = f->src.addr_data32[0];
            p->ip6h->ip6_dst[1] = f->src.addr_data32[1];
            p->ip6h->ip6_dst[2] = f->src.addr_data32[2];
            p->ip6h->ip6_dst[3] = f->src.addr_data32[3];
        }

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 40);
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

    if (f->src.family == AF_INET) {
        p->tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p->ip4h->ip_src),
                                               (uint16_t *)p->tcph, 20);
    } else {
        p->tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p->ip6h->ip6_src),
                                               (uint16_t *)p->tcph, 20);
    }

    memset(&p->ts, 0, sizeof(struct timeval));
    TimeGet(&p->ts);

    AppLayerSetEOF(f);

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
 * \internal
 * \brief Forces reassembly for flow if it needs it.
 *
 *        The function requires flow to be locked beforehand.
 *
 * \param f Pointer to the flow.
 *
 * \retval 0 This flow doesn't need any reassembly processing; 1 otherwise.
 */
int FlowForceReassemblyForFlowV2(Flow *f)
{
    TcpSession *ssn;

    int client_ok = 1;
    int server_ok = 1;

    /* looks like we have no flows in this queue */
    if (f == NULL || f->flags & FLOW_TIMEOUT_REASSEMBLY_DONE) {
        return 0;
    }

    /* Get the tcp session for the flow */
    ssn = (TcpSession *)f->protoctx;
    /* \todo Also skip flows that shouldn't be inspected */
    if (ssn == NULL) {
        return 0;
    }

    if (!StreamHasUnprocessedSegments(ssn, 0)) {
        client_ok = 0;
    }
    if (!StreamHasUnprocessedSegments(ssn, 1)) {
        server_ok = 0;
    }

    /* nothing to do */
    if (client_ok == 0 && server_ok == 0) {
        return 0;
    }

    /* move this unlock after the strream reassemble call */
    SCSpinUnlock(&f->fb->s);

    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;

    /* The packets we use are based on what segments in what direction are
     * unprocessed.
     * p1 if we have client segments for reassembly purpose only.  If we
     * have no server segments p2 can be a toserver packet with dummy
     * seq/ack, and if we have server segments p2 has to carry out reassembly
     * for server segment as well, in which case we will also need a p3 in the
     * toclient which is now dummy since all we need it for is detection */

    /* insert a pseudo packet in the toserver direction */
    if (client_ok == 1) {
        p1 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 0);
        if (p1 == NULL) {
            return 1;
        }

        if (server_ok == 1) {
            p2 = FlowForceReassemblyPseudoPacketGet( 0, f, ssn, 0);
            if (p2 == NULL) {
                TmqhOutputPacketpool(NULL,p1);
                return 1;
            }

            p3 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 0);
            if (p3 == NULL) {
                TmqhOutputPacketpool(NULL, p1);
                TmqhOutputPacketpool(NULL, p2);
                return 1;
            }
        } else {
            p2 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 1);
            if (p2 == NULL) {
                TmqhOutputPacketpool(NULL, p1);
                return 1;
            }
        }
    } else {
        p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 0);
        if (p1 == NULL) {
            return 1;
        }

        p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
        if (p2 == NULL) {
            TmqhOutputPacketpool(NULL, p1);
            return 1;
        }
    }
    f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    SCMutexLock(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq.mutex_q);
    PacketEnqueue(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq, p1);
    PacketEnqueue(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq, p2);
    if (p3 != NULL)
        PacketEnqueue(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq, p3);
    SCMutexUnlock(&stream_pseudo_pkt_decode_tm_slot->slot_post_pq.mutex_q);
    if (stream_pseudo_pkt_decode_TV->inq != NULL) {
        SCCondSignal(&trans_q[stream_pseudo_pkt_decode_TV->inq->id].cond_q);
    }

    return 1;
}

/**
 * \internal
 * \brief Forces reassembly for flows that need it.
 *
 *        Please note we don't use locks anywhere.  This function is to be
 *        called right when the engine is not doing anything.
 *
 * \param q The queue to process flows from.
 */
static inline void FlowForceReassemblyForQ(FlowQueue *q)
{
    Flow *f;
    TcpSession *ssn;
    int client_ok;
    int server_ok;

    /* no locks needed, since the engine is virtually dead.
     * We are the kings here */

    /* get the topmost flow from the QUEUE */
    f = q->top;

    /* We use this packet just for reassembly purpose */
    Packet *reassemble_p = PacketGetFromAlloc();
    if (reassemble_p == NULL)
        return;

    /* we need to loop through all the flows in the queue */
    while (f != NULL) {
        PACKET_RECYCLE(reassemble_p);

        client_ok = 0;
        server_ok = 0;

        /* Get the tcp session for the flow */
        ssn = (TcpSession *)f->protoctx;

        /* \todo Also skip flows that shouldn't be inspected */
        if (ssn == NULL) {
            f = f->lnext;
            continue;
        }

        /* ah ah!  We have some unattended toserver segments */
        if (StreamHasUnprocessedSegments(ssn, 0)) {
            client_ok = 1;

            StreamTcpThread *stt = stream_pseudo_pkt_stream_tm_slot->slot_data;

            ssn->client.last_ack = (ssn->client.seg_list_tail->seq +
                                    ssn->client.seg_list_tail->payload_len);
            FlowForceReassemblyPseudoPacketSetup(reassemble_p, 1, f, ssn, 1);
            StreamTcpReassembleHandleSegment(stream_pseudo_pkt_detect_TV,
                                             stt->ra_ctx, ssn, &ssn->server,
                                             reassemble_p, NULL);
            StreamTcpReassembleProcessAppLayer(stt->ra_ctx);
        }
        /* oh oh!  We have some unattended toclient segments */
        if (StreamHasUnprocessedSegments(ssn, 1)) {
            server_ok = 1;
            StreamTcpThread *stt = stream_pseudo_pkt_stream_tm_slot->slot_data;

            ssn->server.last_ack = (ssn->server.seg_list_tail->seq +
                                    ssn->server.seg_list_tail->payload_len);
            FlowForceReassemblyPseudoPacketSetup(reassemble_p, 0, f, ssn, 1);
            StreamTcpReassembleHandleSegment(stream_pseudo_pkt_detect_TV,
                                             stt->ra_ctx, ssn, &ssn->client,
                                             reassemble_p, NULL);
            StreamTcpReassembleProcessAppLayer(stt->ra_ctx);
        }

        /* insert a pseudo packet in the toserver direction */
        if (client_ok == 1) {
            Packet *p = FlowForceReassemblyPseudoPacketGet(0, f, ssn, 1);
            if (p == NULL) {
                TmqhOutputPacketpool(NULL, reassemble_p);
                return;
            }

            if (stream_pseudo_pkt_detect_prev_TV != NULL) {
                stream_pseudo_pkt_detect_prev_TV->
                    tmqh_out(stream_pseudo_pkt_detect_prev_TV, p);
            } else {
                TmSlot *s = stream_pseudo_pkt_detect_tm_slot;
                while (s != NULL) {
                    s->SlotFunc(NULL, p, s->slot_data, &s->slot_pre_pq,
                                &s->slot_post_pq);
                    s = s->slot_next;
                }

                if (stream_pseudo_pkt_detect_TV != NULL) {
                    stream_pseudo_pkt_detect_TV->
                        tmqh_out(stream_pseudo_pkt_detect_TV, p);
                }
            }
        } /* if (ssn->client.seg_list != NULL) */
        if (server_ok == 1) {
            Packet *p = FlowForceReassemblyPseudoPacketGet(1, f, ssn, 1);
            if (p == NULL) {
                TmqhOutputPacketpool(NULL, reassemble_p);
                return;
            }

            if (stream_pseudo_pkt_detect_prev_TV != NULL) {
                stream_pseudo_pkt_detect_prev_TV->
                    tmqh_out(stream_pseudo_pkt_detect_prev_TV, p);
            } else {
                TmSlot *s = stream_pseudo_pkt_detect_tm_slot;
                while (s != NULL) {
                    s->SlotFunc(NULL, p, s->slot_data, &s->slot_pre_pq,
                                &s->slot_post_pq);
                    s = s->slot_next;
                }

                if (stream_pseudo_pkt_detect_TV != NULL) {
                    stream_pseudo_pkt_detect_TV->
                        tmqh_out(stream_pseudo_pkt_detect_TV, p);
                }
            }
        } /* if (ssn->server.seg_list != NULL) */

        /* next flow in the queue */
        f = f->lnext;
    } /* while (f != NULL) */

    TmqhOutputPacketpool(NULL, reassemble_p);

    return;
}

/**
 * \brief Force reassembly for all the flows that have unprocessed segments.
 */
void FlowForceReassembly(void)
{
    /* Do remember.  We need to have packet acquire disabled by now */

    /** ----- Part 1 ----- **/
    /* First we need to kill the flow manager thread */
    FlowKillFlowManagerThread();

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
            }
        }
        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);

    /** ----- Part 3 ----- **/
    /* Carry out flow reassembly for unattended flows */
    FlowForceReassemblyForQ(&flow_new_q[FLOW_PROTO_TCP]);
    FlowForceReassemblyForQ(&flow_est_q[FLOW_PROTO_TCP]);
    FlowForceReassemblyForQ(&flow_close_q[FLOW_PROTO_TCP]);

    return;
}

void FlowForceReassemblySetup(void)
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
    if (stream_pseudo_pkt_detect_TV->next == NULL) {
        stream_pseudo_pkt_detect_TV = NULL;
    }

    stream_pseudo_pkt_decode_tm_slot = TmThreadGetFirstTmSlotForPartialPattern("Decode");
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
