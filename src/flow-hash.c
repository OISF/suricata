/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Flow Hashing functions.
 */

#include "suricata-common.h"
#include "threads.h"

#include "decode.h"
#include "debug.h"

#include "flow.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"

#include "util-time.h"
#include "util-debug.h"

#ifdef FLOW_DEBUG_STATS
#define FLOW_DEBUG_STATS_PROTO_ALL      0
#define FLOW_DEBUG_STATS_PROTO_TCP      1
#define FLOW_DEBUG_STATS_PROTO_UDP      2
#define FLOW_DEBUG_STATS_PROTO_ICMP     3
#define FLOW_DEBUG_STATS_PROTO_OTHER    4

static uint64_t flow_hash_count[5] = { 0, 0, 0, 0, 0 };        /* how often are we looking for a hash */
static uint64_t flow_hash_loop_count[5] = { 0, 0, 0, 0, 0 };   /* how often do we loop through a hash bucket */
static FILE *flow_hash_count_fp = NULL;
static SCSpinlock flow_hash_count_lock;

#define FlowHashCountUpdate do { \
    SCSpinLock(&flow_hash_count_lock); \
    flow_hash_count[FLOW_DEBUG_STATS_PROTO_ALL]++; \
    flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ALL] += _flow_hash_counter; \
    if (f != NULL) { \
        if (p->proto == IPPROTO_TCP) { \
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_TCP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP] += _flow_hash_counter; \
        } else if (p->proto == IPPROTO_UDP) {\
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_UDP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_UDP] += _flow_hash_counter; \
        } else if (p->proto == IPPROTO_ICMP) {\
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_ICMP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ICMP] += _flow_hash_counter; \
        } else  {\
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_OTHER]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_OTHER] += _flow_hash_counter; \
        } \
    } \
    SCSpinUnlock(&flow_hash_count_lock); \
} while(0);

#define FlowHashCountInit uint64_t _flow_hash_counter = 0
#define FlowHashCountIncr _flow_hash_counter++;

void FlowHashDebugInit(void) {
#ifdef FLOW_DEBUG_STATS
    SCSpinInit(&flow_hash_count_lock, 0);
#endif
    flow_hash_count_fp = fopen("flow-debug.log", "w+");
    if (flow_hash_count_fp != NULL) {
        fprintf(flow_hash_count_fp, "ts,all,tcp,udp,icmp,other\n");
    }
}

void FlowHashDebugPrint(uint32_t ts) {
#ifdef FLOW_DEBUG_STATS
    if (flow_hash_count_fp == NULL)
        return;

    float avg_all = 0, avg_tcp = 0, avg_udp = 0, avg_icmp = 0, avg_other = 0;
    SCSpinLock(&flow_hash_count_lock);
    if (flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ALL] != 0)
        avg_all = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ALL]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_ALL]));
    if (flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP] != 0)
        avg_tcp = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_TCP]));
    if (flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_UDP] != 0)
        avg_udp = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_UDP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_UDP]));
    if (flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ICMP] != 0)
        avg_icmp= (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ICMP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_ICMP]));
    if (flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_OTHER] != 0)
        avg_other= (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_OTHER]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_OTHER]));
    fprintf(flow_hash_count_fp, "%"PRIu32",%02.3f,%02.3f,%02.3f,%02.3f,%02.3f\n", ts, avg_all, avg_tcp, avg_udp, avg_icmp, avg_other);
    fflush(flow_hash_count_fp);
    memset(&flow_hash_count, 0, sizeof(flow_hash_count));
    memset(&flow_hash_loop_count, 0, sizeof(flow_hash_loop_count));
    SCSpinUnlock(&flow_hash_count_lock);
#endif
}

void FlowHashDebugDeinit(void) {
#ifdef FLOW_DEBUG_STATS
    struct timeval ts;
    memset(&ts, 0, sizeof(ts));
    TimeGet(&ts);
    FlowHashDebugPrint((uint32_t)ts.tv_sec);
    if (flow_hash_count_fp != NULL)
        fclose(flow_hash_count_fp);
    SCSpinDestroy(&flow_hash_count_lock);
#endif
}

#else

#define FlowHashCountUpdate
#define FlowHashCountInit
#define FlowHashCountIncr

#endif /* FLOW_DEBUG_STATS */

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source port
 *  destination port
 *  source address
 *  destination address
 *  recursion level -- for tunnels, make sure different tunnel layers can
 *                     never get mixed up.
 *
 *  For ICMP we only consider UNREACHABLE errors atm.
 */
uint32_t FlowGetKey(Packet *p) {
    FlowKey *k = (FlowKey *)p;
    uint32_t key;

    if (p->ip4h != NULL) {
        if (p->tcph != NULL || p->udph != NULL) {
            key = (flow_config.hash_rand + k->proto + k->sp + k->dp + \
                    k->src.addr_data32[0] + k->dst.addr_data32[0] + \
                    k->recursion_level) % flow_config.hash_size;
/*
            SCLogDebug("TCP/UCP key %"PRIu32, key);

            SCLogDebug("proto %u, sp %u, dp %u, src %u, dst %u, reclvl %u",
                    k->proto, k->sp, k->dp, k->src.addr_data32[0], k->dst.addr_data32[0],
                    k->recursion_level);
*/
        } else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
//            SCLogDebug("valid ICMPv4 DEST UNREACH error packet");

            key = (flow_config.hash_rand + ICMPV4_GET_EMB_PROTO(p) +
                    p->icmpv4vars.emb_sport + \
                    p->icmpv4vars.emb_dport + \
                    IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p)) + \
                    IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p)) + \
                    k->recursion_level) % flow_config.hash_size;
/*
            SCLogDebug("ICMP DEST UNREACH key %"PRIu32, key);

            SCLogDebug("proto %u, sp %u, dp %u, src %u, dst %u, reclvl %u",
                    ICMPV4_GET_EMB_PROTO(p), p->icmpv4vars.emb_sport,
                    p->icmpv4vars.emb_dport, IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p)),
                    IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p)), k->recursion_level);
*/
        } else {
            key = (flow_config.hash_rand + k->proto + \
                    k->src.addr_data32[0] + k->dst.addr_data32[0] + \
                    k->recursion_level) % flow_config.hash_size;

        }
    } else if (p->ip6h != NULL)
        key = (flow_config.hash_rand + k->proto + k->sp + k->dp + \
               k->src.addr_data32[0] + k->src.addr_data32[1] + \
               k->src.addr_data32[2] + k->src.addr_data32[3] + \
               k->dst.addr_data32[0] + k->dst.addr_data32[1] + \
               k->dst.addr_data32[2] + k->dst.addr_data32[3] + \
               k->recursion_level) % flow_config.hash_size;
    else
        key = 0;

    return key;
}

/* Since two or more flows can have the same hash key, we need to compare
 * the flow with the current flow key. */
#define CMP_FLOW(f1,f2) \
    (((CMP_ADDR(&(f1)->src, &(f2)->src) && \
       CMP_ADDR(&(f1)->dst, &(f2)->dst) && \
       CMP_PORT((f1)->sp, (f2)->sp) && CMP_PORT((f1)->dp, (f2)->dp)) || \
      (CMP_ADDR(&(f1)->src, &(f2)->dst) && \
       CMP_ADDR(&(f1)->dst, &(f2)->src) && \
       CMP_PORT((f1)->sp, (f2)->dp) && CMP_PORT((f1)->dp, (f2)->sp))) && \
     (f1)->proto == (f2)->proto && \
     (f1)->recursion_level == (f2)->recursion_level)

/**
 *  \brief See if a ICMP packet belongs to a flow by comparing the embedded
 *         packet in the ICMP error packet to the flow.
 *
 *  \param f flow
 *  \param p ICMP packet
 *
 *  \retval 1 match
 *  \retval 0 no match
 */
static inline int FlowCompareICMPv4(Flow *f, Packet *p) {
    if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
        /* first check the direction of the flow, in other words, the client ->
         * server direction as it's most likely the ICMP error will be a
         * response to the clients traffic */
        if ((f->src.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->dst.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->sp == p->icmpv4vars.emb_sport &&
                f->dp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level)
        {
            return 1;

        /* check the less likely case where the ICMP error was a response to
         * a packet from the server. */
        } else if ((f->dst.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->src.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->dp == p->icmpv4vars.emb_sport &&
                f->sp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level)
        {
            return 1;
        }

        /* no match, fall through */
    } else {
        /* just treat ICMP as a normal proto for now */
        return CMP_FLOW(f, p);
    }

    return 0;
}

static inline int FlowCompare(Flow *f, Packet *p) {
    if (p->proto == IPPROTO_ICMP) {
        return FlowCompareICMPv4(f, p);
    } else {
        return CMP_FLOW(f, p);
    }
}

/**
 *  \brief Check if we should create a flow based on a packet
 *
 *  We use this check to filter out flow creation based on:
 *  - ICMP error messages
 *
 *  \param p packet
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowCreateCheck(Packet *p) {
    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

/* FlowGetFlowFromHash
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 * If the flow is not found or the bucket was emtpy, a new flow is taken from
 * the queue. FlowDequeue() will alloc new flows as long as we stay within our
 * memcap limit.
 *
 * returns a *LOCKED* flow or NULL
 */
Flow *FlowGetFlowFromHash (Packet *p)
{
    Flow *f = NULL;
    FlowHashCountInit;

    /* get the key to our bucket */
    uint32_t key = FlowGetKey(p);
    /* get our hash bucket and lock it */
    FlowBucket *fb = &flow_hash[key];
    SCSpinLock(&fb->s);

    SCLogDebug("fb %p fb->f %p", fb, fb->f);

    FlowHashCountIncr;

    /* see if the bucket already has a flow */
    if (fb->f == NULL) {
        if (FlowCreateCheck(p) == 0) {
            SCSpinUnlock(&fb->s);
            FlowHashCountUpdate;
            return NULL;
        }

        /* no, so get a new one */
        f = fb->f = FlowDequeue(&flow_spare_q);
        if (f == NULL) {
            flow_flags |= FLOW_EMERGENCY; /* XXX mutex this */

            f = fb->f = FlowAlloc();
            if (f == NULL) {
                SCSpinUnlock(&fb->s);
                FlowHashCountUpdate;
                return NULL;
            }
        }
        /* these are protected by the bucket lock */
        f->hnext = NULL;
        f->hprev = NULL;

        /* got one, now lock, initialize and return */
        SCMutexLock(&f->m);
        FlowInit(f,p);
        FlowRequeue(f, NULL, &flow_new_q[f->protomap]);
        f->flags |= FLOW_NEW_LIST;
        f->fb = fb;

        SCSpinUnlock(&fb->s);
        FlowHashCountUpdate;
        return f;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    f = fb->f;
    /* lock the 'root' flow */
    SCMutexLock(&f->m);

    /* see if this is the flow we are looking for */
    if (FlowCompare(f, p) == 0) {
        Flow *pf = NULL; /* previous flow */
        SCMutexUnlock(&f->m);

        while (f) {
            FlowHashCountIncr;

            pf = f; /* pf is not locked at this point */
            f = f->hnext;

            if (f == NULL) {
                if (FlowCreateCheck(p) == 0) {
                    SCSpinUnlock(&fb->s);
                    FlowHashCountUpdate;
                    return NULL;
                }

                /* get us a new one and put it and the list tail */
                f = pf->hnext = FlowDequeue(&flow_spare_q);
                if (f == NULL) {
                    flow_flags |= FLOW_EMERGENCY; /* XXX mutex this */

                    f = fb->f = FlowAlloc();
                    if (f == NULL) {
                        SCSpinUnlock(&fb->s);
                        FlowHashCountUpdate;
                        return NULL;
                    }
                }

                f->hnext = NULL;
                f->hprev = pf;

                /* lock, initialize and return */
                SCMutexLock(&f->m);
                FlowInit(f,p);
                FlowRequeue(f, NULL, &flow_new_q[f->protomap]);

                f->flags |= FLOW_NEW_LIST;
                f->fb = fb;

                SCSpinUnlock(&fb->s);
                FlowHashCountUpdate;
                return f;
            }

            SCMutexLock(&f->m);

            if (FlowCompare(f, p) != 0) {
                /* we found our flow, lets put it on top of the
                 * hash list -- this rewards active flows */
                if (f->hnext) f->hnext->hprev = f->hprev;
                if (f->hprev) f->hprev->hnext = f->hnext;

                f->hnext = fb->f;
                f->hprev = NULL;
                fb->f->hprev = f;
                fb->f = f;

                /* found our flow */
                SCSpinUnlock(&fb->s);
                FlowHashCountUpdate;
                return f;
            }

            /* not found, try the next... */
            SCMutexUnlock(&f->m);
        }
    }

    /* The 'root' flow was our flow, return it.
     * It's already locked. */
    SCSpinUnlock(&fb->s);

    FlowHashCountUpdate;
    return f;
}

