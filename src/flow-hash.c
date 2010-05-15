/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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

#include "util-debug.h"

//#define FLOW_DEBUG_STATS

#ifdef FLOW_DEBUG_STATS
#define FLOW_DEBUG_STATS_PROTO_ALL      0
#define FLOW_DEBUG_STATS_PROTO_TCP      1
#define FLOW_DEBUG_STATS_PROTO_UDP      2
#define FLOW_DEBUG_STATS_PROTO_ICMP     3
#define FLOW_DEBUG_STATS_PROTO_OTHER    4

static uint64_t flow_hash_count[5] = { 0, 0, 0, 0, 0 };        /* how often are we looking for a hash */
static uint64_t flow_hash_loop_count[5] = { 0, 0, 0, 0, 0 };   /* how often do we loop through a hash bucket */
static SCSpinlock flow_hash_count_lock;

#define FlowHashCountUpdate do { \
    SCSpinLock(&flow_hash_count_lock); \
    flow_hash_count[FLOW_DEBUG_STATS_PROTO_ALL]++; \
    flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ALL] += _flow_hash_counter; \
    if (f != NULL) { \
        if (f->proto == IPPROTO_TCP) { \
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_TCP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP] += _flow_hash_counter; \
        } else if (f->proto == IPPROTO_UDP) {\
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_UDP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_UDP] += _flow_hash_counter; \
        } else if (f->proto == IPPROTO_ICMP) {\
            flow_hash_count[FLOW_DEBUG_STATS_PROTO_ICMP]++; \
            flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ICMP] += _flow_hash_counter; \
        } \
    } \
    SCSpinUnlock(&flow_hash_count_lock); \
} while(0);

#define FlowHashCountInit uint64_t _flow_hash_counter = 0
#define FlowHashCountIncr _flow_hash_counter++;

#else

#define FlowHashCountUpdate
#define FlowHashCountInit
#define FlowHashCountIncr

#endif /* FLOW_DEBUG_STATS */

void FlowHashDebugInit(void) {
#ifdef FLOW_DEBUG_STATS
    SCSpinInit(&flow_hash_count_lock, 0);
#endif
}

void FlowHashDebugDeinit(void) {
#ifdef FLOW_DEBUG_STATS
    SCSpinDestroy(&flow_hash_count_lock);
    SCLogInfo("TCP %"PRIu64" %"PRIu64, flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP], flow_hash_count[FLOW_DEBUG_STATS_PROTO_TCP]);
#endif
}

void FlowHashDebugPrint(void) {
#ifdef FLOW_DEBUG_STATS
    float avg_all, avg_tcp, avg_udp, avg_icmp;
    SCSpinLock(&flow_hash_count_lock);
    avg_all = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ALL]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_ALL]));
    avg_tcp = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_TCP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_TCP]));
    avg_udp = (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_UDP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_UDP]));
    avg_icmp= (float)(flow_hash_loop_count[FLOW_DEBUG_STATS_PROTO_ICMP]/(float)(flow_hash_count[FLOW_DEBUG_STATS_PROTO_ICMP]));
    SCSpinUnlock(&flow_hash_count_lock);
    SCLogInfo("Avg flowbucket walk: all %02.3f, tcp %02.3f, udp %02.3f, icmp %02.3f", avg_all, avg_tcp, avg_udp, avg_icmp);
#endif
}

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
 */
uint32_t FlowGetKey(Packet *p) {
    FlowKey *k = (FlowKey *)p;
    uint32_t key;

    if (p->ip4h != NULL)
        key = (flow_config.hash_rand + k->proto + k->sp + k->dp + \
               k->src.addr_data32[0] + k->dst.addr_data32[0] + \
               k->recursion_level) % flow_config.hash_size;
    else if (p->ip6h != NULL)
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
    if (CMP_FLOW(f, p) == 0) {
        Flow *pf = NULL; /* previous flow */
        SCMutexUnlock(&f->m);

        while (f) {
            FlowHashCountIncr;

            pf = f; /* pf is not locked at this point */
            f = f->hnext;

            if (f == NULL) {
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

            if (CMP_FLOW(f, p) != 0) {
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

