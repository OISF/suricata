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

    /* get the key to our bucket */
    uint32_t key = FlowGetKey(p);
    /* get our hash bucket and lock it */
    FlowBucket *fb = &flow_hash[key];
    SCMutexLock(&fb->m);

    SCLogDebug("fb %p fb->f %p", fb, fb->f);

    /* see if the bucket already has a flow */
    if (fb->f == NULL) {
        /* no, so get a new one */
        f = fb->f = FlowDequeue(&flow_spare_q);
        if (f == NULL) {
            flow_flags |= FLOW_EMERGENCY; /* XXX mutex this */

            f = fb->f = FlowAlloc();
            if (f == NULL) {
                SCMutexUnlock(&fb->m);
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

        SCMutexUnlock(&fb->m);
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
            pf = f; /* pf is not locked at this point */
            f = f->hnext;

            if (f == NULL) {
                /* get us a new one and put it and the list tail */
                f = pf->hnext = FlowDequeue(&flow_spare_q);
                if (f == NULL) {
                    flow_flags |= FLOW_EMERGENCY; /* XXX mutex this */

                    f = fb->f = FlowAlloc();
                    if (f == NULL) {
                        SCMutexUnlock(&fb->m);
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

                SCMutexUnlock(&fb->m);
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
                SCMutexUnlock(&fb->m);
                return f;
            }

            /* not found, try the next... */
            SCMutexUnlock(&f->m);
        }
    }

    /* The 'root' flow was our flow, return it.
     * It's already locked. */
    SCMutexUnlock(&fb->m);
    return f;
}

