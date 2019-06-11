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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 *  Flow Hashing functions.
 */

#include "suricata-common.h"
#include "threads.h"

#include "decode.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"
#include "flow-manager.h"
#include "flow-storage.h"
#include "app-layer-parser.h"

#include "util-time.h"
#include "util-debug.h"

#include "util-hash-lookup3.h"

#include "conf.h"
#include "output.h"
#include "output-flow.h"

#define FLOW_DEFAULT_FLOW_PRUNE 5

SC_ATOMIC_EXTERN(unsigned int, flow_prune_idx);
SC_ATOMIC_EXTERN(unsigned int, flow_flags);

static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv);

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the FlowHashKey6 struct, without all
 *        the SCNtohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 */
static inline int FlowHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

typedef struct FlowHashKey4_ {
    union {
        struct {
            uint32_t addrs[2];
            uint16_t ports[2];
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[2];
        };
        const uint32_t u32[5];
    };
} FlowHashKey4;

typedef struct FlowHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint16_t ports[2];
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[2];
        };
        const uint32_t u32[11];
    };
} FlowHashKey6;

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
static inline uint32_t FlowGetHash(const Packet *p)
{
    uint32_t hash = 0;

    if (p->ip4h != NULL) {
        if (p->tcph != NULL || p->udph != NULL) {
            FlowHashKey4 fhk;

            int ai = (p->src.addr_data32[0] > p->dst.addr_data32[0]);
            fhk.addrs[1-ai] = p->src.addr_data32[0];
            fhk.addrs[ai] = p->dst.addr_data32[0];

            const int pi = (p->sp > p->dp);
            fhk.ports[1-pi] = p->sp;
            fhk.ports[pi] = p->dp;

            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);

        } else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            uint32_t psrc = IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p));
            uint32_t pdst = IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p));
            FlowHashKey4 fhk;

            const int ai = (psrc > pdst);
            fhk.addrs[1-ai] = psrc;
            fhk.addrs[ai] = pdst;

            const int pi = (p->icmpv4vars.emb_sport > p->icmpv4vars.emb_dport);
            fhk.ports[1-pi] = p->icmpv4vars.emb_sport;
            fhk.ports[pi] = p->icmpv4vars.emb_dport;

            fhk.proto = (uint16_t)ICMPV4_GET_EMB_PROTO(p);
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);

        } else {
            FlowHashKey4 fhk;
            const int ai = (p->src.addr_data32[0] > p->dst.addr_data32[0]);
            fhk.addrs[1-ai] = p->src.addr_data32[0];
            fhk.addrs[ai] = p->dst.addr_data32[0];
            fhk.ports[0] = 0xfeed;
            fhk.ports[1] = 0xbeef;
            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);
        }
    } else if (p->ip6h != NULL) {
        FlowHashKey6 fhk;
        if (FlowHashRawAddressIPv6GtU32(p->src.addr_data32, p->dst.addr_data32)) {
            fhk.src[0] = p->src.addr_data32[0];
            fhk.src[1] = p->src.addr_data32[1];
            fhk.src[2] = p->src.addr_data32[2];
            fhk.src[3] = p->src.addr_data32[3];
            fhk.dst[0] = p->dst.addr_data32[0];
            fhk.dst[1] = p->dst.addr_data32[1];
            fhk.dst[2] = p->dst.addr_data32[2];
            fhk.dst[3] = p->dst.addr_data32[3];
        } else {
            fhk.src[0] = p->dst.addr_data32[0];
            fhk.src[1] = p->dst.addr_data32[1];
            fhk.src[2] = p->dst.addr_data32[2];
            fhk.src[3] = p->dst.addr_data32[3];
            fhk.dst[0] = p->src.addr_data32[0];
            fhk.dst[1] = p->src.addr_data32[1];
            fhk.dst[2] = p->src.addr_data32[2];
            fhk.dst[3] = p->src.addr_data32[3];
        }

        const int pi = (p->sp > p->dp);
        fhk.ports[1-pi] = p->sp;
        fhk.ports[pi] = p->dp;
        fhk.proto = (uint16_t)p->proto;
        fhk.recur = (uint16_t)p->recursion_level;
        fhk.vlan_id[0] = p->vlan_id[0];
        fhk.vlan_id[1] = p->vlan_id[1];

        hash = hashword(fhk.u32, 11, flow_config.hash_rand);
    }

    return hash;
}

/**
 * Basic hashing function for FlowKey
 *
 * \note Function only used for bypass and TCP or UDP flows
 *
 * \note this is only used at start to create Flow from pinned maps
 * so fairness is not an issue
 */
uint32_t FlowKeyGetHash(FlowKey *fk)
{
    uint32_t hash = 0;

    if (fk->src.family == AF_INET) {
        FlowHashKey4 fhk;
        int ai = (fk->src.address.address_un_data32[0] > fk->dst.address.address_un_data32[0]);
        fhk.addrs[1-ai] = fk->src.address.address_un_data32[0];
        fhk.addrs[ai] = fk->dst.address.address_un_data32[0];

        const int pi = (fk->sp > fk->dp);
        fhk.ports[1-pi] = fk->sp;
        fhk.ports[pi] = fk->dp;

        fhk.proto = (uint16_t)fk->proto;
        fhk.recur = (uint16_t)fk->recursion_level;
        fhk.vlan_id[0] = fk->vlan_id[0];
        fhk.vlan_id[1] = fk->vlan_id[1];

        hash = hashword(fhk.u32, 5, flow_config.hash_rand);
    } else {
        FlowHashKey6 fhk;
        if (FlowHashRawAddressIPv6GtU32(fk->src.address.address_un_data32,
                    fk->dst.address.address_un_data32)) {
            fhk.src[0] = fk->src.address.address_un_data32[0];
            fhk.src[1] = fk->src.address.address_un_data32[1];
            fhk.src[2] = fk->src.address.address_un_data32[2];
            fhk.src[3] = fk->src.address.address_un_data32[3];
            fhk.dst[0] = fk->dst.address.address_un_data32[0];
            fhk.dst[1] = fk->dst.address.address_un_data32[1];
            fhk.dst[2] = fk->dst.address.address_un_data32[2];
            fhk.dst[3] = fk->dst.address.address_un_data32[3];
        } else {
            fhk.src[0] = fk->dst.address.address_un_data32[0];
            fhk.src[1] = fk->dst.address.address_un_data32[1];
            fhk.src[2] = fk->dst.address.address_un_data32[2];
            fhk.src[3] = fk->dst.address.address_un_data32[3];
            fhk.dst[0] = fk->src.address.address_un_data32[0];
            fhk.dst[1] = fk->src.address.address_un_data32[1];
            fhk.dst[2] = fk->src.address.address_un_data32[2];
            fhk.dst[3] = fk->src.address.address_un_data32[3];
        }

        const int pi = (fk->sp > fk->dp);
        fhk.ports[1-pi] = fk->sp;
        fhk.ports[pi] = fk->dp;
        fhk.proto = (uint16_t)fk->proto;
        fhk.recur = (uint16_t)fk->recursion_level;
        fhk.vlan_id[0] = fk->vlan_id[0];
        fhk.vlan_id[1] = fk->vlan_id[1];

        hash = hashword(fhk.u32, 11, flow_config.hash_rand);
    }
return hash;
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
     (f1)->recursion_level == (f2)->recursion_level && \
     (f1)->vlan_id[0] == (f2)->vlan_id[0] && \
     (f1)->vlan_id[1] == (f2)->vlan_id[1])
#define CMP_FLOW_ICMP(f1,f2) \
    (((CMP_ADDR(&(f1)->src, &(f2)->src) && \
       CMP_ADDR(&(f1)->dst, &(f2)->dst) && \
       CMP_PORT((f1)->icmp_s.type, (f2)->icmp_s.type) && CMP_PORT((f1)->icmp_d.type, (f2)->icmp_d.type)) || \
      (CMP_ADDR(&(f1)->src, &(f2)->dst) && \
       CMP_ADDR(&(f1)->dst, &(f2)->src) && \
       CMP_PORT((f1)->icmp_d.type, (f2)->icmp_s.type) && CMP_PORT((f1)->icmp_s.type, (f2)->icmp_d.type))) && \
     (f1)->proto == (f2)->proto && \
     (f1)->recursion_level == (f2)->recursion_level && \
     (f1)->vlan_id[0] == (f2)->vlan_id[0] && \
     (f1)->vlan_id[1] == (f2)->vlan_id[1])

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
static inline int FlowCompareICMPv4(Flow *f, const Packet *p)
{
    if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
        /* first check the direction of the flow, in other words, the client ->
         * server direction as it's most likely the ICMP error will be a
         * response to the clients traffic */
        if ((f->src.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->dst.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->sp == p->icmpv4vars.emb_sport &&
                f->dp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level &&
                f->vlan_id[0] == p->vlan_id[0] &&
                f->vlan_id[1] == p->vlan_id[1])
        {
            return 1;

        /* check the less likely case where the ICMP error was a response to
         * a packet from the server. */
        } else if ((f->dst.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->src.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->dp == p->icmpv4vars.emb_sport &&
                f->sp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level &&
                f->vlan_id[0] == p->vlan_id[0] &&
                f->vlan_id[1] == p->vlan_id[1])
        {
            return 1;
        }

        /* no match, fall through */
    } else {
        /* just treat ICMP as a normal proto for now */
        return CMP_FLOW_ICMP(f, p);
    }

    return 0;
}

void FlowSetupPacket(Packet *p)
{
    p->flags |= PKT_WANTS_FLOW;
    p->flow_hash = FlowGetHash(p);
}

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, void *tcp_ssn);

static inline int FlowCompare(Flow *f, const Packet *p)
{
    if (p->proto == IPPROTO_ICMP) {
        return FlowCompareICMPv4(f, p);
    } else if (p->proto == IPPROTO_TCP) {
        if (CMP_FLOW(f, p) == 0)
            return 0;

        /* if this session is 'reused', we don't return it anymore,
         * so return false on the compare */
        if (f->flags & FLOW_TCP_REUSED)
            return 0;

        return 1;
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
static inline int FlowCreateCheck(const Packet *p)
{
    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

static inline void FlowUpdateCounter(ThreadVars *tv, DecodeThreadVars *dtv,
        uint8_t proto)
{
#ifdef UNITTESTS
    if (tv && dtv) {
#endif
        switch (proto){
            case IPPROTO_UDP:
                StatsIncr(tv, dtv->counter_flow_udp);
                break;
            case IPPROTO_TCP:
                StatsIncr(tv, dtv->counter_flow_tcp);
                break;
            case IPPROTO_ICMP:
                StatsIncr(tv, dtv->counter_flow_icmp4);
                break;
            case IPPROTO_ICMPV6:
                StatsIncr(tv, dtv->counter_flow_icmp6);
                break;
        }
#ifdef UNITTESTS
    }
#endif
}

/**
 *  \brief Get a new flow
 *
 *  Get a new flow. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f *LOCKED* flow on succes, NULL on error.
 */
static Flow *FlowGetNew(ThreadVars *tv, DecodeThreadVars *dtv, const Packet *p)
{
    Flow *f = NULL;

    if (FlowCreateCheck(p) == 0) {
        return NULL;
    }

    /* get a flow from the spare queue */
    f = FlowDequeue(&flow_spare_q);
    if (f == NULL) {
        /* If we reached the max memcap, we get a used flow */
        if (!(FLOW_CHECK_MEMCAP(sizeof(Flow) + FlowStorageSize()))) {
            /* declare state of emergency */
            if (!(SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)) {
                SC_ATOMIC_OR(flow_flags, FLOW_EMERGENCY);

                FlowTimeoutsEmergency();

                /* under high load, waking up the flow mgr each time leads
                 * to high cpu usage. Flows are not timed out much faster if
                 * we check a 1000 times a second. */
                FlowWakeupFlowManagerThread();
            }

            f = FlowGetUsedFlow(tv, dtv);
            if (f == NULL) {
                /* max memcap reached, so increments the counter */
                if (tv != NULL && dtv != NULL) {
                    StatsIncr(tv, dtv->counter_flow_memcap);
                }

                /* very rare, but we can fail. Just giving up */
                return NULL;
            }

            /* freed a flow, but it's unlocked */
        } else {
            /* now see if we can alloc a new flow */
            f = FlowAlloc();
            if (f == NULL) {
                if (tv != NULL && dtv != NULL) {
                    StatsIncr(tv, dtv->counter_flow_memcap);
                }
                return NULL;
            }

            /* flow is initialized but *unlocked* */
        }
    } else {
        /* flow has been recycled before it went into the spare queue */

        /* flow is initialized (recylced) but *unlocked* */
    }

    FLOWLOCK_WRLOCK(f);
    FlowUpdateCounter(tv, dtv, p->proto);
    return f;
}

static Flow *TcpReuseReplace(ThreadVars *tv, DecodeThreadVars *dtv,
                             FlowBucket *fb, Flow *old_f,
                             const uint32_t hash, const Packet *p)
{
    /* tag flow as reused so future lookups won't find it */
    old_f->flags |= FLOW_TCP_REUSED;
    /* get some settings that we move over to the new flow */
    FlowThreadId thread_id = old_f->thread_id;

    /* since fb lock is still held this flow won't be found until we are done */
    FLOWLOCK_UNLOCK(old_f);

    /* Get a new flow. It will be either a locked flow or NULL */
    Flow *f = FlowGetNew(tv, dtv, p);
    if (f == NULL) {
        return NULL;
    }

    /* flow is locked */

    /* put at the start of the list */
    f->hnext = fb->head;
    fb->head->hprev = f;
    fb->head = f;

    /* initialize and return */
    FlowInit(f, p);
    f->flow_hash = hash;
    f->fb = fb;

    f->thread_id = thread_id;
    return f;
}

/** \brief Get Flow for packet
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 * If the flow is not found or the bucket was emtpy, a new flow is taken from
 * the queue. FlowDequeue() will alloc new flows as long as we stay within our
 * memcap limit.
 *
 * The p->flow pointer is updated to point to the flow.
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f *LOCKED* flow or NULL
 */
Flow *FlowGetFlowFromHash(ThreadVars *tv, DecodeThreadVars *dtv, const Packet *p, Flow **dest)
{
    Flow *f = NULL;

    /* get our hash bucket and lock it */
    const uint32_t hash = p->flow_hash;
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* see if the bucket already has a flow */
    if (fb->head == NULL) {
        f = FlowGetNew(tv, dtv, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }

        /* flow is locked */
        fb->head = f;
        fb->tail = f;

        /* got one, now lock, initialize and return */
        FlowInit(f, p);
        f->flow_hash = hash;
        f->fb = fb;
        FlowUpdateState(f, FLOW_STATE_NEW);

        FlowReference(dest, f);

        FBLOCK_UNLOCK(fb);
        return f;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    f = fb->head;

    /* see if this is the flow we are looking for */
    if (FlowCompare(f, p) == 0) {
        Flow *pf = NULL; /* previous flow */

        while (f) {
            pf = f;
            f = f->hnext;

            if (f == NULL) {
                f = pf->hnext = FlowGetNew(tv, dtv, p);
                if (f == NULL) {
                    FBLOCK_UNLOCK(fb);
                    return NULL;
                }
                fb->tail = f;

                /* flow is locked */

                f->hprev = pf;

                /* initialize and return */
                FlowInit(f, p);
                f->flow_hash = hash;
                f->fb = fb;
                FlowUpdateState(f, FLOW_STATE_NEW);

                FlowReference(dest, f);

                FBLOCK_UNLOCK(fb);
                return f;
            }

            if (FlowCompare(f, p) != 0) {
                /* we found our flow, lets put it on top of the
                 * hash list -- this rewards active flows */
                if (f->hnext) {
                    f->hnext->hprev = f->hprev;
                }
                if (f->hprev) {
                    f->hprev->hnext = f->hnext;
                }
                if (f == fb->tail) {
                    fb->tail = f->hprev;
                }

                f->hnext = fb->head;
                f->hprev = NULL;
                fb->head->hprev = f;
                fb->head = f;

                /* found our flow, lock & return */
                FLOWLOCK_WRLOCK(f);
                if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
                    f = TcpReuseReplace(tv, dtv, fb, f, hash, p);
                    if (f == NULL) {
                        FBLOCK_UNLOCK(fb);
                        return NULL;
                    }
                }

                FlowReference(dest, f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
        }
    }

    /* lock & return */
    FLOWLOCK_WRLOCK(f);
    if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
        f = TcpReuseReplace(tv, dtv, fb, f, hash, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }
    }

    FlowReference(dest, f);

    FBLOCK_UNLOCK(fb);
    return f;
}

static inline int FlowCompareKey(Flow *f, FlowKey *key)
{
    if ((f->proto != IPPROTO_TCP) && (f->proto != IPPROTO_UDP))
        return 0;
    return CMP_FLOW(f, key);
}

/** \brief Get or create a Flow using a FlowKey
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 * Return a new Flow if ever no Flow was found.
 *
 *
 *  \param key Pointer to FlowKey build using flow to look for
 *  \param ttime time to use for flow creation
 *  \param hash Value of the flow hash
 *  \retval f *LOCKED* flow or NULL
 */

Flow *FlowGetFromFlowKey(FlowKey *key, struct timespec *ttime, const uint32_t hash)
{
    Flow *f = FlowGetExistingFlowFromHash(key, hash);

    if (f != NULL) {
        return f;
    }

    /* No existing flow so let's get one new */
    f = FlowDequeue(&flow_spare_q);
    if (f == NULL) {
        /* now see if we can alloc a new flow */
        f = FlowAlloc();
        if (f == NULL) {
            SCLogDebug("Can't get a spare flow at start");
            return NULL;
        }
    }
    f->proto = key->proto;
    f->vlan_id[0] = key->vlan_id[0];
    f->vlan_id[1] = key->vlan_id[1];
    f->src.addr_data32[0] = key->src.addr_data32[0];
    f->src.addr_data32[1] = key->src.addr_data32[1];
    f->src.addr_data32[2] = key->src.addr_data32[2];
    f->src.addr_data32[3] = key->src.addr_data32[3];
    f->dst.addr_data32[0] = key->dst.addr_data32[0];
    f->dst.addr_data32[1] = key->dst.addr_data32[1];
    f->dst.addr_data32[2] = key->dst.addr_data32[2];
    f->dst.addr_data32[3] = key->dst.addr_data32[3];
    f->sp = key->sp;
    f->dp = key->dp;
    f->recursion_level = 0;
    f->flow_hash = hash;
    if (key->src.family == AF_INET) {
        f->flags |= FLOW_IPV4;
    } else if (key->src.family == AF_INET6) {
        f->flags |= FLOW_IPV6;
    }
    FlowUpdateState(f, FLOW_STATE_CAPTURE_BYPASSED);

    f->protomap = FlowGetProtoMapping(f->proto);
    /* set timestamp to now */
    f->startts.tv_sec = ttime->tv_sec;
    f->startts.tv_usec = ttime->tv_nsec * 1000;
    f->lastts = f->startts;

    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);
    f->fb = fb;
    if (fb->head == NULL) {
        fb->head = f;
        fb->tail = f;
    } else {
        f->hprev = fb->tail;
        f->hprev->hnext = f;
        fb->tail = f;
    }
    FLOWLOCK_WRLOCK(f);
    FBLOCK_UNLOCK(fb);

    return f;
}

/** \brief Look for existing Flow using a FlowKey
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 *
 *  \param key Pointer to FlowKey build using flow to look for
 *  \param hash Value of the flow hash
 *  \retval f *LOCKED* flow or NULL
 */
Flow *FlowGetExistingFlowFromHash(FlowKey *key, const uint32_t hash)
{
    /* get our hash bucket and lock it */
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* return if the bucket don't have a flow */
    if (fb->head == NULL) {
        FBLOCK_UNLOCK(fb);
        return NULL;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    Flow *f = fb->head;

    /* see if this is the flow we are looking for */
    if (FlowCompareKey(f, key) == 0) {
        while (f) {
            f = f->hnext;

            if (f == NULL) {
                FBLOCK_UNLOCK(fb);
                return NULL;
            }

            if (FlowCompareKey(f, key) != 0) {
                /* found our flow, lock & return */
                FLOWLOCK_WRLOCK(f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
        }
    }

    /* lock & return */
    FLOWLOCK_WRLOCK(f);

    FBLOCK_UNLOCK(fb);
    return f;
}

/** \internal
 *  \brief Get a flow from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a flow can be freed. Timeouts are disregarded, use_cnt
 *  is adhered to. "flow_prune_idx" atomic int makes sure we don't start at the
 *  top each time since that would clear the top of the hash leading to longer
 *  and longer search times under high pressure (observed).
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f flow or NULL
 */
static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv)
{
    uint32_t idx = SC_ATOMIC_GET(flow_prune_idx) % flow_config.hash_size;
    uint32_t cnt = flow_config.hash_size;

    while (cnt--) {
        if (++idx >= flow_config.hash_size)
            idx = 0;

        FlowBucket *fb = &flow_hash[idx];

        if (FBLOCK_TRYLOCK(fb) != 0)
            continue;

        Flow *f = fb->tail;
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            continue;
        }

        if (FLOWLOCK_TRYWRLOCK(f) != 0) {
            FBLOCK_UNLOCK(fb);
            continue;
        }

        /** never prune a flow that is used by a packet or stream msg
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(f->use_cnt) > 0) {
            FBLOCK_UNLOCK(fb);
            FLOWLOCK_UNLOCK(f);
            continue;
        }

        /* remove from the hash */
        if (f->hprev != NULL)
            f->hprev->hnext = f->hnext;
        if (f->hnext != NULL)
            f->hnext->hprev = f->hprev;
        if (fb->head == f)
            fb->head = f->hnext;
        if (fb->tail == f)
            fb->tail = f->hprev;

        f->hnext = NULL;
        f->hprev = NULL;
        f->fb = NULL;
        SC_ATOMIC_SET(fb->next_ts, 0);
        FBLOCK_UNLOCK(fb);

        int state = SC_ATOMIC_GET(f->flow_state);
        if (state == FLOW_STATE_NEW)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_NEW;
        else if (state == FLOW_STATE_ESTABLISHED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_ESTABLISHED;
        else if (state == FLOW_STATE_CLOSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_CLOSED;
        else if (state == FLOW_STATE_CAPTURE_BYPASSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_BYPASSED;
        else if (state == FLOW_STATE_LOCAL_BYPASSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_BYPASSED;

        f->flow_end_flags |= FLOW_END_FLAG_FORCED;

        if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
            f->flow_end_flags |= FLOW_END_FLAG_EMERGENCY;

        /* invoke flow log api */
        if (dtv && dtv->output_flow_thread_data)
            (void)OutputFlowLog(tv, dtv->output_flow_thread_data, f);

        FlowClearMemory(f, f->protomap);

        FlowUpdateState(f, FLOW_STATE_NEW);

        FLOWLOCK_UNLOCK(f);

        (void) SC_ATOMIC_ADD(flow_prune_idx, (flow_config.hash_size - cnt));
        return f;
    }

    return NULL;
}
