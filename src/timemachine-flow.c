/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Mat Oldham <mat.oldham@gmail.com>
 *
 * Flow related functions for usage within TimeMachine
 */
#include "suricata-common.h"

#include "flow-private.h"

#include "util-hash-lookup3.h"

#include "timemachine.h"
#include "timemachine-flow.h"
#include "timemachine-packet.h"

typedef struct TimeMachineFlowHashKey4_ TimeMachineFlowHashKey4;
typedef struct TimeMachineFlowHashKey6_ TimeMachineFlowHashKey6;
typedef struct TimeMachineFlowNode_ TimeMachineFlowNode;

struct TimeMachineFlowHashKey4_ {
    union {
        struct {
            uint32_t src, dst;
            uint16_t sp, dp;
            uint32_t proto;
        };
        const uint32_t u32[4];
    };
};

struct TimeMachineFlowHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint16_t sp, dp;
            uint32_t proto;
        };
        const uint32_t u32[10];
    };
};

/* TimeMachineFlowNode's are entries within a SPLAY tree */
struct TimeMachineFlowNode_ {
    uint32_t  hash;
    void      *data;

    SPLAY_ENTRY(TimeMachineFlowNode_) ent;
};

/* SPLAY tree comparison callback */
static inline int TimeMachineFlowCompare(TimeMachineFlowNode *a, TimeMachineFlowNode *b) {
    
    if (a->hash == b->hash) {
        return 0;
    }

    if (a->hash < b->hash) {
        return -1;
    }

    if (a->hash > b->hash) {
        return 1;
    }

    return 0;
}

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the FlowHashKey6 struct, without all
 *        the ntohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 */
static inline int TimeMachineFlowHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    for (int i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

/* SPLAY Tree Macros */
SPLAY_PROTOTYPE(TimeMachineFlows_, TimeMachineFlowNode_, ent, TimeMachineFlowCompare);
SPLAY_GENERATE(TimeMachineFlows_, TimeMachineFlowNode_, ent, TimeMachineFlowCompare);

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source port
 *  destination port
 *  source address
 *  destination address
 *
 *  For ICMP we only consider UNREACHABLE errors atm.
 */
static inline uint32_t TimeMachineFlowGetKey(const Packet* p) {
    uint32_t key;
    
    if (p->ip4h != NULL) {
                    
        if (p->tcph != NULL || p->udph != NULL) {
            TimeMachineFlowHashKey4 fhk;
            
            if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
                fhk.src = p->src.addr_data32[0];
                fhk.dst = p->dst.addr_data32[0];
            } else {
                fhk.src = p->dst.addr_data32[0];
                fhk.dst = p->src.addr_data32[0];
            }
            
            if (p->sp > p->dp) {
                fhk.sp = p->sp;
                fhk.dp = p->dp;
            } else {
                fhk.sp = p->dp;
                fhk.dp = p->sp;
            }
            fhk.proto = (uint32_t)p->proto;

            key = hashword(fhk.u32, 4, flow_config.hash_rand);         
        } else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            uint32_t psrc = IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p));
            uint32_t pdst = IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p));
            TimeMachineFlowHashKey4 fhk;
            if (psrc > pdst) {
                fhk.src = psrc;
                fhk.dst = pdst;
            } else {
                fhk.src = pdst;
                fhk.dst = psrc;
            }
            if (p->icmpv4vars.emb_sport > p->icmpv4vars.emb_dport) {
                fhk.sp = p->icmpv4vars.emb_sport;
                fhk.dp = p->icmpv4vars.emb_dport;
            } else {
                fhk.sp = p->icmpv4vars.emb_dport;
                fhk.dp = p->icmpv4vars.emb_sport;
            }
            fhk.proto = (uint32_t)ICMPV4_GET_EMB_PROTO(p);

            key = hashword(fhk.u32, 4, flow_config.hash_rand);
        } else {
            TimeMachineFlowHashKey4 fhk;
            if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
                fhk.src = p->src.addr_data32[0];
                fhk.dst = p->dst.addr_data32[0];
            } else {
                fhk.src = p->dst.addr_data32[0];
                fhk.dst = p->src.addr_data32[0];
            }
            fhk.sp = 0xfeed;
            fhk.dp = 0xbeef;
            fhk.proto = (uint32_t)p->proto;

            key = hashword(fhk.u32, 4, flow_config.hash_rand);
        }
    } else if (p->ip6h != NULL) {

        TimeMachineFlowHashKey6 fhk;
        if (TimeMachineFlowHashRawAddressIPv6GtU32(p->src.addr_data32, p->dst.addr_data32)) {
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
        if (p->sp > p->dp) {
            fhk.sp = p->sp;
            fhk.dp = p->dp;
        } else {
            fhk.sp = p->dp;
            fhk.dp = p->sp;
        }
        fhk.proto = (uint32_t)p->proto;
        
        key = hashword(fhk.u32, 10, flow_config.hash_rand);
    } else
        key = 0;

    return key;
}

TimeMachineFlow* TimeMachineFlowNew(TimeMachineFlows* flows, Packet* p) {
    TimeMachineFlow* flow;
    TimeMachineFlowNode* ent;
        
    flow = SCMalloc(sizeof(TimeMachineFlow));
        
    if (p->ip4h != NULL) {
        FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, &flow->src);
        FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, &flow->dst);
        flow->datalink = p->datalink;
        flow->ip_hdr = 1;
          
        if (p->tcph != NULL || p->udph != NULL) {
            flow->sp = p->sp;
            flow->dp = p->dp;
            flow->proto = (uint8_t)p->proto;
        }   
        else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            flow->sp = p->icmpv4vars.emb_sport;
            flow->dp = p->icmpv4vars.emb_dport;
            flow->proto = (uint8_t)ICMPV4_GET_EMB_PROTO(p);
        } 
        else {
            flow->sp = 0xfeed;
            flow->dp = 0xbeef;
            flow->proto = (uint8_t)p->proto;
        }
    }
    else if (p->ip6h != NULL) {
        FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, &flow->src);
        FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, &flow->dst);
        flow->proto = (uint8_t)p->proto;
        flow->datalink = p->datalink;        
        flow->sp = p->sp;
        flow->dp = p->dp;
        flow->ip_hdr = 2;
    }
    else {
        return NULL;
    }
    
    memcpy(&flow->ts, &p->ts, sizeof(struct timeval));
    TAILQ_INIT(&flow->packets);
    flow->packet_count = 0;
    flow->output = NULL;  
    
    ent = SCMalloc(sizeof(TimeMachineFlowNode));
    ent->hash = TimeMachineFlowGetKey(p);
    ent->data = flow;
    flow->ent = ent;

    SPLAY_INSERT(TimeMachineFlows_, flows, ent);  
    return flow;         
}

void TimeMachineFlowDestroy(TimeMachineFlows* flows, TimeMachineFlow* flow) {
    TimeMachineFlowNode search;
    TimeMachineFlowNode* ret;
    
    search = *flow->ent;     
    ret = SPLAY_FIND(TimeMachineFlows_, flows, &search);

    if (ret == NULL) {
        return;
    }

    SPLAY_REMOVE(TimeMachineFlows_, flows, ret);
    SCFree(ret);
    SCFree(flow);
}

TimeMachineFlow* TimeMachineFlowLookup(TimeMachineFlows* flows, Packet* p) {
    TimeMachineFlowNode search;
    TimeMachineFlowNode* ret;
    
    search.hash = TimeMachineFlowGetKey(p);
        
    ret = SPLAY_FIND(TimeMachineFlows_, flows, &search);
    
    if (ret) {
        return ret->data;
    }
   
    return NULL;
}

TimeMachineFlow* TimeMachineFlowFirst(TimeMachineFlows* flows) {
    TimeMachineFlowNode* ret;
    
    ret = SPLAY_MIN(TimeMachineFlows_, flows);
    
    if (ret) {
        return ret->data;
    }
    
    return NULL;
}