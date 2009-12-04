/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_PRIVATE_H__
#define __FLOW_PRIVATE_H__

#include "flow-hash.h"
#include "flow-queue.h"

/* per flow flags */
#define FLOW_TO_SRC_SEEN            0x0001
#define FLOW_TO_DST_SEEN            0x0002

#define FLOW_NEW_LIST               0x0004
#define FLOW_EST_LIST               0x0008
#define FLOW_CLOSED_LIST            0x0010

#define FLOW_TOSERVER_IPONLY_SET    0x0020
#define FLOW_TOCLIENT_IPONLY_SET    0x0040

#define FLOW_NOPACKET_INSPECTION    0x0080  /**< Flag to indicate the packet belongs to this flow should not be inspected*/
#define FLOW_NOPAYLOAD_INSPECTION   0x0100  /**< Flag to indicate the contents or the packet which belongs to this flow should not be inspected*/

/* global flow flags */
#define FLOW_EMERGENCY   0x01

/* Flow Time out values */
#define FLOW_DEFAULT_NEW_TIMEOUT 30
#define FLOW_DEFAULT_EST_TIMEOUT 300
#define FLOW_DEFAULT_CLOSED_TIMEOUT 0
#define FLOW_IPPROTO_TCP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_TCP_EST_TIMEOUT 300
#define FLOW_IPPROTO_UDP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_UDP_EST_TIMEOUT 300
#define FLOW_IPPROTO_ICMP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_ICMP_EST_TIMEOUT 300

#define FLOW_DEFAULT_EMERG_NEW_TIMEOUT 10
#define FLOW_DEFAULT_EMERG_EST_TIMEOUT 100
#define FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT 0
#define FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT 100

enum {
    FLOW_PROTO_DEFAULT = 0,
    FLOW_PROTO_TCP,
    FLOW_PROTO_UDP,
    FLOW_PROTO_ICMP,

    /* should be last */
    FLOW_PROTO_MAX,
};

/*
 * Variables
 */

/** FlowProto specific timeouts and free/state functions */
FlowProto flow_proto[FLOW_PROTO_MAX];

/** spare/unused/prealloced flows live here */
FlowQueue flow_spare_q;

/** Flows in the new/unreplied state live here */
FlowQueue flow_new_q[FLOW_PROTO_MAX];

/** All "established" flows live here, the top holds the
 *  last recently used (lru) flow, so we can remove
 *  that in case of memory problems and check it for
 *  timeouts. */
FlowQueue flow_est_q[FLOW_PROTO_MAX];

/** All "closing" flows live here, the top holds the
 *  last recently used (lru) flow, so we can remove
 *  that in case of memory problems and check it for
 *  timeouts. */
FlowQueue flow_close_q[FLOW_PROTO_MAX];

FlowBucket *flow_hash;
FlowConfig flow_config;

uint8_t flow_flags;

uint32_t flow_memuse;
SCMutex flow_memuse_mutex;

#define FLOWBITS_STATS
#ifdef FLOWBITS_STATS
uint32_t flowbits_memuse;
uint32_t flowbits_memuse_max;
uint32_t flowbits_added;
uint32_t flowbits_removed;
SCMutex flowbits_mutex;
#endif /* FLOWBITS_STATS */

#endif /* __FLOW_PRIVATE_H__ */

