/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_PRIVATE_H__
#define __FLOW_PRIVATE_H__

#include "flow-hash.h"
#include "flow-queue.h"

/* per flow flags */
#define FLOW_TO_SRC_SEEN         0x01
#define FLOW_TO_DST_SEEN         0x02
#define FLOW_NEW_LIST            0x04
#define FLOW_EST_LIST            0x08
#define FLOW_TOSERVER_IPONLY_SET 0x10
#define FLOW_TOCLIENT_IPONLY_SET 0x20

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

/*
 * Variables
 */

FlowQueue flow_spare_q; /* Spare flow's. Prealloced flows in here */
FlowQueue flow_new_q;   /* Flows in the unreplied state live here */
FlowQueue flow_est_q;   /* All other flows live here, the top holds the
                         * last recently used (lru) flow, so we can remove
                         * that in case of memory problems and check it for
                         * timeouts. */
FlowBucket *flow_hash;
FlowConfig flow_config;

uint8_t flow_flags;

uint32_t flow_memuse;
pthread_mutex_t flow_memuse_mutex;

#define FLOWBITS_STATS
#ifdef FLOWBITS_STATS
uint32_t flowbits_memuse;
uint32_t flowbits_memuse_max;
uint32_t flowbits_added;
uint32_t flowbits_removed;
pthread_mutex_t flowbits_mutex;
#endif /* FLOWBITS_STATS */

#endif /* __FLOW_PRIVATE_H__ */

