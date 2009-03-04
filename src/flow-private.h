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

u_int8_t flow_flags;

u_int32_t flow_memuse;
pthread_mutex_t flow_memuse_mutex;

#define FLOWBITS_STATS
#ifdef FLOWBITS_STATS
u_int32_t flowbits_memuse;
u_int32_t flowbits_memuse_max;
u_int32_t flowbits_added;
u_int32_t flowbits_removed;
pthread_mutex_t flowbits_mutex;
#endif /* FLOWBITS_STATS */

#endif /* __FLOW_PRIVATE_H__ */

