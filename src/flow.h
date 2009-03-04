/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_H__
#define __FLOW_H__

#include "decode.h"
#include "util-var.h"

/* pkt flow flags */
#define FLOW_PKT_TOSERVER            0x01
#define FLOW_PKT_TOCLIENT            0x02
#define FLOW_PKT_ESTABLISHED         0x04
#define FLOW_PKT_STATELESS           0x08
#define FLOW_PKT_TOSERVER_IPONLY_SET 0x10
#define FLOW_PKT_TOCLIENT_IPONLY_SET 0x20

/* global flow config */
typedef struct _FlowCnf
{
    u_int32_t hash_rand;
    u_int32_t hash_size;
    u_int32_t max_flows;
    u_int32_t memcap;
    u_int32_t memuse;
    u_int32_t prealloc;

    u_int32_t timeout_new;
    u_int32_t timeout_est;

    u_int32_t emerg_timeout_new;
    u_int32_t emerg_timeout_est;

} FlowConfig;

typedef struct _FlowKey
{
    Address src, dst;
    Port sp, dp;
    u_int8_t proto;
    u_int8_t recursion_level;

} FlowKey;

typedef struct _Flow
{
    Address src, dst;
    Port sp, dp;
    u_int8_t proto;
    u_int8_t recursion_level;

    u_int8_t flags;

    /* ts of flow init and last update */
    struct timeval startts;
    struct timeval lastts;

    /* pointer to the var list */
    GenericVar *flowvar;

    u_int32_t todstpktcnt;
    u_int32_t tosrcpktcnt;
    u_int64_t bytecnt;

    pthread_mutex_t m;

    /* list flow ptrs
     * NOTE!!! These are NOT protected by the
     * above mutex, but by the FlowQ's */
    struct _Flow *hnext; /* hash list */
    struct _Flow *hprev;
    struct _Flow *lnext; /* list */
    struct _Flow *lprev;

    struct _FlowBucket *fb;
} Flow;

void FlowHandlePacket (ThreadVars *, Packet *);
void FlowInitConfig (void);
void FlowPrintFlows (void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, char);

void *FlowManagerThread(void *td);

#endif /* __FLOW_H__ */

