/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_H__
#define __FLOW_H__

#include "decode.h"
#include "util-var.h"

#define FLOW_QUIET      TRUE
#define FLOW_VERBOSE    FALSE

/* pkt flow flags */
#define FLOW_PKT_TOSERVER            0x01
#define FLOW_PKT_TOCLIENT            0x02
#define FLOW_PKT_ESTABLISHED         0x04
#define FLOW_PKT_STATELESS           0x08
#define FLOW_PKT_TOSERVER_IPONLY_SET 0x10
#define FLOW_PKT_TOCLIENT_IPONLY_SET 0x20
#define FLOW_PKT_NOSTREAM            0x40
#define FLOW_PKT_STREAMONLY          0x80

/* global flow config */
typedef struct FlowCnf_
{
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t max_flows;
    uint32_t memcap;
    uint32_t memuse;
    uint32_t prealloc;

    uint32_t timeout_new;
    uint32_t timeout_est;

    uint32_t emerg_timeout_new;
    uint32_t emerg_timeout_est;

} FlowConfig;

/* Hash key for the flow hash */
typedef struct FlowKey_
{
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint8_t recursion_level;

} FlowKey;

typedef struct Flow_
{
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint8_t recursion_level;

    uint8_t flags;

    /* ts of flow init and last update */
    struct timeval startts;
    struct timeval lastts;

    /* pointer to the var list */
    GenericVar *flowvar;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t bytecnt;

    void *stream;
    uint16_t use_cnt; /** how many pkts and stream msgs are
                           using the flow *right now* */

    pthread_mutex_t m;

    /* list flow ptrs
     * NOTE!!! These are NOT protected by the
     * above mutex, but by the FlowQ's */
    struct Flow_ *hnext; /* hash list */
    struct Flow_ *hprev;
    struct Flow_ *lnext; /* list */
    struct Flow_ *lprev;

    struct FlowBucket_ *fb;
} Flow;

void FlowHandlePacket (ThreadVars *, Packet *);
void FlowInitConfig (char);
void FlowPrintFlows (void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, char);
void FlowDecrUsecnt(ThreadVars *, Packet *);

void *FlowManagerThread(void *td);

void FlowManagerThreadSpawn(void);

#endif /* __FLOW_H__ */

