/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_NFQ_H__
#define __SOURCE_NFQ_H__

#ifdef NFQ

#include "threads.h"
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQ_MAX_QUEUE 16

/* idea: set the recv-thread id in the packet to
 * select an verdict-queue */

typedef struct NFQPacketVars_
{
    int id; /* this nfq packets id */

    uint32_t mark;
    uint32_t ifi;
    uint32_t ifo;
    uint16_t hw_protocol;
} NFQPacketVars;

typedef struct NFQThreadVars_
{
    struct nfq_handle *h;
    struct nfnl_handle *nh;
    /* 2 threads deal with the queue handle, so add a mutex */
    struct nfq_q_handle *qh;
    SCMutex mutex_qh;
    /* this one should be not changing after init */
    uint16_t queue_num;
    int fd;
#ifdef DBG_PERF
    int dbg_maxreadsize;
#endif /* DBG_PERF */

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;

    ThreadVars *tv;
} NFQThreadVars;

typedef struct NFQGlobalVars_
{
    char unbind;
} NFQGlobalVars;

#endif /* NFQ */
#endif /* __SOURCE_NFQ_H__ */

