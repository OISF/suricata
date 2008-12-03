/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_NFQ_H__
#define __SOURCE_NFQ_H__

#include <pthread.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQ_MAX_QUEUE 16

/* idea: set the recv-thread id in the packet to
 * select an verdict-queue */

typedef struct _NFQPacketVars
{
    int id; /* this nfq packets id */

    u_int32_t mark;
    u_int32_t ifi;
    u_int32_t ifo;
    u_int16_t hw_protocol;
} NFQPacketVars;

typedef struct _NFQThreadVars
{
    struct nfq_handle *h;
    struct nfnl_handle *nh;
    /* 2 threads deal with the queue handle, so add a mutex */
    struct nfq_q_handle *qh;
    pthread_mutex_t mutex_qh;
    /* this one should be not changing after init */
    u_int16_t queue_num;
    int fd;

#ifdef DBG_PERF
    int dbg_maxreadsize;
#endif /* DBG_PERF */

    /* counters */
    u_int32_t pkts;
    u_int64_t bytes;
    u_int32_t errs;
    u_int32_t accepted;
    u_int32_t dropped;

    ThreadVars *tv;
} NFQThreadVars;

typedef struct _NFQGlobalVars
{
    char unbind;
} NFQGlobalVars;

#endif /* __SOURCE_NFQ_H__ */

