/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_QUEUE_H__
#define __FLOW_QUEUE_H__

#include "flow.h"

/* Define a queue for storing flows */
typedef struct FlowQueue_
{
    Flow *top;
    Flow *bot;
    uint32_t len;
    pthread_mutex_t mutex_q;
    pthread_cond_t cond_q;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
} FlowQueue;

/* prototypes */
void FlowEnqueue (FlowQueue *, Flow *);
Flow *FlowDequeue (FlowQueue *);
void FlowRequeue(Flow *, FlowQueue *, FlowQueue *);

#endif /* __FLOW_QUEUE_H__ */

