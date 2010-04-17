/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_QUEUE_H__
#define __FLOW_QUEUE_H__

#include "suricata-common.h"
#include "flow.h"

/* Define a queue for storing flows */
typedef struct FlowQueue_
{
    Flow *top;
    Flow *bot;
    uint32_t len;
    SCMutex mutex_q;
    SCCondT cond_q;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
} FlowQueue;

/* prototypes */
FlowQueue *FlowQueueNew();
FlowQueue *FlowQueueInit(FlowQueue *);
void FlowQueueDestroy (FlowQueue *);

void FlowEnqueue (FlowQueue *, Flow *);
Flow *FlowDequeue (FlowQueue *);
void FlowRequeue(Flow *, FlowQueue *, FlowQueue *);

#endif /* __FLOW_QUEUE_H__ */

