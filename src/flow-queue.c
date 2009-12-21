/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "flow-queue.h"
#include "flow-util.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"
#include <string.h>

FlowQueue *FlowQueueNew() {
    FlowQueue *q = (FlowQueue *)malloc(sizeof(FlowQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,"Error allocating flow queue");
        exit(EXIT_SUCCESS);
    }
    q = FlowQueueInit(q);
    return q;
}

FlowQueue *FlowQueueInit (FlowQueue *q) {
    if (q != NULL) {
        memset(q, 0, sizeof(FlowQueue));
        SCMutexInit(&q->mutex_q, NULL);
        SCCondInit(&q->cond_q, NULL);
    }
    return q;
}

void FlowEnqueue (FlowQueue *q, Flow *f) {
    /* more packets in queue */
    if (q->top != NULL) {
        f->lnext = q->top;
        q->top->lprev = f;
        q->top = f;
    /* only packet */
    } else {
        q->top = f;
        q->bot = f;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
}

Flow *FlowDequeue (FlowQueue *q) {
    SCMutexLock(&q->mutex_q);

    Flow *f = q->bot;
    if (f == NULL) {
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->lprev != NULL) {
        q->bot = q->bot->lprev;
        q->bot->lnext = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    q->len--;

    f->lnext = NULL;
    f->lprev = NULL;

    SCMutexUnlock(&q->mutex_q);
    return f;
}

void FlowRequeue(Flow *f, FlowQueue *srcq, FlowQueue *dstq)
{
    if (srcq != NULL)
    {
        SCMutexLock(&srcq->mutex_q);

        /* remove from old queue */
        if (srcq->top == f)
            srcq->top = f->lnext;       /* remove from queue top */
        if (srcq->bot == f)
            srcq->bot = f->lprev;       /* remove from queue bot */
        if (f->lprev)
            f->lprev->lnext = f->lnext; /* remove from flow prev */
        if (f->lnext)
            f->lnext->lprev = f->lprev; /* remove from flow next */

        srcq->len--; /* adjust len */

        f->lnext = NULL;
        f->lprev = NULL;

        /* don't unlock if src and dst are the same */
        if (srcq != dstq) SCMutexUnlock(&srcq->mutex_q);
    }

    /* now put it in dst */
    if (srcq != dstq) SCMutexLock(&dstq->mutex_q);

    /* add to new queue (append) */
    f->lprev = dstq->bot;
    if (f->lprev)
        f->lprev->lnext = f;
    f->lnext = NULL;
    dstq->bot = f;
    if (dstq->top == NULL)
        dstq->top = f;

    dstq->len++;
#ifdef DBG_PERF
    if (dstq->len > dstq->dbg_maxlen)
        dstq->dbg_maxlen = dstq->len;
#endif /* DBG_PERF */

    SCMutexUnlock(&dstq->mutex_q);
}

