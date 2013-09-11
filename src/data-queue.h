/**
 * Copyright (c) 2009, 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * \file Generic queues.  Any instance that wants to get itself on the generic
 *       queue, would have to implement the template struct SCDQGenericQData_
 *       defined below.
 */

#ifndef __DATA_QUEUE_H__
#define __DATA_QUEUE_H__

#include "threads.h"

/**
 * \brief Generic template for any data structure that wants to be on the
 *        queue.  Any other data structure that wants to be on the queue
 *        needs to use this template and define its own members from
 *        <your_own_structure_members_from_here_on> onwards.
 */
typedef struct SCDQGenericQData_ {
    /* this is needed when we want to supply a list of data items */
    struct SCDQGenericQData_ *next;
    struct SCDQGenericQData_ *prev;
    /* if we want to consider this pointer as the head of a list, this var
     * holds the no of elements in the list.  Else it holds a <need_to_think>. */
    //uint16_t len;
    /* in case this data instance is the head of a list, we can refer the
     * bottomost instance directly using this var */
    //struct SCDQGenericaQData *bot;


    /* any other data structure that wants to be on the queue can implement
     * its own memebers from here on, in its structure definition.  Just note
     * that the first 2 members should always be next and prev in the same
     * order */
    // <your_own_structure_members_from_here_on>
} SCDQGenericQData;

/**
 * \brief The data queue to hold instances that implement the template
 *        SCDQGenericQData.
 */
typedef struct SCDQDataQueue_ {
    /* holds the item at the top of the queue */
    SCDQGenericQData *top;
    /* holds the item at the bottom of the queue */
    SCDQGenericQData *bot;
    /* no of items currently in the queue */
    uint16_t len;
#ifdef DBG_PERF
    uint16_t dbg_maxlen;
#endif /* DBG_PERF */

    SCMutex mutex_q;
    SCCondT cond_q;

} __attribute__((aligned(CLS))) SCDQDataQueue;

void SCDQDataEnqueue(SCDQDataQueue *, SCDQGenericQData *);
SCDQGenericQData *SCDQDataDequeue(SCDQDataQueue *);

#endif /* __DATA_QUEUE_H__ */
