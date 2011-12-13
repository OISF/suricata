/**
 * Copyright (c) 2009, 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "data-queue.h"
#include "threads.h"

/**
 * \brief Enqueues data on the queue.
 *
 * \param q    Pointer to the data queue.
 * \param data Pointer to the data to be queued.  It should be a pointer to a
 *             structure instance that implements the template structure
 *             struct SCDQGenericQData_ defined in data-queue.h.
 */
void SCDQDataEnqueue(SCDQDataQueue *q, SCDQGenericQData *data)
{
    /* we already have some data in queue */
    if (q->top != NULL) {
        data->next = q->top;
        q->top->prev = data;
        q->top = data;

    /* the queue is empty */
    } else {
        q->top = data;
        q->bot = data;
    }

    q->len++;

#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */

    return;
}

/**
 * \brief Dequeues and returns an entry from the queue.
 *
 * \param q      Pointer to the data queue.
 * \param retval Pointer to the data that has been enqueued.  The instance
 *               returned is/should be a pointer to a structure instance that
 *               implements the template structure struct SCDQGenericQData_
 *               defined in data-queue.h.
 */
SCDQGenericQData *SCDQDataDequeue(SCDQDataQueue *q)
{
    SCDQGenericQData *data = NULL;

    /* if the queue is empty there are is no data left and we return NULL */
    if (q->len == 0) {
        return NULL;
    }

    /* If we are going to get the last packet, set len to 0
     * before doing anything else (to make the threads to follow
     * the SCondWait as soon as possible) */
    q->len--;

    /* pull the bottom packet from the queue */
    data = q->bot;

#ifdef OS_DARWIN
    /* Weird issue in OS_DARWIN
     * Sometimes it looks that two thread arrive here at the same time
     * so the bot ptr is NULL */
    if (data == NULL) {
        printf("No data to dequeue!\n");
        return NULL;
    }
#endif /* OS_DARWIN */

    /* more data in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    data->next = NULL;
    data->prev = NULL;

    return data;
}
