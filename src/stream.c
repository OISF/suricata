/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include "eidps.h"
#include "decode.h"
#include "threads.h"

#include "stream.h"

#include "util-pool.h"

static StreamMsgQueue stream_q;

/* per queue setting */
static u_int16_t toserver_min_init_chunk_len = 0;
static u_int16_t toserver_min_chunk_len = 0;
static u_int16_t toclient_min_init_chunk_len = 0;
static u_int16_t toclient_min_chunk_len = 0;

static Pool *stream_msg_pool = NULL;
static pthread_mutex_t stream_msg_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

void *StreamMsgAlloc(void *null) {
    StreamMsg *s = malloc(sizeof(StreamMsg));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(StreamMsg));
    return s;
}

void StreamMsgFree(void *ptr) {
    if (ptr == NULL)
        return;

    StreamMsg *s = (StreamMsg *)ptr;
    free(s);
    return;
}

static void StreamMsgEnqueue (StreamMsgQueue *q, StreamMsg *s) {
    /* more packets in queue */
    if (q->top != NULL) {
        s->next = q->top;
        q->top->prev = s;
        q->top = s;
    /* only packet */
    } else {
        q->top = s;
        q->bot = s;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
}

static StreamMsg *StreamMsgDequeue (StreamMsgQueue *q) {
    /* if the queue is empty there are no packets left.
     * In that case we sleep and try again. */
    if (q->len == 0) {
        return NULL;
    }

    /* pull the bottom packet from the queue */
    StreamMsg *s = q->bot;

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }
    q->len--;

    s->next = NULL;
    s->prev = NULL;
    return s;
}

/* Used by stream reassembler to get msgs */
StreamMsg *StreamMsgGetFromPool(void)
{
    mutex_lock(&stream_msg_pool_mutex);
    StreamMsg *s = (StreamMsg *)PoolGet(stream_msg_pool);
    mutex_unlock(&stream_msg_pool_mutex);
    return s;
}

/* Used by l7inspection to return msgs to pool */
void StreamMsgReturnToPool(StreamMsg *s) {
    mutex_lock(&stream_msg_pool_mutex);
    PoolReturn(stream_msg_pool, (void *)s);
    mutex_unlock(&stream_msg_pool_mutex);
}

/* Used by l7inspection to get msgs with data */
StreamMsg *StreamMsgGetFromQueue(StreamMsgQueue *q)
{
    mutex_lock(&q->mutex_q);
    if (q->len == 0) {
        struct timespec cond_time;
        cond_time.tv_sec = time(NULL) + 5;
        cond_time.tv_nsec = 0;

        /* if we have no stream msgs in queue, wait... for 5 seconds */
        pthread_cond_timedwait(&q->cond_q, &q->mutex_q, &cond_time);
    }
    if (q->len > 0) {
        StreamMsg *s = StreamMsgDequeue(q);
        mutex_unlock(&q->mutex_q);
        return s;
    } else {
        /* return NULL if we have no stream msg. Should only happen on signals. */
        mutex_unlock(&q->mutex_q);
        return NULL;
    }
}

/* Used by stream reassembler to fill the queue for l7inspect reading */
void StreamMsgPutInQueue(StreamMsg *s)
{
    StreamMsgQueue *q = &stream_q;

    mutex_lock(&q->mutex_q);
    StreamMsgEnqueue(q, s);
    printf("StreamMsgPutInQueue: q->len %u\n", q->len);
    pthread_cond_signal(&q->cond_q);
    mutex_unlock(&q->mutex_q);
}

void StreamMsgQueuesInit(void) {
    memset(&stream_q, 0, sizeof(stream_q));

    stream_msg_pool = PoolInit(5000,250,StreamMsgAlloc,NULL,StreamMsgFree);
    if (stream_msg_pool == NULL)
        exit(1); /* XXX */ 
}

StreamMsgQueue *StreamMsgQueueGetByPort(u_int16_t port) {
    /* XXX implement this */
    return &stream_q;
}

/* XXX hack */
void StreamMsgSignalQueueHack(void) {
    pthread_cond_signal(&stream_q.cond_q);
}

void StreamMsgQueueSetMinInitChunkLen(u_int8_t dir, u_int16_t len) {
    if (dir == FLOW_PKT_TOSERVER) {
        toserver_min_init_chunk_len = len;
    } else {
        toclient_min_init_chunk_len = len;
    }
}

void StreamMsgQueueSetMinChunkLen(u_int8_t dir, u_int16_t len) {
    if (dir == FLOW_PKT_TOSERVER) {
        toserver_min_chunk_len = len;
    } else {
        toclient_min_chunk_len = len;
    }
}

u_int16_t StreamMsgQueueGetMinInitChunkLen(u_int8_t dir) {
    if (dir == FLOW_PKT_TOSERVER) {
        return toserver_min_init_chunk_len;
    } else {
        return toclient_min_init_chunk_len;
    }
}

u_int16_t StreamMsgQueueGetMinChunkLen(u_int8_t dir) {
    if (dir == FLOW_PKT_TOSERVER) {
        return toserver_min_chunk_len;
    } else {
        return toclient_min_chunk_len;
    }
}

/* StreamL7RegisterModule
 */
static u_int8_t l7_module_id = 0;
u_int8_t StreamL7RegisterModule(void) {
    u_int8_t id = l7_module_id;
    l7_module_id++;
    return id;
}

u_int8_t StreamL7GetStorageSize(void) {
    return l7_module_id;
}

