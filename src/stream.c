/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Stream Handling API
 */

#include "suricata-common.h"
#include "decode.h"
#include "threads.h"
#include "stream.h"
#include "util-pool.h"
#include "util-debug.h"

static SCMutex stream_pool_memuse_mutex;
static uint64_t stream_pool_memuse = 0;
static uint64_t stream_pool_memcnt = 0;

//static StreamMsgQueue stream_q;

/* per queue setting */
static uint16_t toserver_min_init_chunk_len = 0;
static uint16_t toserver_min_chunk_len = 0;
static uint16_t toclient_min_init_chunk_len = 0;
static uint16_t toclient_min_chunk_len = 0;

static Pool *stream_msg_pool = NULL;
static SCMutex stream_msg_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

void *StreamMsgAlloc(void *null) {
    StreamMsg *s = SCMalloc(sizeof(StreamMsg));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(StreamMsg));

    SCMutexLock(&stream_pool_memuse_mutex);
    stream_pool_memuse += sizeof(StreamMsg);
    stream_pool_memcnt ++;
    SCMutexUnlock(&stream_pool_memuse_mutex);
    return s;
}

void StreamMsgFree(void *ptr) {
    if (ptr == NULL)
        return;

    StreamMsg *s = (StreamMsg *)ptr;
    SCFree(s);
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
    SCMutexLock(&stream_msg_pool_mutex);
    StreamMsg *s = (StreamMsg *)PoolGet(stream_msg_pool);
    SCMutexUnlock(&stream_msg_pool_mutex);
    return s;
}

/* Used by l7inspection to return msgs to pool */
void StreamMsgReturnToPool(StreamMsg *s) {
    SCMutexLock(&stream_msg_pool_mutex);
    PoolReturn(stream_msg_pool, (void *)s);
    SCMutexUnlock(&stream_msg_pool_mutex);
}

/* Used by l7inspection to get msgs with data */
StreamMsg *StreamMsgGetFromQueue(StreamMsgQueue *q)
{
    SCMutexLock(&q->mutex_q);
    if (q->len == 0) {
        struct timespec cond_time;
        cond_time.tv_sec = time(NULL) + 5;
        cond_time.tv_nsec = 0;

        /* if we have no stream msgs in queue, wait... for 5 seconds */
        SCCondTimedwait(&q->cond_q, &q->mutex_q, &cond_time);
    }
    if (q->len > 0) {
        StreamMsg *s = StreamMsgDequeue(q);
        SCMutexUnlock(&q->mutex_q);
        return s;
    } else {
        /* return NULL if we have no stream msg. Should only happen on signals. */
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }
}

/* Used by stream reassembler to fill the queue for l7inspect reading */
void StreamMsgPutInQueue(StreamMsgQueue *q, StreamMsg *s)
{
    SCMutexLock(&q->mutex_q);
    StreamMsgEnqueue(q, s);
    SCLogDebug("q->len %" PRIu32 "", q->len);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
}

void StreamMsgQueuesInit(void) {
    SCMutexInit(&stream_pool_memuse_mutex, NULL);
    //memset(&stream_q, 0, sizeof(stream_q));

    stream_msg_pool = PoolInit(5000,250,StreamMsgAlloc,NULL,StreamMsgFree);
    if (stream_msg_pool == NULL)
        exit(EXIT_FAILURE); /* XXX */
}

void StreamMsgQueuesDeinit(char quiet) {
    PoolFree(stream_msg_pool);
    SCMutexDestroy(&stream_pool_memuse_mutex);

    if (quiet == FALSE)
        SCLogDebug("stream_pool_memuse %"PRIu64", stream_pool_memcnt %"PRIu64"", stream_pool_memuse, stream_pool_memcnt);
}

/** \brief alloc a stream msg queue
 *  \retval smq ptr to the queue or NULL */
StreamMsgQueue *StreamMsgQueueGetNew(void) {
    StreamMsgQueue *smq = SCMalloc(sizeof(StreamMsgQueue));
    if (smq == NULL) {
        return NULL;
    }

    memset(smq, 0x00, sizeof(StreamMsgQueue));
    SCMutexInit(&smq->mutex_q, NULL);
    SCCondInit(&smq->cond_q, NULL);
    return smq;
}

/** \brief Free a StreamMsgQueue
 *  \param q the queue to free
 *  \todo we may want to consider non empty queue's
 */
void StreamMsgQueueFree(StreamMsgQueue *q) {
    SCFree(q);
}

StreamMsgQueue *StreamMsgQueueGetByPort(uint16_t port) {
    /* XXX implement this */
    return NULL;//&stream_q;
}

/* XXX hack */
void StreamMsgSignalQueueHack(void) {
    //SCCondSignal(&stream_q.cond_q);
}

void StreamMsgQueueSetMinInitChunkLen(uint8_t dir, uint16_t len) {
    if (dir == FLOW_PKT_TOSERVER) {
        toserver_min_init_chunk_len = len;
    } else {
        toclient_min_init_chunk_len = len;
    }
}

void StreamMsgQueueSetMinChunkLen(uint8_t dir, uint16_t len) {
    if (dir == FLOW_PKT_TOSERVER) {
        toserver_min_chunk_len = len;
    } else {
        toclient_min_chunk_len = len;
    }
}

uint16_t StreamMsgQueueGetMinInitChunkLen(uint8_t dir) {
    if (dir == FLOW_PKT_TOSERVER) {
        return toserver_min_init_chunk_len;
    } else {
        return toclient_min_init_chunk_len;
    }
}

uint16_t StreamMsgQueueGetMinChunkLen(uint8_t dir) {
    if (dir == FLOW_PKT_TOSERVER) {
        return toserver_min_chunk_len;
    } else {
        return toclient_min_chunk_len;
    }
}

/* StreamL7RegisterModule
 */
static uint8_t l7_module_id = 0;
uint8_t StreamL7RegisterModule(void) {
    uint8_t id = l7_module_id;
    l7_module_id++;
    return id;
}

uint8_t StreamL7GetStorageSize(void) {
    return l7_module_id;
}

