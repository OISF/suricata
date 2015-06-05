/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Stream Chunk Handling API
 */

#include "suricata-common.h"
#include "decode.h"
#include "threads.h"
#include "stream.h"
#include "util-pool.h"
#include "util-debug.h"
#include "stream-tcp.h"
#include "flow-util.h"

#ifdef DEBUG
static SCMutex stream_pool_memuse_mutex;
static uint64_t stream_pool_memuse = 0;
static uint64_t stream_pool_memcnt = 0;
#endif

/* per queue setting */
static uint16_t toserver_min_chunk_len = 2560;
static uint16_t toclient_min_chunk_len = 2560;

static Pool *stream_msg_pool = NULL;
static SCMutex stream_msg_pool_mutex = SCMUTEX_INITIALIZER;

static void StreamMsgEnqueue (StreamMsgQueue *q, StreamMsg *s)
{
    SCEnter();
    SCLogDebug("s %p", s);
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
    SCReturn;
}

static StreamMsg *StreamMsgDequeue (StreamMsgQueue *q)
{
    SCEnter();

    /* if the queue is empty there are no packets left.
     * In that case we sleep and try again. */
    if (q->len == 0) {
        SCReturnPtr(NULL, "StreamMsg");
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
    SCReturnPtr(s, "StreamMsg");
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
void StreamMsgReturnToPool(StreamMsg *s)
{
    SCLogDebug("s %p", s);
    SCMutexLock(&stream_msg_pool_mutex);
    PoolReturn(stream_msg_pool, (void *)s);
    SCMutexUnlock(&stream_msg_pool_mutex);
}

/* Used by l7inspection to get msgs with data */
StreamMsg *StreamMsgGetFromQueue(StreamMsgQueue *q)
{
    if (q->len > 0) {
        StreamMsg *s = StreamMsgDequeue(q);
        return s;
    } else {
        /* return NULL if we have no stream msg. Should only happen on signals. */
        return NULL;
    }
}

/* Used by stream reassembler to fill the queue for l7inspect reading */
void StreamMsgPutInQueue(StreamMsgQueue *q, StreamMsg *s)
{
    StreamMsgEnqueue(q, s);
    SCLogDebug("q->len %" PRIu32 "", q->len);
}

#define SIZE 4072
void *StreamMsgPoolAlloc(void)
{
    if (StreamTcpReassembleCheckMemcap((uint32_t)(sizeof(StreamMsg)+SIZE)) == 0)
        return NULL;

    StreamMsg *m = SCCalloc(1, (sizeof(StreamMsg) + SIZE));
    if (m != NULL) {
        m->data = (uint8_t *)m + sizeof(StreamMsg);
        m->data_size = SIZE;

        StreamTcpReassembleIncrMemuse((uint32_t)(sizeof(StreamMsg)+SIZE));
    }

    return m;
}

int StreamMsgInit(void *data, void *initdata)
{
    StreamMsg *s = data;
    memset(s->data, 0, s->data_size);

#ifdef DEBUG
    SCMutexLock(&stream_pool_memuse_mutex);
    stream_pool_memuse += (sizeof(StreamMsg) + SIZE);
    stream_pool_memcnt ++;
    SCMutexUnlock(&stream_pool_memuse_mutex);
#endif
    return 1;
}

void StreamMsgPoolFree(void *ptr)
{
    if (ptr) {
        SCFree(ptr);
        StreamTcpReassembleDecrMemuse((uint32_t)(sizeof(StreamMsg)+SIZE));
    }
}

void StreamMsgQueuesInit(uint32_t prealloc)
{
#ifdef DEBUG
    SCMutexInit(&stream_pool_memuse_mutex, NULL);
#endif
    SCMutexLock(&stream_msg_pool_mutex);
    stream_msg_pool = PoolInit(0, prealloc, 0,
            StreamMsgPoolAlloc,StreamMsgInit,
            NULL,NULL,StreamMsgPoolFree);
    if (stream_msg_pool == NULL)
        exit(EXIT_FAILURE); /* XXX */
    SCMutexUnlock(&stream_msg_pool_mutex);
}

void StreamMsgQueuesDeinit(char quiet)
{
    if (quiet == FALSE) {
        if (stream_msg_pool->max_outstanding > stream_msg_pool->allocated)
            SCLogInfo("TCP segment chunk pool had a peak use of %u chunks, "
                    "more than the prealloc setting of %u",
                    stream_msg_pool->max_outstanding, stream_msg_pool->allocated);
    }

    SCMutexLock(&stream_msg_pool_mutex);
    PoolFree(stream_msg_pool);
    SCMutexUnlock(&stream_msg_pool_mutex);

#ifdef DEBUG
    SCMutexDestroy(&stream_pool_memuse_mutex);

    if (quiet == FALSE)
        SCLogDebug("stream_pool_memuse %"PRIu64", stream_pool_memcnt %"PRIu64"", stream_pool_memuse, stream_pool_memcnt);
#endif
}

/** \brief alloc a stream msg queue
 *  \retval smq ptr to the queue or NULL */
StreamMsgQueue *StreamMsgQueueGetNew(void)
{
    if (StreamTcpReassembleCheckMemcap((uint32_t)sizeof(StreamMsgQueue)) == 0)
        return NULL;

    StreamMsgQueue *smq = SCMalloc(sizeof(StreamMsgQueue));
    if (unlikely(smq == NULL))
        return NULL;

    StreamTcpReassembleIncrMemuse((uint32_t)sizeof(StreamMsgQueue));

    memset(smq, 0x00, sizeof(StreamMsgQueue));
    return smq;
}

/** \brief Free a StreamMsgQueue
 *  \param q the queue to free
 *  \todo we may want to consider non empty queue's
 */
void StreamMsgQueueFree(StreamMsgQueue *q)
{
    SCFree(q);
    StreamTcpReassembleDecrMemuse((uint32_t)sizeof(StreamMsgQueue));
}

void StreamMsgQueueSetMinChunkLen(uint8_t dir, uint16_t len)
{
    if (dir == FLOW_PKT_TOSERVER) {
        toserver_min_chunk_len = len;
    } else {
        toclient_min_chunk_len = len;
    }
}

uint16_t StreamMsgQueueGetMinChunkLen(uint8_t dir)
{
    if (dir == FLOW_PKT_TOSERVER) {
        return toserver_min_chunk_len;
    } else {
        return toclient_min_chunk_len;
    }
}

/** \brief Return a list of smsgs to the pool */
void StreamMsgReturnListToPool(void *list)
{
    /* if we have (a) smsg(s), return to the pool */
    StreamMsg *smsg = (StreamMsg *)list;
    while (smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
}

/** \brief Run callback for all segments
 *
 * \return -1 in case of error, the number of segment in case of success
 */
int StreamSegmentForEach(const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    switch(p->proto) {
        case IPPROTO_TCP:
            return StreamTcpSegmentForEach(p, flag, CallbackFunc, data);
            break;
#ifdef DEBUG
        case IPPROTO_UDP:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "UDP is currently unsupported");
            break;
        default:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "This protocol is currently unsupported");
            break;
#endif
    }
    return 0;
}
