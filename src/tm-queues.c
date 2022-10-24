/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * Thread module management functions
 */

#include "suricata.h"
#include "threads.h"
#include "tm-queues.h"
#include "util-debug.h"

static TAILQ_HEAD(TmqList_, Tmq_) tmq_list = TAILQ_HEAD_INITIALIZER(tmq_list);

static uint16_t tmq_id = 0;

Tmq *TmqCreateQueue(const char *name)
{
    Tmq *q = SCCalloc(1, sizeof(*q));
    if (q == NULL)
        FatalError(SC_ENOMEM, "SCCalloc failed");

    q->name = SCStrdup(name);
    if (q->name == NULL)
        FatalError(SC_ENOMEM, "SCStrdup failed");

    q->id = tmq_id++;
    q->is_packet_pool = (strcmp(q->name, "packetpool") == 0);
    if (!q->is_packet_pool) {
        q->pq = PacketQueueAlloc();
        if (q->pq == NULL)
            FatalError(SC_ENOMEM, "PacketQueueAlloc failed");
    }

    TAILQ_INSERT_HEAD(&tmq_list, q, next);

    SCLogDebug("created queue \'%s\', %p", name, q);
    return q;
}

Tmq *TmqGetQueueByName(const char *name)
{
    Tmq *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        if (strcmp(tmq->name, name) == 0)
            return tmq;
    }
    return NULL;
}

void TmqDebugList(void)
{
    Tmq *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        /* get a lock accessing the len */
        SCMutexLock(&tmq->pq->mutex_q);
        printf("TmqDebugList: id %" PRIu32 ", name \'%s\', len %" PRIu32 "\n", tmq->id, tmq->name, tmq->pq->len);
        SCMutexUnlock(&tmq->pq->mutex_q);
    }
}

void TmqResetQueues(void)
{
    Tmq *tmq;

    while ((tmq = TAILQ_FIRST(&tmq_list))) {
        TAILQ_REMOVE(&tmq_list, tmq, next);
        if (tmq->name) {
            SCFree(tmq->name);
        }
        if (tmq->pq) {
            PacketQueueFree(tmq->pq);
        }
        SCFree(tmq);
    }
    tmq_id = 0;
}

/**
 * \brief Checks if all the queues allocated so far have at least one reader
 *        and writer.
 */
void TmValidateQueueState(void)
{
    bool err = false;

    Tmq *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        SCMutexLock(&tmq->pq->mutex_q);
        if (tmq->reader_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a reader (id %d max %u)",
                    tmq->name, tmq->id, tmq_id);
            err = true;
        } else if (tmq->writer_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a writer (id %d, max %u)",
                    tmq->name, tmq->id, tmq_id);
            err = true;
        }
        SCMutexUnlock(&tmq->pq->mutex_q);

        if (err == true)
            goto error;
    }

    return;

error:
    FatalError(SC_ERR_FATAL, "fatal error during threading setup");
}
