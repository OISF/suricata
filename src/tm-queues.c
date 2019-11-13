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

#define TMQ_MAX_QUEUES 256

static uint16_t tmq_id = 0;
static Tmq tmqs[TMQ_MAX_QUEUES];

Tmq *TmqCreateQueue(const char *name)
{
    if (tmq_id >= TMQ_MAX_QUEUES)
        goto error;

    Tmq *q = &tmqs[tmq_id];
    q->name = SCStrdup(name);
    if (q->name == NULL)
        goto error;

    q->id = tmq_id++;
    q->is_packet_pool = (strcmp(q->name, "packetpool") == 0);

    q->pq = PacketQueueAlloc();
    if (q->pq == NULL)
        goto error;

    SCLogDebug("created queue \'%s\', %p", name, q);
    return q;

error:
    SCLogError(SC_ERR_THREAD_QUEUE, "thread queue setup failed for '%s'", name);
    return NULL;
}

Tmq *TmqGetQueueByName(const char *name)
{
    for (uint16_t i = 0; i < tmq_id; i++) {
        if (strcmp(tmqs[i].name, name) == 0)
            return &tmqs[i];
    }
    return NULL;
}

void TmqDebugList(void)
{
    for (int i = 0; i < tmq_id; i++) {
        /* get a lock accessing the len */
        SCMutexLock(&tmqs[i].pq->mutex_q);
        printf("TmqDebugList: id %" PRIu32 ", name \'%s\', len %" PRIu32 "\n", tmqs[i].id, tmqs[i].name, tmqs[i].pq->len);
        SCMutexUnlock(&tmqs[i].pq->mutex_q);
    }
}

void TmqResetQueues(void)
{
    for (int i = 0; i < TMQ_MAX_QUEUES; i++) {
        if (tmqs[i].name) {
            SCFree(tmqs[i].name);
        }
        if (tmqs[i].pq) {
            PacketQueueFree(tmqs[i].pq);
        }
    }
    memset(&tmqs, 0x00, sizeof(tmqs));
    tmq_id = 0;
}

/**
 * \brief Checks if all the queues allocated so far have at least one reader
 *        and writer.
 */
void TmValidateQueueState(void)
{
    bool err = false;

    for (int i = 0; i < tmq_id; i++) {
        SCMutexLock(&tmqs[i].pq->mutex_q);
        if (tmqs[i].reader_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a reader (id %d, max %u)", tmqs[i].name, i, tmq_id);
            err = true;
        } else if (tmqs[i].writer_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a writer (id %d, max %u)", tmqs[i].name, i, tmq_id);
            err = true;
        }
        SCMutexUnlock(&tmqs[i].pq->mutex_q);

        if (err == true)
            goto error;
    }

    return;

error:
    FatalError(SC_ERR_FATAL, "fatal error during threading setup");
}
