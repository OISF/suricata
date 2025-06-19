/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 */

#ifndef SURICATA_UTIL_MPM_AC_QUEUE_H
#define SURICATA_UTIL_MPM_AC_QUEUE_H

#define STATE_QUEUE_CONTAINER_SIZE 65536

/**
 * \brief Helper structure used by AC during state table creation
 */
typedef struct StateQueue_ {
    uint32_t top;
    uint32_t bot;
    uint32_t size;
    int32_t *store;
} StateQueue;

StateQueue *SCACStateQueueAlloc(void);
void SCACStateQueueFree(StateQueue *q);

static inline int SCACStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACEnqueue(StateQueue *q, int32_t state)
{
    /*if we already have this */
    for (uint32_t i = q->bot; i < q->top; i++) {
        if (q->store[i] == state)
            return;
    }

    q->store[q->top++] = state;

    if (q->top == q->size)
        q->top = 0;

    if (q->top == q->bot) {
        // allocate a new store and copy + realign
        int32_t *tmp = SCCalloc(q->size + STATE_QUEUE_CONTAINER_SIZE, sizeof(int32_t));
        if (tmp == NULL) {
            FatalError("Error reallocating memory");
        }
        memcpy(tmp, q->store + q->bot, (q->size - q->bot) * sizeof(int32_t));
        memcpy(tmp + (q->size - q->bot), q->store, q->top * sizeof(int32_t));
        SCFree(q->store);
        q->store = tmp;
        q->bot = 0;
        q->top = q->size;
        q->size += STATE_QUEUE_CONTAINER_SIZE;
    }
}

static inline int32_t SCACDequeue(StateQueue *q)
{
    if (q->bot == q->size)
        q->bot = 0;

    if (q->bot == q->top) {
        FatalError("StateQueue behaving weirdly.  "
                   "Fatal Error.  Exiting.  Please file a bug report on this");
    }

    return q->store[q->bot++];
}

#endif /* SURICATA_UTIL_MPM_AC_QUEUE_H */
