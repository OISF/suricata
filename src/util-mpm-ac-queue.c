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

#define STATE_QUEUE_CONTAINER_SIZE 65536

/**
 * \brief Helper structure used by AC during state table creation
 */
typedef struct StateQueue_ {
    int top;
    int bot;
    uint32_t size;
    int32_t *store;
} StateQueue;

static inline StateQueue *SCACStateQueueAlloc(void)
{
    StateQueue *q = SCCalloc(1, sizeof(StateQueue));
    if (q == NULL) {
        FatalError("Error allocating memory");
    }
    q->store = SCCalloc(STATE_QUEUE_CONTAINER_SIZE, sizeof(int32_t));
    if (q->store == NULL) {
        FatalError("Error allocating memory");
    }
    q->size = STATE_QUEUE_CONTAINER_SIZE;
    return q;
}

static inline void SCACStateQueueFree(StateQueue *q)
{
    SCFree(q->store);
    SCFree(q);
}

static inline int SCACStateQueueIsEmpty(StateQueue *q)
{
    if (q->top == q->bot)
        return 1;
    else
        return 0;
}

static inline void SCACEnqueue(StateQueue *q, int32_t state)
{
    int i = 0;

    /*if we already have this */
    for (i = q->bot; i < q->top; i++) {
        if (q->store[i] == state)
            return;
    }

    q->store[q->top++] = state;

    if (q->top == STATE_QUEUE_CONTAINER_SIZE)
        q->top = 0;

    if (q->top == q->bot) {
        FatalError("Just ran out of space in the queue.  "
                   "Fatal Error.  Exiting.  Please file a bug report on this");
    }
}

static inline int32_t SCACDequeue(StateQueue *q)
{
    if (q->bot == STATE_QUEUE_CONTAINER_SIZE)
        q->bot = 0;

    if (q->bot == q->top) {
        FatalError("StateQueue behaving weirdly.  "
                   "Fatal Error.  Exiting.  Please file a bug report on this");
    }

    return q->store[q->bot++];
}
