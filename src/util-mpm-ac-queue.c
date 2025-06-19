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

#include "suricata-common.h"
#include "util-debug.h"
#include "util-mpm-ac-queue.h"

StateQueue *SCACStateQueueAlloc(void)
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

void SCACStateQueueFree(StateQueue *q)
{
    SCFree(q->store);
    SCFree(q);
}
