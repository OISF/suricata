/* Copyright (C) 2024 Open Information Security Foundation
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

#include "flow-callbacks.h"

typedef struct FlowInitCallback_ {
    SCFlowInitCallbackFn fn;
    struct FlowInitCallback_ *next;
} FlowInitCallback;

static FlowInitCallback *init_callbacks = NULL;

typedef struct FlowUpdateCallback_ {
    SCFlowUpdateCallbackFn fn;
    struct FlowUpdateCallback_ *next;
} FlowUpdateCallback;

static FlowUpdateCallback *update_callbacks = NULL;

bool SCFlowRegisterInitCallback(SCFlowInitCallbackFn fn)
{
    FlowInitCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->fn = fn;
    if (init_callbacks == NULL) {
        init_callbacks = cb;
    } else {
        FlowInitCallback *current = init_callbacks;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = cb;
    }
    return true;
}

void SCFlowRunInitCallbacks(Flow *f, const Packet *p)
{
    FlowInitCallback *cb = init_callbacks;
    while (cb != NULL) {
        cb->fn(f, p);
        cb = cb->next;
    }
}

bool SCFlowRegisterUpdateCallback(SCFlowUpdateCallbackFn fn)
{
    FlowUpdateCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->fn = fn;
    if (update_callbacks == NULL) {
        update_callbacks = cb;
    } else {
        FlowUpdateCallback *current = update_callbacks;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = cb;
    }
    return true;
}

void SCFlowRunUpdateCallbacks(Flow *f, Packet *p, ThreadVars *tv)
{
    FlowUpdateCallback *cb = update_callbacks;
    while (cb != NULL) {
        cb->fn(f, p, tv);
        cb = cb->next;
    }
}
