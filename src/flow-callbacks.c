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
    SCFlowInitCallbackFn Callback;
    void *user;
    struct FlowInitCallback_ *next;
} FlowInitCallback;

static FlowInitCallback *init_callbacks = NULL;

typedef struct FlowUpdateCallback_ {
    SCFlowUpdateCallbackFn Callback;
    void *user;
    struct FlowUpdateCallback_ *next;
} FlowUpdateCallback;

static FlowUpdateCallback *update_callbacks = NULL;

typedef struct FlowFinishCallback_ {
    SCFlowFinishCallbackFn Callback;
    void *user;
    struct FlowFinishCallback_ *next;
} FlowFinishCallback;

static FlowFinishCallback *finish_callbacks = NULL;

bool SCFlowRegisterInitCallback(SCFlowInitCallbackFn fn, void *user)
{
    FlowInitCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->Callback = fn;
    cb->user = user;
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

void SCFlowRunInitCallbacks(ThreadVars *tv, Flow *f, const Packet *p)
{
    FlowInitCallback *cb = init_callbacks;
    while (cb != NULL) {
        cb->Callback(tv, f, p, cb->user);
        cb = cb->next;
    }
}

bool SCFlowRegisterUpdateCallback(SCFlowUpdateCallbackFn fn, void *user)
{
    FlowUpdateCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->Callback = fn;
    cb->user = user;
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

void SCFlowRunUpdateCallbacks(ThreadVars *tv, Flow *f, Packet *p)
{
    FlowUpdateCallback *cb = update_callbacks;
    while (cb != NULL) {
        cb->Callback(tv, f, p, cb->user);
        cb = cb->next;
    }
}

bool SCFlowRegisterFinishCallback(SCFlowFinishCallbackFn fn, void *user)
{
    FlowFinishCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->Callback = fn;
    cb->user = user;
    if (finish_callbacks == NULL) {
        finish_callbacks = cb;
    } else {
        FlowFinishCallback *current = finish_callbacks;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = cb;
    }
    return true;
}

void SCFlowRunFinishCallbacks(ThreadVars *tv, Flow *f)
{
    FlowFinishCallback *cb = finish_callbacks;
    while (cb != NULL) {
        cb->Callback(tv, f, cb->user);
        cb = cb->next;
    }
}
