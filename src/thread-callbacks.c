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

#include "thread-callbacks.h"

typedef struct ThreadInitCallback_ {
    SCThreadInitCallbackFn Callback;
    void *user;
    struct ThreadInitCallback_ *next;
} ThreadInitCallback;

static ThreadInitCallback *init_callbacks = NULL;

bool SCThreadRegisterInitCallback(SCThreadInitCallbackFn fn, void *user)
{
    ThreadInitCallback *cb = SCCalloc(1, sizeof(*cb));
    if (cb == NULL) {
        return false;
    }
    cb->Callback = fn;
    cb->user = user;
    if (init_callbacks == NULL) {
        init_callbacks = cb;
    } else {
        ThreadInitCallback *current = init_callbacks;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = cb;
    }
    return true;
}

void SCThreadRunInitCallbacks(ThreadVars *tv)
{
    ThreadInitCallback *cb = init_callbacks;
    while (cb != NULL) {
        cb->Callback(tv, cb->user);
        cb = cb->next;
    }
}
