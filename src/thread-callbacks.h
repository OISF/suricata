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

#ifndef SURICATA_THREAD_CALLBACKS_H
#define SURICATA_THREAD_CALLBACKS_H

#include "suricata-common.h"
#include "threadvars.h"

/** \brief Function type for thread intialization callbacks.
 *
 * Once registered by SCThreadRegisterInitCallback, this function will
 * be called for every thread being initialized during Suricata
 * startup.
 *
 * \param tv The ThreadVars struct that has just been initialized.
 * \param user The user data provided when registering the callback.
 */
typedef void (*SCThreadInitCallbackFn)(ThreadVars *tv, void *user);

/** \brief Register a thread init callback.
 *
 * Register a user provided function to be called every time a thread is
 * initialized for use.
 *
 * \param fn Pointer to function to be called
 * \param user Additional user data to be passed to callback
 *
 * \returns true if callback was registered, otherwise false if the
 *     callback could not be registered due to memory allocation error.
 */
bool SCThreadRegisterInitCallback(SCThreadInitCallbackFn fn, void *user);

/** \internal
 *
 * Run all registered flow init callbacks.
 */
void SCThreadRunInitCallbacks(ThreadVars *tv);

#endif /* SURICATA_THREAD_CALLBACKS_H */
