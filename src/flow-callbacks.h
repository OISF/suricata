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

#ifndef SURICATA_FLOW_CALLBACKS_H
#define SURICATA_FLOW_CALLBACKS_H

#include "suricata-common.h"
#include "flow.h"

typedef void (*SCFlowInitCallbackFn)(ThreadVars *tv, Flow *f, const Packet *p, void *user);

/** \brief Register a flow init callback.
 *
 * Register a user provided function to be called every time a flow is
 * initialized for use.
 *
 * \param fn Pointer to function to be called
 * \param user Additional user data to be passed to callback
 *
 * \returns true if callback was registered, otherwise false if the
 *     callback could not be registered due to memory allocation error.
 */
bool SCFlowRegisterInitCallback(SCFlowInitCallbackFn fn, void *user);

/** \internal
 *
 * Run all registered flow init callbacks.
 */
void SCFlowRunInitCallbacks(ThreadVars *tv, Flow *f, const Packet *p);

typedef void (*SCFlowUpdateCallbackFn)(ThreadVars *tv, Flow *f, Packet *p, void *user);

/** \brief Register a flow update callback.
 *
 * Register a user provided function to be called everytime a flow is
 * updated.
 *
 * \param fn Pointer to function to be called
 * \param user Additional user data to be passed to callback
 *
 * \returns true if callback was registered, otherwise false if the
 *     callback could not be registered due to memory allocation error.
 */
bool SCFlowRegisterUpdateCallback(SCFlowUpdateCallbackFn fn, void *user);

/** \internal
 *
 * Run all registered flow update callbacks.
 */
void SCFlowRunUpdateCallbacks(ThreadVars *tv, Flow *f, Packet *p);

typedef void (*SCFlowFinishCallbackFn)(ThreadVars *tv, Flow *f, void *user);

/** \brief Register a flow init callback.
 *
 * Register a user provided function to be called every time a flow is
 * finished.
 *
 * \param fn Pointer to function to be called
 * \param user Additional user data to be passed to callback
 *
 * \returns true if callback was registered, otherwise false if the
 *     callback could not be registered due to memory allocation error.
 */
bool SCFlowRegisterFinishCallback(SCFlowFinishCallbackFn fn, void *user);

/** \internal
 *
 * Run all registered flow init callbacks.
 */
void SCFlowRunFinishCallbacks(ThreadVars *tv, Flow *f);

#endif /* SURICATA_FLOW_CALLBACKS_H */
