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

/**
 * \file
 *
 * \brief EVE logging subsystem
 *
 * This file will attempt to the main module for EVE logging
 * sub-system. Currently most of the API resides in output-json.[ch],
 * but due to some circular dependencies between EVE, and LogFileCtx,
 * it made it hard to add EVE filetype modules there until some
 * include issues are figured out.
 */

#ifndef SURICATA_OUTPUT_EVE_H
#define SURICATA_OUTPUT_EVE_H

#include "suricata-common.h"
#include "rust.h"
#include "conf.h"
#include "output-eve-bindgen.h"

bool SCRegisterEveFileType(SCEveFileType *);

SCEveFileType *SCEveFindFileType(const char *name);

/** \brief Function type for EVE callbacks.
 *
 * The function type for callbacks registered with
 * SCEveRegisterCallback. This function will be called with the
 * SCJsonBuilder just prior to the top-level object being closed. New
 * fields may be added, however, there is no way to alter existing
 * objects already added to the SCJsonBuilder.
 *
 * \param tv The ThreadVars for the thread performing the logging.
 * \param p Packet if available.
 * \param f Flow if available.
 * \param user User data provided during callback registration.
 */
typedef void (*SCEveUserCallbackFn)(
        ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *jb, void *user);

/** \brief Register a callback for adding extra information to EVE logs.
 *
 * Allow users to register a callback for each EVE log. The callback
 * is called just before the root object on the SCJsonBuilder is to be
 * closed.
 *
 * New objects and fields can be appended, but existing entries cannot be modified.
 *
 * Packet and Flow will be provided if available, but will otherwise be
 * NULL.
 *
 * Limitations: At this time the callbacks will only be called for EVE
 * loggers that use SCJsonBuilder, notably this means it won't be called
 * for stats records at this time.
 *
 * \returns true if callback is registered, false is not due to memory
 *     allocation error.
 */
bool SCEveRegisterCallback(SCEveUserCallbackFn fn, void *user);

/** \internal
 *
 * Run EVE callbacks.
 */
void SCEveRunCallbacks(ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *jb);

#endif
