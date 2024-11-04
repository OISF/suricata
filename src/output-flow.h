/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * Flow Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_FLOW_H
#define SURICATA_OUTPUT_FLOW_H

#include "decode.h"
#include "tm-modules.h"
#include "flow.h"

/**
 * \brief Flow logger function pointer type.
 */
typedef int (*FlowLogger)(ThreadVars *, void *thread_data, Flow *f);

/** \brief Register a flow logger.
 *
 * \param name An informational name for this logger. Used only for
 *     debugging.
 * \param LogFunc A function that will be called to log each flow.
 * \param initdata A pointer to initialization data that will be
 *     passed the ThreadInit.
 * \param ThreadInit Thread initialization callback.
 * \param ThreadDeinit Thread de-initialization callback.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCOutputRegisterFlowLogger(const char *name, FlowLogger LogFunc, void *initdata,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

/** Internal function: private API. */
void OutputFlowShutdown(void);

/** Internal function: private API. */
TmEcode OutputFlowLog(ThreadVars *tv, void *thread_data, Flow *f);

/** Internal function: private API. */
TmEcode OutputFlowLogThreadInit(ThreadVars *tv, void **data);

/** Internal function: private API. */
TmEcode OutputFlowLogThreadDeinit(ThreadVars *tv, void *thread_data);

#endif /* SURICATA_OUTPUT_FLOW_H */
