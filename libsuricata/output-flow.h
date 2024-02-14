/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __OUTPUT_FLOW_H__
#define __OUTPUT_FLOW_H__

#include "tm-modules.h"

/** flow logger function pointer type */
typedef int (*FlowLogger)(ThreadVars *, void *thread_data, Flow *f);

int OutputRegisterFlowLogger(const char *name, FlowLogger LogFunc,
    OutputCtx *, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats);

void OutputFlowShutdown(void);

TmEcode OutputFlowLog(ThreadVars *tv, void *thread_data, Flow *f);
TmEcode OutputFlowLogThreadInit(ThreadVars *tv, void *initdata, void **data);
TmEcode OutputFlowLogThreadDeinit(ThreadVars *tv, void *thread_data);
void OutputFlowLogExitPrintStats(ThreadVars *tv, void *thread_data);

#endif /* __OUTPUT_FLOW_H__ */
