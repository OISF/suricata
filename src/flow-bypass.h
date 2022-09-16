/* Copyright (C) 2016-2018 Open Information Security Foundation
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
 * \author Eric Leblond <eleblond@stamus-networks.com>
 */

#ifndef __FLOW_BYPASS_H__
#define __FLOW_BYPASS_H__

#include "threadvars.h"
#include "flow.h"

struct flows_stats {
    uint64_t count;
    uint64_t packets;
    uint64_t bytes;
};

typedef int (*BypassedCheckFunc)(ThreadVars *th_v,
                                 struct flows_stats *bypassstats,
                                 struct timespec *curtime, void *data);
typedef int (*BypassedCheckFuncInit)(ThreadVars *th_v,
                                     struct timespec *curtime, void *data);
typedef int (*BypassedUpdateFunc)(Flow *f, Packet *p, void *data);

void FlowAddToBypassed(Flow *f);

void BypassedFlowManagerThreadSpawn(void);
void TmModuleBypassedFlowManagerRegister(void);

int BypassedFlowManagerRegisterCheckFunc(BypassedCheckFunc CheckFunc,
                                         BypassedCheckFuncInit CheckFuncInit, void *data);
int BypassedFlowManagerRegisterUpdateFunc(BypassedUpdateFunc UpdateFunc, void *data);

void BypassedFlowUpdate(Flow *f, Packet *p);

#endif


