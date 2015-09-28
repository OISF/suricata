/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Mat Oldham <mat.oldham@gmail.com>
 *
 * Provides Flow related data structures required for the timemachine module 
 */

#ifndef __TIMEMACHINE_FLOW_H__
#define __TIMEMACHINE_FLOW_H__

#include "suricata-common.h"
#include "flow.h"
#include "timemachine.h"
#include "timemachine-packet.h"

struct TimeMachineFlows_;

#define TIMEMACHINE_FLOW_IS_IPV4 1
#define TIMEMACHINE_FLOW_IS_IPV6 2

/* represents a network flow */
struct TimeMachineFlow_ {

    struct timeval ts;
    FlowAddress src, dst;
    union {
        Port sp;
        uint8_t type;
    };
    union {
        Port dp;
        uint8_t code;
    };
    uint8_t proto;
    uint8_t ip_hdr;
    int datalink;
    
    TimeMachineThreadData* td;
    TimeMachineOutput* output;
    TimeMachineFlowNode* ent;   
    
    size_t              packet_count;
    TimeMachinePackets  packets;
};

/* SPLAY Tree Macros */
SPLAY_HEAD(TimeMachineFlows_, TimeMachineFlowNode_);

TimeMachineFlow* TimeMachineFlowNew(TimeMachineFlows*, Packet*);
void TimeMachineFlowDestroy(TimeMachineFlows*, TimeMachineFlow*);

TimeMachineFlow* TimeMachineFlowLookup(TimeMachineFlows*, Packet*);
TimeMachineFlow* TimeMachineFlowFirst(TimeMachineFlows*);

#endif /* __TIMEMACHINE_FLOW_H__ */
