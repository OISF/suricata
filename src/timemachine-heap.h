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
 * Heap related functions for usage within TimeMachine
 */

#ifndef __TIMEMACHINE_HEAP_H__
#define __TIMEMACHINE_HEAP_H__

#include "suricata-common.h"
#include "timemachine.h"
#include "timemachine-packet.h"

struct TimeMachineHeaps_;

struct TimeMachineHeapConf_ {
    const char*                         name;
    uint32_t                            expand_by;
    uint32_t                            prealloc_count;
    uint32_t                            max_packet_size;
    TAILQ_ENTRY(TimeMachineHeapConf_)   next;
};

struct TimeMachineMemPool_ {
    TimeMachinePacket                   *packet;
    void                                *mem;
    TAILQ_ENTRY(TimeMachineMemPool_)    next;
};


/* TAILQ Macros */
TAILQ_HEAD(TimeMachineMemPools_, TimeMachineMemPool_);

typedef struct TimeMachineHeap_ {
    TimeMachineHeapConf                 *conf;

    size_t                              used_pool_count;
    size_t                              unused_pool_count;

    TimeMachineMemPools                 used_mem_pools;
    TimeMachineMemPools                 unused_mem_pools;
    TimeMachinePackets                  unused_packets;
    
    TAILQ_ENTRY(TimeMachineHeap_)       next;
} TimeMachineHeap;

/* prototypes */
TimeMachineHeap* TimeMachineHeapNew(TimeMachineThreadVars*, TimeMachineHeapConf*);
void TimeMachineHeapDestroy(TimeMachineHeap*);

uint32_t TimeMachineHeapExpand(TimeMachineThreadVars*, TimeMachineHeap*, uint32_t);
int TimeMachineHeapCanExpand(TimeMachineThreadVars*);

#endif /* __TIMEMACHINE_HEAP_H__ */
