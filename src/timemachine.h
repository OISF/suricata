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
 * In-memory PCAP buffer for retrieving previously seen packets after an alert 
 * fires
 */

#ifndef __TIMEMACHINE_H__
#define __TIMEMACHINE_H__

typedef struct TimeMachineData_ TimeMachineData;
typedef struct TimeMachineThreadData_ TimeMachineThreadData;
typedef struct TimeMachineFlow_ TimeMachineFlow;
typedef struct TimeMachineFlows_ TimeMachineFlows;
typedef struct TimeMachineFlowNode_ TimeMachineFlowNode;
typedef struct TimeMachineHeap_ TimeMachineHeap;
typedef struct TimeMachineHeapConf_ TimeMachineHeapConf;
typedef struct TimeMachineMemPool_ TimeMachineMemPool;
typedef struct TimeMachineMemPools_ TimeMachineMemPools;
typedef struct TimeMachineOutput_ TimeMachineOutput;
typedef struct TimeMachinePacket_ TimeMachinePacket;
typedef struct TimeMachinePackets_ TimeMachinePackets;

/* main time machine struct to hold config data */
struct TimeMachineData_ {
    uint64_t                            max_memory;
    uint64_t                            current_memory;
    uint32_t                            min_payload; 
    uint32_t                            heap_prealloc_count;
    uint32_t                            heap_expand_by;
    uint32_t                            heap_count;
    uint32_t                            output_count;
    uint32_t                            output_timeout;
        
    SCMutex                             tm_lock;  

    TAILQ_HEAD(,TimeMachineHeapConf_)   heap_confs;
    int                                 threads; 
};

struct TimeMachineThreadData_ {
    TimeMachineData                     *tm_data;

    uint32_t                            heap_count;
    TAILQ_HEAD(,TimeMachineHeap_)       heaps;
    
    uint32_t                            flow_count;
    TimeMachineFlows                    *flows;
    
    uint32_t                            output_count;    
    TAILQ_HEAD(,TimeMachineOutput_)     outputs;
};

void TmModuleTimeMachineRegister(void);

#endif /* __TIMEMACHINE_H__ */