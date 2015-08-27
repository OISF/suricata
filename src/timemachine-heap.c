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

#include "suricata-common.h"
#include "timemachine.h"
#include "timemachine-flow.h"
#include "timemachine-heap.h"
#include "timemachine-packet.h"

TimeMachineHeap* TimeMachineHeapNew(TimeMachineData* tm, TimeMachineHeapConf* conf) {

    TimeMachineHeap *heap = SCMalloc(sizeof(TimeMachineHeap));
    
    if (heap == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error could not create TimeMachine heap. Exiting...");
        exit(EXIT_FAILURE);        
    }

    heap->conf = conf;
    heap->used_pool_count = 0;
    heap->unused_pool_count = 0;
    
    TAILQ_INIT(&heap->used_mem_pools);
    TAILQ_INIT(&heap->unused_mem_pools);
    TAILQ_INIT(&heap->unused_packets);    
    
    TimeMachineHeapExpand(tm, heap);
    return heap;
}

void TimeMachineHeapDestroy(TimeMachineHeap* heap) {
    
    if (heap == NULL) {
        return;
    }
    
    /* delete all the used pool data */
    while (heap->used_pool_count > 0) {
        TimeMachineMemPool* mem_pool;
            
        mem_pool = TAILQ_FIRST(&heap->used_mem_pools);
        TAILQ_REMOVE(&heap->used_mem_pools, mem_pool, next);
        SCFree(mem_pool);

        heap->used_pool_count--;    
    }
    
    /* delete all the unused pool data */
    while (heap->unused_pool_count > 0) {
        TimeMachinePacket* packet;
        TimeMachineMemPool* mem_pool;

        packet = TAILQ_FIRST(&heap->unused_packets);
        TAILQ_REMOVE(&heap->unused_packets, packet, next);
        TimeMachinePacketDestroy(packet);
            
        mem_pool = TAILQ_FIRST(&heap->unused_mem_pools);
        TAILQ_REMOVE(&heap->unused_mem_pools, mem_pool, next);
        SCFree(mem_pool);
                
        heap->unused_pool_count--;
    }    
}

uint32_t TimeMachineHeapExpand(TimeMachineData* tm, TimeMachineHeap* heap) {
    uint32_t i;
    
    if (heap == NULL) {
        return 0;
    }
    
    for (i = 0; i < heap->conf->expand_by; i++) {
        TimeMachineMemPool* mem_pool;
        TimeMachinePacket* packet;
        
        mem_pool = SCCalloc(sizeof(TimeMachineMemPool), 1);
        if (mem_pool == NULL) {
            return i;
        }    
        
        mem_pool->mem = SCMalloc(heap->conf->max_packet_size);
        if (mem_pool->mem == NULL) {
            SCFree(mem_pool);
            return i;
        }
        
        packet = TimeMachinePacketNew();
        
        tm->current_memory += sizeof(TimeMachineMemPool) + heap->conf->max_packet_size +
                              sizeof(TimeMachinePacket);
                              
        TAILQ_INSERT_TAIL(&heap->unused_mem_pools, mem_pool, next);
        TAILQ_INSERT_TAIL(&heap->unused_packets, packet, next);
        heap->unused_pool_count += 1;
    }
    
    return i;
}

int TimeMachineHeapCanExpand(TimeMachineData *tm) {

    /* first check time machine mem usage < % of total ram */
    if (tm->current_memory > tm->max_memory) {
        return 0;
    }
            
    return 1;
}