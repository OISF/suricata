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

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"
#include "conf.h"
#include "output.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-cpu.h"
#include "util-atomic.h"
#include "util-time.h"

#include "timemachine.h"
#include "timemachine-flow.h"
#include "timemachine-heap.h"
#include "timemachine-output.h"
#include "timemachine-packet.h"

#define MODULE_NAME                               "TimeMachine"
#define DEFAULT_MAX_MEMORY                        1024 * 1024 * 1024
#define DEFAULT_MAX_PACKET_SIZE                   1500
#define DEFAULT_HEAP_PREALLOC_COUNT               5000
#define DEFAULT_HEAP_EXPAND_BY                    1000
#define DEFAULT_OUTPUT_TIMEOUT                    21600

SC_ATOMIC_DECLARE(uint32_t, thread_cnt);

/* global pcap data for when we're using multi mode. At exit we'll
 * merge counters into this one and then report counters. */
static TimeMachineData *g_tm_data = NULL;

static TmEcode TimeMachineProcess(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
static TmEcode TimeMachineInit(ThreadVars *, void *, void **);
static TmEcode TimeMachineDeinit(ThreadVars *, void *);
static OutputCtx *TimeMachineInitCtx(ConfNode *);
static void TimeMachineDeInitCtx(OutputCtx *);

void TmModuleTimeMachineRegister(void)
{
    tmm_modules[TMM_TIMEMACHINE].name = MODULE_NAME;
    tmm_modules[TMM_TIMEMACHINE].ThreadInit = TimeMachineInit;
    tmm_modules[TMM_TIMEMACHINE].Func = TimeMachineProcess;
    tmm_modules[TMM_TIMEMACHINE].ThreadDeinit = TimeMachineDeinit;
    tmm_modules[TMM_TIMEMACHINE].RegisterTests = NULL;

    OutputRegisterModule(MODULE_NAME, "timemachine", TimeMachineInitCtx);

    SC_ATOMIC_INIT(thread_cnt);
    return;
}

/**
 * \brief TimeMachine main logging function
 *
 * \param t threadvar
 * \param p packet
 * \param data thread module specific data
 * \param pq pre-packet-queue
 * \param postpq post-packet-queue
 *
 * \retval TM_ECODE_OK on succes
 * \retval TM_ECODE_FAILED on serious error
 */
static TmEcode TimeMachineProcess(ThreadVars *t, Packet *p, void *thread_data, PacketQueue *pq,
                 PacketQueue *postpq)
{    
    TimeMachineFlow *flow;
    TimeMachineHeap *heap;
    TimeMachineMemPool *mem_pool;
    TimeMachinePacket *packet;
    struct pcap_pkthdr pkthdr;
    struct timeval current_time;
    
    TimeGet(&current_time);
    
    TimeMachineThreadData *td = (TimeMachineThreadData *)thread_data;
    TimeMachineData *tm = td->tm_data;
    
    /* make sure packet has real data */
    if (GET_PKT_PAYLOAD_LEN(p) == 0) {
        return TM_ECODE_OK;
    }
    
    /* check whether a corresponding flow already exists */
    if (!(flow = TimeMachineFlowLookup(td->flows, p))) {
        flow = TimeMachineFlowNew(td->flows, p);       
        td->flow_count++;
        flow->td = td;
    }
       
    /* if this packet has an alert but flow doesn't have a output, create one */
    if (p->alerts.cnt > 0 && flow->output == NULL) {
        flow->output = TimeMachineOutputNew(flow);
        TAILQ_INSERT_TAIL(&td->outputs, flow->output, next);
        td->output_count += 1;
    }
     
     /* create the packet header info */
    pkthdr.ts.tv_sec = p->ts.tv_sec;
    pkthdr.ts.tv_usec = p->ts.tv_usec;
    pkthdr.caplen = GET_PKT_LEN(p);
    pkthdr.len = GET_PKT_LEN(p);
                                         
    /* dump the traffic if this has already been marked as a output */
    if (flow->output != NULL) {
        pcap_dump((u_char*)flow->output->output_file, &pkthdr, GET_PKT_DATA(p));
        fflush(flow->output->output_file);
        memcpy(&flow->output->updated, &current_time, sizeof(struct timeval));
        
        /* make this the most recently accessed output */
        TAILQ_REMOVE(&td->outputs, flow->output, next);
        TAILQ_INSERT_TAIL(&td->outputs,flow->output, next);
        
        return TM_ECODE_OK;
    } 
    
    /* find the queue the packet should fall in */
    TAILQ_FOREACH(heap, &td->heaps, next) {
        if (pkthdr.caplen <= heap->conf->max_packet_size) {
            break;
        }
    }
   
    /* see if something is already available in the unusued mem pool */
    if (TAILQ_EMPTY(&heap->unused_mem_pools)) {

        /* first check if the heap can expand, if so then expand it */
        SCMutexLock(&tm->tm_lock);   
        if (TimeMachineHeapCanExpand(tm)) {
            TimeMachineHeapExpand(tm, heap);
            SCMutexUnlock(&tm->tm_lock);
        }
        /* couldn't expand, need to remove the first entry */
        else {
            SCMutexUnlock(&tm->tm_lock);
           
            TimeMachineFlow* rem_flow;                                                                                                                                                                                                                                        
            TimeMachineMemPool* rem_mem_pool;
            TimeMachinePacket* rem_packet;
            
            /* get the most recent entry from the heap (packet and flow) */
            rem_mem_pool = TAILQ_FIRST(&heap->used_mem_pools);
            rem_packet = rem_mem_pool->packet;
            rem_flow = rem_packet->flow;
            
            TAILQ_REMOVE(&heap->used_mem_pools, rem_mem_pool, next);
            TAILQ_REMOVE(&rem_flow->packets, rem_packet, next);
            heap->used_pool_count--;
            
            if (rem_flow != flow) {
                if (TAILQ_EMPTY(&rem_flow->packets)) {
                    TimeMachineFlowDestroy(td->flows, rem_flow);
                    SCFree(rem_flow);
                    td->flow_count--;
                }
            }
            
            rem_mem_pool->packet = NULL;
            TAILQ_INSERT_TAIL(&heap->unused_mem_pools, rem_mem_pool, next);
            TAILQ_INSERT_TAIL(&heap->unused_packets, rem_packet, next);
            heap->unused_pool_count++;
        }
    }

    /* remove the heap from the unusued to used list */        
    mem_pool = TAILQ_FIRST(&heap->unused_mem_pools);
    TAILQ_REMOVE(&heap->unused_mem_pools, mem_pool, next);
    heap->unused_pool_count--;
    
    TAILQ_INSERT_TAIL(&heap->used_mem_pools, mem_pool, next);
    heap->used_pool_count++;
    
    /* remove the packet from the unused to used list */
    packet = TAILQ_FIRST(&heap->unused_packets);
    TAILQ_REMOVE(&heap->unused_packets, packet, next);
    TAILQ_INSERT_TAIL(&flow->packets, packet, next);
 
    /* make sure this heap points to the corresponding packet */   
    mem_pool->packet = packet; 
    memcpy(&packet->header, &pkthdr, sizeof(struct pcap_pkthdr));
    
    packet->data = mem_pool->mem;
    memcpy(packet->data, GET_PKT_DATA(p), GET_PKT_LEN(p));
    
    /* make sure the packet is associated with a flow */
    packet->flow = flow;
    flow->packet_count++;
       
    /* make sure the packet can reference the heap and mempool */
    packet->heap = heap;
    packet->mem_pool = mem_pool;
    
    /* remove any open outputs that have been open for a time period */
    TimeMachineOutput* output = TAILQ_FIRST(&td->outputs);
    while (td->output_count > 0) {
        output = TAILQ_FIRST(&td->outputs);
        if (current_time.tv_sec - output->updated.tv_sec < 600) {
            break;
        }     

        /* delete the flow, which will destroy the output */
        TimeMachineFlowDestroy(td->flows, output->flow);
        td->flow_count--;
        
        /* remove the output from the list of outputs */
        TAILQ_REMOVE(&td->outputs, output, next);
        TimeMachineOutputDestroy(output);
        td->output_count--;          
    }
     
    return TM_ECODE_OK;
}

static TmEcode TimeMachineInit(ThreadVars *t, void *initdata, void **data)
{
    TimeMachineHeapConf *heap_conf;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for TimeMachine. \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    TimeMachineData *tm = ((OutputCtx *)initdata)->data;

    TimeMachineThreadData *td = SCCalloc(1, sizeof(*td));
    if (unlikely(td == NULL))
        return TM_ECODE_FAILED;

    /* create the flows tree for this thread */
    td->flows = SCMalloc(sizeof(TimeMachineFlows));
    SPLAY_INIT(td->flows);
    td->flow_count = 0;
    
    /* create all the open outputs */
    TAILQ_INIT(&td->outputs);
    td->output_count = 0;
    
    /* create all the heaps for this thread */
    TAILQ_INIT(&td->heaps);
    
    TAILQ_FOREACH(heap_conf, &tm->heap_confs, next) {
        SCMutexLock(&tm->tm_lock);
        TimeMachineHeap* heap = TimeMachineHeapNew(tm, heap_conf);
        SCMutexUnlock(&tm->tm_lock);
        
        TAILQ_INSERT_TAIL(&td->heaps, heap, next);
        td->heap_count++;
    }
        
    td->tm_data = tm;
    
    /* count threads in the global structure */
    SCMutexLock(&tm->tm_lock);
    tm->threads++;
    SCMutexUnlock(&tm->tm_lock);

    *data = (void *)td;
    return TM_ECODE_OK;
}

/**
 *  \brief Thread DeInit function.
 *
 *  \param t Thread Variable containing input/output queue, cpu affinity etc.
 *  \param thread_data TimeMachine thread data.
 *
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 **/
static TmEcode TimeMachineDeinit(ThreadVars *t, void *thread_data)
{
    TimeMachineThreadData *td = (TimeMachineThreadData *)thread_data;
    
    /* cleanup all the open output files */
    while (td->output_count > 0) {
        TimeMachineOutput* output = TAILQ_FIRST(&td->outputs);
        TimeMachineFlowDestroy(td->flows, output->flow);
        td->flow_count--;
        
        TAILQ_REMOVE(&td->outputs, output, next);
        TimeMachineOutputDestroy(output);
        td->output_count--;          
    }
    
    /* cleanup all the heaps */
    while (td->heap_count > 0) {
        TimeMachineHeap* heap = TAILQ_FIRST(&td->heaps);
        TimeMachineHeapDestroy(heap);

        TAILQ_REMOVE(&td->heaps, heap, next);
        td->heap_count--;
    }
    
    /* cleanup all the flows */
    while (td->flow_count > 0) {
        TimeMachineFlow* flow = TimeMachineFlowFirst(td->flows);
        TimeMachineFlowDestroy(td->flows, flow);
        td->flow_count--;
    }
        
    SCFree(td->flows);
    return TM_ECODE_OK;
}

/** \brief Fill in timemachine struct from the provided ConfNode.
 *
 *  \param conf The configuration node for this output.
 *
 *  \retval output_ctx
 **/
static OutputCtx *TimeMachineInitCtx(ConfNode *conf) 
{       
    TimeMachineData *tm = SCMalloc(sizeof(TimeMachineData));

    if (unlikely(tm == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for TimeMachineData");
        exit(EXIT_FAILURE);
    }
    memset(tm, 0, sizeof(TimeMachineData));

    SCMutexInit(&tm->tm_lock, NULL);

    tm->max_memory = DEFAULT_MAX_MEMORY;
    if (conf != NULL) {
        const char *max_memory_s = NULL;
        max_memory_s = ConfNodeLookupChildValue(conf, "max-memory");
        if (max_memory_s != NULL) {
            if (ParseSizeStringU64(max_memory_s, &tm->max_memory) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize max memory for timemachien output "
                    "invalid limit: %s", max_memory_s);
                exit(EXIT_FAILURE);
            }
        }
    }

    uint32_t global_heap_prealloc_count = DEFAULT_HEAP_PREALLOC_COUNT;
    if (conf != NULL) {
        const char* global_heap_prealloc_count_s = NULL;
        global_heap_prealloc_count_s = 
          ConfNodeLookupChildValue(conf, "heap-prealloc-count");
        
        if (global_heap_prealloc_count_s != NULL) {
            if (ByteExtractStringUint32(&global_heap_prealloc_count, 10, 0, 
                                        global_heap_prealloc_count_s) == -1) {
              SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                         "timemachine output, invalid heap-packet-prealloc-count: %s",
                         global_heap_prealloc_count_s);
              exit(EXIT_FAILURE);
            } else if (global_heap_prealloc_count < 1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize timemachine output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            } else {
                tm->heap_prealloc_count = global_heap_prealloc_count;
            }
        }
    }

    uint32_t global_heap_expand_by = DEFAULT_HEAP_EXPAND_BY;
    if (conf != NULL) {
        const char* global_heap_expand_by_s = NULL;
        global_heap_expand_by_s = ConfNodeLookupChildValue(conf, "heap-expand-by");
        if (global_heap_expand_by_s != NULL) {
            if (ByteExtractStringUint32(&global_heap_expand_by, 10, 0, 
                                        global_heap_expand_by_s) == -1) {
              SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                         "timemachine output, invalid heap-expand-by count: %s",
                         global_heap_expand_by_s);
              exit(EXIT_FAILURE);
            } else if (global_heap_expand_by < 1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize timemachine output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            } else {
                tm->heap_expand_by = global_heap_expand_by;
            }
        }
    }
    
    uint32_t global_output_timeout = DEFAULT_OUTPUT_TIMEOUT;
    if (conf != NULL) {
        const char* global_output_timeout_s = NULL;
        global_output_timeout_s = ConfNodeLookupChildValue(conf, "output-timeout");
        if (global_output_timeout_s != NULL) {
            if (ByteExtractStringUint32(&global_output_timeout, 10, 0,
                                        global_output_timeout_s) == -1) {
              SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                         "timemachine output, invalid output timeout: %s",
                         global_output_timeout_s);
              exit(EXIT_FAILURE);
            } else if (global_output_timeout < 1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize timemachine output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            } else {
                tm->output_timeout = global_output_timeout;
            }
        }
    }
        
    TAILQ_INIT(&tm->heap_confs);

    if (conf != NULL) {
        ConfNode* heaps = ConfNodeLookupChild(conf, "heaps");
        if (heaps != NULL) {

            if (!ConfNodeIsSequence(heaps)) {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid timemachine "
                             "heap configuration section, expected a list");
            }
            else {
                ConfNode* heap_conf_node = NULL;
                TAILQ_FOREACH(heap_conf_node, &heaps->head, next) {
                    /* create a new heap */
                    TimeMachineHeapConf *heap_conf = SCMalloc(sizeof(TimeMachineHeapConf));
                    heap_conf->name = ConfNodeLookupChildValue(heap_conf_node, "name");
                    if (heap_conf->name == NULL) {
                        SCLogError(SC_ERR_INVALID_ARGUMENT, "Heaps must have a "
                                   "corresponding name field");
                        exit(EXIT_FAILURE);
                    }

                    const char* max_packet_size_s = NULL;
                    max_packet_size_s = ConfNodeLookupChildValue(heap_conf_node, "max-packet-size");
                    if (max_packet_size_s != NULL) {
                        uint32_t heap_max_packet_size;
                        if (ByteExtractStringUint32(&heap_max_packet_size, 10, 0, 
                                                    max_packet_size_s) == -1) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                                       "timemachine output, invalidate min_payload count: %s",
                                       max_packet_size_s);
                            exit(EXIT_FAILURE);
                        }
                        else if (heap_max_packet_size < 1) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                                       "timemachine output, max heap packet size cannot "
                                       "be zero: %s", max_packet_size_s);
                            exit(EXIT_FAILURE);        
                        }
                        else {
                            heap_conf->max_packet_size = heap_max_packet_size;
                        }
                    }

                    const char* heap_prealloc_count_s = NULL;
                    heap_prealloc_count_s = ConfNodeLookupChildValue(heap_conf_node, "heap-prealloc-count");
                    if (heap_prealloc_count_s != NULL) {
                        uint32_t heap_prealloc_count;
                        if (ByteExtractStringUint32(&heap_prealloc_count, 10, 0, 
                                                    heap_prealloc_count_s) == -1) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                                       "timemachine output, invalid heap-prealloc-count: %s",
                                       heap_prealloc_count_s);
                            exit(EXIT_FAILURE);
                        }
                        heap_conf->prealloc_count = heap_prealloc_count;
                    }
                    else {
                        heap_conf->prealloc_count = global_heap_prealloc_count;
                    }
                    
                    const char* heap_expand_by_s = NULL;
                    heap_expand_by_s = ConfNodeLookupChildValue(heap_conf_node, "heap-expand-by");
                    if (heap_expand_by_s != NULL) {
                        uint32_t heap_expand_by;
                        if (ByteExtractStringUint32(&heap_expand_by, 10, 0,
                                                    heap_expand_by_s) == -1) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                                       "timemachine output, invalid heap-expand-by-count: %s",
                                       heap_expand_by_s);
                            exit(EXIT_FAILURE);
                        }
                        else if (heap_expand_by < 1) {
                            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                                       "timemachine output, heap_expand_by_count cannot be "
                                       "zero: %s", heap_expand_by_s);
                            exit(EXIT_FAILURE);
                        }
                        else {
                            heap_conf->expand_by = heap_expand_by;
                        }                                        
                    }
                    else {
                        heap_conf->expand_by = global_heap_expand_by;
                    }
                    
                    TAILQ_INSERT_TAIL(&tm->heap_confs, heap_conf, next);
                }
            }
        }
    }

    /* use the default-packet-size for max_packet_size of default heap */
    TimeMachineHeapConf *default_heap_conf = SCMalloc(sizeof(TimeMachineHeapConf));

    const char* default_packet_size_s = NULL;
    default_packet_size_s = ConfNodeLookupChildValue(conf, "default-packet-size");
    if (default_packet_size_s != NULL) {
        if (ByteExtractStringUint32(&default_packet_size, 10, 0, 
                                    default_packet_size_s) == -1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                       "default heap max packet size, using default: %s",
                       default_packet_size_s);
            default_heap_conf->max_packet_size = DEFAULT_MAX_PACKET_SIZE;
        }
        else if (default_packet_size < 1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                       "default heap max packet size, using default: %s",
                       default_packet_size_s); 
            default_heap_conf->max_packet_size = DEFAULT_MAX_PACKET_SIZE;                   
        } 
        else {
            default_heap_conf->max_packet_size = DEFAULT_MAX_PACKET_SIZE;
        }              
    }
    else {
        default_heap_conf->max_packet_size = DEFAULT_MAX_PACKET_SIZE;
    }

    /* there is always one heap, it's the default heap */
    default_heap_conf->name = "default";
    default_heap_conf->expand_by = global_heap_expand_by;
    default_heap_conf->prealloc_count = global_heap_prealloc_count;
    TAILQ_INSERT_TAIL(&tm->heap_confs, default_heap_conf, next);

    /* create the output ctx and send it back */
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for OutputCtx.");
        exit(EXIT_FAILURE);
    }

    output_ctx->data = tm;
    output_ctx->DeInit = TimeMachineDeInitCtx;
    
    /* assignment the global tm data struct */
    g_tm_data = tm;
    return output_ctx;
}

/** \brief Deinitialize the time machine context
 *  \param output_ctx The output context generated from TimeMachineInitCtx
 **/
static void TimeMachineDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx == NULL) 
        return;
        
    TimeMachineData *tm = output_ctx->data;
    
    TimeMachineHeapConf *heap_conf = NULL;
    while (!TAILQ_EMPTY(&tm->heap_confs)) {
        heap_conf = TAILQ_FIRST(&tm->heap_confs);
        TAILQ_REMOVE(&tm->heap_confs, heap_conf, next);
        SCFree(heap_conf);
    }

    SCFree(output_ctx);
    return;
}
