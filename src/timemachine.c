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

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-cpu.h"
#include "util-atomic.h"
#include "util-time.h"
#include "util-pool.h"

#include "timemachine.h"
#include "timemachine-heap.h"
#include "timemachine-packet.h"

#define DEFAULT_MAX_MEMORY                        1024 * 1024 * 256
#define DEFAULT_MAX_PACKET_SIZE                   1514
#define DEFAULT_HEAP_PREALLOC_COUNT               5000
#define DEFAULT_HEAP_EXPAND_BY                    1000

/** \brief Initialize the time machine config 
 *  \warning Not thread safe but neither is flow 
 **/
void TimeMachineInitConfig() 
{
    SCLogDebug("initializing time machine...");

    memset(&timemachine_config, 0, sizeof(TimeMachineConfig));

    char *conf_val;
    if ((ConfGet("timemachine.enabled", &conf_val)) == 1) {
        if ((ConfValIsTrue(conf_val)) == 1) {
            timemachine_config.enabled = 1;
        }
    }

    timemachine_config.max_memory = DEFAULT_MAX_MEMORY;
    if ((ConfGet("timemachine.max-memory", &conf_val)) == 1) {
        if (ParseSizeStringU64(conf_val, &timemachine_config.max_memory) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize max memory for timemachine "
                "invalid limit: %s", conf_val);
            exit(EXIT_FAILURE);
        } 
    }

    uint32_t global_heap_prealloc_count = DEFAULT_HEAP_PREALLOC_COUNT;
    if ((ConfGet("timemachine.heap-prealloc-count", &conf_val)) == 1) {
        if (ByteExtractStringUint32(&global_heap_prealloc_count, 10, 0, 
                                     conf_val) == -1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                       "timemachine, invalid heap-packet-prealloc-count: %s",
                       conf_val);
            exit(EXIT_FAILURE);
        } else if (global_heap_prealloc_count < 1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize timemachine output, limit less than "
                "allowed minimum.");
            exit(EXIT_FAILURE);
        } else {
            timemachine_config.heap_prealloc_count = global_heap_prealloc_count;
        }
    }

    uint32_t global_heap_expand_by = DEFAULT_HEAP_EXPAND_BY;
    if ((ConfGet("timemachine.heap-expand-by", &conf_val)) == 1) {
        if (ByteExtractStringUint32(&global_heap_expand_by, 10, 0, 
                                    conf_val) == -1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                       "timemachine output, invalid heap-expand-by count: %s",
                       conf_val);
            exit(EXIT_FAILURE);
        } else if (global_heap_expand_by < 1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to initialize timemachine, heap-expand-by limit less than "
                "allowed minimum.");
            exit(EXIT_FAILURE);
        } else {
            timemachine_config.heap_expand_by = global_heap_expand_by;
        }
    }

    TAILQ_INIT(&timemachine_config.heap_confs);

    ConfNode* heaps = ConfGetNode("timemachine.heaps");
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
                if (unlikely(heap_conf == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for TimeMachineFlowNode");
                    exit(EXIT_FAILURE);
                }  

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
                 
                TAILQ_INSERT_TAIL(&timemachine_config.heap_confs, heap_conf, next);
                timemachine_config.heap_confs_count += 1;
            }
        }
    }

    /* if time machine is enabled, there is at least one heap, we'll call this 
       default, use the default-packet-size for max_packet_size of default heap */
    if (timemachine_config.heap_confs_count == 0) {
        TimeMachineHeapConf *default_heap_conf = SCMalloc(sizeof(TimeMachineHeapConf));
        if (unlikely(default_heap_conf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for TimeMachineFlowNode");
            exit(EXIT_FAILURE);
        }  

        const char* default_packet_size_s = NULL;
        if ((ConfGet("default-packet-size", &conf_val)) == 1) {
            if (ByteExtractStringUint32(&default_packet_size, 10, 0, 
                                        conf_val) == -1) {
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

        default_heap_conf->name = "default";
        default_heap_conf->expand_by = global_heap_expand_by;
        default_heap_conf->prealloc_count = global_heap_prealloc_count;
        
        TAILQ_INSERT_TAIL(&timemachine_config.heap_confs, default_heap_conf, next);
        timemachine_config.heap_confs_count = 1;
    }
}

TimeMachineThreadVars* TimeMachineThreadVarsAlloc() {
    TimeMachineThreadVars *tmtv = NULL;
    TimeMachineHeapConf *heap_conf = NULL;

    if ((tmtv = SCMalloc(sizeof(TimeMachineThreadVars))) == NULL)
        return NULL;
    memset(tmtv, 0, sizeof(TimeMachineThreadVars));

    /* create all the heaps for this thread */
    TAILQ_INIT(&tmtv->heaps);

    TAILQ_FOREACH(heap_conf, &timemachine_config.heap_confs, next) {              
        TimeMachineHeap* heap = TimeMachineHeapNew(tmtv, heap_conf);
        TAILQ_INSERT_TAIL(&tmtv->heaps, heap, next);
        tmtv->heap_count++;
    }

    return tmtv;
}

void TimeMachineThreadVarsFree(TimeMachineThreadVars* tmtv) {

    if (tmtv == NULL) {
        return;
    }

    while (tmtv->heap_count > 0) {
        TimeMachineHeap* heap = TAILQ_FIRST(&tmtv->heaps);
        TAILQ_REMOVE(&tmtv->heaps, heap, next);
        TimeMachineHeapDestroy(heap);        
        tmtv->heap_count--;
        SCFree(heap);
    }
}
