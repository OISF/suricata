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
 * Provides output related data structures required for the timemachine module 
 */
 
#include "suricata-common.h"

#include "util-path.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-time.h"

#include "timemachine.h"
#include "timemachine-flow.h"
#include "timemachine-heap.h"
#include "timemachine-output.h"
#include "timemachine-packet.h"
 
TimeMachineOutput* TimeMachineOutputNew(TimeMachineFlow* flow) {
    TimeMachineOutput* output;
    TimeMachinePacket* packet;
    
    char proto[16] = "", timebuf[64] = "";
    char srcip[46] = "", dstip[46] = "", directory[PATH_MAX], filename[PATH_MAX];
         
    if (flow == NULL) {
        return NULL;
    }
     
    output = SCMalloc(sizeof(TimeMachineOutput));
    if (unlikely(output == NULL)) {
        SCLogError(SC_ERR_FATAL, "Fatal error could not create TimeMachine output. Exiting...");
        exit(EXIT_FAILURE);             
     }
     
    output->pcap_out = pcap_open_dead(flow->datalink, 65535);
    if (output->pcap_out == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error, could not create TimeMachine pcap output. Exiting...");
        exit(EXIT_FAILURE);
    }

    CreateIsoTimeString(&flow->ts, timebuf, sizeof(timebuf));
    
    if (flow->ip_hdr == TIMEMACHINE_FLOW_IS_IPV4) {
        PrintInet(AF_INET, (const void*)&flow->src.addr_data32[0], srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void*)&flow->dst.addr_data32[0], dstip, sizeof(dstip));
    } else if (flow->ip_hdr == TIMEMACHINE_FLOW_IS_IPV6) {
        PrintInet(AF_INET, (const void*)&flow->src.addr_data32, srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void*)&flow->dst.addr_data32, dstip, sizeof(dstip));
    }

    if (SCProtoNameValid(flow->proto) == TRUE) {
        strlcpy(proto, known_proto[flow->proto], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "%03" PRIu32, flow->proto);
    }

    snprintf(directory, sizeof(directory), "%s/tm/%.10s/%s-%s", 
             ConfigGetLogDirectory(), timebuf, srcip, dstip);

    if (flow->proto == IPPROTO_ICMP) {
        snprintf(filename, sizeof(filename), "%s/%s-%s-%s.ICMP.cap", 
                 directory, srcip, dstip, timebuf); 
    } else {
        snprintf(filename, sizeof(filename), "%s/%s:%hu-%s:%hu-%s.%s.cap", 
                 directory, srcip, flow->sp, dstip, flow->dp, timebuf, proto);
    }

    struct stat stat_buf;
    if (stat(directory, &stat_buf) != 0) {
        int ret;
        ret = MakePath(filename, S_IRWXU|S_IXGRP|S_IRGRP);
        if (ret != 0) {
            int err = errno;
            if (err != EEXIST) {
                SCLogError(SC_ERR_LOGDIR_CONFIG,
                           "Cannot create file drop directory %s: %s",
                           directory, strerror(err));
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Created timemachine pcap directory %s",
                      directory);
        }
    }    

    output->pcap_dumper = pcap_dump_open(output->pcap_out, filename);
    if (output->pcap_dumper == NULL) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, 
                   "Cannot create timemachine output file %s: %s",
                   filename, pcap_geterr(output->pcap_out));
        exit(EXIT_FAILURE);
    }    

    output->output_file=pcap_dump_file(output->pcap_dumper);
    
    while (flow->packet_count > 0) {
        packet = TAILQ_FIRST(&flow->packets);
        pcap_dump((u_char*)output->output_file, &packet->header, packet->data);

        /* remove this packet from the heap and flow */
        TimeMachineMemPool *rem_mem_pool = packet->mem_pool;

        TimeMachineHeap *heap = packet->heap;
        TAILQ_REMOVE(&heap->used_mem_pools, rem_mem_pool, next);
        TAILQ_REMOVE(&flow->packets, packet, next);
        heap->used_pool_count--;
        
        rem_mem_pool->packet = NULL;
        TAILQ_INSERT_TAIL(&heap->unused_mem_pools, rem_mem_pool, next);
        TAILQ_INSERT_TAIL(&heap->unused_packets, packet, next);
        heap->unused_pool_count++;
        flow->packet_count--;
    }    
        
    fflush(output->output_file);
    TimeGet(&output->updated); 
    output->flow = flow;
    return output;
}

void TimeMachineOutputDestroy(TimeMachineOutput* output) {
    
    if (output->pcap_dumper) {
        pcap_dump_flush(output->pcap_dumper);
        pcap_dump_close(output->pcap_dumper);
    }
    
    if (output->pcap_out) {
        pcap_close(output->pcap_out);
    }
    
    SCFree(output);
}
