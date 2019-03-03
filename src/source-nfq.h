/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 */

#ifndef __SOURCE_NFQ_H__
#define __SOURCE_NFQ_H__

#ifdef NFQ

#include "threads.h"
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

// Netfilter's limit
#define NFQ_MAX_QUEUE 65535

/* idea: set the recv-thread id in the packet to
 * select an verdict-queue */

typedef struct NFQPacketVars_
{
    int id; /* this nfq packets id */
    uint16_t nfq_index; /* index in NFQ array */
    uint8_t verdicted;

    uint32_t mark;
    uint32_t ifi;
    uint32_t ifo;
    uint16_t hw_protocol;
} NFQPacketVars;

typedef struct NFQQueueVars_
{
    struct nfq_handle *h;
    struct nfnl_handle *nh;
    int fd;
    uint8_t use_mutex;
    /* 2 threads deal with the queue handle, so add a mutex */
    struct nfq_q_handle *qh;
    SCMutex mutex_qh;
    /* this one should be not changing after init */
    uint16_t queue_num;
    /* position into the NFQ queue var array */
    uint16_t nfq_index;

#ifdef DBG_PERF
    int dbg_maxreadsize;
#endif /* DBG_PERF */

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
    uint32_t replaced;
    struct {
        uint32_t packet_id; /* id of last processed packet */
        uint32_t verdict;
        uint32_t mark;
        uint8_t mark_valid:1;
        uint8_t len;
        uint8_t maxlen;
    } verdict_cache;

} NFQQueueVars;

typedef struct NFQGlobalVars_
{
    char unbind;
} NFQGlobalVars;

void NFQInitConfig(char quiet);
int NFQRegisterQueue(const uint16_t number);
int NFQParseAndRegisterQueues(const char *queues);
int NFQGetQueueCount(void);
void *NFQGetQueue(int number);
int NFQGetQueueNum(int number);
void *NFQGetThread(int number);
void NFQContextsClean(void);
#endif /* NFQ */
#endif /* __SOURCE_NFQ_H__ */

