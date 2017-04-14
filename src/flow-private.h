/* Copyright (C) 2007-2016 Open Information Security Foundation
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

#ifndef __FLOW_PRIVATE_H__
#define __FLOW_PRIVATE_H__

#include "flow-hash.h"
#include "flow-queue.h"

#include "util-atomic.h"

/* global flow flags */

/** Flow engine is in emergency mode. This means it doesn't have enough spare
 *  flows for new flows and/or it's memcap limit it reached. In this state the
 *  flow engine with evaluate flows with lower timeout settings. */
#define FLOW_EMERGENCY   0x01

/* Flow Time out values */
#define FLOW_DEFAULT_NEW_TIMEOUT 30
#define FLOW_DEFAULT_EST_TIMEOUT 300
#define FLOW_DEFAULT_CLOSED_TIMEOUT 0
#define FLOW_DEFAULT_BYPASSED_TIMEOUT 100
#define FLOW_IPPROTO_TCP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_TCP_EST_TIMEOUT 300
#define FLOW_IPPROTO_TCP_BYPASSED_TIMEOUT 100
#define FLOW_IPPROTO_UDP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_UDP_EST_TIMEOUT 300
#define FLOW_IPPROTO_UDP_BYPASSED_TIMEOUT 100
#define FLOW_IPPROTO_ICMP_NEW_TIMEOUT 30
#define FLOW_IPPROTO_ICMP_EST_TIMEOUT 300
#define FLOW_IPPROTO_ICMP_BYPASSED_TIMEOUT 100

#define FLOW_DEFAULT_EMERG_NEW_TIMEOUT 10
#define FLOW_DEFAULT_EMERG_EST_TIMEOUT 100
#define FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT 0
#define FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT 50
#define FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT 100

#define FLOW_BYPASSED_TIMEOUT   6

enum {
    FLOW_PROTO_TCP = 0,
    FLOW_PROTO_UDP,
    FLOW_PROTO_ICMP,
    FLOW_PROTO_SCTP,
    FLOW_PROTO_DEFAULT,

    /* should be last */
    FLOW_PROTO_MAX,
};
/* max used in app-layer (counters) */
#define FLOW_PROTO_APPLAYER_MAX FLOW_PROTO_UDP + 1

/*
 * Variables
 */

/** FlowProto specific timeouts and free/state functions */

FlowProtoTimeout flow_timeouts_normal[FLOW_PROTO_MAX];
FlowProtoTimeout flow_timeouts_emerg[FLOW_PROTO_MAX];
FlowProtoFreeFunc flow_freefuncs[FLOW_PROTO_MAX];

/** spare/unused/prealloced flows live here */
FlowQueue flow_spare_q;

/** queue to pass flows to cleanup/log thread(s) */
FlowQueue flow_recycle_q;

FlowBucket *flow_hash;
FlowConfig flow_config;

/** flow memuse counter (atomic), for enforcing memcap limit */
SC_ATOMIC_DECLARE(uint64_t, flow_memuse);

#endif /* __FLOW_PRIVATE_H__ */

