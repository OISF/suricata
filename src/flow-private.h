/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#define FLOW_IPPROTO_TCP_CLOSED_TIMEOUT 10
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
#define FLOW_IPPROTO_TCP_EMERG_CLOSED_TIMEOUT 5
#define FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT 100
#define FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT 10
#define FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT 100

#define FLOW_BYPASSED_TIMEOUT   100

enum {
    FLOW_PROTO_TCP = 0,
    FLOW_PROTO_UDP,
    FLOW_PROTO_ICMP,
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

extern FlowProtoTimeout flow_timeouts_normal[FLOW_PROTO_MAX];
extern FlowProtoTimeout flow_timeouts_emerg[FLOW_PROTO_MAX];
extern FlowProtoFreeFunc flow_freefuncs[FLOW_PROTO_MAX];

/** spare/unused/prealloced flows live here */
//extern FlowQueue flow_spare_q;

/** queue to pass flows to cleanup/log thread(s) */
extern FlowQueue flow_recycle_q;

extern FlowBucket *flow_hash;
extern FlowConfig flow_config;

/** flow memuse counter (atomic), for enforcing memcap limit */
SC_ATOMIC_EXTERN(uint64_t, flow_memuse);

typedef FlowProtoTimeout *FlowProtoTimeoutPtr;
SC_ATOMIC_EXTERN(FlowProtoTimeoutPtr, flow_timeouts);

static inline uint32_t FlowGetFlowTimeoutDirect(
        const FlowProtoTimeoutPtr flow_timeouts,
        const enum FlowState state, const uint8_t protomap)
{
    uint32_t timeout;
    switch (state) {
        default:
        case FLOW_STATE_NEW:
            timeout = flow_timeouts[protomap].new_timeout;
            break;
        case FLOW_STATE_ESTABLISHED:
            timeout = flow_timeouts[protomap].est_timeout;
            break;
        case FLOW_STATE_CLOSED:
            timeout = flow_timeouts[protomap].closed_timeout;
            break;
#ifdef CAPTURE_OFFLOAD
        case FLOW_STATE_CAPTURE_BYPASSED:
            timeout = FLOW_BYPASSED_TIMEOUT;
            break;
#endif
        case FLOW_STATE_LOCAL_BYPASSED:
            timeout = flow_timeouts[protomap].bypassed_timeout;
            break;
    }
    return timeout;
}

/** \internal
 *  \brief get timeout for flow
 *
 *  \param f flow
 *  \param state flow state
 *
 *  \retval timeout timeout in seconds
 */
static inline uint32_t FlowGetFlowTimeout(const Flow *f, enum FlowState state)
{
    FlowProtoTimeoutPtr flow_timeouts = SC_ATOMIC_GET(flow_timeouts);
    return FlowGetFlowTimeoutDirect(flow_timeouts, state, f->protomap);
}

/** \internal
 *  \brief get timeout policy for flow
 *  \note does not take emergency mode into account. Always
 *        returns the 'normal' policy.
 *
 *  \param f flow
 *
 *  \retval timeout timeout in seconds
 */
static inline uint32_t FlowGetTimeoutPolicy(const Flow *f)
{
    uint32_t timeout;
    FlowProtoTimeoutPtr flow_timeouts = flow_timeouts_normal;
    switch (f->flow_state) {
        default:
        case FLOW_STATE_NEW:
            timeout = flow_timeouts[f->protomap].new_timeout;
            break;
        case FLOW_STATE_ESTABLISHED:
            timeout = flow_timeouts[f->protomap].est_timeout;
            break;
        case FLOW_STATE_CLOSED:
            timeout = flow_timeouts[f->protomap].closed_timeout;
            break;
#ifdef CAPTURE_OFFLOAD
        case FLOW_STATE_CAPTURE_BYPASSED:
            timeout = FLOW_BYPASSED_TIMEOUT;
            break;
#endif
        case FLOW_STATE_LOCAL_BYPASSED:
            timeout = flow_timeouts[f->protomap].bypassed_timeout;
            break;
    }
    return timeout;
}
#endif /* __FLOW_PRIVATE_H__ */
