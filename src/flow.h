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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __FLOW_H__
#define __FLOW_H__

#include "decode.h"
#include "util-var.h"
#include "util-atomic.h"
#include "detect-tag.h"

#define FLOW_QUIET      TRUE
#define FLOW_VERBOSE    FALSE

#define TOSERVER 0
#define TOCLIENT 1

/* per flow flags */

/** At least on packet from the source address was seen */
#define FLOW_TO_SRC_SEEN            0x0001
/** At least on packet from the destination address was seen */
#define FLOW_TO_DST_SEEN            0x0002

/** Flow lives in the flow-state-NEW list */
#define FLOW_NEW_LIST               0x0004
/** Flow lives in the flow-state-EST (established) list */
#define FLOW_EST_LIST               0x0008
/** Flow lives in the flow-state-CLOSED list */
#define FLOW_CLOSED_LIST            0x0010

/** Flow was inspected against IP-Only sigs in the toserver direction */
#define FLOW_TOSERVER_IPONLY_SET    0x0020
/** Flow was inspected against IP-Only sigs in the toclient direction */
#define FLOW_TOCLIENT_IPONLY_SET    0x0040

/** Packet belonging to this flow should not be inspected at all */
#define FLOW_NOPACKET_INSPECTION    0x0080
/** Packet payloads belonging to this flow should not be inspected */
#define FLOW_NOPAYLOAD_INSPECTION   0x0100

/** All packets in this flow should be dropped */
#define FLOW_ACTION_DROP            0x0200
/** All packets in this flow should be accepted */
#define FLOW_ACTION_PASS            0x0400

/** Sgh for toserver direction set (even if it's NULL) */
#define FLOW_SGH_TOSERVER           0x0800
/** Sgh for toclient direction set (even if it's NULL) */
#define FLOW_SGH_TOCLIENT           0x1000

/* pkt flow flags */
#define FLOW_PKT_TOSERVER               0x01
#define FLOW_PKT_TOCLIENT               0x02
#define FLOW_PKT_ESTABLISHED            0x04
#define FLOW_PKT_STATELESS              0x08
#define FLOW_PKT_TOSERVER_IPONLY_SET    0x10
#define FLOW_PKT_TOCLIENT_IPONLY_SET    0x20
#define FLOW_PKT_NOSTREAM               0x40
#define FLOW_PKT_STREAMONLY             0x80

/* global flow config */
typedef struct FlowCnf_
{
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t max_flows;
    uint32_t memcap;
    uint32_t prealloc;

    uint32_t timeout_new;
    uint32_t timeout_est;

    uint32_t emerg_timeout_new;
    uint32_t emerg_timeout_est;
    uint32_t flow_try_release;
    uint32_t emergency_recovery;

} FlowConfig;

/* Hash key for the flow hash */
typedef struct FlowKey_
{
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint8_t recursion_level;

} FlowKey;

/**
 *  \brief Flow data structure.
 *
 *  The flow is a global data structure that is created for new packets of a
 *  flow and then looked up for the following packets of a flow.
 *
 *  Locking
 *
 *  The flow is updated/used by multiple packets at the same time. This is why
 *  there is a flow-mutex. It's a mutex and not a spinlock because some
 *  operations on the flow can be quite expensive, thus spinning would be
 *  too expensive.
 *
 *  The flow "header" (addresses, ports, proto, recursion level) are static
 *  after the initialization and remain read-only throughout the entire live
 *  of a flow. This is why we can access those without protection of the lock.
 */

typedef struct Flow_
{
    /* flow "header", used for hashing and flow lookup. Static after init,
     * so safe to look at without lock */
    Address src, dst;
    union {
        Port sp;        /**< tcp/udp source port */
        uint8_t type;   /**< icmp type */
    };
    union {
        Port dp;        /**< tcp/udp destination port */
        uint8_t code;   /**< icmp code */
    };
    uint8_t proto;
    uint8_t recursion_level;

    /* end of flow "header" */

    uint16_t flags;

    /* ts of flow init and last update */
    struct timeval startts;
    struct timeval lastts;

    /* pointer to the var list */
    GenericVar *flowvar;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t bytecnt;

    /** mapping to Flow's protocol specific protocols for timeouts
        and state and free functions. */
    uint8_t protomap;

    /** protocol specific data pointer, e.g. for TcpSession */
    void *protoctx;

    /** how many pkts and stream msgs are using the flow *right now*. This
     *  variable is atomic so not protected by the Flow mutex "m".
     *
     *  On receiving a packet the counter is incremented while the flow
     *  bucked is locked, which is also the case on timeout pruning.
     */
    SC_ATOMIC_DECLARE(unsigned short, use_cnt);

    /** detection engine state */
    struct DetectEngineState_ *de_state;
    SCMutex de_state_m;          /**< mutex lock for the de_state object */

    /** toclient sgh for this flow. Only use when FLOW_SGH_TOCLIENT flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toclient;
    /** toserver sgh for this flow. Only use when FLOW_SGH_TOSERVER flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toserver;

    SCMutex m;

    /** List of tags of this flow (from "tag" keyword of type "session") */
    DetectTagDataEntryList *tag_list;

    /* list flow ptrs
     * NOTE!!! These are NOT protected by the
     * above mutex, but by the FlowQ's */
    struct Flow_ *hnext; /* hash list */
    struct Flow_ *hprev;
    struct Flow_ *lnext; /* list */
    struct Flow_ *lprev;

    struct FlowBucket_ *fb;

    uint16_t alproto; /**< application level protocol */
    void **aldata; /**< application level storage ptrs */
    uint8_t alflags; /**< application level specific flags */

} Flow;

/** Flow Application Level flags */
#define FLOW_AL_PROTO_UNKNOWN           0x01
#define FLOW_AL_PROTO_DETECT_DONE       0x02
#define FLOW_AL_NO_APPLAYER_INSPECTION  0x04 /** \todo move to flow flags later */
#define FLOW_AL_STREAM_START            0x08
#define FLOW_AL_STREAM_EOF              0x10
#define FLOW_AL_STREAM_TOSERVER         0x20
#define FLOW_AL_STREAM_TOCLIENT         0x40
#define FLOW_AL_STREAM_GAP              0x80

enum {
    FLOW_STATE_NEW = 0,
    FLOW_STATE_ESTABLISHED,
    FLOW_STATE_CLOSED,
};

typedef struct FlowProto_ {
    uint32_t new_timeout;
    uint32_t est_timeout;
    uint32_t closed_timeout;
    uint32_t emerg_new_timeout;
    uint32_t emerg_est_timeout;
    uint32_t emerg_closed_timeout;
    void (*Freefunc)(void *);
    int (*GetProtoState)(void *);
} FlowProto;

void FlowHandlePacket (ThreadVars *, Packet *);
void FlowInitConfig (char);
void FlowPrintQueueInfo (void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, char);
void FlowSetIPOnlyFlagNoLock(Flow *, char);

void FlowIncrUsecnt(Flow *);
void FlowDecrUsecnt(Flow *);

uint32_t FlowPruneFlowsCnt(struct timeval *, int);
uint32_t FlowKillFlowsCnt(int);

void *FlowManagerThread(void *td);

void FlowManagerThreadSpawn(void);
void FlowRegisterTests (void);
int FlowSetProtoTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoFreeFunc (uint8_t , void (*Free)(void *));
int FlowSetFlowStateFunc (uint8_t , int (*GetProtoState)(void *));
void FlowUpdateQueue(Flow *);

static inline void FlowLockSetNoPacketInspectionFlag(Flow *);
static inline void FlowSetNoPacketInspectionFlag(Flow *);
static inline void FlowLockSetNoPayloadInspectionFlag(Flow *);
static inline void FlowSetNoPayloadInspectionFlag(Flow *);
static inline void FlowSetSessionNoApplayerInspectionFlag(Flow *);

int FlowGetPacketDirection(Flow *, Packet *);

void FlowL7DataPtrInit(Flow *);
void FlowL7DataPtrFree(Flow *);

/** ----- Inline functions ----- */

/** \brief Set the No Packet Inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowLockSetNoPacketInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    SCMutexLock(&f->m);
    f->flags |= FLOW_NOPACKET_INSPECTION;
    SCMutexUnlock(&f->m);

    SCReturn;
}

/** \brief Set the No Packet Inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline  void FlowSetNoPacketInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPACKET_INSPECTION;

    SCReturn;
}

/** \brief Set the No payload inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowLockSetNoPayloadInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    SCMutexLock(&f->m);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;
    SCMutexUnlock(&f->m);

    SCReturn;
}

/** \brief Set the No payload inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowSetNoPayloadInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;

    SCReturn;
}

/** \brief set flow flag to disable app layer inspection
 *
 *  \param f *LOCKED* flow
 */
static inline void FlowSetSessionNoApplayerInspectionFlag(Flow *f) {
    f->alflags |= FLOW_AL_NO_APPLAYER_INSPECTION;
}


#endif /* __FLOW_H__ */

