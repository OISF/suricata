/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#include "util-optimize.h"

/* Part of the flow structure, so we declare it here.
 * The actual declaration is in app-layer-parser.c */
typedef struct AppLayerParserState_ AppLayerParserState;

#define FLOW_QUIET      TRUE
#define FLOW_VERBOSE    FALSE

#define TOSERVER 0
#define TOCLIENT 1

/* per flow flags */

/** At least on packet from the source address was seen */
#define FLOW_TO_SRC_SEEN                  0x00000001
/** At least on packet from the destination address was seen */
#define FLOW_TO_DST_SEEN                  0x00000002
/** Don't return this from the flow hash. It has been replaced. */
#define FLOW_TCP_REUSED                   0x00000004
/** no magic on files in this flow */
#define FLOW_FILE_NO_MAGIC_TS             0x00000008
#define FLOW_FILE_NO_MAGIC_TC             0x00000010

/** Flow was inspected against IP-Only sigs in the toserver direction */
#define FLOW_TOSERVER_IPONLY_SET          0x00000020
/** Flow was inspected against IP-Only sigs in the toclient direction */
#define FLOW_TOCLIENT_IPONLY_SET          0x00000040

/** Packet belonging to this flow should not be inspected at all */
#define FLOW_NOPACKET_INSPECTION          0x00000080
/** Packet payloads belonging to this flow should not be inspected */
#define FLOW_NOPAYLOAD_INSPECTION         0x00000100

/** All packets in this flow should be dropped */
#define FLOW_ACTION_DROP                  0x00000200

/** Sgh for toserver direction set (even if it's NULL) */
#define FLOW_SGH_TOSERVER                 0x00000800
/** Sgh for toclient direction set (even if it's NULL) */
#define FLOW_SGH_TOCLIENT                 0x00001000

/** packet to server direction has been logged in drop file (only in IPS mode) */
#define FLOW_TOSERVER_DROP_LOGGED         0x00002000
/** packet to client direction has been logged in drop file (only in IPS mode) */
#define FLOW_TOCLIENT_DROP_LOGGED         0x00004000
/** alproto detect done.  Right now we need it only for udp */
#define FLOW_ALPROTO_DETECT_DONE          0x00008000

// vacany 1x

/** Pattern matcher alproto detection done */
#define FLOW_TS_PM_ALPROTO_DETECT_DONE    0x00020000
/** Probing parser alproto detection done */
#define FLOW_TS_PP_ALPROTO_DETECT_DONE    0x00040000
/** Pattern matcher alproto detection done */
#define FLOW_TC_PM_ALPROTO_DETECT_DONE    0x00100000
/** Probing parser alproto detection done */
#define FLOW_TC_PP_ALPROTO_DETECT_DONE    0x00200000
#define FLOW_TIMEOUT_REASSEMBLY_DONE      0x00800000
/** even if the flow has files, don't store 'm */
#define FLOW_FILE_NO_STORE_TS             0x01000000
#define FLOW_FILE_NO_STORE_TC             0x02000000

/** flow is ipv4 */
#define FLOW_IPV4                         0x04000000
/** flow is ipv6 */
#define FLOW_IPV6                         0x08000000

/** no md5 on files in this flow */
#define FLOW_FILE_NO_MD5_TS               0x10000000
#define FLOW_FILE_NO_MD5_TC               0x20000000

/** no size tracking of files in this flow */
#define FLOW_FILE_NO_SIZE_TS              0x40000000
#define FLOW_FILE_NO_SIZE_TC              0x80000000

#define FLOW_IS_IPV4(f) \
    (((f)->flags & FLOW_IPV4) == FLOW_IPV4)
#define FLOW_IS_IPV6(f) \
    (((f)->flags & FLOW_IPV6) == FLOW_IPV6)

#define FLOW_COPY_IPV4_ADDR_TO_PACKET(fa, pa) do {      \
        (pa)->family = AF_INET;                         \
        (pa)->addr_data32[0] = (fa)->addr_data32[0];    \
    } while (0)

#define FLOW_COPY_IPV6_ADDR_TO_PACKET(fa, pa) do {      \
        (pa)->family = AF_INET6;                        \
        (pa)->addr_data32[0] = (fa)->addr_data32[0];    \
        (pa)->addr_data32[1] = (fa)->addr_data32[1];    \
        (pa)->addr_data32[2] = (fa)->addr_data32[2];    \
        (pa)->addr_data32[3] = (fa)->addr_data32[3];    \
    } while (0)

/* Set the IPv4 addressesinto the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, a) do {             \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

#define FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, a) do {             \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define FLOW_CLEAR_ADDR(a) do {  \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the IPv6 addressesinto the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, a) do {   \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)

#define FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, a) do {   \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)

/* pkt flow flags */
#define FLOW_PKT_TOSERVER               0x01
#define FLOW_PKT_TOCLIENT               0x02
#define FLOW_PKT_ESTABLISHED            0x04
#define FLOW_PKT_TOSERVER_IPONLY_SET    0x08
#define FLOW_PKT_TOCLIENT_IPONLY_SET    0x10
#define FLOW_PKT_TOSERVER_FIRST         0x20
#define FLOW_PKT_TOCLIENT_FIRST         0x40

#define FLOW_END_FLAG_STATE_NEW         0x01
#define FLOW_END_FLAG_STATE_ESTABLISHED 0x02
#define FLOW_END_FLAG_STATE_CLOSED      0x04
#define FLOW_END_FLAG_EMERGENCY         0x08
#define FLOW_END_FLAG_TIMEOUT           0x10
#define FLOW_END_FLAG_FORCED            0x20
#define FLOW_END_FLAG_SHUTDOWN          0x40

/** Mutex or RWLocks for the flow. */
//#define FLOWLOCK_RWLOCK
#define FLOWLOCK_MUTEX

#ifdef FLOWLOCK_RWLOCK
    #ifdef FLOWLOCK_MUTEX
        #error Cannot enable both FLOWLOCK_RWLOCK and FLOWLOCK_MUTEX
    #endif
#endif

#ifdef FLOWLOCK_RWLOCK
    #define FLOWLOCK_INIT(fb) SCRWLockInit(&(fb)->r, NULL)
    #define FLOWLOCK_DESTROY(fb) SCRWLockDestroy(&(fb)->r)
    #define FLOWLOCK_RDLOCK(fb) SCRWLockRDLock(&(fb)->r)
    #define FLOWLOCK_WRLOCK(fb) SCRWLockWRLock(&(fb)->r)
    #define FLOWLOCK_TRYRDLOCK(fb) SCRWLockTryRDLock(&(fb)->r)
    #define FLOWLOCK_TRYWRLOCK(fb) SCRWLockTryWRLock(&(fb)->r)
    #define FLOWLOCK_UNLOCK(fb) SCRWLockUnlock(&(fb)->r)
#elif defined FLOWLOCK_MUTEX
    #define FLOWLOCK_INIT(fb) SCMutexInit(&(fb)->m, NULL)
    #define FLOWLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->m)
    #define FLOWLOCK_RDLOCK(fb) SCMutexLock(&(fb)->m)
    #define FLOWLOCK_WRLOCK(fb) SCMutexLock(&(fb)->m)
    #define FLOWLOCK_TRYRDLOCK(fb) SCMutexTrylock(&(fb)->m)
    #define FLOWLOCK_TRYWRLOCK(fb) SCMutexTrylock(&(fb)->m)
    #define FLOWLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->m)
#else
    #error Enable FLOWLOCK_RWLOCK or FLOWLOCK_MUTEX
#endif

#define FLOW_IS_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_IS_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_SET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_SET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_RESET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PP_ALPROTO_DETECT_DONE))

/* global flow config */
typedef struct FlowCnf_
{
    uint32_t hash_rand;
    uint32_t hash_size;
    uint64_t memcap;
    uint32_t max_flows;
    uint32_t prealloc;

    uint32_t timeout_new;
    uint32_t timeout_est;

    uint32_t emerg_timeout_new;
    uint32_t emerg_timeout_est;
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

typedef struct FlowAddress_ {
    union {
        uint32_t       address_un_data32[4]; /* type-specific field */
        uint16_t       address_un_data16[8]; /* type-specific field */
        uint8_t        address_un_data8[16]; /* type-specific field */
    } address;
} FlowAddress;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8

#ifdef __tile__
/* Atomic Ints performance better on Tile. */
typedef unsigned int FlowRefCount;
#else
typedef unsigned short FlowRefCount;
#endif

#ifdef __tile__
/* Atomic Ints performance better on Tile. */
typedef unsigned int FlowStateType;
#else
typedef unsigned short FlowStateType;
#endif

/** Local Thread ID */
typedef uint16_t FlowThreadId;

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
    FlowAddress src, dst;
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
    uint16_t vlan_id[2];

    /* end of flow "header" */

    SC_ATOMIC_DECLARE(FlowStateType, flow_state);

    /** how many pkts and stream msgs are using the flow *right now*. This
     *  variable is atomic so not protected by the Flow mutex "m".
     *
     *  On receiving a packet the counter is incremented while the flow
     *  bucked is locked, which is also the case on timeout pruning.
     */
    SC_ATOMIC_DECLARE(FlowRefCount, use_cnt);

    /** flow queue id, used with autofp */
    SC_ATOMIC_DECLARE(int16_t, autofp_tmqh_flow_qid);

    /** flow tenant id, used to setup flow timeout and stream pseudo
     *  packets with the correct tenant id set */
    uint32_t tenant_id;

    uint32_t probing_parser_toserver_alproto_masks;
    uint32_t probing_parser_toclient_alproto_masks;

    uint32_t flags;

    /* time stamp of last update (last packet). Set/updated under the
     * flow and flow hash row locks, safe to read under either the
     * flow lock or flow hash row lock. */
    struct timeval lastts;

#ifdef FLOWLOCK_RWLOCK
    SCRWLock r;
#elif defined FLOWLOCK_MUTEX
    SCMutex m;
#else
    #error Enable FLOWLOCK_RWLOCK or FLOWLOCK_MUTEX
#endif

    /** protocol specific data pointer, e.g. for TcpSession */
    void *protoctx;

    /** mapping to Flow's protocol specific protocols for timeouts
        and state and free functions. */
    uint8_t protomap;

    uint8_t flow_end_flags;
    /* coccinelle: Flow:flow_end_flags:FLOW_END_FLAG_ */

    AppProto alproto; /**< \brief application level protocol */
    AppProto alproto_ts;
    AppProto alproto_tc;

    uint32_t data_al_so_far[2];

    /** detection engine ctx id used to inspect this flow. Set at initial
     *  inspection. If it doesn't match the currently in use de_ctx, the
     *  de_state and stored sgh ptrs are reset. */
    uint32_t de_ctx_id;

    /** Thread ID for the stream/detect portion of this flow */
    FlowThreadId thread_id;

    /** detect state 'alversion' inspected for both directions */
    uint8_t detect_alversion[2];

    /** application level storage ptrs.
     *
     */
    AppLayerParserState *alparser;     /**< parser internal state */
    void *alstate;      /**< application layer state */

    /** detection engine state */
    struct DetectEngineStateFlow_ *de_state;

    /** toclient sgh for this flow. Only use when FLOW_SGH_TOCLIENT flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toclient;
    /** toserver sgh for this flow. Only use when FLOW_SGH_TOSERVER flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toserver;

    /* pointer to the var list */
    GenericVar *flowvar;

    /** hash list pointers, protected by fb->s */
    struct Flow_ *hnext; /* hash list */
    struct Flow_ *hprev;
    struct FlowBucket_ *fb;

    /** queue list pointers, protected by queue mutex */
    struct Flow_ *lnext; /* list */
    struct Flow_ *lprev;
    struct timeval startts;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t todstbytecnt;
    uint64_t tosrcbytecnt;
} Flow;

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
} FlowProto;

void FlowHandlePacket (ThreadVars *, DecodeThreadVars *, Packet *);
void FlowInitConfig (char);
void FlowPrintQueueInfo (void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, char);
void FlowSetIPOnlyFlagNoLock(Flow *, char);

void FlowRegisterTests (void);
int FlowSetProtoTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoFreeFunc (uint8_t , void (*Free)(void *));
void FlowUpdateQueue(Flow *);

struct FlowQueue_;

int FlowUpdateSpareFlows(void);

static inline void FlowLockSetNoPacketInspectionFlag(Flow *);
static inline void FlowSetNoPacketInspectionFlag(Flow *);
static inline void FlowLockSetNoPayloadInspectionFlag(Flow *);
static inline void FlowSetNoPayloadInspectionFlag(Flow *);

int FlowGetPacketDirection(const Flow *, const Packet *);

void FlowCleanupAppLayer(Flow *);

/** ----- Inline functions ----- */

/** \brief Set the No Packet Inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowLockSetNoPacketInspectionFlag(Flow *f)
{
    SCEnter();

    SCLogDebug("flow %p", f);
    FLOWLOCK_WRLOCK(f);
    f->flags |= FLOW_NOPACKET_INSPECTION;
    FLOWLOCK_UNLOCK(f);

    SCReturn;
}

/** \brief Set the No Packet Inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline  void FlowSetNoPacketInspectionFlag(Flow *f)
{
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPACKET_INSPECTION;

    SCReturn;
}

/** \brief Set the No payload inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowLockSetNoPayloadInspectionFlag(Flow *f)
{
    SCEnter();

    SCLogDebug("flow %p", f);
    FLOWLOCK_WRLOCK(f);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;
    FLOWLOCK_UNLOCK(f);

    SCReturn;
}

/** \brief Set the No payload inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
static inline void FlowSetNoPayloadInspectionFlag(Flow *f)
{
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;

    SCReturn;
}

/**
 *  \brief increase the use count of a flow
 *
 *  \param f flow to decrease use count for
 */
static inline void FlowIncrUsecnt(Flow *f)
{
    if (f == NULL)
        return;

    (void) SC_ATOMIC_ADD(f->use_cnt, 1);
}

/**
 *  \brief decrease the use count of a flow
 *
 *  \param f flow to decrease use count for
 */
static inline void FlowDecrUsecnt(Flow *f)
{
    if (f == NULL)
        return;

    (void) SC_ATOMIC_SUB(f->use_cnt, 1);
}

/** \brief Reference the flow, bumping the flows use_cnt
 *  \note This should only be called once for a destination
 *        pointer */
static inline void FlowReference(Flow **d, Flow *f)
{
    if (likely(f != NULL)) {
#ifdef DEBUG_VALIDATION
        BUG_ON(*d == f);
#else
        if (*d == f)
            return;
#endif
        FlowIncrUsecnt(f);
        *d = f;
    }
}

static inline void FlowDeReference(Flow **d)
{
    if (likely(*d != NULL)) {
        FlowDecrUsecnt(*d);
        *d = NULL;
    }
}

int FlowClearMemory(Flow *,uint8_t );

AppProto FlowGetAppProtocol(const Flow *f);
void *FlowGetAppState(const Flow *f);
uint8_t FlowGetDisruptionFlags(const Flow *f, uint8_t flags);

void FlowHandlePacketUpdateRemove(Flow *f, Packet *p);
void FlowHandlePacketUpdate(Flow *f, Packet *p);

Flow *FlowGetFlowFromHashByPacket(const Packet *p);
Flow *FlowLookupFlowFromHash(const Packet *p);

#endif /* __FLOW_H__ */

