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

/* forward declaration for macset include */
typedef struct FlowStorageId FlowStorageId;

#include "decode.h"
#include "util-exception-policy.h"
#include "util-var.h"
#include "util-optimize.h"
#include "app-layer-protos.h"

/* Part of the flow structure, so we declare it here.
 * The actual declaration is in app-layer-parser.c */
typedef struct AppLayerParserState_ AppLayerParserState;

#define FLOW_QUIET   true
#define FLOW_VERBOSE false

#define TOSERVER 0
#define TOCLIENT 1

/* per flow flags */

/** At least one packet from the source address was seen */
#define FLOW_TO_SRC_SEEN                BIT_U32(0)
/** At least one packet from the destination address was seen */
#define FLOW_TO_DST_SEEN                BIT_U32(1)
/** Don't return this from the flow hash. It has been replaced. */
#define FLOW_TCP_REUSED                 BIT_U32(2)

/** Flow was inspected against IP-Only sigs in the toserver direction */
#define FLOW_TOSERVER_IPONLY_SET        BIT_U32(3)
/** Flow was inspected against IP-Only sigs in the toclient direction */
#define FLOW_TOCLIENT_IPONLY_SET        BIT_U32(4)

/** Packet belonging to this flow should not be inspected at all */
#define FLOW_NOPACKET_INSPECTION        BIT_U32(5)
/** Packet payloads belonging to this flow should not be inspected */
#define FLOW_NOPAYLOAD_INSPECTION       BIT_U32(6)

/** All packets in this flow should be dropped */
#define FLOW_ACTION_DROP                BIT_U32(7)

/** Sgh for toserver direction set (even if it's NULL) */
#define FLOW_SGH_TOSERVER               BIT_U32(8)
/** Sgh for toclient direction set (even if it's NULL) */
#define FLOW_SGH_TOCLIENT               BIT_U32(9)

/** packet to server direction has been logged in drop file (only in IPS mode) */
#define FLOW_TOSERVER_DROP_LOGGED       BIT_U32(10)
/** packet to client direction has been logged in drop file (only in IPS mode) */
#define FLOW_TOCLIENT_DROP_LOGGED       BIT_U32(11)

/** flow has alerts */
#define FLOW_HAS_ALERTS                 BIT_U32(12)

/** Pattern matcher alproto detection done */
#define FLOW_TS_PM_ALPROTO_DETECT_DONE  BIT_U32(13)
/** Probing parser alproto detection done */
#define FLOW_TS_PP_ALPROTO_DETECT_DONE  BIT_U32(14)
/** Expectation alproto detection done */
#define FLOW_TS_PE_ALPROTO_DETECT_DONE  BIT_U32(15)
/** Pattern matcher alproto detection done */
#define FLOW_TC_PM_ALPROTO_DETECT_DONE  BIT_U32(16)
/** Probing parser alproto detection done */
#define FLOW_TC_PP_ALPROTO_DETECT_DONE  BIT_U32(17)
/** Expectation alproto detection done */
#define FLOW_TC_PE_ALPROTO_DETECT_DONE  BIT_U32(18)
#define FLOW_TIMEOUT_REASSEMBLY_DONE    BIT_U32(19)

/** flow is ipv4 */
#define FLOW_IPV4                       BIT_U32(20)
/** flow is ipv6 */
#define FLOW_IPV6                       BIT_U32(21)

#define FLOW_PROTO_DETECT_TS_DONE       BIT_U32(22)
#define FLOW_PROTO_DETECT_TC_DONE       BIT_U32(23)

/** Indicate that alproto detection for flow should be done again */
#define FLOW_CHANGE_PROTO               BIT_U32(24)

#define FLOW_WRONG_THREAD               BIT_U32(25)
/** Protocol detection told us flow is picked up in wrong direction (midstream) */
#define FLOW_DIR_REVERSED               BIT_U32(26)
/** Indicate that the flow did trigger an expectation creation */
#define FLOW_HAS_EXPECTATION            BIT_U32(27)

/** All packets in this flow should be passed */
#define FLOW_ACTION_PASS BIT_U32(28)

/* File flags */

#define FLOWFILE_INIT                   0

/** no magic on files in this flow */
#define FLOWFILE_NO_MAGIC_TS            BIT_U16(0)
#define FLOWFILE_NO_MAGIC_TC            BIT_U16(1)

/** even if the flow has files, don't store 'm */
#define FLOWFILE_NO_STORE_TS            BIT_U16(2)
#define FLOWFILE_NO_STORE_TC            BIT_U16(3)
/** no md5 on files in this flow */
#define FLOWFILE_NO_MD5_TS              BIT_U16(4)
#define FLOWFILE_NO_MD5_TC              BIT_U16(5)

/** no sha1 on files in this flow */
#define FLOWFILE_NO_SHA1_TS             BIT_U16(6)
#define FLOWFILE_NO_SHA1_TC             BIT_U16(7)

/** no sha256 on files in this flow */
#define FLOWFILE_NO_SHA256_TS           BIT_U16(8)
#define FLOWFILE_NO_SHA256_TC           BIT_U16(9)

/** no size tracking of files in this flow */
#define FLOWFILE_NO_SIZE_TS             BIT_U16(10)
#define FLOWFILE_NO_SIZE_TC             BIT_U16(11)

/** no mime type tracking of files in this flow */
#define FLOWFILE_NO_MIMETYPE_TS         BIT_U16(12)
#define FLOWFILE_NO_MIMETYPE_TC         BIT_U16(13)

#define FLOWFILE_NONE_TS (FLOWFILE_NO_MAGIC_TS | \
                          FLOWFILE_NO_STORE_TS | \
                          FLOWFILE_NO_MD5_TS   | \
                          FLOWFILE_NO_SHA1_TS  | \
                          FLOWFILE_NO_SHA256_TS| \
                          FLOWFILE_NO_SIZE_TS  |\
                          FLOWFILE_NO_MIMETYPE_TS)
#define FLOWFILE_NONE_TC (FLOWFILE_NO_MAGIC_TC | \
                          FLOWFILE_NO_STORE_TC | \
                          FLOWFILE_NO_MD5_TC   | \
                          FLOWFILE_NO_SHA1_TC  | \
                          FLOWFILE_NO_SHA256_TC| \
                          FLOWFILE_NO_SIZE_TC  | \
                          FLOWFILE_NO_MIMETYPE_TC)
#define FLOWFILE_NONE    (FLOWFILE_NONE_TS|FLOWFILE_NONE_TC)

#define FLOW_IS_IPV4(f) \
    (((f)->flags & FLOW_IPV4) == FLOW_IPV4)
#define FLOW_IS_IPV6(f) \
    (((f)->flags & FLOW_IPV6) == FLOW_IPV6)

#define FLOW_GET_SP(f)  \
    ((f)->flags & FLOW_DIR_REVERSED) ? (f)->dp : (f)->sp;
#define FLOW_GET_DP(f)  \
    ((f)->flags & FLOW_DIR_REVERSED) ? (f)->sp : (f)->dp;

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
/** last pseudo packet in the flow. Can be used to trigger final clean,
 *  logging, etc. */
#define FLOW_PKT_LAST_PSEUDO            0x80

#define FLOW_END_FLAG_STATE_NEW         0x01
#define FLOW_END_FLAG_STATE_ESTABLISHED 0x02
#define FLOW_END_FLAG_STATE_CLOSED      0x04
#define FLOW_END_FLAG_EMERGENCY         0x08
#define FLOW_END_FLAG_TIMEOUT           0x10
#define FLOW_END_FLAG_FORCED            0x20
#define FLOW_END_FLAG_SHUTDOWN          0x40
#define FLOW_END_FLAG_STATE_BYPASSED    0x80

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
#define FLOW_IS_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PE_ALPROTO_DETECT_DONE))

#define FLOW_SET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_SET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PP_ALPROTO_DETECT_DONE))
#define FLOW_SET_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PE_ALPROTO_DETECT_DONE))

#define FLOW_RESET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PP_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PE_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PE_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PE_ALPROTO_DETECT_DONE))

/* global flow config */
typedef struct FlowCnf_
{
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t max_flows;
    uint32_t prealloc;

    uint32_t timeout_new;
    uint32_t timeout_est;

    uint32_t emerg_timeout_new;
    uint32_t emerg_timeout_est;
    uint32_t emergency_recovery;

    enum ExceptionPolicy memcap_policy;

    SC_ATOMIC_DECLARE(uint64_t, memcap);
} FlowConfig;

/* Hash key for the flow hash */
typedef struct FlowKey_
{
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint8_t recursion_level;
    uint16_t vlan_id[2];
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

typedef unsigned short FlowRefCount;

typedef unsigned short FlowStateType;

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
        struct {
            uint8_t type;   /**< icmp type */
            uint8_t code;   /**< icmp code */
        } icmp_s;

        struct {
            uint32_t spi; /**< esp spi */
        } esp;
    };
    union {
        Port dp;        /**< tcp/udp destination port */
        struct {
            uint8_t type;   /**< icmp type */
            uint8_t code;   /**< icmp code */
        } icmp_d;
    };
    uint8_t proto;
    uint8_t recursion_level;
    uint16_t vlan_id[2];
    /** how many references exist to this flow *right now*
     *
     *  On receiving a packet the counter is incremented while the flow
     *  bucked is locked, which is also the case on timeout pruning.
     */
    FlowRefCount use_cnt;

    uint8_t vlan_idx;

    /* track toserver/toclient flow timeout needs */
    union {
        struct {
            uint8_t ffr_ts:4;
            uint8_t ffr_tc:4;
        };
        uint8_t ffr;
    };

    /** timestamp in seconds of the moment this flow will timeout
     *  according to the timeout policy. Does *not* take emergency
     *  mode into account. */
    uint32_t timeout_at;

    /** Thread ID for the stream/detect portion of this flow */
    FlowThreadId thread_id[2];

    struct Flow_ *next; /* (hash) list next */
    /** Incoming interface */
    struct LiveDevice_ *livedev;

    /** flow hash - the flow hash before hash table size mod. */
    uint32_t flow_hash;

    /* time stamp of last update (last packet). Set/updated under the
     * flow and flow hash row locks, safe to read under either the
     * flow lock or flow hash row lock. */
    struct timeval lastts;

    /* end of flow "header" */

    /** timeout policy value in seconds to add to the lastts.tv_sec
     *  when a packet has been received. */
    uint32_t timeout_policy;

    FlowStateType flow_state;

    /** flow tenant id, used to setup flow timeout and stream pseudo
     *  packets with the correct tenant id set */
    uint32_t tenant_id;

    uint32_t probing_parser_toserver_alproto_masks;
    uint32_t probing_parser_toclient_alproto_masks;

    uint32_t flags;         /**< generic flags */

    uint16_t file_flags;    /**< file tracking/extraction flags */

    /** destination port to be used in protocol detection. This is meant
     *  for use with STARTTLS and HTTP CONNECT detection */
    uint16_t protodetect_dp; /**< 0 if not used */

    /* Parent flow id for protocol like ftp */
    int64_t parent_id;

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

    /** original application level protocol. Used to indicate the previous
       protocol when changing to another protocol , e.g. with STARTTLS. */
    AppProto alproto_orig;
    /** expected app protocol: used in protocol change/upgrade like in
     *  STARTTLS. */
    AppProto alproto_expect;

    /** detection engine ctx version used to inspect this flow. Set at initial
     *  inspection. If it doesn't match the currently in use de_ctx, the
     *  stored sgh ptrs are reset. */
    uint32_t de_ctx_version;

    /** ttl tracking */
    uint8_t min_ttl_toserver;
    uint8_t max_ttl_toserver;
    uint8_t min_ttl_toclient;
    uint8_t max_ttl_toclient;

    /** application level storage ptrs.
     *
     */
    AppLayerParserState *alparser;     /**< parser internal state */
    void *alstate;      /**< application layer state */

    /** toclient sgh for this flow. Only use when FLOW_SGH_TOCLIENT flow flag
     *  has been set. */
    const struct SigGroupHead_ *sgh_toclient;
    /** toserver sgh for this flow. Only use when FLOW_SGH_TOSERVER flow flag
     *  has been set. */
    const struct SigGroupHead_ *sgh_toserver;

    /* pointer to the var list */
    GenericVar *flowvar;

    struct FlowBucket_ *fb;

    struct timeval startts;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t todstbytecnt;
    uint64_t tosrcbytecnt;
} Flow;

enum FlowState {
    FLOW_STATE_NEW = 0,
    FLOW_STATE_ESTABLISHED,
    FLOW_STATE_CLOSED,
    FLOW_STATE_LOCAL_BYPASSED,
#ifdef CAPTURE_OFFLOAD
    FLOW_STATE_CAPTURE_BYPASSED,
#endif
};
#ifdef CAPTURE_OFFLOAD
#define FLOW_STATE_SIZE 5
#else
#define FLOW_STATE_SIZE 4
#endif

typedef struct FlowProtoTimeout_ {
    uint32_t new_timeout;
    uint32_t est_timeout;
    uint32_t closed_timeout;
    uint32_t bypassed_timeout;
} FlowProtoTimeout;

typedef struct FlowProtoFreeFunc_ {
    void (*Freefunc)(void *);
} FlowProtoFreeFunc;

typedef struct FlowBypassInfo_ {
    bool (* BypassUpdate)(Flow *f, void *data, time_t tsec);
    void (* BypassFree)(void *data);
    void *bypass_data;
    uint64_t tosrcpktcnt;
    uint64_t tosrcbytecnt;
    uint64_t todstpktcnt;
    uint64_t todstbytecnt;
} FlowBypassInfo;

#include "flow-queue.h"

typedef struct FlowLookupStruct_ // TODO name
{
    /** thread store of spare queues */
    FlowQueuePrivate spare_queue;
    DecodeThreadVars *dtv;
    FlowQueuePrivate work_queue;
    uint32_t emerg_spare_sync_stamp;
} FlowLookupStruct;

/** \brief prepare packet for a life with flow
 *  Set PKT_WANTS_FLOW flag to incidate workers should do a flow lookup
 *  and calc the hash value to be used in the lookup and autofp flow
 *  balancing. */
void FlowSetupPacket(Packet *p);
void FlowHandlePacket (ThreadVars *, FlowLookupStruct *, Packet *);
void FlowInitConfig(bool);
void FlowPrintQueueInfo (void);
void FlowReset(void);
void FlowShutdown(void);
void FlowSetIPOnlyFlag(Flow *, int);
void FlowSetHasAlertsFlag(Flow *);
int FlowHasAlerts(const Flow *);
void FlowSetChangeProtoFlag(Flow *);
void FlowUnsetChangeProtoFlag(Flow *);
int FlowChangeProto(Flow *);
void FlowSwap(Flow *);

void FlowRegisterTests (void);
int FlowSetProtoTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t ,uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoFreeFunc (uint8_t , void (*Free)(void *));
void FlowUpdateQueue(Flow *);

int FlowUpdateSpareFlows(void);

static inline void FlowSetNoPacketInspectionFlag(Flow *);
static inline void FlowSetNoPayloadInspectionFlag(Flow *);

int FlowGetPacketDirection(const Flow *, const Packet *);

void FlowCleanupAppLayer(Flow *);

void FlowUpdateState(Flow *f, enum FlowState s);

int FlowSetMemcap(uint64_t size);
uint64_t FlowGetMemcap(void);
uint64_t FlowGetMemuse(void);

FlowStorageId GetFlowBypassInfoID(void);
void RegisterFlowBypassInfo(void);

void FlowGetLastTimeAsParts(Flow *flow, uint64_t *secs, uint64_t *usecs);
uint32_t FlowGetFlags(Flow *flow);
uint16_t FlowGetSourcePort(Flow *flow);
uint16_t FlowGetDestinationPort(Flow *flow);

/** ----- Inline functions ----- */

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

    f->use_cnt++;
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

    f->use_cnt--;
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

/** \brief create a flow id that is as unique as possible
 *  \retval flow_id signed 64bit id
 *  \note signed because of the signedness of json_integer_t in
 *        the json output
 */
static inline int64_t FlowGetId(const Flow *f)
{
    int64_t id = (int64_t)f->flow_hash << 31 |
        (int64_t)(f->startts.tv_sec & 0x0000FFFF) << 16 |
        (int64_t)(f->startts.tv_usec & 0x0000FFFF);
    /* reduce to 51 bits as Javascript and even JSON often seem to
     * max out there. */
    id &= 0x7ffffffffffffLL;
    return id;
}

static inline void FlowSetEndFlags(Flow *f)
{
    const int state = f->flow_state;
    if (state == FLOW_STATE_NEW)
        f->flow_end_flags |= FLOW_END_FLAG_STATE_NEW;
    else if (state == FLOW_STATE_ESTABLISHED)
        f->flow_end_flags |= FLOW_END_FLAG_STATE_ESTABLISHED;
    else if (state == FLOW_STATE_CLOSED)
        f->flow_end_flags |= FLOW_END_FLAG_STATE_CLOSED;
    else if (state == FLOW_STATE_LOCAL_BYPASSED)
        f->flow_end_flags |= FLOW_END_FLAG_STATE_BYPASSED;
#ifdef CAPTURE_OFFLOAD
    else if (state == FLOW_STATE_CAPTURE_BYPASSED)
        f->flow_end_flags = FLOW_END_FLAG_STATE_BYPASSED;
#endif
}

static inline bool FlowIsBypassed(const Flow *f)
{
    if (
#ifdef CAPTURE_OFFLOAD
            f->flow_state == FLOW_STATE_CAPTURE_BYPASSED ||
#endif
            f->flow_state == FLOW_STATE_LOCAL_BYPASSED) {
        return true;
    }
    return false;
}

int FlowClearMemory(Flow *,uint8_t );

AppProto FlowGetAppProtocol(const Flow *f);
void *FlowGetAppState(const Flow *f);
uint8_t FlowGetDisruptionFlags(const Flow *f, uint8_t flags);

void FlowHandlePacketUpdate(Flow *f, Packet *p, ThreadVars *tv, DecodeThreadVars *dtv);

#endif /* __FLOW_H__ */
