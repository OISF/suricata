/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 *
 *  Flow implementation.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "action-globals.h"
#include "packet.h"
#include "decode.h"
#include "conf.h"
#include "threadvars.h"

#include "util-random.h"
#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"
#include "flow-manager.h"
#include "flow-storage.h"
#include "flow-bypass.h"
#include "flow-spare-pool.h"
#include "flow-callbacks.h"

#include "stream-tcp-private.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-macset.h"

#include "util-debug.h"

#include "app-layer-parser.h"
#include "app-layer-expectation.h"

#define FLOW_DEFAULT_EMERGENCY_RECOVERY 30

//#define FLOW_DEFAULT_HASHSIZE    262144
#define FLOW_DEFAULT_HASHSIZE    65536
//#define FLOW_DEFAULT_MEMCAP      128 * 1024 * 1024 /* 128 MB */
#define FLOW_DEFAULT_MEMCAP      (32 * 1024 * 1024) /* 32 MB */

#define FLOW_DEFAULT_PREALLOC    10000

SC_ATOMIC_DECLARE(FlowProtoTimeoutPtr, flow_timeouts);

/** atomic int that is used when freeing a flow from the hash. In this
 *  case we walk the hash to find a flow to free. This var records where
 *  we left off in the hash. Without this only the top rows of the hash
 *  are freed. This isn't just about fairness. Under severe pressure, the
 *  hash rows on top would be all freed and the time to find a flow to
 *  free increased with every run. */
SC_ATOMIC_DECLARE(unsigned int, flow_prune_idx);

/** atomic flags */
SC_ATOMIC_DECLARE(unsigned int, flow_flags);

/** FlowProto specific timeouts and free/state functions */

FlowProtoTimeout flow_timeouts_normal[FLOW_PROTO_MAX];
FlowProtoTimeout flow_timeouts_emerg[FLOW_PROTO_MAX];
FlowProtoTimeout flow_timeouts_delta[FLOW_PROTO_MAX];
FlowProtoFreeFunc flow_freefuncs[FLOW_PROTO_MAX];

FlowConfig flow_config;

/** flow memuse counter (atomic), for enforcing memcap limit */
SC_ATOMIC_DECLARE(uint64_t, flow_memuse);

void FlowRegisterTests(void);
void FlowInitFlowProto(void);
int FlowSetProtoFreeFunc(uint8_t, void (*Free)(void *));

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int FlowSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(flow_memuse) < size) {
        SC_ATOMIC_SET(flow_config.memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \retval memcap value
 */
uint64_t FlowGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(flow_config.memcap);
    return memcapcopy;
}

uint64_t FlowGetMemuse(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(flow_memuse);
    return memusecopy;
}

enum ExceptionPolicy FlowGetMemcapExceptionPolicy(void)
{
    return flow_config.memcap_policy;
}

void FlowCleanupAppLayer(Flow *f)
{
    if (f == NULL || f->proto == 0)
        return;

    AppLayerParserStateCleanup(f, f->alstate, f->alparser);
    f->alstate = NULL;
    f->alparser = NULL;
}

/** \brief Set the IPOnly scanned flag for 'direction'.
  *
  * \param f Flow to set the flag in
  * \param direction direction to set the flag in
  */
void FlowSetIPOnlyFlag(Flow *f, int direction)
{
    direction ? (f->flags |= FLOW_TOSERVER_IPONLY_SET) : (f->flags |= FLOW_TOCLIENT_IPONLY_SET);
}

/** \brief Set flag to indicate that flow has alerts
 *
 * \param f flow
 */
void FlowSetHasAlertsFlag(Flow *f)
{
    f->flags |= FLOW_HAS_ALERTS;
}

/** \brief Check if flow has alerts
 *
 * \param f flow
 * \retval 1 has alerts
 * \retval 0 has not alerts
 */
int FlowHasAlerts(const Flow *f)
{
    if (f->flags & FLOW_HAS_ALERTS) {
        return 1;
    }

    return 0;
}

/** \brief Set flag to indicate to change proto for the flow
 *
 * \param f flow
 */
void FlowSetChangeProtoFlag(Flow *f)
{
    f->flags |= FLOW_CHANGE_PROTO;
}

/** \brief Unset flag to indicate to change proto for the flow
 *
 * \param f flow
 */
void FlowUnsetChangeProtoFlag(Flow *f)
{
    f->flags &= ~FLOW_CHANGE_PROTO;
}

/** \brief Check if change proto flag is set for flow
 * \param f flow
 * \retval 1 change proto flag is set
 * \retval 0 change proto flag is not set
 */
int FlowChangeProto(Flow *f)
{
    if (f->flags & FLOW_CHANGE_PROTO) {
        return 1;
    }

    return 0;
}

static inline void FlowSwapFlags(Flow *f)
{
    SWAP_FLAGS(f->flags, FLOW_TO_SRC_SEEN, FLOW_TO_DST_SEEN);
    SWAP_FLAGS(f->flags, FLOW_TOSERVER_IPONLY_SET, FLOW_TOCLIENT_IPONLY_SET);
    SWAP_FLAGS(f->flags, FLOW_SGH_TOSERVER, FLOW_SGH_TOCLIENT);

    SWAP_FLAGS(f->flags, FLOW_TOSERVER_DROP_LOGGED, FLOW_TOCLIENT_DROP_LOGGED);
    SWAP_FLAGS(f->flags, FLOW_TS_PM_ALPROTO_DETECT_DONE, FLOW_TC_PM_ALPROTO_DETECT_DONE);
    SWAP_FLAGS(f->flags, FLOW_TS_PP_ALPROTO_DETECT_DONE, FLOW_TC_PP_ALPROTO_DETECT_DONE);
    SWAP_FLAGS(f->flags, FLOW_TS_PE_ALPROTO_DETECT_DONE, FLOW_TC_PE_ALPROTO_DETECT_DONE);

    SWAP_FLAGS(f->flags, FLOW_PROTO_DETECT_TS_DONE, FLOW_PROTO_DETECT_TC_DONE);
}

static inline void FlowSwapFileFlags(Flow *f)
{
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_MAGIC_TS, FLOWFILE_NO_MAGIC_TC);
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_STORE_TS, FLOWFILE_NO_STORE_TC);
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_MD5_TS, FLOWFILE_NO_MD5_TC);
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_SHA1_TS, FLOWFILE_NO_SHA1_TC);
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_SHA256_TS, FLOWFILE_NO_SHA256_TC);
    SWAP_FLAGS(f->file_flags, FLOWFILE_NO_SIZE_TS, FLOWFILE_NO_SIZE_TC);
}

static inline void TcpStreamFlowSwap(Flow *f)
{
    TcpSession *ssn = f->protoctx;
    SWAP_VARS(TcpStream, ssn->server, ssn->client);
    if (ssn->data_first_seen_dir & STREAM_TOSERVER) {
        ssn->data_first_seen_dir = STREAM_TOCLIENT;
    } else if (ssn->data_first_seen_dir & STREAM_TOCLIENT) {
        ssn->data_first_seen_dir = STREAM_TOSERVER;
    }
}

/** \brief swap the flow's direction
 *  \note leaves the 'header' untouched. Interpret that based
 *        on FLOW_DIR_REVERSED flag.
 *  \warning: only valid before applayer parsing started. This
 *            function doesn't swap anything in Flow::alparser,
 *            Flow::alstate
 */
void FlowSwap(Flow *f)
{
    f->flags |= FLOW_DIR_REVERSED;

    SWAP_VARS(uint32_t, f->probing_parser_toserver_alproto_masks,
                   f->probing_parser_toclient_alproto_masks);

    FlowSwapFlags(f);
    FlowSwapFileFlags(f);

    SWAP_VARS(FlowThreadId, f->thread_id[0], f->thread_id[1]);

    if (f->proto == IPPROTO_TCP) {
        TcpStreamFlowSwap(f);
    }

    SWAP_VARS(AppProto, f->alproto_ts, f->alproto_tc);
    SWAP_VARS(uint8_t, f->min_ttl_toserver, f->max_ttl_toserver);
    SWAP_VARS(uint8_t, f->min_ttl_toclient, f->max_ttl_toclient);

    /* not touching Flow::alparser and Flow::alstate */

    SWAP_VARS(const void *, f->sgh_toclient, f->sgh_toserver);

    SWAP_VARS(uint32_t, f->todstpktcnt, f->tosrcpktcnt);
    SWAP_VARS(uint64_t, f->todstbytecnt, f->tosrcbytecnt);
}

/**
 *  \brief determine the direction of the packet compared to the flow
 *  \retval 0 to_server
 *  \retval 1 to_client
 */
int FlowGetPacketDirection(const Flow *f, const Packet *p)
{
    const int reverse = (f->flags & FLOW_DIR_REVERSED) != 0;

    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
        if (!(CMP_PORT(p->sp,p->dp))) {
            /* update flags and counters */
            if (CMP_PORT(f->sp,p->sp)) {
                return TOSERVER ^ reverse;
            } else {
                return TOCLIENT ^ reverse;
            }
        } else {
            if (CMP_ADDR(&f->src,&p->src)) {
                return TOSERVER ^ reverse;
            } else {
                return TOCLIENT ^ reverse;
            }
        }
    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        if (CMP_ADDR(&f->src,&p->src)) {
            return TOSERVER  ^ reverse;
        } else {
            return TOCLIENT ^ reverse;
        }
    }

    /* default to toserver */
    return TOSERVER;
}

/**
 *  \brief Check to update "seen" flags
 *
 *  \param p packet
 *
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowUpdateSeenFlag(const Packet *p)
{
    if (PacketIsICMPv4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p->icmp_s.type)) {
            return 0;
        }
    }

    return 1;
}

static inline void FlowUpdateTtlTS(Flow *f, uint8_t ttl)
{
    if (f->min_ttl_toserver == 0) {
        f->min_ttl_toserver = ttl;
    } else {
        f->min_ttl_toserver = MIN(f->min_ttl_toserver, ttl);
    }
    f->max_ttl_toserver = MAX(f->max_ttl_toserver, ttl);
}

static inline void FlowUpdateTtlTC(Flow *f, uint8_t ttl)
{
    if (f->min_ttl_toclient == 0) {
        f->min_ttl_toclient = ttl;
    } else {
        f->min_ttl_toclient = MIN(f->min_ttl_toclient, ttl);
    }
    f->max_ttl_toclient = MAX(f->max_ttl_toclient, ttl);
}

static inline void FlowUpdateEthernet(
        ThreadVars *tv, DecodeThreadVars *dtv, Flow *f, const Packet *p, bool toserver)
{
    if (PacketIsEthernet(p) && MacSetFlowStorageEnabled()) {
        const EthernetHdr *ethh = PacketGetEthernet(p);
        MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
        if (ms != NULL) {
            if (toserver) {
                MacSetAddWithCtr(ms, ethh->eth_src, ethh->eth_dst, tv,
                                 dtv->counter_max_mac_addrs_src,
                                 dtv->counter_max_mac_addrs_dst);
            } else {
                MacSetAddWithCtr(ms, ethh->eth_dst, ethh->eth_src, tv,
                                 dtv->counter_max_mac_addrs_dst,
                                 dtv->counter_max_mac_addrs_src);
            }
        }
    }
}

/** \brief Update Packet and Flow
 *
 *  Updates packet and flow based on the new packet.
 *
 *  \param f locked flow
 *  \param p packet
 *
 *  \note overwrites p::flowflags
 */
void FlowHandlePacketUpdate(Flow *f, Packet *p, ThreadVars *tv, DecodeThreadVars *dtv)
{
    SCLogDebug("packet %"PRIu64" -- flow %p", p->pcap_cnt, f);

    const int pkt_dir = FlowGetPacketDirection(f, p);
#ifdef CAPTURE_OFFLOAD
    int state = f->flow_state;

    if (state != FLOW_STATE_CAPTURE_BYPASSED) {
#endif
        /* update the last seen timestamp of this flow */
        if (SCTIME_CMP_GT(p->ts, f->lastts)) {
            f->lastts = p->ts;
            const uint32_t timeout_at = (uint32_t)SCTIME_SECS(f->lastts) + f->timeout_policy;
            if (timeout_at != f->timeout_at) {
                f->timeout_at = timeout_at;
            }
        }
#ifdef CAPTURE_OFFLOAD
    } else {
        /* still seeing packet, we downgrade to local bypass */
        if (SCTIME_SECS(p->ts) - SCTIME_SECS(f->lastts) > FLOW_BYPASSED_TIMEOUT / 2) {
            SCLogDebug("Downgrading flow to local bypass");
            f->lastts = p->ts;
            FlowUpdateState(f, FLOW_STATE_LOCAL_BYPASSED);
        } else {
            /* In IPS mode the packet could come from the other interface so it would
             * need to be bypassed */
            if (EngineModeIsIPS()) {
                BypassedFlowUpdate(f, p);
            }
        }
    }
#endif
    /* update flags and counters */
    if (pkt_dir == TOSERVER) {
        f->todstpktcnt++;
        f->todstbytecnt += GET_PKT_LEN(p);
        p->flowflags = FLOW_PKT_TOSERVER;
        if (!(f->flags & FLOW_TO_DST_SEEN)) {
            if (FlowUpdateSeenFlag(p)) {
                f->flags |= FLOW_TO_DST_SEEN;
                p->flowflags |= FLOW_PKT_TOSERVER_FIRST;
            }
        }
        /* xfer proto detect ts flag to first packet in ts dir */
        if (f->flags & FLOW_PROTO_DETECT_TS_DONE) {
            f->flags &= ~FLOW_PROTO_DETECT_TS_DONE;
            p->flags |= PKT_PROTO_DETECT_TS_DONE;
        }
        FlowUpdateEthernet(tv, dtv, f, p, true);
        /* update flow's ttl fields if needed */
        if (PacketIsIPv4(p)) {
            const IPV4Hdr *ip4h = PacketGetIPv4(p);
            FlowUpdateTtlTS(f, IPV4_GET_RAW_IPTTL(ip4h));
        } else if (PacketIsIPv6(p)) {
            const IPV6Hdr *ip6h = PacketGetIPv6(p);
            FlowUpdateTtlTS(f, IPV6_GET_RAW_HLIM(ip6h));
        }
    } else {
        f->tosrcpktcnt++;
        f->tosrcbytecnt += GET_PKT_LEN(p);
        p->flowflags = FLOW_PKT_TOCLIENT;
        if (!(f->flags & FLOW_TO_SRC_SEEN)) {
            if (FlowUpdateSeenFlag(p)) {
                f->flags |= FLOW_TO_SRC_SEEN;
                p->flowflags |= FLOW_PKT_TOCLIENT_FIRST;
            }
        }
        /* xfer proto detect tc flag to first packet in tc dir */
        if (f->flags & FLOW_PROTO_DETECT_TC_DONE) {
            f->flags &= ~FLOW_PROTO_DETECT_TC_DONE;
            p->flags |= PKT_PROTO_DETECT_TC_DONE;
        }
        FlowUpdateEthernet(tv, dtv, f, p, false);
        /* update flow's ttl fields if needed */
        if (PacketIsIPv4(p)) {
            const IPV4Hdr *ip4h = PacketGetIPv4(p);
            FlowUpdateTtlTC(f, IPV4_GET_RAW_IPTTL(ip4h));
        } else if (PacketIsIPv6(p)) {
            const IPV6Hdr *ip6h = PacketGetIPv6(p);
            FlowUpdateTtlTC(f, IPV6_GET_RAW_HLIM(ip6h));
        }
    }

    if (f->flow_state == FLOW_STATE_ESTABLISHED) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", p);
        p->flowflags |= FLOW_PKT_ESTABLISHED;

    } else if (f->proto == IPPROTO_TCP) {
        TcpSession *ssn = (TcpSession *)f->protoctx;
        if (ssn != NULL && ssn->state >= TCP_ESTABLISHED) {
            p->flowflags |= FLOW_PKT_ESTABLISHED;
        }
    } else if ((f->flags & (FLOW_TO_DST_SEEN|FLOW_TO_SRC_SEEN)) ==
            (FLOW_TO_DST_SEEN|FLOW_TO_SRC_SEEN)) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", p);
        p->flowflags |= FLOW_PKT_ESTABLISHED;

        if (
#ifdef CAPTURE_OFFLOAD
                (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED) &&
#endif
                (f->flow_state != FLOW_STATE_LOCAL_BYPASSED)) {
            FlowUpdateState(f, FLOW_STATE_ESTABLISHED);
        }
    }

    if (f->flags & FLOW_ACTION_DROP) {
        PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_FLOW_DROP);
    }
    /*set the detection bypass flags*/
    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        SCLogDebug("setting FLOW_NOPACKET_INSPECTION flag on flow %p", f);
        DecodeSetNoPacketInspectionFlag(p);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        SCLogDebug("setting FLOW_NOPAYLOAD_INSPECTION flag on flow %p", f);
        DecodeSetNoPayloadInspectionFlag(p);
    }

    SCFlowRunUpdateCallbacks(tv, f, p);
}

/** \brief Entry point for packet flow handling
 *
 * This is called for every packet.
 *
 *  \param tv threadvars
 *  \param dtv decode thread vars (for flow output api thread data)
 *  \param p packet to handle flow for
 */
void FlowHandlePacket(ThreadVars *tv, FlowLookupStruct *fls, Packet *p)
{
    /* Get this packet's flow from the hash. FlowHandlePacket() will setup
     * a new flow if necessary. If we get NULL, we're out of flow memory.
     * The returned flow is locked. */
    Flow *f = FlowGetFlowFromHash(tv, fls, p, &p->flow);
    if (f != NULL) {
        /* set the flow in the packet */
        p->flags |= PKT_HAS_FLOW;
    }
}

/** \brief initialize the configuration
 *  \warning Not thread safe */
void FlowInitConfig(bool quiet)
{
    SCLogDebug("initializing flow engine...");

    memset(&flow_config,  0, sizeof(flow_config));
    SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(flow_memuse);
    SC_ATOMIC_INIT(flow_prune_idx);
    SC_ATOMIC_INIT(flow_config.memcap);
    FlowQueueInit(&flow_recycle_q);

    /* set defaults */
    flow_config.hash_rand   = (uint32_t)RandomGet();
    flow_config.hash_size   = FLOW_DEFAULT_HASHSIZE;
    flow_config.prealloc    = FLOW_DEFAULT_PREALLOC;
    SC_ATOMIC_SET(flow_config.memcap, FLOW_DEFAULT_MEMCAP);

    /* If we have specific config, overwrite the defaults with them,
     * otherwise, leave the default values */
    intmax_t val = 0;
    if (ConfGetInt("flow.emergency-recovery", &val) == 1) {
        if (val <= 100 && val >= 1) {
            flow_config.emergency_recovery = (uint8_t)val;
        } else {
            SCLogError("flow.emergency-recovery must be in the range of "
                       "1 and 100 (as percentage)");
            flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
        }
    } else {
        SCLogDebug("flow.emergency-recovery, using default value");
        flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
    }

    /* Check if we have memcap and hash_size defined at config */
    const char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    uint64_t flow_memcap_copy = 0;
    if ((ConfGet("flow.memcap", &conf_val)) == 1)
    {
        if (conf_val == NULL) {
            FatalError("Invalid value for flow.memcap: NULL");
        }

        if (ParseSizeStringU64(conf_val, &flow_memcap_copy) < 0) {
            SCLogError("Error parsing flow.memcap "
                       "from conf file - %s.  Killing engine",
                    conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(flow_config.memcap, flow_memcap_copy);
        }
    }
    if ((ConfGet("flow.hash-size", &conf_val)) == 1)
    {
        if (conf_val == NULL) {
            FatalError("Invalid value for flow.hash-size: NULL");
        }

        if (StringParseUint32(&configval, 10, strlen(conf_val), conf_val) && configval != 0) {
            flow_config.hash_size = configval;
        } else {
            FatalError("Invalid value for flow.hash-size. Must be a numeric value in the range "
                       "1-4294967295");
        }
    }
    if ((ConfGet("flow.prealloc", &conf_val)) == 1)
    {
        if (conf_val == NULL) {
            FatalError("Invalid value for flow.prealloc: NULL");
        }

        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            flow_config.prealloc = configval;
        }
    }

    flow_config.memcap_policy = ExceptionPolicyParse("flow.memcap-policy", false);

    SCLogDebug("Flow config from suricata.yaml: memcap: %"PRIu64", hash-size: "
               "%"PRIu32", prealloc: %"PRIu32, SC_ATOMIC_GET(flow_config.memcap),
               flow_config.hash_size, flow_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = flow_config.hash_size * sizeof(FlowBucket);
    if (!(FLOW_CHECK_MEMCAP(hash_size))) {
        SCLogError("allocating flow hash failed: "
                   "max flow memcap is smaller than projected hash size. "
                   "Memcap: %" PRIu64 ", Hash table size %" PRIu64 ". Calculate "
                   "total hash size by multiplying \"flow.hash-size\" with %" PRIuMAX ", "
                   "which is the hash bucket size.",
                SC_ATOMIC_GET(flow_config.memcap), hash_size, (uintmax_t)sizeof(FlowBucket));
        exit(EXIT_FAILURE);
    }
    flow_hash = SCMallocAligned(flow_config.hash_size * sizeof(FlowBucket), CLS);
    if (unlikely(flow_hash == NULL)) {
        FatalError("Fatal error encountered in FlowInitConfig. Exiting...");
    }
    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));

    uint32_t i = 0;
    for (i = 0; i < flow_config.hash_size; i++) {
        FBLOCK_INIT(&flow_hash[i]);
        SC_ATOMIC_INIT(flow_hash[i].next_ts);
    }
    (void) SC_ATOMIC_ADD(flow_memuse, (flow_config.hash_size * sizeof(FlowBucket)));

    if (!quiet) {
        SCLogConfig("allocated %"PRIu64" bytes of memory for the flow hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(flow_memuse), flow_config.hash_size,
                  (uintmax_t)sizeof(FlowBucket));
    }
    FlowSparePoolInit();
    if (!quiet) {
        SCLogConfig("flow memory usage: %"PRIu64" bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(flow_memuse), SC_ATOMIC_GET(flow_config.memcap));
    }

    FlowInitFlowProto();

    uint32_t sz = sizeof(Flow) + FlowStorageSize();
    SCLogConfig("flow size %u, memcap allows for %" PRIu64 " flows. Per hash row in perfect "
                "conditions %" PRIu64,
            sz, flow_memcap_copy / sz, (flow_memcap_copy / sz) / flow_config.hash_size);
}

void FlowReset(void)
{
    // resets the flows (for reuse by fuzzing)
    for (uint32_t u = 0; u < flow_config.hash_size; u++) {
        Flow *f = flow_hash[u].head;
        while (f) {
            Flow *n = f->next;
            uint8_t proto_map = FlowGetProtoMapping(f->proto);
            FlowClearMemory(f, proto_map);
            FlowFree(f);
            f = n;
        }
        flow_hash[u].head = NULL;
    }
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void FlowShutdown(void)
{
    Flow *f;
    while ((f = FlowDequeue(&flow_recycle_q))) {
        FlowFree(f);
    }

    /* clear and free the hash */
    if (flow_hash != NULL) {
        /* clean up flow mutexes */
        for (uint32_t u = 0; u < flow_config.hash_size; u++) {
            f = flow_hash[u].head;
            while (f) {
                Flow *n = f->next;
                uint8_t proto_map = FlowGetProtoMapping(f->proto);
                FlowClearMemory(f, proto_map);
                FlowFree(f);
                f = n;
            }
            f = flow_hash[u].evicted;
            while (f) {
                Flow *n = f->next;
                uint8_t proto_map = FlowGetProtoMapping(f->proto);
                FlowClearMemory(f, proto_map);
                FlowFree(f);
                f = n;
            }

            FBLOCK_DESTROY(&flow_hash[u]);
        }
        SCFreeAligned(flow_hash);
        flow_hash = NULL;
    }
    (void) SC_ATOMIC_SUB(flow_memuse, flow_config.hash_size * sizeof(FlowBucket));
    FlowQueueDestroy(&flow_recycle_q);
    FlowSparePoolDestroy();
    DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(flow_memuse) != 0);
}

/**
 *  \brief  Function to set the default timeout, free function and flow state
 *          function for all supported flow_proto.
 */

void FlowInitFlowProto(void)
{
    FlowTimeoutsInit();

#define SET_DEFAULTS(p, n, e, c, b, ne, ee, ce, be)     \
    flow_timeouts_normal[(p)].new_timeout = (n);     \
    flow_timeouts_normal[(p)].est_timeout = (e);     \
    flow_timeouts_normal[(p)].closed_timeout = (c);  \
    flow_timeouts_normal[(p)].bypassed_timeout = (b); \
    flow_timeouts_emerg[(p)].new_timeout = (ne);     \
    flow_timeouts_emerg[(p)].est_timeout = (ee);     \
    flow_timeouts_emerg[(p)].closed_timeout = (ce); \
    flow_timeouts_emerg[(p)].bypassed_timeout = (be); \

    SET_DEFAULTS(FLOW_PROTO_DEFAULT,
                FLOW_DEFAULT_NEW_TIMEOUT, FLOW_DEFAULT_EST_TIMEOUT,
                    0, FLOW_DEFAULT_BYPASSED_TIMEOUT,
                FLOW_DEFAULT_EMERG_NEW_TIMEOUT, FLOW_DEFAULT_EMERG_EST_TIMEOUT,
                    0, FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(FLOW_PROTO_TCP,
                FLOW_IPPROTO_TCP_NEW_TIMEOUT, FLOW_IPPROTO_TCP_EST_TIMEOUT,
                    FLOW_IPPROTO_TCP_CLOSED_TIMEOUT, FLOW_IPPROTO_TCP_BYPASSED_TIMEOUT,
                FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT, FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT,
                    FLOW_IPPROTO_TCP_EMERG_CLOSED_TIMEOUT, FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(FLOW_PROTO_UDP,
                FLOW_IPPROTO_UDP_NEW_TIMEOUT, FLOW_IPPROTO_UDP_EST_TIMEOUT,
                    0, FLOW_IPPROTO_UDP_BYPASSED_TIMEOUT,
                FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT, FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT,
                    0, FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(FLOW_PROTO_ICMP,
                FLOW_IPPROTO_ICMP_NEW_TIMEOUT, FLOW_IPPROTO_ICMP_EST_TIMEOUT,
                    0, FLOW_IPPROTO_ICMP_BYPASSED_TIMEOUT,
                FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT, FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT,
                    0, FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);

    flow_freefuncs[FLOW_PROTO_DEFAULT].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_TCP].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_UDP].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_ICMP].Freefunc = NULL;

    /* Let's see if we have custom timeouts defined from config */
    const char *new = NULL;
    const char *established = NULL;
    const char *closed = NULL;
    const char *bypassed = NULL;
    const char *emergency_new = NULL;
    const char *emergency_established = NULL;
    const char *emergency_closed = NULL;
    const char *emergency_bypassed = NULL;

    ConfNode *flow_timeouts = ConfGetNode("flow-timeouts");
    if (flow_timeouts != NULL) {
        ConfNode *proto = NULL;
        uint32_t configval = 0;

        /* Defaults. */
        proto = ConfNodeLookupChild(flow_timeouts, "default");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency-closed");
            emergency_bypassed = ConfNodeLookupChildValue(proto,
                "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {

                    flow_timeouts_normal[FLOW_PROTO_DEFAULT].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_timeouts_normal[FLOW_PROTO_DEFAULT].est_timeout = configval;
            }
            if (closed != NULL &&
                StringParseUint32(&configval, 10, strlen(closed),
                                        closed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_DEFAULT].closed_timeout = configval;
            }
            if (bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(bypassed),
                                            bypassed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_DEFAULT].bypassed_timeout = configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_established),
                                            emergency_established) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].est_timeout= configval;
            }
            if (emergency_closed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_closed),
                                            emergency_closed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].closed_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_bypassed),
                                            emergency_bypassed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].bypassed_timeout = configval;
            }
        }

        /* TCP. */
        proto = ConfNodeLookupChild(flow_timeouts, "tcp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency-closed");
            emergency_bypassed = ConfNodeLookupChildValue(proto,
                "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {

                flow_timeouts_normal[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_timeouts_normal[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (closed != NULL &&
                StringParseUint32(&configval, 10, strlen(closed),
                                        closed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(bypassed),
                                            bypassed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_TCP].bypassed_timeout = configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (emergency_closed != NULL &&
                StringParseUint32(&configval, 10,
                                        strlen(emergency_closed),
                                        emergency_closed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_bypassed),
                                            emergency_bypassed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_TCP].bypassed_timeout = configval;
            }
        }

        /* UDP. */
        proto = ConfNodeLookupChild(flow_timeouts, "udp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_bypassed = ConfNodeLookupChildValue(proto,
                "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {

                flow_timeouts_normal[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_timeouts_normal[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(bypassed),
                                            bypassed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_UDP].bypassed_timeout = configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_bypassed),
                                            emergency_bypassed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_UDP].bypassed_timeout = configval;
            }
        }

        /* ICMP. */
        proto = ConfNodeLookupChild(flow_timeouts, "icmp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency-established");
            emergency_bypassed = ConfNodeLookupChildValue(proto,
                "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {

                flow_timeouts_normal[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                        established) > 0) {

                flow_timeouts_normal[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(bypassed),
                                            bypassed) > 0) {

                flow_timeouts_normal[FLOW_PROTO_ICMP].bypassed_timeout = configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                        emergency_new) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10,
                                        strlen(emergency_established),
                                        emergency_established) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                    StringParseUint32(&configval, 10,
                                            strlen(emergency_bypassed),
                                            emergency_bypassed) > 0) {

                flow_timeouts_emerg[FLOW_PROTO_ICMP].bypassed_timeout = configval;
            }
        }
    }

    /* validate and if needed update emergency timeout values */
    for (uint8_t i = 0; i < FLOW_PROTO_MAX; i++) {
        const FlowProtoTimeout *n = &flow_timeouts_normal[i];
        FlowProtoTimeout *e = &flow_timeouts_emerg[i];

        if (e->est_timeout > n->est_timeout) {
            SCLogWarning("emergency timeout value %u for \'established\' "
                         "must be below regular value %u",
                    e->est_timeout, n->est_timeout);
            e->est_timeout = n->est_timeout / 10;
        }

        if (e->new_timeout > n->new_timeout) {
            SCLogWarning("emergency timeout value %u for \'new\' must be "
                         "below regular value %u",
                    e->new_timeout, n->new_timeout);
            e->new_timeout = n->new_timeout / 10;
        }

        if (e->closed_timeout > n->closed_timeout) {
            SCLogWarning("emergency timeout value %u for \'closed\' must "
                         "be below regular value %u",
                    e->closed_timeout, n->closed_timeout);
            e->closed_timeout = n->closed_timeout / 10;
        }

        if (e->bypassed_timeout > n->bypassed_timeout) {
            SCLogWarning("emergency timeout value %u for \'bypassed\' "
                         "must be below regular value %u",
                    e->bypassed_timeout, n->bypassed_timeout);
            e->bypassed_timeout = n->bypassed_timeout / 10;
        }
    }

    for (uint8_t i = 0; i < FLOW_PROTO_MAX; i++) {
        FlowProtoTimeout *n = &flow_timeouts_normal[i];
        FlowProtoTimeout *e = &flow_timeouts_emerg[i];
        FlowProtoTimeout *d = &flow_timeouts_delta[i];

        if (e->est_timeout > n->est_timeout) {
            SCLogWarning("emergency timeout value for \'established\' must be below normal value");
            e->est_timeout = n->est_timeout / 10;
        }
        d->est_timeout = n->est_timeout - e->est_timeout;

        if (e->new_timeout > n->new_timeout) {
            SCLogWarning("emergency timeout value for \'new\' must be below normal value");
            e->new_timeout = n->new_timeout / 10;
        }
        d->new_timeout = n->new_timeout - e->new_timeout;

        if (e->closed_timeout > n->closed_timeout) {
            SCLogWarning("emergency timeout value for \'closed\' must be below normal value");
            e->closed_timeout = n->closed_timeout / 10;
        }
        d->closed_timeout = n->closed_timeout - e->closed_timeout;

        if (e->bypassed_timeout > n->bypassed_timeout) {
            SCLogWarning("emergency timeout value for \'bypassed\' must be below normal value");
            e->bypassed_timeout = n->bypassed_timeout / 10;
        }
        d->bypassed_timeout = n->bypassed_timeout - e->bypassed_timeout;

        SCLogDebug("deltas: new: -%u est: -%u closed: -%u bypassed: -%u",
                d->new_timeout, d->est_timeout, d->closed_timeout, d->bypassed_timeout);
    }
}

/**
 *  \brief  Function clear the flow memory before queueing it to spare flow
 *          queue.
 *
 *  \param  f           pointer to the flow needed to be cleared.
 *  \param  proto_map   mapped value of the protocol to FLOW_PROTO's.
 */

int FlowClearMemory(Flow* f, uint8_t proto_map)
{
    SCEnter();

    if (unlikely(f->flags & FLOW_HAS_EXPECTATION)) {
        AppLayerExpectationClean(f);
    }

    /* call the protocol specific free function if we have one */
    if (flow_freefuncs[proto_map].Freefunc != NULL) {
        flow_freefuncs[proto_map].Freefunc(f->protoctx);
    }

    FlowFreeStorage(f);

    FLOW_RECYCLE(f);

    SCReturnInt(1);
}

/**
 *  \brief  Function to set the function to get protocol specific flow state.
 *
 *  \param   proto  protocol of which function is needed to be set.
 *  \param   Free   Function pointer which will be called to free the protocol
 *                  specific memory.
 */

int FlowSetProtoFreeFunc (uint8_t proto, void (*Free)(void *))
{
    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_freefuncs[proto_map].Freefunc = Free;
    return 1;
}

/**
 *  \brief get 'disruption' flags: GAP/DEPTH/PASS
 *  \param f locked flow
 *  \param flags existing flags to be amended
 *  \retval flags original flags + disrupt flags (if any)
 *  \TODO handle UDP
 */
uint8_t FlowGetDisruptionFlags(const Flow *f, uint8_t flags)
{
    if (f->proto != IPPROTO_TCP) {
        return flags;
    }
    if (f->protoctx == NULL) {
        return flags;
    }

    uint8_t newflags = flags;
    TcpSession *ssn = f->protoctx;
    TcpStream *stream = flags & STREAM_TOSERVER ? &ssn->client : &ssn->server;

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        newflags |= STREAM_DEPTH;
    }
    /* todo: handle pass case (also for UDP!) */

    return newflags;
}

void FlowUpdateState(Flow *f, const enum FlowState s)
{
    if (s != f->flow_state) {
        /* set the state */
        // Explicit cast from the enum type to the compact version
        f->flow_state = (FlowStateType)s;

        /* update timeout policy and value */
        const uint32_t timeout_policy = FlowGetTimeoutPolicy(f);
        if (timeout_policy != f->timeout_policy) {
            f->timeout_policy = timeout_policy;
            const uint32_t timeout_at = (uint32_t)SCTIME_SECS(f->lastts) + timeout_policy;
            if (timeout_at != f->timeout_at)
                f->timeout_at = timeout_at;
        }
    }
#ifdef UNITTESTS
    if (f->fb != NULL) {
#endif
        /* and reset the flow bucket next_ts value so that the flow manager
         * has to revisit this row */
        SC_ATOMIC_SET(f->fb->next_ts, 0);
#ifdef UNITTESTS
    }
#endif
}

/**
 * \brief Get flow last time as individual values.
 *
 * Instead of returning a pointer to the timeval copy the timeval
 * parts into output pointers to make it simpler to call from Rust
 * over FFI using only basic data types.
 */
void FlowGetLastTimeAsParts(Flow *flow, uint64_t *secs, uint64_t *usecs)
{
    *secs = (uint64_t)SCTIME_SECS(flow->lastts);
    *usecs = (uint64_t)SCTIME_USECS(flow->lastts);
}

/**
 * \brief Get flow source port.
 *
 * A function to get the flow sport useful when the caller only has an
 * opaque pointer to the flow structure.
 */
uint16_t FlowGetSourcePort(Flow *flow)
{
    return flow->sp;
}

/**
 * \brief Get flow destination port.
 *
 * A function to get the flow dport useful when the caller only has an
 * opaque pointer to the flow structure.
 */

uint16_t FlowGetDestinationPort(Flow *flow)
{
    return flow->dp;
}
/**
 * \brief Get flow flags.
 *
 * A function to get the flow flags useful when the caller only has an
 * opaque pointer to the flow structure.
 */

uint32_t FlowGetFlags(Flow *flow)
{
    return flow->flags;
}
/************************************Unittests*******************************/

#ifdef UNITTESTS
#include "threads.h"

/**
 *  \test   Test the setting of the per protocol timeouts.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest01 (void)
{
    uint8_t proto_map;

    FlowInitFlowProto();
    proto_map = FlowGetProtoMapping(IPPROTO_TCP);
    FAIL_IF(flow_timeouts_normal[proto_map].new_timeout != FLOW_IPPROTO_TCP_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_normal[proto_map].est_timeout != FLOW_IPPROTO_TCP_EST_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].new_timeout != FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].est_timeout != FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT);

    proto_map = FlowGetProtoMapping(IPPROTO_UDP);
    FAIL_IF(flow_timeouts_normal[proto_map].new_timeout != FLOW_IPPROTO_UDP_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_normal[proto_map].est_timeout != FLOW_IPPROTO_UDP_EST_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].new_timeout != FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].est_timeout != FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT);

    proto_map = FlowGetProtoMapping(IPPROTO_ICMP);
    FAIL_IF(flow_timeouts_normal[proto_map].new_timeout != FLOW_IPPROTO_ICMP_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_normal[proto_map].est_timeout != FLOW_IPPROTO_ICMP_EST_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].new_timeout != FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].est_timeout != FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT);

    proto_map = FlowGetProtoMapping(IPPROTO_DCCP);
    FAIL_IF(flow_timeouts_normal[proto_map].new_timeout != FLOW_DEFAULT_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_normal[proto_map].est_timeout != FLOW_DEFAULT_EST_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].new_timeout != FLOW_DEFAULT_EMERG_NEW_TIMEOUT);
    FAIL_IF(flow_timeouts_emerg[proto_map].est_timeout != FLOW_DEFAULT_EMERG_EST_TIMEOUT);

    PASS;
}

/*Test function for the unit test FlowTest02*/

static void test(void *f) {}

/**
 *  \test   Test the setting of the per protocol free function to free the
 *          protocol specific memory.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest02 (void)
{
    FlowSetProtoFreeFunc(IPPROTO_DCCP, test);
    FlowSetProtoFreeFunc(IPPROTO_TCP, test);
    FlowSetProtoFreeFunc(IPPROTO_UDP, test);
    FlowSetProtoFreeFunc(IPPROTO_ICMP, test);

    FAIL_IF(flow_freefuncs[FLOW_PROTO_DEFAULT].Freefunc != test);
    FAIL_IF(flow_freefuncs[FLOW_PROTO_TCP].Freefunc != test);
    FAIL_IF(flow_freefuncs[FLOW_PROTO_UDP].Freefunc != test);
    FAIL_IF(flow_freefuncs[FLOW_PROTO_ICMP].Freefunc != test);

    PASS;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest07 (void)
{
    int result = 0;
    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = FlowSpareGetPoolSize();
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_config.prealloc = 100;

    /* Let's get the flow spare pool empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* should time out normal */
    TimeSetIncrementTime(2000);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine entered emerg mode: should happen as easy
     * with flow mgr activated */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    FlowShutdown();
    memcpy(&flow_config, &backup, sizeof(FlowConfig));

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest08 (void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = FlowSpareGetPoolSize();
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_config.prealloc = 100;

    /* Let's get the flow spare pool empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* By default we use 30  for timing out new flows. This means
     * that the Emergency mode should be set */
    TimeSetIncrementTime(20);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine released 5 flows by emergency timeout */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest09 (void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = FlowSpareGetPoolSize();
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_config.prealloc = 100;

    /* Let's get the flow spare pool empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* No timeout will work */
    TimeSetIncrementTime(5);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* engine in emerg mode */
    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

#endif /* UNITTESTS */

/**
 *  \brief   Function to register the Flow Unitests.
 */
void FlowRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowTest01 -- Protocol Specific Timeouts", FlowTest01);
    UtRegisterTest("FlowTest02 -- Setting Protocol Specific Free Function",
                   FlowTest02);
    UtRegisterTest("FlowTest07 -- Test flow Allocations when it reach memcap",
                   FlowTest07);
    UtRegisterTest("FlowTest08 -- Test flow Allocations when it reach memcap",
                   FlowTest08);
    UtRegisterTest("FlowTest09 -- Test flow Allocations when it reach memcap",
                   FlowTest09);

    RegisterFlowStorageTests();
#endif /* UNITTESTS */
}
