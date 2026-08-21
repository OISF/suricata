/* Copyright (C) 2007-2026 Open Information Security Foundation
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
 * DefragTracker hash table: lookup, allocation, memcap, eviction.
 * Locking order: row lock, then tracker mutex. use_cnt keeps a
 * tracker alive across lock drops; the pruner won't touch it while
 * it's non-zero.
 */

#include "suricata-common.h"
#include "conf.h"
#include "defrag-hash.h"
#include "defrag-stack.h"
#include "defrag-config.h"
#include "defrag-timeout.h"
#include "util-random.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-hash-lookup3.h"
#include "util-validate.h"

/** Bucket array, sized by defrag.hash-size. */
DefragTrackerHashRow *defragtracker_hash;

/** Global defrag config. */
DefragConfig defrag_config;

/** Bytes charged against defrag.memcap. */
SC_ATOMIC_DECLARE(uint64_t,defrag_memuse);

/** Trackers currently attached to a bucket. */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_counter);

/** Rolling start point for the eviction sweep. */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_prune_idx);

static DefragTracker *DefragTrackerGetUsedDefragTracker(
        ThreadVars *tv, const DecodeThreadVars *dtv);

/** Free list of trackers, LIFO. */
static DefragTrackerStack defragtracker_spare_q;

/** \brief Set memcap. Refuses values below current memuse.
 *  \retval 1 applied, 0 rejected */
int DefragTrackerSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(defrag_memuse) < size) {
        SC_ATOMIC_SET(defrag_config.memcap, size);
        return 1;
    }

    return 0;
}

/** \brief Return the current memcap. */
uint64_t DefragTrackerGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(defrag_config.memcap);
    return memcapcopy;
}

/** \brief Return the current memory usage. */
uint64_t DefragTrackerGetMemuse(void)
{
    uint64_t memusecopy = (uint64_t)SC_ATOMIC_GET(defrag_memuse);
    return memusecopy;
}

/** \brief Configured memcap exception policy. */
enum ExceptionPolicy DefragGetMemcapExceptionPolicy(void)
{
    return defrag_config.memcap_policy;
}

/** \brief Return a tracker to the spare stack. Memory stays
 *         allocated. */
void DefragTrackerMoveToSpare(DefragTracker *h)
{
    DefragTrackerEnqueue(&defragtracker_spare_q, h);
    (void) SC_ATOMIC_SUB(defragtracker_counter, 1);
}

/** \internal
 *  \brief Allocate a new tracker. Charges memcap before calloc so
 *         a racing allocator can't push us over. Returned unlocked. */
static DefragTracker *DefragTrackerAlloc(void)
{
    if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(defrag_memuse, sizeof(DefragTracker));

    DefragTracker *dt = SCCalloc(1, sizeof(DefragTracker));
    if (unlikely(dt == NULL)) {
        (void)SC_ATOMIC_SUB(defrag_memuse, sizeof(DefragTracker));
        return NULL;
    }
    SCMutexInit(&dt->lock, NULL);
    SC_ATOMIC_INIT(dt->use_cnt);
    return dt;
}

/** \internal
 *  \brief Fully free a tracker. Shutdown path only; runtime uses
 *         the spare stack. */
static void DefragTrackerFree(DefragTracker *dt)
{
    if (dt != NULL) {
        DefragTrackerClearMemory(dt);

        SCMutexDestroy(&dt->lock);
        SCFree(dt);
        (void) SC_ATOMIC_SUB(defrag_memuse, sizeof(DefragTracker));
    }
}

/* Refcount. Incremented on lookup, dropped on release. Stops the pruner
 * from freeing a tracker while another thread still holds it. */
#define DefragTrackerIncrUsecnt(dt) \
    SC_ATOMIC_ADD((dt)->use_cnt, 1)
#define DefragTrackerDecrUsecnt(dt) \
    SC_ATOMIC_SUB((dt)->use_cnt, 1)

/** \internal
 *  \brief Fill a new tracker from its first packet. Both addresses
 *         copied; direction is handled at compare time. */
static void DefragTrackerInit(DefragTracker *dt, Packet *p)
{
    COPY_ADDRESS(&p->src, &dt->src_addr);
    COPY_ADDRESS(&p->dst, &dt->dst_addr);

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        dt->id = (int32_t)IPV4_GET_RAW_IPID(ip4h);
        dt->af = AF_INET;
    } else {
        DEBUG_VALIDATE_BUG_ON(!PacketIsIPv6(p));
        dt->id = (int32_t)IPV6_EXTHDR_GET_FH_ID(p);
        dt->af = AF_INET6;
    }
    dt->proto = PacketGetIPProto(p);
    memcpy(&dt->vlan_id[0], &p->vlan_id[0], sizeof(dt->vlan_id));
    dt->policy = DefragGetOsPolicy(p);
    dt->host_timeout = DefragPolicyGetHostTimeout(p);
    dt->remove = 0;
    dt->seen_last = 0;

    (void) DefragTrackerIncrUsecnt(dt);
}


/** \brief Drop the caller's ref and unlock. Decrement must happen
 *         while the tracker is still known valid. */
void DefragTrackerRelease(DefragTracker *t)
{
    (void) DefragTrackerDecrUsecnt(t);
    SCMutexUnlock(&t->lock);
}

/** \brief Free attached fragments; the tracker itself stays. */
void DefragTrackerClearMemory(DefragTracker *dt)
{
    DefragTrackerFreeFrags(dt);
}

#define DEFRAG_DEFAULT_HASHSIZE 4096
#define DEFRAG_DEFAULT_MEMCAP 16777216
#define DEFRAG_DEFAULT_PREALLOC 1000

/** \brief initialize the configuration
 * Build the hash table, read config, optionally prealloc.
 * Aborts if the bucket array alone exceeds memcap.
 *  \warning Startup only, not thread-safe. */
void DefragInitConfig(bool quiet)
{
    SCLogDebug("initializing defrag engine...");

    memset(&defrag_config, 0, sizeof(defrag_config));
    SC_ATOMIC_INIT(defragtracker_counter);
    SC_ATOMIC_INIT(defrag_memuse);
    SC_ATOMIC_INIT(defragtracker_prune_idx);
    SC_ATOMIC_INIT(defrag_config.memcap);
    DefragTrackerStackInit(&defragtracker_spare_q);

    /* defaults; reseed hash_rand per run */
    defrag_config.hash_rand   = (uint32_t)RandomGet();
    defrag_config.hash_size   = DEFRAG_DEFAULT_HASHSIZE;
    defrag_config.prealloc    = DEFRAG_DEFAULT_PREALLOC;
    SC_ATOMIC_SET(defrag_config.memcap, DEFRAG_DEFAULT_MEMCAP);
    defrag_config.memcap_policy = ExceptionPolicyParse("defrag.memcap-policy", false);

    /* overrides from suricata.yaml */
    const char *conf_val;
    uint32_t configval = 0;

    uint64_t defrag_memcap;
        /** set config values for memcap, prealloc and hash_size */
    if ((SCConfGetNonNull("defrag.memcap", &conf_val)) == 1) {
        if (ParseSizeStringU64(conf_val, &defrag_memcap) < 0) {
            SCLogError("Error parsing defrag.memcap "
                       "from conf file - %s.  Killing engine",
                    conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(defrag_config.memcap, defrag_memcap);
        }
    }
    if ((SCConfGetNonNull("defrag.hash-size", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            defrag_config.hash_size = configval;
        } else {
            WarnInvalidConfEntry("defrag.hash-size", "%"PRIu32, defrag_config.hash_size);
        }
    }

    if ((SCConfGetNonNull("defrag.trackers", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            defrag_config.prealloc = configval;
        } else {
            WarnInvalidConfEntry("defrag.trackers", "%"PRIu32, defrag_config.prealloc);
        }
    }
    SCLogDebug("DefragTracker config from suricata.yaml: memcap: %"PRIu64", hash-size: "
               "%"PRIu32", prealloc: %"PRIu32, SC_ATOMIC_GET(defrag_config.memcap),
               defrag_config.hash_size, defrag_config.prealloc);

    /* bucket array must fit in memcap on its own */
    uint64_t hash_size = defrag_config.hash_size * sizeof(DefragTrackerHashRow);
    if (!(DEFRAG_CHECK_MEMCAP(hash_size))) {
        SCLogError("allocating defrag hash failed: "
                   "max defrag memcap is smaller than projected hash size. "
                   "Memcap: %" PRIu64 ", Hash table size %" PRIu64 ". Calculate "
                   "total hash size by multiplying \"defrag.hash-size\" with %" PRIuMAX ", "
                   "which is the hash bucket size.",
                SC_ATOMIC_GET(defrag_config.memcap), hash_size,
                (uintmax_t)sizeof(DefragTrackerHashRow));
        exit(EXIT_FAILURE);
    }
    defragtracker_hash = SCCalloc(defrag_config.hash_size, sizeof(DefragTrackerHashRow));
    if (unlikely(defragtracker_hash == NULL)) {
        FatalError("Fatal error encountered in DefragTrackerInitConfig. Exiting...");
    }
    memset(defragtracker_hash, 0, defrag_config.hash_size * sizeof(DefragTrackerHashRow));

    uint32_t i = 0;
    for (i = 0; i < defrag_config.hash_size; i++) {
        DRLOCK_INIT(&defragtracker_hash[i]);
    }
    (void) SC_ATOMIC_ADD(defrag_memuse, (defrag_config.hash_size * sizeof(DefragTrackerHashRow)));

    if (!quiet) {
        SCLogConfig("allocated %"PRIu64" bytes of memory for the defrag hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(defrag_memuse), defrag_config.hash_size,
                  (uintmax_t)sizeof(DefragTrackerHashRow));
    }

    /* prealloc surfaces RAM shortages at boot rather than under traffic */
    if ((SCConfGetNonNull("defrag.prealloc", &conf_val)) == 1) {
        if (SCConfValIsTrue(conf_val)) {
            for (i = 0; i < defrag_config.prealloc; i++) {
                if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
                    SCLogError("preallocating defrag trackers failed: "
                               "max defrag memcap reached. Memcap %" PRIu64 ", "
                               "Memuse %" PRIu64 ".",
                            SC_ATOMIC_GET(defrag_config.memcap),
                            ((uint64_t)SC_ATOMIC_GET(defrag_memuse) +
                                    (uint64_t)sizeof(DefragTracker)));
                    exit(EXIT_FAILURE);
                }

                DefragTracker *h = DefragTrackerAlloc();
                if (h == NULL) {
                    SCLogError("preallocating defrag failed: %s", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                DefragTrackerEnqueue(&defragtracker_spare_q,h);
            }
            if (!quiet) {
                SCLogConfig("preallocated %" PRIu32 " defrag trackers of size %" PRIuMAX "",
                        DefragTrackerStackSize(&defragtracker_spare_q),
                        (uintmax_t)sizeof(DefragTracker));
            }
        }
    }

    if (!quiet) {
        SCLogConfig("defrag memory usage: %"PRIu64" bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(defrag_memuse), SC_ATOMIC_GET(defrag_config.memcap));
    }
}

/** \brief Tear down what DefragInitConfig built. Any surviving
 *         use_cnt > 0 is a bug.
 *  \warning Shutdown only, after workers have joined. */
void DefragHashShutdown(void)
{
    DefragTracker *dt;

    /* free spare queue */
    while((dt = DefragTrackerDequeue(&defragtracker_spare_q))) {
        BUG_ON(SC_ATOMIC_GET(dt->use_cnt) > 0);
        DefragTrackerFree(dt);
    }

    /* clear and free the hash */
    if (defragtracker_hash != NULL) {
        for (uint32_t u = 0; u < defrag_config.hash_size; u++) {
            dt = defragtracker_hash[u].head;
            while (dt) {
                DefragTracker *n = dt->hnext;
                DefragTrackerClearMemory(dt);
                DefragTrackerFree(dt);
                dt = n;
            }

            DRLOCK_DESTROY(&defragtracker_hash[u]);
        }
        SCFree(defragtracker_hash);
        defragtracker_hash = NULL;
    }
    (void) SC_ATOMIC_SUB(defrag_memuse, defrag_config.hash_size * sizeof(DefragTrackerHashRow));
    DefragTrackerStackDestroy(&defragtracker_spare_q);
}

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the DefragHashKey6 struct, without all
 *        the SCNtohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 */
static inline int DefragHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    for (int i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

/* Hash key structs, consumed by hashword() via the u32[] union.
 * pad[1] rounds the size and makes zero-init obvious.*/
typedef struct DefragHashKey4_ {
    union {
        struct {
            uint32_t src, dst;
            uint32_t id;
            uint16_t vlan_id[VLAN_MAX_LAYERS];
            uint16_t pad[1];
        };
        uint32_t u32[5];
    };
} DefragHashKey4;

typedef struct DefragHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint32_t id;
            uint16_t vlan_id[VLAN_MAX_LAYERS];
            uint16_t pad[1];
        };
        uint32_t u32[11];
    };
} DefragHashKey6;

/** \brief calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source address
 *  destination address
 *  id
 *  vlan_id
 */
static inline uint32_t DefragHashGetKey(Packet *p)
{
    uint32_t key;

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        DefragHashKey4 dhk = { .pad[0] = 0 };
        if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
            dhk.src = p->src.addr_data32[0];
            dhk.dst = p->dst.addr_data32[0];
        } else {
            dhk.src = p->dst.addr_data32[0];
            dhk.dst = p->src.addr_data32[0];
        }
        dhk.id = (uint32_t)IPV4_GET_RAW_IPID(ip4h);
        memcpy(&dhk.vlan_id[0], &p->vlan_id[0], sizeof(dhk.vlan_id));

        uint32_t hash =
                hashword(dhk.u32, sizeof(dhk.u32) / sizeof(uint32_t), defrag_config.hash_rand);
        key = hash % defrag_config.hash_size;
    } else if (PacketIsIPv6(p)) {
        DefragHashKey6 dhk = { .pad[0] = 0 };
        if (DefragHashRawAddressIPv6GtU32(p->src.addr_data32, p->dst.addr_data32)) {
            dhk.src[0] = p->src.addr_data32[0];
            dhk.src[1] = p->src.addr_data32[1];
            dhk.src[2] = p->src.addr_data32[2];
            dhk.src[3] = p->src.addr_data32[3];
            dhk.dst[0] = p->dst.addr_data32[0];
            dhk.dst[1] = p->dst.addr_data32[1];
            dhk.dst[2] = p->dst.addr_data32[2];
            dhk.dst[3] = p->dst.addr_data32[3];
        } else {
            dhk.src[0] = p->dst.addr_data32[0];
            dhk.src[1] = p->dst.addr_data32[1];
            dhk.src[2] = p->dst.addr_data32[2];
            dhk.src[3] = p->dst.addr_data32[3];
            dhk.dst[0] = p->src.addr_data32[0];
            dhk.dst[1] = p->src.addr_data32[1];
            dhk.dst[2] = p->src.addr_data32[2];
            dhk.dst[3] = p->src.addr_data32[3];
        }
        dhk.id = IPV6_EXTHDR_GET_FH_ID(p);
        memcpy(&dhk.vlan_id[0], &p->vlan_id[0], sizeof(dhk.vlan_id));

        uint32_t hash =
                hashword(dhk.u32, sizeof(dhk.u32) / sizeof(uint32_t), defrag_config.hash_rand);
        key = hash % defrag_config.hash_size;
    } else {
        key = 0;
    }
    return key;
}

/* Since two or more trackers can have the same hash key, we need to compare
 * the tracker with the current tracker key. */
#define CMP_DEFRAGTRACKER(d1, d2, id)                                                              \
    (((CMP_ADDR(&(d1)->src_addr, &(d2)->src) && CMP_ADDR(&(d1)->dst_addr, &(d2)->dst)) ||          \
             (CMP_ADDR(&(d1)->src_addr, &(d2)->dst) && CMP_ADDR(&(d1)->dst_addr, &(d2)->src))) &&  \
            (d1)->proto == PacketGetIPProto(d2) && (d1)->id == (id) &&                             \
            (d1)->vlan_id[0] == (d2)->vlan_id[0] && (d1)->vlan_id[1] == (d2)->vlan_id[1] &&        \
            (d1)->vlan_id[2] == (d2)->vlan_id[2])

/** \internal
 *  \brief AF check, then full tuple compare. */
static inline int DefragTrackerCompare(DefragTracker *t, Packet *p)
{
    uint32_t id;
    if (PacketIsIPv4(p)) {
        if (t->af != AF_INET)
            return 0;
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        id = (uint32_t)IPV4_GET_RAW_IPID(ip4h);
    } else {
        if (t->af != AF_INET6)
            return 0;
        id = IPV6_EXTHDR_GET_FH_ID(p);
    }

    return CMP_DEFRAGTRACKER(t, p, id);
}

/** \internal
 *  \brief Bump the memcap-hit counter for the current policy.
 *         Counter ids are cached on dtv. */
static void DefragExceptionPolicyStatsIncr(
        ThreadVars *tv, DecodeThreadVars *dtv, enum ExceptionPolicy policy)
{
    StatsCounterId id = dtv->counter_defrag_memcap_eps.eps_id[policy];
    if (likely(id.id > 0)) {
        StatsCounterIncr(&tv->stats, id);
    }
}

/** \internal
 *  \brief Get a locked tracker when the bucket had no match.
 *
 * Tries the spare stack, then alloc, then eviction.
 * On total failure applies the exception policy.
 *  \retval dt locked tracker, NULL on failure */
static DefragTracker *DefragTrackerGetNew(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
#ifdef QA_SIMULATION
    if (g_eps_defrag_memcap != UINT64_MAX && g_eps_defrag_memcap == PcapPacketCntGet(p)) {
        SCLogNotice("simulating memcap hit for packet %" PRIu64, PcapPacketCntGet(p));
        ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
        DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
        return NULL;
    }
#endif

    DefragTracker *dt = NULL;

    /* try spare stack first */
    dt = DefragTrackerDequeue(&defragtracker_spare_q);
    if (dt == NULL) {
        if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
            /* memcap full: steal one */
            dt = DefragTrackerGetUsedDefragTracker(tv, dtv);
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }
        } else {
            /* room left: allocate */
            dt = DefragTrackerAlloc();
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }
        }
    }

    (void) SC_ATOMIC_ADD(defragtracker_counter, 1);
    SCMutexLock(&dt->lock);
    return dt;
}

/** \brief Find or create the tracker for a packet. Entry point
 *         called by Defrag().
 *
 *  Walks the bucket chain, reaping timed-out entries as it goes.
 *  New trackers go in at the head (fresh ones tend to see more
 *  fragments soon). Returns with the tracker locked but the row
 *  lock released; caller must go through DefragTrackerRelease.
 *
 *  Locking order: row lock outer, tracker lock inner. The
 *  `goto tracker_removed` keeps prev_dt correct when an entry is
 *  spliced out mid-walk.
 *
 *  \retval dt   locked tracker, caller MUST release
 *  \retval NULL memcap exhausted, nothing evictable */
DefragTracker *DefragGetTrackerFromHash(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    DefragTracker *dt = NULL;

    uint32_t key = DefragHashGetKey(p);
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* empty bucket, drop a new tracker in */
    if (hb->head == NULL) {
        dt = DefragTrackerGetNew(tv, dtv, p);
        if (dt == NULL) {
            DRLOCK_UNLOCK(hb);
            return NULL;
        }

        hb->head = dt;
        DefragTrackerInit(dt,p);

        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* walk the chain */
    DefragTracker *prev_dt = NULL;
    dt = hb->head;

    do {
        DefragTracker *next_dt = NULL;

        SCMutexLock(&dt->lock);
        if (DefragTrackerTimedOut(dt, p->ts)) {
            /* reap while we're here */
            next_dt = dt->hnext;
            dt->hnext = NULL;
            if (prev_dt) {
                prev_dt->hnext = next_dt;
            } else {
                hb->head = next_dt;
            }
            DefragTrackerClearMemory(dt);
            SCMutexUnlock(&dt->lock);

            DefragTrackerMoveToSpare(dt);
            StatsCounterIncr(&tv->stats, dtv->counter_defrag_tracker_timeout);
            goto tracker_removed;
        } else if (!dt->remove && DefragTrackerCompare(dt, p)) {
            /* match, keep locked and return */
            (void)DefragTrackerIncrUsecnt(dt);
            DRLOCK_UNLOCK(hb);
            return dt;
        }
        SCMutexUnlock(&dt->lock);
        prev_dt = dt;
        next_dt = dt->hnext;

    tracker_removed:
        if (next_dt == NULL) {
            /* end of chain, insert at head */
            dt = DefragTrackerGetNew(tv, dtv, p);
            if (dt == NULL) {
                DRLOCK_UNLOCK(hb);
                return NULL;
            }
            dt->hnext = hb->head;
            hb->head = dt;

            DefragTrackerInit(dt, p);

            DRLOCK_UNLOCK(hb);
            return dt;
        }
        dt = next_dt;
    } while (dt != NULL);

    /* unreachable */
    BUG_ON(1);
    return NULL;
}

/** \brief Read-only lookup. Never allocates, evicts, or runs
 *         timeout logic. Used by tests and inspection paths.
 *  \retval dt   locked tracker
 *  \retval NULL no match */
DefragTracker *DefragLookupTrackerFromHash (Packet *p)
{
    DefragTracker *dt = NULL;

    /* get the key to our bucket */
    uint32_t key = DefragHashGetKey(p);
    /* get our hash bucket and lock it */
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* see if the bucket already has a tracker */
    if (hb->head == NULL) {
        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* ok, we have a tracker in the bucket. Let's find out if it is our tracker */
    dt = hb->head;

    do {
        if (!dt->remove && DefragTrackerCompare(dt, p)) {
            /* found our tracker, lock & return */
            SCMutexLock(&dt->lock);
            (void)DefragTrackerIncrUsecnt(dt);
            DRLOCK_UNLOCK(hb);
            return dt;

        } else if (dt->hnext == NULL) {
            DRLOCK_UNLOCK(hb);
            return NULL;
        }

        dt = dt->hnext;
    } while (dt != NULL);

    /* unreachable */
    BUG_ON(1);
    return NULL;
}

/** \internal
 *  \brief Steal an idle tracker from the hash so its slot can be
 *         reused. The pressure-relief path.
 *
 *  Sweeps from a rolling cursor (defragtracker_prune_idx) so we
 *  don't keep hitting the same low-index buckets. All lock
 *  acquisitions are trylocks; this runs on the packet hot path and
 *  can't afford to block. Trackers with use_cnt > 0 are skipped.
 *
 *  Hard reuse (stealing a live tracker) and soft reuse (already
 *  flagged remove) are counted separately. Sustained hard reuse
 *  means memcap or prealloc should go up.
 *
 *  \retval dt   unlocked, cleared tracker
 *  \retval NULL full sweep, nothing evictable */
static DefragTracker *DefragTrackerGetUsedDefragTracker(ThreadVars *tv, const DecodeThreadVars *dtv)
{
    uint32_t idx = SC_ATOMIC_GET(defragtracker_prune_idx) % defrag_config.hash_size;
    uint32_t cnt = defrag_config.hash_size;

    while (cnt--) {
        if (++idx >= defrag_config.hash_size)
            idx = 0;

        DefragTrackerHashRow *hb = &defragtracker_hash[idx];

        if (DRLOCK_TRYLOCK(hb) != 0)
            continue;

        DefragTracker *dt = hb->head;
        if (dt == NULL) {
            DRLOCK_UNLOCK(hb);
            continue;
        }

        if (SCMutexTrylock(&dt->lock) != 0) {
            DRLOCK_UNLOCK(hb);
            continue;
        }

        /* in-flight, skip */
        if (SC_ATOMIC_GET(dt->use_cnt) > 0) {
            DRLOCK_UNLOCK(hb);
            SCMutexUnlock(&dt->lock);
            continue;
        }

        /* forced reuse only counted when the tracker was still live */
        bool incr_reuse_cnt = !dt->remove;

        /* unlink */
        hb->head = dt->hnext;

        dt->hnext = NULL;
        DRLOCK_UNLOCK(hb);

        DefragTrackerClearMemory(dt);

        SCMutexUnlock(&dt->lock);

        if (incr_reuse_cnt) {
            StatsCounterIncr(&tv->stats, dtv->counter_defrag_tracker_hard_reuse);
        } else {
            StatsCounterIncr(&tv->stats, dtv->counter_defrag_tracker_soft_reuse);
        }

        (void) SC_ATOMIC_ADD(defragtracker_prune_idx, (defrag_config.hash_size - cnt));
        return dt;
    }

    return NULL;
}
