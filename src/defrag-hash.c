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
 * Defrag tracker hash: one tracker per datagram being reassembled.
 *
 * New trackers come from the spare pool, else a fresh allocation, else
 * (at memcap) an idle tracker evicted from the hash. Lookups return the
 * tracker locked with its use count raised; DefragTrackerRelease()
 * undoes both. A tracker with use_cnt > 0 is never evicted.
 *
 * Lock order: bucket lock, then tracker lock.
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

/** defrag tracker hash table */
DefragTrackerHashRow *defragtracker_hash;
DefragConfig defrag_config;
SC_ATOMIC_DECLARE(uint64_t,defrag_memuse);              /**< bytes in use */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_counter);  /**< trackers in use */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_prune_idx);/**< bucket where eviction resumes */

static DefragTracker *DefragTrackerGetUsedDefragTracker(
        ThreadVars *tv, const DecodeThreadVars *dtv);

/** spare trackers, ready for reuse */
static DefragTrackerStack defragtracker_spare_q;

/**
 *  \brief Set a new memcap.
 *
 *  \param size new memcap in bytes; must be above current memuse
 *  \retval 1 set, 0 rejected
 */
int DefragTrackerSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(defrag_memuse) < size) {
        SC_ATOMIC_SET(defrag_config.memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Get the memcap.
 *  \retval memcap in bytes
 */
uint64_t DefragTrackerGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(defrag_config.memcap);
    return memcapcopy;
}

/**
 *  \brief Get current memory use.
 *  \retval bytes in use (hash table, trackers and fragments)
 */
uint64_t DefragTrackerGetMemuse(void)
{
    uint64_t memusecopy = (uint64_t)SC_ATOMIC_GET(defrag_memuse);
    return memusecopy;
}

/** \brief Policy applied to a packet when no tracker can be had. */
enum ExceptionPolicy DefragGetMemcapExceptionPolicy(void)
{
    return defrag_config.memcap_policy;
}

/** \brief Return a tracker to the spare pool.
 *  It must already be unlinked from the hash and cleared. */
void DefragTrackerMoveToSpare(DefragTracker *h)
{
    DefragTrackerEnqueue(&defragtracker_spare_q, h);
    (void) SC_ATOMIC_SUB(defragtracker_counter, 1);
}

/** \return new *unlocked* tracker, or NULL if over memcap or out of memory */
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

/** \brief Free a tracker and its fragments, updating memuse. */
static void DefragTrackerFree(DefragTracker *dt)
{
    if (dt != NULL) {
        DefragTrackerClearMemory(dt);

        SCMutexDestroy(&dt->lock);
        SCFree(dt);
        (void) SC_ATOMIC_SUB(defrag_memuse, sizeof(DefragTracker));
    }
}

/* use_cnt: number of packets currently holding the tracker */
#define DefragTrackerIncrUsecnt(dt) \
    SC_ATOMIC_ADD((dt)->use_cnt, 1)
#define DefragTrackerDecrUsecnt(dt) \
    SC_ATOMIC_SUB((dt)->use_cnt, 1)

/** \brief Set up a tracker for the datagram \p p belongs to, and mark
 *  it in use. */
static void DefragTrackerInit(DefragTracker *dt, Packet *p)
{
    /* copy addresses */
    COPY_ADDRESS(&p->src, &dt->src_addr);
    COPY_ADDRESS(&p->dst, &dt->dst_addr);

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        dt->id = IPV4_GET_RAW_IPID(ip4h);
        dt->af = AF_INET;
    } else {
        DEBUG_VALIDATE_BUG_ON(!PacketIsIPv6(p));
        dt->id = IPV6_EXTHDR_GET_FH_ID(p);
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

/** \brief Give back a tracker obtained from a lookup: drop the use
 *  count and unlock it. */
void DefragTrackerRelease(DefragTracker *t)
{
    (void) DefragTrackerDecrUsecnt(t);
    SCMutexUnlock(&t->lock);
}

/** \brief Free the fragments stored in the tracker. */
void DefragTrackerClearMemory(DefragTracker *dt)
{
    DefragTrackerFreeFrags(dt);
}

/* defaults, overridable in the `defrag` YAML section */
#define DEFRAG_DEFAULT_HASHSIZE 4096
#define DEFRAG_DEFAULT_MEMCAP 16777216
#define DEFRAG_DEFAULT_PREALLOC 1000

/** \brief Read the 'defrag' config, allocate the hash and, if
 *  'defrag.prealloc' is true, fill the spare pool.
 *  Exits if the memcap is invalid or too small for the hash/prealloc.
 *  \warning Not thread safe */
void DefragInitConfig(bool quiet)
{
    SCLogDebug("initializing defrag engine...");

    memset(&defrag_config, 0, sizeof(defrag_config));
    SC_ATOMIC_INIT(defragtracker_counter);
    SC_ATOMIC_INIT(defrag_memuse);
    SC_ATOMIC_INIT(defragtracker_prune_idx);
    SC_ATOMIC_INIT(defrag_config.memcap);
    DefragTrackerStackInit(&defragtracker_spare_q);

    /* set defaults */
    defrag_config.hash_rand   = (uint32_t)RandomGet();
    defrag_config.hash_size   = DEFRAG_DEFAULT_HASHSIZE;
    defrag_config.prealloc    = DEFRAG_DEFAULT_PREALLOC;
    SC_ATOMIC_SET(defrag_config.memcap, DEFRAG_DEFAULT_MEMCAP);
    defrag_config.memcap_policy = ExceptionPolicyParse("defrag.memcap-policy", false);

    /* override defaults with values from the config, if any */
    const char *conf_val;
    uint32_t configval = 0;

    uint64_t defrag_memcap;
    /** memcap (fatal if invalid), hash-size and trackers (warn and keep
     *  default if invalid) */
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

    /* allocate the hash table; it counts toward the memcap */
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

    if ((SCConfGetNonNull("defrag.prealloc", &conf_val)) == 1) {
        if (SCConfValIsTrue(conf_val)) {
            /* preallocate 'defrag.trackers' trackers into the spare pool */
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

/** \brief Shut down the defrag hash: free the spare pool, every tracker
 *  in the hash, and the hash itself.
 *  \warning Not thread safe */
void DefragHashShutdown(void)
{
    DefragTracker *dt;

    /* free the spare pool; none of these may be in use */
    while((dt = DefragTrackerDequeue(&defragtracker_spare_q))) {
        BUG_ON(SC_ATOMIC_GET(dt->use_cnt) > 0);
        DefragTrackerFree(dt);
    }

    /* free every tracker in the hash, then the hash */
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

/** \brief Order two raw IPv6 addresses.
 *
 *  \note Only used to put the addresses in a fixed order in
 *        DefragHashKey6, so both directions hash the same. Works on raw
 *        (network order) words, so it is not a numeric compare.
 *  \warning Do not reuse elsewhere: not a real comparison.
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

/* Hash keys, overlaid with u32[] so hashword() can read them as words.
 * pad must be zeroed. */
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

/* Bucket index for this packet, hashed from:
 *  - hash_rand (random seed set at init)
 *  - source and destination addresses, sorted so both directions match
 *  - fragment id (IPv4 IP ID or IPv6 fragment header id)
 *  - vlan ids
 * Non-IP packets go to bucket 0.
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

/* Several trackers can share a bucket, so do a full match of tracker d1
 * against packet d2: addresses (either direction), protocol, fragment
 * id and vlan ids. */
#define CMP_DEFRAGTRACKER(d1, d2, id)                                                              \
    (((CMP_ADDR(&(d1)->src_addr, &(d2)->src) && CMP_ADDR(&(d1)->dst_addr, &(d2)->dst)) ||          \
             (CMP_ADDR(&(d1)->src_addr, &(d2)->dst) && CMP_ADDR(&(d1)->dst_addr, &(d2)->src))) &&  \
            (d1)->proto == PacketGetIPProto(d2) && (d1)->id == (id) &&                             \
            (d1)->vlan_id[0] == (d2)->vlan_id[0] && (d1)->vlan_id[1] == (d2)->vlan_id[1] &&        \
            (d1)->vlan_id[2] == (d2)->vlan_id[2])

/** \retval 1 tracker \p t belongs to packet \p p, 0 otherwise */
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

/** \brief Count a memcap exception policy hit, if that counter exists. */
static void DefragExceptionPolicyStatsIncr(
        ThreadVars *tv, DecodeThreadVars *dtv, enum ExceptionPolicy policy)
{
    StatsCounterId id = dtv->counter_defrag_memcap_eps.eps_id[policy];
    if (likely(id.id > 0)) {
        StatsCounterIncr(&tv->stats, id);
    }
}

/**
 *  \brief Get an empty tracker.
 *
 *  Tries the spare pool, then a new allocation. At memcap, evicts an
 *  idle tracker from the hash instead. If all fail, applies the memcap
 *  exception policy to \p p. Caller holds the bucket lock.
 *
 *  \retval dt *LOCKED* tracker on success, NULL on failure
 */
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

    /* first choice: a tracker from the spare pool */
    dt = DefragTrackerDequeue(&defragtracker_spare_q);
    if (dt == NULL) {
        /* at memcap: evict an idle tracker from the hash */
        if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
            dt = DefragTrackerGetUsedDefragTracker(tv, dtv);
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }

            /* evicted tracker is cleared and *unlocked* */
        } else {
            /* below memcap: allocate a new one */
            dt = DefragTrackerAlloc();
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }

            /* new tracker is zeroed and *unlocked* */
        }
    } else {
        /* spare trackers were cleared before entering the pool */

        /* so it is ready to use, and *unlocked* */
    }

    (void) SC_ATOMIC_ADD(defragtracker_counter, 1);
    SCMutexLock(&dt->lock);
    return dt;
}

/** \brief Find the tracker for this packet, or create one.
 *
 * Hashes the packet to a bucket and walks its chain for a match.
 * Timed-out trackers met on the way are unlinked and moved to
 * the spare pool. With no match, a new tracker is added at the
 * head of the bucket.
 *
 * \retval a *LOCKED* tracker with its use count raised, or NULL if no
 * tracker could be had (memcap).
 */
DefragTracker *DefragGetTrackerFromHash(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    DefragTracker *dt = NULL;

    /* get the bucket for this packet */
    uint32_t key = DefragHashGetKey(p);
    /* and lock it */
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* empty bucket: create the first tracker */
    if (hb->head == NULL) {
        dt = DefragTrackerGetNew(tv, dtv, p);
        if (dt == NULL) {
            DRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* tracker is locked */
        hb->head = dt;

        /* initialize and return it */
        DefragTrackerInit(dt,p);

        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* bucket has trackers: look for ours */
    DefragTracker *prev_dt = NULL;
    dt = hb->head;

    do {
        DefragTracker *next_dt = NULL;

        SCMutexLock(&dt->lock);
        if (DefragTrackerTimedOut(dt, p->ts)) {
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
            /* found it: return it still locked */
            (void)DefragTrackerIncrUsecnt(dt);
            DRLOCK_UNLOCK(hb);
            return dt;
        }
        SCMutexUnlock(&dt->lock);
        /* prev_dt advances only when dt stays in the chain, so it is
         * correct for unlinking on the next iteration. */
        prev_dt = dt;
        next_dt = dt->hnext;

    tracker_removed:
        if (next_dt == NULL) {
            /* end of chain without a match: create a new tracker */
            dt = DefragTrackerGetNew(tv, dtv, p);
            if (dt == NULL) {
                DRLOCK_UNLOCK(hb);
                return NULL;
            }
            dt->hnext = hb->head;
            hb->head = dt;

            /* tracker is locked */

            /* initialize and return it */
            DefragTrackerInit(dt, p);

            DRLOCK_UNLOCK(hb);
            return dt;
        }

        dt = next_dt;
    } while (dt != NULL);

    /* should be unreachable */
    BUG_ON(1);
    return NULL;
}

/** \brief Look up the tracker for a packet. Never creates one.
 *
 *  \param p packet whose datagram to look up
 *  \retval dt *LOCKED* tracker with use count raised, or NULL
 */
DefragTracker *DefragLookupTrackerFromHash (Packet *p)
{
    DefragTracker *dt = NULL;

    /* get the bucket for this packet */
    uint32_t key = DefragHashGetKey(p);
    /* and lock it */
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* empty bucket: nothing to find */
    if (hb->head == NULL) {
        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* bucket has trackers: look for ours */
    dt = hb->head;

    do {
        if (!dt->remove && DefragTrackerCompare(dt, p)) {
            /* found it: lock and return */
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

    /* should be unreachable */
    BUG_ON(1);
    return NULL;
}

/** \internal
 *  \brief Evict a tracker from the hash for reuse.
 *
 *  Used when the spare pool is empty and the memcap is reached.
 *
 *  Scans buckets for an idle tracker at a bucket head, skipping busy
 *  locks. The scan resumes where the last one stopped
 *  (defragtracker_prune_idx): always starting at bucket 0 would drain
 *  the start of the hash and make each search longer under load (observed).
 *
 *  \retval dt cleared, unlinked, *unlocked* tracker, or NULL if none
 */
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

        /** never evict a tracker held by a packet that some thread is
         *  still processing */
        if (SC_ATOMIC_GET(dt->use_cnt) > 0) {
            DRLOCK_UNLOCK(hb);
            SCMutexUnlock(&dt->lock);
            continue;
        }

        /* "hard" reuse: the tracker was still live. "Soft": it was
         * already marked for removal. */
        bool incr_reuse_cnt = !dt->remove;

        /* unlink from the bucket */
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
