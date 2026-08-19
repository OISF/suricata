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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Hash table for DefragTracker objects: lookup, allocation,
 * memcap accounting, and eviction under pressure.
 *
 * Locking order is always row-lock (DRLOCK) then tracker mutex.
 * use_cnt is an atomic refcount that keeps a tracker alive across
 * lock drops; the pruner refuses to evict trackers with use_cnt > 0.
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

/** Bucket array for the tracker hash. Allocated in DefragInitConfig,
 *  freed in DefragHashShutdown. Sized by defrag.hash-size. */
DefragTrackerHashRow *defragtracker_hash;

/** Process-wide defrag hash config: memcap (atomic), hash size,
 *  prealloc count, per-run random seed, and exception policy. */
DefragConfig defrag_config;

/** Total bytes charged against defrag.memcap: hash buckets +
 *  every live and spare DefragTracker. Atomic so the fast path
 *  can check it without taking a lock. */
SC_ATOMIC_DECLARE(uint64_t,defrag_memuse);

/** Count of trackers currently in service (handed out to a
 *  bucket, not sitting in the spare queue). Bumped by
 *  DefragTrackerGetNew, dropped by DefragTrackerMoveToSpare. */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_counter);

/** Rolling cursor into the hash used by
 *  DefragTrackerGetUsedDefragTracker so successive eviction sweeps
 *  don't repeatedly hammer the low-index buckets. */
SC_ATOMIC_DECLARE(unsigned int,defragtracker_prune_idx);

static DefragTracker *DefragTrackerGetUsedDefragTracker(
        ThreadVars *tv, const DecodeThreadVars *dtv);

/** Spare/free stack of DefragTrackers. LIFO so the most recently
 *  freed tracker (still likely to be cache-hot) is handed out first.
 *  Filled by defrag.prealloc at startup and by runtime recycling. */
static DefragTrackerStack defragtracker_spare_q;

/**
 * \brief Raise the memcap at runtime (atomic).
 *
 * Refuses to lower the cap below current memuse; that would leave
 * every subsequent allocation permanently failing the memcap check.
 *
 * \retval 1 updated, 0 rejected (size below current usage)
 */
int DefragTrackerSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(defrag_memuse) < size) {
        SC_ATOMIC_SET(defrag_config.memcap, size);
        return 1;
    }

    return 0;
}

/** \brief Atomic read of the current memcap. */
uint64_t DefragTrackerGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(defrag_config.memcap);
    return memcapcopy;
}

/** \brief Atomic read of the current memuse. */
uint64_t DefragTrackerGetMemuse(void)
{
    uint64_t memusecopy = (uint64_t)SC_ATOMIC_GET(defrag_memuse);
    return memusecopy;
}

/**
 * \brief Report the configured exception policy for memcap hits.
 */
enum ExceptionPolicy DefragGetMemcapExceptionPolicy(void)
{
    return defrag_config.memcap_policy;
}

/**
 * \brief Push a tracker back onto the spare stack for reuse.
 *
 * Struct and its memcap charge stay allocated; only the
 * in-service counter is decremented.
 */
void DefragTrackerMoveToSpare(DefragTracker *h)
{
    DefragTrackerEnqueue(&defragtracker_spare_q, h);
    (void) SC_ATOMIC_SUB(defragtracker_counter, 1);
}

/**
 * \internal
 * \brief Allocate and initialise a bare DefragTracker.
 *
 * Charges memcap BEFORE calling SCCalloc so a racing
 * allocator can't slip in and push us over budget. On calloc
 * failure the charge is rolled back.
 *
 * The tracker is returned unlocked with use_cnt initialised to 0.
 * Callers (DefragTrackerGetNew) lock it before handing it out.
 *
 * \retval dt   new tracker
 * \retval NULL memcap exhausted or calloc failed
 */
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

/**
 * \internal
 * \brief Fully destroy a DefragTracker.
 *
 * Releases any attached fragments, destroys the mutex, frees
 * the struct, and refunds the memcap charge. Normal runtime
 * recycling goes through the spare stack instead.
 */
static void DefragTrackerFree(DefragTracker *dt)
{
    if (dt != NULL) {
        DefragTrackerClearMemory(dt);

        SCMutexDestroy(&dt->lock);
        SCFree(dt);
        (void) SC_ATOMIC_SUB(defrag_memuse, sizeof(DefragTracker));
    }
}

/* Atomic refcount helpers. The count is bumped whenever a caller
 * takes a pointer to a tracker (lookup returns) and dropped when
 * they're done (Release). The pruner refuses to evict trackers
 * with use_cnt > 0, so this refcount is what prevents another
 * thread from stealing a tracker mid-use even after the tracker
 * lock has been dropped. */
#define DefragTrackerIncrUsecnt(dt) \
    SC_ATOMIC_ADD((dt)->use_cnt, 1)
#define DefragTrackerDecrUsecnt(dt) \
    SC_ATOMIC_SUB((dt)->use_cnt, 1)

/**
 * \internal
 * \brief Fill a newly acquired tracker from its first packet.
 *
 * Copies both addresses (both directions: src<->dst comparison at
 * lookup time handles either order), captures IP id, protocol, and
 * the VLAN stack, and looks up the per-destination reassembly
 * policy and host timeout. Also bumps use_cnt for the caller
 * that requested the tracker.
 */
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


 /**
 * \brief Drop the caller's reference and unlock. Decrement must
 *        happen while the tracker is still valid.
 *
 * The atomic decrement must happen while the tracker is
 * still valid (i.e. hasn't been freed by a pruner racing on the
 * bucket lock).
 */
void DefragTrackerRelease(DefragTracker *t)
{
    (void) DefragTrackerDecrUsecnt(t);
    SCMutexUnlock(&t->lock);
}

/**
 * \brief Detach every Frag from a tracker; the tracker itself
 *        stays valid.
 */
void DefragTrackerClearMemory(DefragTracker *dt)
{
    DefragTrackerFreeFrags(dt);
}

#define DEFRAG_DEFAULT_HASHSIZE 4096
#define DEFRAG_DEFAULT_MEMCAP 16777216
#define DEFRAG_DEFAULT_PREALLOC 1000

/**
 * \brief Build the hash table, apply yaml config, optionally
 *        prealloc trackers.
 *
 * Fails fatally if the configured hash size alone would exceed
 * memcap, better than failing every allocation forever.
 * Called once from DefragInit() (in defrag.c) during engine
 * start-up, before any packets are processed.
 *
 * Sequence:
 *   1. Zero the config struct; initialise the atomics; init the
 *      spare-stack lock structure.
 *   2. Seed hash_rand from the process RNG so bucket assignment
 *      isn't predictable across runs.
 *   3. Apply defaults, then override from suricata.yaml.
 *   4. Verify hash_size * sizeof(DefragTrackerHashRow) fits in
 *      memcap; refusing to start if not.
 *   5. Allocate the bucket array, init each row lock, charge the
 *      allocation against memuse.
 *   6. If defrag.prealloc is true, DefragTrackerAlloc() up to
 *      `prealloc` trackers and push them onto the spare stack.
 *      Preallocation faults early on RAM shortage rather than
 *      failing under traffic.
 *
 * \warning Not thread-safe. Only ever called on the main thread
 *          before workers are spawned, and once at test setup.
 */
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

    /* Check if we have memcap and hash_size defined at config */
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

    /* alloc hash memory */
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

    /* Prealloc surfaces RAM shortage now rather than under traffic. */
    if ((SCConfGetNonNull("defrag.prealloc", &conf_val)) == 1) {
        if (SCConfValIsTrue(conf_val)) {
            /* pre allocate defrag trackers */
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

 /**
 * \brief Tear down everything DefragInitConfig set up.
 *
 * Drains the spare stack, then walks every bucket freeing any
 * tracker still linked in, then frees the bucket array and refunds
 * the memcap charge. Any tracker whose use_cnt is still non-zero
 * at this point is a bug, nothing should hold a tracker
 * reference after workers have joined.
 *
 * \warning Not thread-safe. Only called during engine shutdown
 *          after all worker threads have exited.
 */
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

/**
 * \internal
 * \brief Byte-wise "greater than" over two 128-bit raw IPv6
 *        addresses viewed as four uint32_t words.
 *
 * Purpose is strictly to give DefragHashGetKey a stable ordering so
 * (src, dst) and (dst, src) hash to the same bucket. The comparison
 * is done in the raw wire order without SCNtohl, endianness is
 * irrelevant as long as the ordering is deterministic.
 *
 * \warning Do NOT use this for real IPv6 address comparison
 *          elsewhere in the codebase. detect-engine-address-ipv6.c
 *          has proper byte-order-aware helpers for that. This
 *          function exists only for hash-key normalisation.
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

/* Packed key structs fed into hashword(). The union with a flat
 * uint32_t array lets Jenkins lookup3 consume the key as a word
 * stream while the named fields document what each word means.
 *
 * The `pad[1]` slot forces the u32 count to a round number and
 * makes it explicit that the struct is zeroed on init (memset via
 * designated initialiser), otherwise padding bytes could leak
 * uninitialised bits into the hash. */
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

/**
 * \internal
 * \brief Compute the bucket index for a fragment.
 *
 * Key material:
 *   - hash_rand    (per-run seed, defeats collision attacks)
 *   - source IP    ┐ sorted so both directions of a datagram
 *   - dest IP      ┘ hash to the same bucket
 *   - IP id        (16-bit v4, 32-bit v6 frag header ident)
 *   - VLAN stack   (up to VLAN_MAX_LAYERS entries)
 *
 * Protocol is intentionally NOT hashed but IS compared at bucket
 * walk time (see CMP_DEFRAGTRACKER), this is a deliberate tradeoff
 * favouring bucket-lookup speed over discrimination, since IP id
 * collisions across protocols are rare enough that walking the
 * short chain is cheaper than paying for extra hashing.
 *
 * Non-IPv4/IPv6 packets return key 0. They should never reach here
 * because Defrag() filters them at the entry point.
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

/* Full tuple match; addresses may be src<->dst swapped. */
#define CMP_DEFRAGTRACKER(d1, d2, id)                                                              \
    (((CMP_ADDR(&(d1)->src_addr, &(d2)->src) && CMP_ADDR(&(d1)->dst_addr, &(d2)->dst)) ||          \
             (CMP_ADDR(&(d1)->src_addr, &(d2)->dst) && CMP_ADDR(&(d1)->dst_addr, &(d2)->src))) &&  \
            (d1)->proto == PacketGetIPProto(d2) && (d1)->id == (id) &&                             \
            (d1)->vlan_id[0] == (d2)->vlan_id[0] && (d1)->vlan_id[1] == (d2)->vlan_id[1] &&        \
            (d1)->vlan_id[2] == (d2)->vlan_id[2])

/**
 * \internal
 * \brief Address-family gate + full tuple comparison.
 *
 * Cheap AF check first, a v4 packet cannot match a v6 tracker no
 * matter how the id and VLANs line up; then delegate to
 * CMP_DEFRAGTRACKER for the tuple.
 */
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

/**
 * \internal
 * \brief Bump the per-policy memcap-hit counter for the current
 *        exception policy.
 *
 * The counter ids are cached per thread (dtv->counter_defrag_memcap_eps)
 * so this hot-path helper stays branchless past the id lookup.
 */
static void DefragExceptionPolicyStatsIncr(
        ThreadVars *tv, DecodeThreadVars *dtv, enum ExceptionPolicy policy)
{
    StatsCounterId id = dtv->counter_defrag_memcap_eps.eps_id[policy];
    if (likely(id.id > 0)) {
        StatsCounterIncr(&tv->stats, id);
    }
}

/**
 * \internal
 * \brief Obtain a locked tracker for a packet that had no existing
 *        entry in its bucket.
 *
 * Three-tier acquisition, tried in order of cost:
 *   1. Pop from the spare stack. Cheapest and common; the tracker already
 *      exists and its memcap charge is already paid.
 *   2. Spare stack empty AND memcap allows another allocation,
 *      DefragTrackerAlloc a new one. Grows the working set.
 *   3. Spare stack empty AND memcap is exhausted,
 *      DefragTrackerGetUsedDefragTracker to steal an idle one.
 *      This walks the hash and is the slowest path.
 *
 * If all three fail, apply the configured exception policy to the
 * packet and bump the per-policy stats counter. NULL is returned to
 * the caller.
 *
 * \retval dt   LOCKED tracker
 * \retval NULL memcap and eviction both failed
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

    /* get a tracker from the spare queue */
    dt = DefragTrackerDequeue(&defragtracker_spare_q);
    if (dt == NULL) {
        /* If we reached the max memcap, we get a used tracker */
        if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
            dt = DefragTrackerGetUsedDefragTracker(tv, dtv);
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }

            /* freed a tracker, but it's unlocked */
        } else {
            /* now see if we can alloc a new tracker */
            dt = DefragTrackerAlloc();
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                DefragExceptionPolicyStatsIncr(tv, dtv, defrag_config.memcap_policy);
                return NULL;
            }

            /* tracker is initialized but *unlocked* */
        }
    } else {
        /* tracker has been recycled before it went into the spare queue */

        /* tracker is initialized (recycled) but *unlocked* */
    }

    (void) SC_ATOMIC_ADD(defragtracker_counter, 1);
    SCMutexLock(&dt->lock);
    return dt;
}

/**
 * \brief Look up (or create) the tracker for a packet.
 *
 * This is the main entry point called by Defrag() in defrag.c.
 *
 * Sequence:
 *   1. Hash the packet to a bucket, lock the row.
 *   2. Empty bucket, call DefragTrackerGetNew, splice it in as
 *      the head, initialise, drop the row lock, return the
 *      (locked) tracker.
 *   3. Non-empty bucket, walk the hnext chain. For each candidate:
 *        a. Lock the tracker.
 *        b. If it has timed out (per DefragTrackerTimedOut against
 *           the packet timestamp): unlink it, clear its frags,
 *           push it back to the spare stack, bump the timeout
 *           counter, and continue walking. Timeout-on-lookup is
 *           opportunistic garbage collection; the flow-manager
 *           thread also sweeps for timeouts, but reaping them
 *           inline saves a full sweep pass on hot buckets.
 *        c. If it is not marked `remove` AND its tuple matches:
 *           bump use_cnt, drop the row lock, return the (still
 *           locked) tracker. Note the tracker stays locked while
 *           we release the row; the caller will unlock it via
 *           DefragTrackerRelease.
 *        d. Otherwise unlock the tracker and advance.
 *   4. End of chain reached, allocate a new tracker via
 *      DefragTrackerGetNew, splice at the HEAD (LIFO - new
 *      trackers are more likely to see more fragments soon),
 *      initialise, drop the row lock, return.
 *
 * Locking order is always row-lock outer, tracker-lock inner. The
 * `goto tracker_removed` construct keeps `prev_dt` correct when
 * a timed-out entry has been spliced out mid-walk.
 *
 * \retval dt   LOCKED tracker; caller MUST DefragTrackerRelease
 * \retval NULL memcap exhausted and no candidate could be evicted
 */
DefragTracker *DefragGetTrackerFromHash(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    DefragTracker *dt = NULL;

    /* get the key to our bucket */
    uint32_t key = DefragHashGetKey(p);
    /* get our hash bucket and lock it */
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* see if the bucket already has a tracker */
    if (hb->head == NULL) {
        dt = DefragTrackerGetNew(tv, dtv, p);
        if (dt == NULL) {
            DRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* tracker is locked */
        hb->head = dt;

        /* got one, now lock, initialize and return */
        DefragTrackerInit(dt,p);

        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* ok, we have a tracker in the bucket. Let's find out if it is our tracker */
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
            /* found our tracker, keep locked & return */
            (void)DefragTrackerIncrUsecnt(dt);
            DRLOCK_UNLOCK(hb);
            return dt;
        }
        SCMutexUnlock(&dt->lock);
        /* unless we removed 'dt', prev_dt needs to point to
         * current 'dt' when adding a new tracker below. */
        prev_dt = dt;
        next_dt = dt->hnext;

    tracker_removed:
        if (next_dt == NULL) {
            dt = DefragTrackerGetNew(tv, dtv, p);
            if (dt == NULL) {
                DRLOCK_UNLOCK(hb);
                return NULL;
            }
            dt->hnext = hb->head;
            hb->head = dt;

            /* tracker is locked */

            /* initialize and return */
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

/**
 * \brief Read-only lookup: return the existing tracker for a packet,
 *        or NULL if there isn't one.
 *
 * Unlike DefragGetTrackerFromHash, this never allocates and never
 * evicts. Used by unit tests and by paths that want to inspect
 * tracker state without registering interest in creating one.
 *
 * Does not run the timeout-on-lookup logic, a read-only caller
 * shouldn't have side effects on the hash.
 *
 * \retval dt   LOCKED tracker
 * \retval NULL no matching tracker in the bucket
 */
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

    /* should be unreachable */
    BUG_ON(1);
    return NULL;
}

/**
 * \internal
 * \brief Find and detach an idle tracker so its slot can be reused.
 *
 * Called by DefragTrackerGetNew when the spare stack is empty and
 * memcap is exhausted. This is the pressure-relief valve of the
 * whole engine.
 *
 * Sweep strategy:
 *   - Start from a rotating cursor (defragtracker_prune_idx),
 *     wrapping on hash_size. The rotation is critical because always
 *     starting at 0 would repeatedly evict the same top-of-table
 *     entries, causing longer and longer search times under high pressure
 *     (observed).
 *   - For each bucket:
 *       DRLOCK_TRYLOCK: skip contended buckets rather than block.
 *       Empty head: skip.
 *       SCMutexTrylock on the first tracker: skip on contention.
 *       use_cnt > 0: in-flight, must not steal so skip.
 *       Otherwise: unlink from the bucket, drop the row lock,
 *       clear the tracker's frags, unlock it, and return it.
 *   - Distinguish "hard reuse" (tracker was live, we're stealing
 *     it) from "soft reuse" (tracker was already marked `remove`
 *     but hadn't been reaped yet). Sustained hard reuse is a
 *     signal to raise memcap or prealloc.
 *   - Advance defragtracker_prune_idx by however many buckets
 *     the sweep consumed so the next call starts where this one
 *     left off.
 *
 * All acquisitions are trylocks precisely because this runs on the
 * packet-processing hot path; blocking here would head-of-line-block
 * every worker.
 *
 * \retval dt   unlocked, cleared tracker ready to be re-initialised
 * \retval NULL a full sweep found nothing evictable
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

        /** never prune a tracker that is used by a packets
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(dt->use_cnt) > 0) {
            DRLOCK_UNLOCK(hb);
            SCMutexUnlock(&dt->lock);
            continue;
        }

        /* only count "forced" reuse */
        bool incr_reuse_cnt = !dt->remove;

        /* remove from the hash */
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
