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

#include "suricata-common.h"
#include "conf.h"
#include "defrag-hash.h"
#include "defrag-queue.h"
#include "defrag-config.h"
#include "util-random.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-hash-lookup3.h"

/** defrag tracker hash table */
DefragTrackerHashRow *defragtracker_hash;
DefragConfig defrag_config;
SC_ATOMIC_DECLARE(uint64_t,defrag_memuse);
SC_ATOMIC_DECLARE(unsigned int,defragtracker_counter);
SC_ATOMIC_DECLARE(unsigned int,defragtracker_prune_idx);

static DefragTracker *DefragTrackerGetUsedDefragTracker(void);

/** queue with spare tracker */
static DefragTrackerQueue defragtracker_spare_q;

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
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
 *  \brief Return memcap value
 *
 *  \retval memcap value
 */
uint64_t DefragTrackerGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(defrag_config.memcap);
    return memcapcopy;
}

/**
 *  \brief Return memuse value
 *
 *  \retval memuse value
 */
uint64_t DefragTrackerGetMemuse(void)
{
    uint64_t memusecopy = (uint64_t)SC_ATOMIC_GET(defrag_memuse);
    return memusecopy;
}

uint32_t DefragTrackerSpareQueueGetSize(void)
{
    return DefragTrackerQueueLen(&defragtracker_spare_q);
}

void DefragTrackerMoveToSpare(DefragTracker *h)
{
    DefragTrackerEnqueue(&defragtracker_spare_q, h);
    (void) SC_ATOMIC_SUB(defragtracker_counter, 1);
}

static DefragTracker *DefragTrackerAlloc(void)
{
    if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(defrag_memuse, sizeof(DefragTracker));

    DefragTracker *dt = SCMalloc(sizeof(DefragTracker));
    if (unlikely(dt == NULL))
        goto error;

    memset(dt, 0x00, sizeof(DefragTracker));

    SCMutexInit(&dt->lock, NULL);
    SC_ATOMIC_INIT(dt->use_cnt);
    return dt;

error:
    return NULL;
}

static void DefragTrackerFree(DefragTracker *dt)
{
    if (dt != NULL) {
        DefragTrackerClearMemory(dt);

        SCMutexDestroy(&dt->lock);
        SCFree(dt);
        (void) SC_ATOMIC_SUB(defrag_memuse, sizeof(DefragTracker));
    }
}

#define DefragTrackerIncrUsecnt(dt) \
    SC_ATOMIC_ADD((dt)->use_cnt, 1)
#define DefragTrackerDecrUsecnt(dt) \
    SC_ATOMIC_SUB((dt)->use_cnt, 1)

static void DefragTrackerInit(DefragTracker *dt, Packet *p)
{
    /* copy address */
    COPY_ADDRESS(&p->src, &dt->src_addr);
    COPY_ADDRESS(&p->dst, &dt->dst_addr);

    if (PKT_IS_IPV4(p)) {
        dt->id = (int32_t)IPV4_GET_IPID(p);
        dt->af = AF_INET;
    } else {
        dt->id = (int32_t)IPV6_EXTHDR_GET_FH_ID(p);
        dt->af = AF_INET6;
    }
    dt->proto = IP_GET_IPPROTO(p);
    dt->vlan_id[0] = p->vlan_id[0];
    dt->vlan_id[1] = p->vlan_id[1];
    dt->policy = DefragGetOsPolicy(p);
    dt->host_timeout = DefragPolicyGetHostTimeout(p);
    dt->remove = 0;
    dt->seen_last = 0;

    (void) DefragTrackerIncrUsecnt(dt);
}

void DefragTrackerRelease(DefragTracker *t)
{
    (void) DefragTrackerDecrUsecnt(t);
    SCMutexUnlock(&t->lock);
}

void DefragTrackerClearMemory(DefragTracker *dt)
{
    DefragTrackerFreeFrags(dt);
}

#define DEFRAG_DEFAULT_HASHSIZE 4096
#define DEFRAG_DEFAULT_MEMCAP 16777216
#define DEFRAG_DEFAULT_PREALLOC 1000

/** \brief initialize the configuration
 *  \warning Not thread safe */
void DefragInitConfig(bool quiet)
{
    SCLogDebug("initializing defrag engine...");

    memset(&defrag_config,  0, sizeof(defrag_config));
    //SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(defragtracker_counter);
    SC_ATOMIC_INIT(defrag_memuse);
    SC_ATOMIC_INIT(defragtracker_prune_idx);
    SC_ATOMIC_INIT(defrag_config.memcap);
    DefragTrackerQueueInit(&defragtracker_spare_q);

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
    if ((ConfGet("defrag.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &defrag_memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing defrag.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(defrag_config.memcap, defrag_memcap);
        }
    }
    if ((ConfGet("defrag.hash-size", &conf_val)) == 1)
    {
        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            defrag_config.hash_size = configval;
        } else {
            WarnInvalidConfEntry("defrag.hash-size", "%"PRIu32, defrag_config.hash_size);
        }
    }


    if ((ConfGet("defrag.trackers", &conf_val)) == 1)
    {
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
        SCLogError(SC_ERR_DEFRAG_INIT, "allocating defrag hash failed: "
                "max defrag memcap is smaller than projected hash size. "
                "Memcap: %"PRIu64", Hash table size %"PRIu64". Calculate "
                "total hash size by multiplying \"defrag.hash-size\" with %"PRIuMAX", "
                "which is the hash bucket size.", SC_ATOMIC_GET(defrag_config.memcap), hash_size,
                (uintmax_t)sizeof(DefragTrackerHashRow));
        exit(EXIT_FAILURE);
    }
    defragtracker_hash = SCCalloc(defrag_config.hash_size, sizeof(DefragTrackerHashRow));
    if (unlikely(defragtracker_hash == NULL)) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in DefragTrackerInitConfig. Exiting...");
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

    if ((ConfGet("defrag.prealloc", &conf_val)) == 1)
    {
        if (ConfValIsTrue(conf_val)) {
            /* pre allocate defrag trackers */
            for (i = 0; i < defrag_config.prealloc; i++) {
                if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
                    SCLogError(SC_ERR_DEFRAG_INIT, "preallocating defrag trackers failed: "
                            "max defrag memcap reached. Memcap %"PRIu64", "
                            "Memuse %"PRIu64".", SC_ATOMIC_GET(defrag_config.memcap),
                            ((uint64_t)SC_ATOMIC_GET(defrag_memuse) + (uint64_t)sizeof(DefragTracker)));
                    exit(EXIT_FAILURE);
                }

                DefragTracker *h = DefragTrackerAlloc();
                if (h == NULL) {
                    SCLogError(SC_ERR_DEFRAG_INIT, "preallocating defrag failed: %s", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                DefragTrackerEnqueue(&defragtracker_spare_q,h);
            }
            if (!quiet) {
                SCLogConfig("preallocated %" PRIu32 " defrag trackers of size %" PRIuMAX "",
                        defragtracker_spare_q.len, (uintmax_t)sizeof(DefragTracker));
            }
        }
    }

    if (!quiet) {
        SCLogConfig("defrag memory usage: %"PRIu64" bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(defrag_memuse), SC_ATOMIC_GET(defrag_config.memcap));
    }

    return;
}

/** \brief print some defrag stats
 *  \warning Not thread safe */
static void DefragTrackerPrintStats (void)
{
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void DefragHashShutdown(void)
{
    DefragTracker *dt;
    uint32_t u;

    DefragTrackerPrintStats();

    /* free spare queue */
    while((dt = DefragTrackerDequeue(&defragtracker_spare_q))) {
        BUG_ON(SC_ATOMIC_GET(dt->use_cnt) > 0);
        DefragTrackerFree(dt);
    }

    /* clear and free the hash */
    if (defragtracker_hash != NULL) {
        for (u = 0; u < defrag_config.hash_size; u++) {
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
    DefragTrackerQueueDestroy(&defragtracker_spare_q);
    return;
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

typedef struct DefragHashKey4_ {
    union {
        struct {
            uint32_t src, dst;
            uint32_t id;
            uint16_t vlan_id[2];
        };
        uint32_t u32[4];
    };
} DefragHashKey4;

typedef struct DefragHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint32_t id;
            uint16_t vlan_id[2];
        };
        uint32_t u32[10];
    };
} DefragHashKey6;

/* calculate the hash key for this packet
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

    if (p->ip4h != NULL) {
        DefragHashKey4 dhk;
        if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
            dhk.src = p->src.addr_data32[0];
            dhk.dst = p->dst.addr_data32[0];
        } else {
            dhk.src = p->dst.addr_data32[0];
            dhk.dst = p->src.addr_data32[0];
        }
        dhk.id = (uint32_t)IPV4_GET_IPID(p);
        dhk.vlan_id[0] = p->vlan_id[0];
        dhk.vlan_id[1] = p->vlan_id[1];

        uint32_t hash = hashword(dhk.u32, 4, defrag_config.hash_rand);
        key = hash % defrag_config.hash_size;
    } else if (p->ip6h != NULL) {
        DefragHashKey6 dhk;
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
        dhk.vlan_id[0] = p->vlan_id[0];
        dhk.vlan_id[1] = p->vlan_id[1];

        uint32_t hash = hashword(dhk.u32, 10, defrag_config.hash_rand);
        key = hash % defrag_config.hash_size;
    } else
        key = 0;

    return key;
}

/* Since two or more trackers can have the same hash key, we need to compare
 * the tracker with the current tracker key. */
#define CMP_DEFRAGTRACKER(d1,d2,id) \
    (((CMP_ADDR(&(d1)->src_addr, &(d2)->src) && \
       CMP_ADDR(&(d1)->dst_addr, &(d2)->dst)) || \
      (CMP_ADDR(&(d1)->src_addr, &(d2)->dst) && \
       CMP_ADDR(&(d1)->dst_addr, &(d2)->src))) && \
     (d1)->proto == IP_GET_IPPROTO(d2) &&   \
     (d1)->id == (id) && \
     (d1)->vlan_id[0] == (d2)->vlan_id[0] && \
     (d1)->vlan_id[1] == (d2)->vlan_id[1])

static inline int DefragTrackerCompare(DefragTracker *t, Packet *p)
{
    uint32_t id;
    if (PKT_IS_IPV4(p)) {
        id = (uint32_t)IPV4_GET_IPID(p);
    } else {
        id = IPV6_EXTHDR_GET_FH_ID(p);
    }

    return CMP_DEFRAGTRACKER(t, p, id);
}

/**
 *  \brief Get a new defrag tracker
 *
 *  Get a new defrag tracker. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \retval dt *LOCKED* tracker on succes, NULL on error.
 */
static DefragTracker *DefragTrackerGetNew(Packet *p)
{
#ifdef DEBUG
    if (g_eps_defrag_memcap != UINT64_MAX && g_eps_defrag_memcap == p->pcap_cnt) {
        SCLogNotice("simulating memcap hit for packet %" PRIu64, p->pcap_cnt);
        ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
        return NULL;
    }
#endif

    DefragTracker *dt = NULL;

    /* get a tracker from the spare queue */
    dt = DefragTrackerDequeue(&defragtracker_spare_q);
    if (dt == NULL) {
        /* If we reached the max memcap, we get a used tracker */
        if (!(DEFRAG_CHECK_MEMCAP(sizeof(DefragTracker)))) {
            /* declare state of emergency */
            //if (!(SC_ATOMIC_GET(defragtracker_flags) & DEFRAG_EMERGENCY)) {
            //    SC_ATOMIC_OR(defragtracker_flags, DEFRAG_EMERGENCY);

                /* under high load, waking up the flow mgr each time leads
                 * to high cpu usage. Flows are not timed out much faster if
                 * we check a 1000 times a second. */
            //    FlowWakeupFlowManagerThread();
            //}

            dt = DefragTrackerGetUsedDefragTracker();
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                return NULL;
            }

            /* freed a tracker, but it's unlocked */
        } else {
            /* now see if we can alloc a new tracker */
            dt = DefragTrackerAlloc();
            if (dt == NULL) {
                ExceptionPolicyApply(p, defrag_config.memcap_policy, PKT_DROP_REASON_DEFRAG_MEMCAP);
                return NULL;
            }

            /* tracker is initialized but *unlocked* */
        }
    } else {
        /* tracker has been recycled before it went into the spare queue */

        /* tracker is initialized (recylced) but *unlocked* */
    }

    (void) SC_ATOMIC_ADD(defragtracker_counter, 1);
    SCMutexLock(&dt->lock);
    return dt;
}

/* DefragGetTrackerFromHash
 *
 * Hash retrieval function for trackers. Looks up the hash bucket containing the
 * tracker pointer. Then compares the packet with the found tracker to see if it is
 * the tracker we need. If it isn't, walk the list until the right tracker is found.
 *
 * returns a *LOCKED* tracker or NULL
 */
DefragTracker *DefragGetTrackerFromHash (Packet *p)
{
    DefragTracker *dt = NULL;

    /* get the key to our bucket */
    uint32_t key = DefragHashGetKey(p);
    /* get our hash bucket and lock it */
    DefragTrackerHashRow *hb = &defragtracker_hash[key];
    DRLOCK_LOCK(hb);

    /* see if the bucket already has a tracker */
    if (hb->head == NULL) {
        dt = DefragTrackerGetNew(p);
        if (dt == NULL) {
            DRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* tracker is locked */
        hb->head = dt;
        hb->tail = dt;

        /* got one, now lock, initialize and return */
        DefragTrackerInit(dt,p);

        DRLOCK_UNLOCK(hb);
        return dt;
    }

    /* ok, we have a tracker in the bucket. Let's find out if it is our tracker */
    dt = hb->head;

    /* see if this is the tracker we are looking for */
    if (dt->remove || DefragTrackerCompare(dt, p) == 0) {
        DefragTracker *pdt = NULL; /* previous tracker */

        while (dt) {
            pdt = dt;
            dt = dt->hnext;

            if (dt == NULL) {
                dt = pdt->hnext = DefragTrackerGetNew(p);
                if (dt == NULL) {
                    DRLOCK_UNLOCK(hb);
                    return NULL;
                }
                hb->tail = dt;

                /* tracker is locked */

                dt->hprev = pdt;

                /* initialize and return */
                DefragTrackerInit(dt,p);

                DRLOCK_UNLOCK(hb);
                return dt;
            }

            if (DefragTrackerCompare(dt, p) != 0) {
                /* we found our tracker, lets put it on top of the
                 * hash list -- this rewards active trackers */
                if (dt->hnext) {
                    dt->hnext->hprev = dt->hprev;
                }
                if (dt->hprev) {
                    dt->hprev->hnext = dt->hnext;
                }
                if (dt == hb->tail) {
                    hb->tail = dt->hprev;
                }

                dt->hnext = hb->head;
                dt->hprev = NULL;
                hb->head->hprev = dt;
                hb->head = dt;

                /* found our tracker, lock & return */
                SCMutexLock(&dt->lock);
                (void) DefragTrackerIncrUsecnt(dt);
                DRLOCK_UNLOCK(hb);
                return dt;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&dt->lock);
    (void) DefragTrackerIncrUsecnt(dt);
    DRLOCK_UNLOCK(hb);
    return dt;
}

/** \brief look up a tracker in the hash
 *
 *  \param a address to look up
 *
 *  \retval h *LOCKED* tracker or NULL
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

    /* see if this is the tracker we are looking for */
    if (DefragTrackerCompare(dt, p) == 0) {
        while (dt) {
            dt = dt->hnext;

            if (dt == NULL) {
                DRLOCK_UNLOCK(hb);
                return dt;
            }

            if (DefragTrackerCompare(dt, p) != 0) {
                /* we found our tracker, lets put it on top of the
                 * hash list -- this rewards active tracker */
                if (dt->hnext) {
                    dt->hnext->hprev = dt->hprev;
                }
                if (dt->hprev) {
                    dt->hprev->hnext = dt->hnext;
                }
                if (dt == hb->tail) {
                    hb->tail = dt->hprev;
                }

                dt->hnext = hb->head;
                dt->hprev = NULL;
                hb->head->hprev = dt;
                hb->head = dt;

                /* found our tracker, lock & return */
                SCMutexLock(&dt->lock);
                (void) DefragTrackerIncrUsecnt(dt);
                DRLOCK_UNLOCK(hb);
                return dt;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&dt->lock);
    (void) DefragTrackerIncrUsecnt(dt);
    DRLOCK_UNLOCK(hb);
    return dt;
}

/** \internal
 *  \brief Get a tracker from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a tracker can be freed. "defragtracker_prune_idx" atomic int makes
 *  sure we don't start at the top each time since that would clear the top of
 *  the hash leading to longer and longer search times under high pressure (observed).
 *
 *  \retval dt tracker or NULL
 */
static DefragTracker *DefragTrackerGetUsedDefragTracker(void)
{
    uint32_t idx = SC_ATOMIC_GET(defragtracker_prune_idx) % defrag_config.hash_size;
    uint32_t cnt = defrag_config.hash_size;

    while (cnt--) {
        if (++idx >= defrag_config.hash_size)
            idx = 0;

        DefragTrackerHashRow *hb = &defragtracker_hash[idx];

        if (DRLOCK_TRYLOCK(hb) != 0)
            continue;

        DefragTracker *dt = hb->tail;
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

        /* remove from the hash */
        if (dt->hprev != NULL)
            dt->hprev->hnext = dt->hnext;
        if (dt->hnext != NULL)
            dt->hnext->hprev = dt->hprev;
        if (hb->head == dt)
            hb->head = dt->hnext;
        if (hb->tail == dt)
            hb->tail = dt->hprev;

        dt->hnext = NULL;
        dt->hprev = NULL;
        DRLOCK_UNLOCK(hb);

        DefragTrackerClearMemory(dt);

        SCMutexUnlock(&dt->lock);

        (void) SC_ATOMIC_ADD(defragtracker_prune_idx, (defrag_config.hash_size - cnt));
        return dt;
    }

    return NULL;
}


