/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * Information about hosts.
 */

#include "suricata-common.h"
#ifdef HOSTBITS_STATS
#include "detect-engine-tag.h"
#include "detect-tag.h"
#include "host-bit.h"
#include "host-storage.h"
#include "util-debug.h"
#include "conf.h"
#endif

#include "host.h"

#include "util-random.h"
#include "util-misc.h"
#include "util-byte.h"
#include "util-validate.h"

#include "host-queue.h"

#include "detect-engine-threshold.h"

#include "util-hash-lookup3.h"

static Host *HostGetUsedHost(void);

/** host hash table */
HostHashRow *host_hash;
/** queue with spare hosts */
static HostQueue host_spare_q;
HostConfig host_config;

SC_ATOMIC_DECLARE(uint64_t,host_memuse);
SC_ATOMIC_DECLARE(uint32_t,host_counter);
SC_ATOMIC_DECLARE(uint32_t,host_prune_idx);

/** size of the host object. Maybe updated in HostInitConfig to include
 *  the storage APIs additions. */
static uint16_t g_host_size = sizeof(Host);

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int HostSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(host_memuse) < size) {
        SC_ATOMIC_SET(host_config.memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \retval memcap value
 */
uint64_t HostGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(host_config.memcap);
    return memcapcopy;
}

/**
 *  \brief Return memuse value
 *
 *  \retval memuse value
 */
uint64_t HostGetMemuse(void)
{
    uint64_t memuse = SC_ATOMIC_GET(host_memuse);
    return memuse;
}

uint32_t HostSpareQueueGetSize(void)
{
    return HostQueueLen(&host_spare_q);
}

void HostMoveToSpare(Host *h)
{
    HostEnqueue(&host_spare_q, h);
    (void) SC_ATOMIC_SUB(host_counter, 1);
}

Host *HostAlloc(void)
{
    if (!(HOST_CHECK_MEMCAP(g_host_size))) {
        return NULL;
    }
    (void) SC_ATOMIC_ADD(host_memuse, g_host_size);

    Host *h = SCMalloc(g_host_size);
    if (unlikely(h == NULL))
        goto error;

    memset(h, 0x00, g_host_size);

    SCMutexInit(&h->m, NULL);
    SC_ATOMIC_INIT(h->use_cnt);
    return h;

error:
    return NULL;
}

void HostFree(Host *h)
{
    if (h != NULL) {
        HostClearMemory(h);
        SCMutexDestroy(&h->m);
        SCFree(h);
        (void) SC_ATOMIC_SUB(host_memuse, g_host_size);
    }
}

static Host *HostNew(Address *a)
{
    Host *h = HostAlloc();
    if (h == NULL)
        goto error;

    /* copy address */
    COPY_ADDRESS(a, &h->a);

    return h;

error:
    return NULL;
}

void HostClearMemory(Host *h)
{
    if (h->iprep != NULL) {
        SRepFreeHostData(h);
    }

    if (HostStorageSize() > 0)
        HostFreeStorage(h);

    BUG_ON(SC_ATOMIC_GET(h->use_cnt) > 0);
}

#define HOST_DEFAULT_HASHSIZE 4096
#define HOST_DEFAULT_MEMCAP 16777216
#define HOST_DEFAULT_PREALLOC 1000

/** \brief initialize the configuration
 *  \warning Not thread safe */
void HostInitConfig(bool quiet)
{
    SCLogDebug("initializing host engine...");
    if (HostStorageSize() > 0) {
        DEBUG_VALIDATE_BUG_ON(sizeof(Host) + HostStorageSize() > UINT16_MAX);
        g_host_size = (uint16_t)(sizeof(Host) + HostStorageSize());
    }

    memset(&host_config,  0, sizeof(host_config));
    //SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(host_counter);
    SC_ATOMIC_INIT(host_memuse);
    SC_ATOMIC_INIT(host_prune_idx);
    SC_ATOMIC_INIT(host_config.memcap);
    HostQueueInit(&host_spare_q);

    /* set defaults */
    host_config.hash_rand   = (uint32_t)RandomGet();
    host_config.hash_size   = HOST_DEFAULT_HASHSIZE;
    host_config.prealloc    = HOST_DEFAULT_PREALLOC;
    SC_ATOMIC_SET(host_config.memcap, HOST_DEFAULT_MEMCAP);

    /* Check if we have memcap and hash_size defined at config */
    const char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("host.memcap", &conf_val)) == 1) {
        uint64_t host_memcap = 0;
        if (ParseSizeStringU64(conf_val, &host_memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing host.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(host_config.memcap, host_memcap);
        }
    }
    if ((ConfGet("host.hash-size", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            host_config.hash_size = configval;
        }
    }

    if ((ConfGet("host.prealloc", &conf_val)) == 1) {
        if (StringParseUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            host_config.prealloc = configval;
        } else {
            WarnInvalidConfEntry("host.prealloc", "%"PRIu32, host_config.prealloc);
        }
    }
    SCLogDebug("Host config from suricata.yaml: memcap: %"PRIu64", hash-size: "
               "%"PRIu32", prealloc: %"PRIu32, SC_ATOMIC_GET(host_config.memcap),
               host_config.hash_size, host_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = host_config.hash_size * sizeof(HostHashRow);
    if (!(HOST_CHECK_MEMCAP(hash_size))) {
        SCLogError(SC_ERR_HOST_INIT, "allocating host hash failed: "
                "max host memcap is smaller than projected hash size. "
                "Memcap: %"PRIu64", Hash table size %"PRIu64". Calculate "
                "total hash size by multiplying \"host.hash-size\" with %"PRIuMAX", "
                "which is the hash bucket size.", SC_ATOMIC_GET(host_config.memcap), hash_size,
                (uintmax_t)sizeof(HostHashRow));
        exit(EXIT_FAILURE);
    }
    host_hash = SCMallocAligned(host_config.hash_size * sizeof(HostHashRow), CLS);
    if (unlikely(host_hash == NULL)) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in HostInitConfig. Exiting...");
    }
    memset(host_hash, 0, host_config.hash_size * sizeof(HostHashRow));

    uint32_t i = 0;
    for (i = 0; i < host_config.hash_size; i++) {
        HRLOCK_INIT(&host_hash[i]);
    }
    (void) SC_ATOMIC_ADD(host_memuse, (host_config.hash_size * sizeof(HostHashRow)));

    if (!quiet) {
        SCLogConfig("allocated %"PRIu64" bytes of memory for the host hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(host_memuse), host_config.hash_size,
                  (uintmax_t)sizeof(HostHashRow));
    }

    /* pre allocate hosts */
    for (i = 0; i < host_config.prealloc; i++) {
        if (!(HOST_CHECK_MEMCAP(g_host_size))) {
            SCLogError(SC_ERR_HOST_INIT, "preallocating hosts failed: "
                    "max host memcap reached. Memcap %"PRIu64", "
                    "Memuse %"PRIu64".", SC_ATOMIC_GET(host_config.memcap),
                    ((uint64_t)SC_ATOMIC_GET(host_memuse) + g_host_size));
            exit(EXIT_FAILURE);
        }

        Host *h = HostAlloc();
        if (h == NULL) {
            SCLogError(SC_ERR_HOST_INIT, "preallocating host failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        HostEnqueue(&host_spare_q,h);
    }

    if (!quiet) {
        SCLogConfig("preallocated %" PRIu32 " hosts of size %" PRIu16 "",
                host_spare_q.len, g_host_size);
        SCLogConfig("host memory usage: %"PRIu64" bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(host_memuse), SC_ATOMIC_GET(host_config.memcap));
    }

    return;
}

/** \brief print some host stats
 *  \warning Not thread safe */
void HostPrintStats (void)
{
#ifdef HOSTBITS_STATS
    SCLogPerf("hostbits added: %" PRIu32 ", removed: %" PRIu32 ", max memory usage: %" PRIu32 "",
        hostbits_added, hostbits_removed, hostbits_memuse_max);
#endif /* HOSTBITS_STATS */
    SCLogPerf("host memory usage: %"PRIu64" bytes, maximum: %"PRIu64,
            SC_ATOMIC_GET(host_memuse), SC_ATOMIC_GET(host_config.memcap));
    return;
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void HostShutdown(void)
{
    Host *h;
    uint32_t u;

    HostPrintStats();

    /* free spare queue */
    while((h = HostDequeue(&host_spare_q))) {
        HostFree(h);
    }

    /* clear and free the hash */
    if (host_hash != NULL) {
        for (u = 0; u < host_config.hash_size; u++) {
            h = host_hash[u].head;
            while (h) {
                Host *n = h->hnext;
                HostFree(h);
                h = n;
            }

            HRLOCK_DESTROY(&host_hash[u]);
        }
        SCFreeAligned(host_hash);
        host_hash = NULL;
    }
    (void) SC_ATOMIC_SUB(host_memuse, host_config.hash_size * sizeof(HostHashRow));
    HostQueueDestroy(&host_spare_q);
    return;
}

/** \brief Cleanup the host engine
 *
 * Cleanup the host engine from tag and threshold.
 *
 */
void HostCleanup(void)
{
    Host *h;
    uint32_t u;

    if (host_hash != NULL) {
        for (u = 0; u < host_config.hash_size; u++) {
            h = host_hash[u].head;
            HostHashRow *hb = &host_hash[u];
            HRLOCK_LOCK(hb);
            while (h) {
                if ((SC_ATOMIC_GET(h->use_cnt) > 0) && (h->iprep != NULL)) {
                    /* iprep is attached to host only clear local storage */
                    HostFreeStorage(h);
                    h = h->hnext;
                } else {
                    Host *n = h->hnext;
                    /* remove from the hash */
                    if (h->hprev != NULL)
                        h->hprev->hnext = h->hnext;
                    if (h->hnext != NULL)
                        h->hnext->hprev = h->hprev;
                    if (hb->head == h)
                        hb->head = h->hnext;
                    if (hb->tail == h)
                        hb->tail = h->hprev;
                    h->hnext = NULL;
                    h->hprev = NULL;
                    HostClearMemory(h);
                    HostMoveToSpare(h);
                    h = n;
                }
            }
            HRLOCK_UNLOCK(hb);
        }
    }

    return;
}

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source address
 */
static inline uint32_t HostGetKey(Address *a)
{
    uint32_t key;

    if (a->family == AF_INET) {
        uint32_t hash = hashword(&a->addr_data32[0], 1, host_config.hash_rand);
        key = hash % host_config.hash_size;
    } else if (a->family == AF_INET6) {
        uint32_t hash = hashword(a->addr_data32, 4, host_config.hash_rand);
        key = hash % host_config.hash_size;
    } else
        key = 0;

    return key;
}

static inline int HostCompare(Host *h, Address *a)
{
    if (h->a.family == a->family) {
        switch (a->family) {
            case AF_INET:
                return (h->a.addr_data32[0] == a->addr_data32[0]);
            case AF_INET6:
                return CMP_ADDR(&h->a, a);
        }
    }
    return 0;
}

/**
 *  \brief Get a new host
 *
 *  Get a new host. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \retval h *LOCKED* host on succes, NULL on error.
 */
static Host *HostGetNew(Address *a)
{
    Host *h = NULL;

    /* get a host from the spare queue */
    h = HostDequeue(&host_spare_q);
    if (h == NULL) {
        /* If we reached the max memcap, we get a used host */
        if (!(HOST_CHECK_MEMCAP(g_host_size))) {
            /* declare state of emergency */
            //if (!(SC_ATOMIC_GET(host_flags) & HOST_EMERGENCY)) {
            //    SC_ATOMIC_OR(host_flags, HOST_EMERGENCY);

                /* under high load, waking up the flow mgr each time leads
                 * to high cpu usage. Flows are not timed out much faster if
                 * we check a 1000 times a second. */
            //    FlowWakeupFlowManagerThread();
            //}

            h = HostGetUsedHost();
            if (h == NULL) {
                return NULL;
            }

            /* freed a host, but it's unlocked */
        } else {
            /* now see if we can alloc a new host */
            h = HostNew(a);
            if (h == NULL) {
                return NULL;
            }

            /* host is initialized but *unlocked* */
        }
    } else {
        /* host has been recycled before it went into the spare queue */

        /* host is initialized (recylced) but *unlocked* */
    }

    (void) SC_ATOMIC_ADD(host_counter, 1);
    SCMutexLock(&h->m);
    return h;
}

static void HostInit(Host *h, Address *a)
{
    COPY_ADDRESS(a, &h->a);
    (void) HostIncrUsecnt(h);
}

void HostRelease(Host *h)
{
    (void) HostDecrUsecnt(h);
    SCMutexUnlock(&h->m);
}

void HostLock(Host *h)
{
    SCMutexLock(&h->m);
}

void HostUnlock(Host *h)
{
    SCMutexUnlock(&h->m);
}


/* HostGetHostFromHash
 *
 * Hash retrieval function for hosts. Looks up the hash bucket containing the
 * host pointer. Then compares the packet with the found host to see if it is
 * the host we need. If it isn't, walk the list until the right host is found.
 *
 * returns a *LOCKED* host or NULL
 */
Host *HostGetHostFromHash (Address *a)
{
    Host *h = NULL;

    /* get the key to our bucket */
    uint32_t key = HostGetKey(a);
    /* get our hash bucket and lock it */
    HostHashRow *hb = &host_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a host */
    if (hb->head == NULL) {
        h = HostGetNew(a);
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* host is locked */
        hb->head = h;
        hb->tail = h;

        /* got one, now lock, initialize and return */
        HostInit(h,a);

        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a host in the bucket. Let's find out if it is our host */
    h = hb->head;

    /* see if this is the host we are looking for */
    if (HostCompare(h, a) == 0) {
        Host *ph = NULL; /* previous host */

        while (h) {
            ph = h;
            h = h->hnext;

            if (h == NULL) {
                h = ph->hnext = HostGetNew(a);
                if (h == NULL) {
                    HRLOCK_UNLOCK(hb);
                    return NULL;
                }
                hb->tail = h;

                /* host is locked */

                h->hprev = ph;

                /* initialize and return */
                HostInit(h,a);

                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (HostCompare(h, a) != 0) {
                /* we found our host, lets put it on top of the
                 * hash list -- this rewards active hosts */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our host, lock & return */
                SCMutexLock(&h->m);
                (void) HostIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) HostIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \brief look up a host in the hash
 *
 *  \param a address to look up
 *
 *  \retval h *LOCKED* host or NULL
 */
Host *HostLookupHostFromHash (Address *a)
{
    Host *h = NULL;

    /* get the key to our bucket */
    uint32_t key = HostGetKey(a);
    /* get our hash bucket and lock it */
    HostHashRow *hb = &host_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a host */
    if (hb->head == NULL) {
        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a host in the bucket. Let's find out if it is our host */
    h = hb->head;

    /* see if this is the host we are looking for */
    if (HostCompare(h, a) == 0) {
        while (h) {
            h = h->hnext;

            if (h == NULL) {
                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (HostCompare(h, a) != 0) {
                /* we found our host, lets put it on top of the
                 * hash list -- this rewards active hosts */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our host, lock & return */
                SCMutexLock(&h->m);
                (void) HostIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) HostIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \internal
 *  \brief Get a host from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a host can be freed. "host_prune_idx" atomic int makes
 *  sure we don't start at the top each time since that would clear the top of
 *  the hash leading to longer and longer search times under high pressure (observed).
 *
 *  \retval h host or NULL
 */
static Host *HostGetUsedHost(void)
{
    uint32_t idx = SC_ATOMIC_GET(host_prune_idx) % host_config.hash_size;
    uint32_t cnt = host_config.hash_size;

    while (cnt--) {
        if (++idx >= host_config.hash_size)
            idx = 0;

        HostHashRow *hb = &host_hash[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        Host *h = hb->tail;
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        if (SCMutexTrylock(&h->m) != 0) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        /** never prune a host that is used by a packets
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(h->use_cnt) > 0) {
            HRLOCK_UNLOCK(hb);
            SCMutexUnlock(&h->m);
            continue;
        }

        /* remove from the hash */
        if (h->hprev != NULL)
            h->hprev->hnext = h->hnext;
        if (h->hnext != NULL)
            h->hnext->hprev = h->hprev;
        if (hb->head == h)
            hb->head = h->hnext;
        if (hb->tail == h)
            hb->tail = h->hprev;

        h->hnext = NULL;
        h->hprev = NULL;
        HRLOCK_UNLOCK(hb);

        HostClearMemory (h);

        SCMutexUnlock(&h->m);

        (void) SC_ATOMIC_ADD(host_prune_idx, (host_config.hash_size - cnt));
        return h;
    }

    return NULL;
}

void HostRegisterUnittests(void)
{
    RegisterHostStorageTests();
}

