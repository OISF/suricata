/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 *
 * Defragmentation module.
 *
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 *
 * References:
 *   - RFC 815
 *   - OpenBSD PF's IP normalizaton (pf_norm.c)
 *
 * \todo pool for frag packet storage
 * \todo policy bsd-right
 * \todo profile hash function
 */

#include <sys/time.h>

#include "queue.h"

#include "eidps.h"
#include "threads.h"
#include "conf.h"
#include "util-hashlist.h"
#include "util-pool.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-fix_checksum.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif

#define MAX(a, b) (a > b ? a : b)

#define DEFAULT_DEFRAG_HASH_SIZE 0xffff

/**
 * Default timeout (in seconds) before a defragmentation tracker will
 * be released.
 */
#define TIMEOUT_DEFAULT 60

/**
 * Maximum allowed timeout, 24 hours.
 */
#define TIMEOUT_MAX 60 * 60 * 24

/**
 * Minimum allowed timeout, 1 second.
 */
#define TIMEOUT_MIN 1

/** Fragment reassembly policies. */
enum defrag_policies {
    POLICY_FIRST = 0,
    POLICY_LAST,
    POLICY_BSD,
    POLICY_BSD_RIGHT,
    POLICY_LINUX,
    POLICY_WINDOWS,
    POLICY_SOLARIS,

    POLICY_DEFAULT = POLICY_BSD,
};

/**
 * A context for an instance of a fragmentation re-assembler, in case
 * we ever need more than one.
 */
typedef struct _DefragContext {
    uint64_t ip4_frags; /**< Number of IPv4 fragments seen. */
    uint64_t ip6_frags; /**< Number of IPv6 fragments seen. */

    HashListTable *frag_table; /**< Hash (list) table of fragment trackers. */
    pthread_mutex_t frag_table_lock;

    Pool *tracker_pool; /**< Pool of trackers. */
    pthread_mutex_t tracker_pool_lock;

    Pool *frag_pool; /**< Pool of fragments. */
    pthread_mutex_t frag_pool_lock;

    time_t timeout; /**< Default timeout. */

    uint8_t default_policy; /**< Default policy. */

} DefragContext;

/**
 * Storage for an individual fragment.
 */
typedef struct _frag {
    DefragContext *dc; /**< The defragmentation context this frag was
                        * allocated under. */

    uint16_t offset; /**< The offset of this fragment, already
                      * multiplied by 8. */

    uint16_t len; /**< The length of this fragment. */

    uint8_t hlen; /**< The length of this fragments IP header. */

    uint8_t more_frags; /**< More frags? */

    uint8_t *pkt; /**< The actual packet. */

    TAILQ_ENTRY(_frag) next; /**< Pointer to next fragment for tailq. */
} Frag;

/**
 * A defragmentation tracker.  Used to track fragments that make up a
 * single packet.
 */
typedef struct _DefragTracker {
    DefragContext *dc; /**< The defragmentation context this tracker
                        * was allocated under. */

    uint8_t policy; /**< Reassembly policy this tracker will use. */

    struct timeval timeout; /**< When this tracker will timeout. */

    uint8_t family; /**< Address family for this tracker, AF_INET or
                     * AF_INET6. */

    uint32_t id; /**< IP ID for this tracker.  32 bits for IPv6, 16
                  * for IPv4. */

    Address src_addr; /**< Source address for this tracker. */
    Address dst_addr; /**< Destination address for this tracker. */

    uint8_t seen_last; /**< Has this tracker seen the last fragment? */

    pthread_mutex_t lock; /**< Mutex for locking list operations on
                           * this tracker. */

    TAILQ_HEAD(frag_tailq, _frag) frags; /**< Head of list of fragments. */
} DefragTracker;

/** A random value used for hash key generation. */
static int defrag_hash_rand;

/** Hash table size, and also the maximum number of trackers that will
 * be allocated. */
static int defrag_hash_size;

/** The global DefragContext so all threads operate from the same
 * context. */
static DefragContext *defrag_context;

/**
 * Utility/debugging function to dump the frags associated with a
 * tracker.  Only enable when unit tests are enabled.
 */
#if 0
#ifdef UNITTESTS
static void
DumpFrags(DefragTracker *tracker)
{
    Frag *frag;

    printf("Dumping frags for packet: ID=%d\n", tracker->id);
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        printf("-> Frag: Offset=%d, Len=%d\n", frag->offset, frag->len);
        PrintRawDataFp(stdout, frag->pkt, frag->len);
    }
}
#endif /* UNITTESTS */
#endif

/**
 * Generate a key for looking of a fragtracker in a hash
 * table. Adapted from the hash function in flow-hash.c.
 *
 * \todo Test performance and distribution.
 */
static uint32_t
DefragHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    DefragTracker *p = (DefragTracker *)data;
    uint32_t key;

    if (p->family == AF_INET) {
        key = (defrag_hash_rand + p->family +
            p->src_addr.addr_data32[0] + p->dst_addr.addr_data32[0]) %
            defrag_hash_size;
    }
    else if (p->family == AF_INET6) {
        key = (defrag_hash_rand + p->family +
            p->src_addr.addr_data32[0] + p->src_addr.addr_data32[1] +
            p->src_addr.addr_data32[2] + p->src_addr.addr_data32[3] +
            p->dst_addr.addr_data32[0] + p->dst_addr.addr_data32[1] +
            p->dst_addr.addr_data32[2] + p->dst_addr.addr_data32[3]) %
            defrag_hash_size;
    }
    else
        key = 0;

    return key;
}

/**
 * \brief Compare 2 DefragTracker nodes in case of hash conflict.
 *
 * \retval 1 if a and b match, otherwise 0.
 */
static char
DefragHashCompare(void *a, uint16_t a_len, void *b, uint16_t b_len)
{
    DefragTracker *dta = (DefragTracker *)a;
    DefragTracker *dtb = (DefragTracker *)b;

    if (dta->family != dtb->family)
        return 0;
    else if (dta->id != dtb->id)
        return 0;
    else if (!CMP_ADDR(&dta->src_addr, &dtb->src_addr))
        return 0;
    else if (!CMP_ADDR(&dta->dst_addr, &dtb->dst_addr))
        return 0;

    /* Match. */
    return 1;
}

/**
 * \brief Called by the hash table when a tracker is removed from the
 *     hash table.
 *
 * We don't actually do anything here.  The tracker will be reset and
 * put back into a memory pool.
 */
static void
DefragHashFree(void *data)
{
}

/**
 * \brief Reset a frag for reuse in a pool.
 */
static void
DefragFragReset(Frag *frag)
{
    DefragContext *dc = frag->dc;

    if (frag->pkt != NULL)
        free(frag->pkt);
    memset(frag, 0, sizeof(*frag));
    frag->dc = dc;
}

/**
 * \brief Allocate a new frag for use in a pool.
 */
static void *
DefragFragNew(void *arg)
{
    DefragContext *dc = arg;
    Frag *frag;

    frag = calloc(1, sizeof(*frag));
    frag->dc = dc;

    return (void *)frag;
}

/**
 * \brief Free a frag when released from a pool.
 */
static void
DefragFragFree(void *arg)
{
    Frag *frag = arg;
    free(frag);
}

/**
 * \brief Free all frags associated with a tracker.
 */
static void
DefragTrackerFreeFrags(DefragTracker *tracker)
{
    Frag *frag;

    /* Lock the frag pool as we'll be return items to it. */
    mutex_lock(&tracker->dc->frag_pool_lock);

    while ((frag = TAILQ_FIRST(&tracker->frags)) != NULL) {
        TAILQ_REMOVE(&tracker->frags, frag, next);

        /* Don't free the frag, just give it back to its pool. */
        DefragFragReset(frag);
        PoolReturn(frag->dc->frag_pool, frag);
    }

    mutex_unlock(&tracker->dc->frag_pool_lock);
}

/**
 * \brief Reset a tracker for reuse.
 */
static void
DefragTrackerReset(DefragTracker *tracker)
{
    DefragContext *saved_dc = tracker->dc;
    pthread_mutex_t saved_lock = tracker->lock;

    DefragTrackerFreeFrags(tracker);
    memset(tracker, 0, sizeof(*tracker));
    tracker->dc = saved_dc;
    tracker->lock = saved_lock;
    TAILQ_INIT(&tracker->frags);
}

/**
 * \brief Allocates a new defragmentation tracker for use in the pool
 *     for trackers.
 *
 * \arg Pointer to DefragContext this new tracker will be associated
 *     with.
 *
 * \retval A new DefragTracker if successfull, NULL on failure.
 */
static void *
DefragTrackerNew(void *arg)
{
    DefragContext *dc = arg;
    DefragTracker *tracker;

    tracker = calloc(1, sizeof(*tracker));
    if (tracker == NULL)
        return NULL;
    if (pthread_mutex_init(&tracker->lock, NULL) != 0)
        return NULL;
    tracker->dc = dc;
    TAILQ_INIT(&tracker->frags);

    return (void *)tracker;
}

/**
 * \brief Free a defragmentation tracker that is being removed from
 *     the pool.
 */
static void
DefragTrackerFree(void *arg)
{
    DefragTracker *tracker = arg;

    pthread_mutex_destroy(&tracker->lock);
    DefragTrackerFreeFrags(tracker);
    free(tracker);
}

/**
 * \brief Create a new DefragContext.
 *
 * \retval On success a return an initialized DefragContext, otherwise
 *     NULL will be returned.
 */
static DefragContext *
DefragContextNew(void)
{
    DefragContext *dc;

    dc = calloc(1, sizeof(*dc));
    if (dc == NULL)
        return NULL;

    /* Initialize the hash table. */
    dc->frag_table = HashListTableInit(DEFAULT_DEFRAG_HASH_SIZE, DefragHashFunc,
        DefragHashCompare, DefragHashFree);
    if (dc == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize hash table.");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_init(&dc->frag_table_lock, NULL) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize hash table mutex.");
        exit(EXIT_FAILURE);
    }

    /* Initialize the pool of trackers. */
    intmax_t tracker_pool_size;
    if (!ConfGetInt("defrag.trackers", &tracker_pool_size)) {
        tracker_pool_size = DEFAULT_DEFRAG_HASH_SIZE;
    }
    dc->tracker_pool = PoolInit(tracker_pool_size, tracker_pool_size,
        DefragTrackerNew, dc, DefragTrackerFree);
    if (dc->tracker_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize tracker pool.");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_init(&dc->tracker_pool_lock, NULL) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize tracker pool mutex.");
        exit(EXIT_FAILURE);
    }

    /* Initialize the pool of frags. */
    int frag_pool_size = 0xffff;
    int frag_pool_prealloc = frag_pool_size / 4;
    dc->frag_pool = PoolInit(frag_pool_size, frag_pool_prealloc,
        DefragFragNew, dc, DefragFragFree);
    if (dc->frag_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize fragment pool.");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_init(&dc->frag_pool_lock, NULL) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize frag pool mutex.");
        exit(EXIT_FAILURE);
    }

    /* Set the default timeout. */
    intmax_t timeout;
    if (!ConfGetInt("defrag.timeout", &timeout)) {
        dc->timeout = TIMEOUT_DEFAULT;
    }
    else {
        if (timeout < TIMEOUT_MIN) {
            SCLogError(SC_INVALID_ARGUMENT,
                "defrag: Timeout less than minimum allowed value.");
            exit(EXIT_FAILURE);
        }
        else if (timeout > TIMEOUT_MAX) {
            SCLogError(SC_INVALID_ARGUMENT,
                "defrag: Tiemout greater than maximum allowed value.");
            exit(EXIT_FAILURE);
        }
        dc->timeout = timeout;
    }

    SCLogDebug("Defrag Initialized:");
    SCLogDebug("\tTimeout: %"PRIuMAX, (uintmax_t)dc->timeout);
    SCLogDebug("\tMaximum defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tPreallocated defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tMaximum fragments: %d", frag_pool_size);
    SCLogDebug("\tPreallocated fragments: %d", frag_pool_prealloc);

    return dc;
}

void DefragContextDestroy(DefragContext *dc) {
    if (dc == NULL)
        return;

    HashListTableFree(dc->frag_table);
    PoolFree(dc->frag_pool);
    PoolFree(dc->tracker_pool);
    free(dc);
}

/**
 * Insert a new IPv4 fragment into a tracker.
 *
 * \todo Allocate packet buffers from a pool.
 */
static void
Defrag4InsertFrag(DefragContext *dc, DefragTracker *tracker, Packet *p)
{
    Frag *frag, *prev, *new;
    uint16_t offset = IPV4_GET_IPOFFSET(p) << 3;
    uint16_t len = IPV4_GET_IPLEN(p);
    uint8_t hlen = IPV4_GET_HLEN(p);
    uint8_t more_frags = IPV4_GET_MF(p);
    int end = offset + len - hlen;

    int ltrim = 0; /* Number of bytes to trim from front of packet. */

    int remove = 0; /* Will be set if we need to remove a fragment. */

    int before = 0; /* Set if fragment should be inserted before
                     * instead of after. */

    /* Lock this tracker as we'll be doing list operations on it. */
    mutex_lock(&tracker->lock);

    /* Update timeout. */
    tracker->timeout = p->ts;
    tracker->timeout.tv_sec += dc->timeout;

    prev = NULL;
    if (!TAILQ_EMPTY(&tracker->frags)) {

        /* First compare against the last frag.  In the normal case
         * this new fragment should fall after the last frag. */
        frag = TAILQ_LAST(&tracker->frags, frag_tailq);
        if (offset >= frag->offset + frag->len - frag->hlen) {
            prev = frag;
            goto insert;
        }

        /* Find where in the list to add this fragment. */
        TAILQ_FOREACH(frag, &tracker->frags, next) {
            int prev_end = frag->offset + frag->len - frag->hlen;
            prev = frag;
            ltrim = 0;

            switch (tracker->policy) {
            case POLICY_LAST:
                if (offset <= frag->offset) {
                    goto insert;
                }
                break;
            case POLICY_FIRST:
                if ((offset >= frag->offset) && (end <= prev_end)) {
                    /* Packet is wholly contained within a previous
                     * packet. Drop. */
                    goto done;
                }
                else if (offset < frag->offset) {
                    before = 1;
                    goto insert;
                }
                else if (offset < prev_end) {
                    ltrim = prev_end - offset;
                    goto insert;
                }
            case POLICY_SOLARIS:
                if ((offset < frag->offset) && (end >= prev_end)) {
                    remove = 1;
                    goto insert;
                }
                /* Fall-through. */
            case POLICY_WINDOWS:
                if (offset < frag->offset) {
                    if (end > prev_end) {
                        /* Starts before previous frag, and ends after
                         * previous drop.  Drop the previous
                         * fragment. */
                        remove = 1;
                    }
                    else {
                        /* Fill hole before previous fragment, trim
                         * this frags length. */
                        len = hlen + (frag->offset - offset);
                    }
                    goto insert;
                }
                else if ((offset >= frag->offset) && (end <= prev_end)) {
                    /* New frag is completey contained within a
                     * previous frag, drop. */
                    goto done;
                }
                else if ((offset == frag->offset) && (end > prev_end)) {
                    /* This fragment is filling a hole afte the
                     * previous frag.  Trim the front . */
                    ltrim = end - prev_end;
                    goto insert;
                }
                /* Fall-through. */
            case POLICY_LINUX: {
                if (offset == frag->offset) {
                    if (end >= prev_end) {
                        /* Fragment starts at same offset as previous
                         * fragment and extends past the end of the
                         * previous fragment.  Replace it
                         * completely. */
                        remove = 1;
                        goto insert;
                    }
                    else if (end < prev_end) {
                        /* Fragment starts at the same offset as
                         * previous fragment but doesn't overlap it
                         * completely, insert it after the previous
                         * fragment and it will take precedence on
                         * re-assembly. */
                        goto insert;
                    }
                }
                /* Fall-through. */
            }
            case POLICY_BSD:
            default:
                if (offset < prev_end) {
                    /* Fragment overlaps with previous fragment,
                     * process. */
                    if (offset >= frag->offset) {
                        if (end <= prev_end) {
                            /* New fragment falls completely within a
                             * previous fragment, new fragment will be
                             * dropped. */
                            goto done;
                        }
                        else {
                            /* New fragment extends past the end of
                             * the previous fragment.  Trim off the
                             * front of the new fragment that overlaps
                             * with the previous fragment. */
                            ltrim = prev_end - offset;
                        }
                    }
                    else {
                        /* New fragment starts before the previous
                         * fragment and extends to the end of past the
                         * end of the previous fragment.  Remove the
                         * previous fragment. */
                        remove = 1;
                    }
                    goto insert;
                }
                break;
            }
        }
    }

insert:

    if (len - hlen - ltrim == 0) {
        /* No data left. */
        goto done;
    }

    /* Allocate frag and insert. */
    mutex_lock(&dc->frag_pool_lock);
    new = PoolGet(dc->frag_pool);
    mutex_unlock(&dc->frag_pool_lock);
    if (new == NULL)
        goto done;
    new->pkt = malloc(len);
    if (new->pkt == NULL) {
        mutex_lock(&dc->frag_pool_lock);
        PoolReturn(dc->frag_pool, new);
        mutex_unlock(&dc->frag_pool_lock);
        goto done;
    }
    BUG_ON(ltrim > len);
    memcpy(new->pkt, (uint8_t *)p->ip4h + ltrim, len - ltrim);
    new->offset = offset + ltrim;
    new->len = len - ltrim;
    new->hlen = hlen;
    new->more_frags = more_frags;

    if (prev) {
        if (before) {
            TAILQ_INSERT_BEFORE(prev, new, next);
        }
        else {
            TAILQ_INSERT_AFTER(&tracker->frags, prev, new, next);
        }
    }
    else
        TAILQ_INSERT_HEAD(&tracker->frags, new, next);

    if (remove) {
        TAILQ_REMOVE(&tracker->frags, prev, next);
        DefragFragReset(prev);
        mutex_lock(&dc->frag_pool_lock);
        PoolReturn(dc->frag_pool, prev);
        mutex_unlock(&dc->frag_pool_lock);
    }

done:
    mutex_unlock(&tracker->lock);
}

/**
 * Attempt to re-assemble a packet.
 *
 * \param tracker The defragmentation tracker to reassemble from.
 */
static Packet *
Defrag4Reassemble(ThreadVars *tv, DefragContext *dc, DefragTracker *tracker,
    Packet *p)
{
    Frag *frag, *prev = NULL;
    Packet *rp = NULL;
    int offset = 0;
    int hlen = 0;
    int len = 0;

    /* Lock the tracker. */
    mutex_lock(&tracker->lock);

    /* Should not be here unless we have seen the last fragment. */
    if (!tracker->seen_last)
        return NULL;

    /* Check that we have all the data. */
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag == TAILQ_FIRST(&tracker->frags)) {
            /* First frag should have an offset of 0. */
            if (frag->offset != 0) {
                goto done;
            }
            len = frag->len - frag->hlen;
            hlen = frag->hlen;
        }
        else {
            if ((frag->offset - frag->hlen) <= len) {
                len = MAX(len, frag->offset + frag->len - frag->hlen);
            }
            else {
                goto done;
            }
        }
    }

    /* Length (ip_len) of re-assembled packet.  The length of the IP
     * header was added when we hit the first fragment above. */
    len += hlen;

    if (tv == NULL) {
        /* Unit test. */
        rp = SetupPkt();
    }
    else {
        /* Not really a tunnel packet, but more of a pseudo packet.
         * But for the most part we should get the same result. */
        rp = TunnelPktSetup(tv, NULL, p, (uint8_t *)p->ip4h, IPV4_GET_IPLEN(p),
            IPV4_GET_IPPROTO(p));
    }

    if (rp == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for fragmentation re-assembly, dumping fragments.");
        mutex_lock(&dc->frag_table_lock);
        HashListTableRemove(dc->frag_table, tracker, sizeof(tracker));
        mutex_unlock(&dc->frag_table_lock);
        DefragTrackerReset(tracker);
        mutex_lock(&dc->tracker_pool_lock);
        PoolReturn(dc->tracker_pool, tracker);
        mutex_unlock(&dc->tracker_pool_lock);
        goto done;
    }

    offset = 0;
    prev = NULL;

    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag->offset == 0) {
            /* This is the first packet.  We use this packets IP
             * header. */
            memcpy(rp->pkt, frag->pkt, frag->len);
            hlen = frag->hlen;
            offset = frag->len - frag->hlen;
        }
        else {
            /* Subsequent packets, copy them in minus their IP header. */

            int diff = 0;
            switch (tracker->policy) {
            case POLICY_LAST:
            case POLICY_FIRST:
            case POLICY_WINDOWS:
            case POLICY_SOLARIS:
                memcpy(rp->pkt + hlen + frag->offset,
                    frag->pkt + frag->hlen,
                    frag->len - frag->hlen);
                break;
            case POLICY_LINUX:
                if (frag->offset == prev->offset) {
                    memcpy(rp->pkt + hlen + frag->offset,
                        frag->pkt + frag->hlen,
                        frag->len - frag->hlen);
                    break;
                }
            case POLICY_BSD:
            default:
                if (frag->offset < offset)
                    diff = offset - frag->offset;
                memcpy(rp->pkt + hlen + frag->offset + diff,
                    frag->pkt + frag->hlen + diff,
                    frag->len - frag->hlen - diff);
                offset = frag->offset + frag->len - frag->hlen;
                break;
            }
        }
        prev = frag;
    }
    rp->pktlen = hlen + offset;
    rp->ip4h = (IPV4Hdr *)rp->pkt;

    /* Checksum fixup. */
    int old = rp->ip4h->ip_len + rp->ip4h->ip_off;
    rp->ip4h->ip_len = htons(offset + hlen);
    rp->ip4h->ip_off = 0;
    rp->ip4h->ip_csum = FixChecksum(rp->ip4h->ip_csum,
        old, rp->ip4h->ip_len + rp->ip4h->ip_off);

    /* Remove the frag tracker. */
    HashListTableRemove(dc->frag_table, tracker, sizeof(tracker));
    DefragTrackerReset(tracker);
    mutex_lock(&dc->tracker_pool_lock);
    PoolReturn(dc->tracker_pool, tracker);
    mutex_unlock(&dc->tracker_pool_lock);

done:
    mutex_unlock(&tracker->lock);
    return rp;
}

/**
 * \brief Timeout a tracker.
 *
 * Called when we fail to get a tracker from the pool.  The first
 * tracker that has expired will be released back to the pool then the
 * function will exit.
 *
 * Intended to be called with the tracker pool already locked.
 *
 * \param dc Current DefragContext.
 * \param p Packet that triggered this timeout run, used for timestamp.
 */
static void
DefragTimeoutTracker(DefragContext *dc, Packet *p)
{
    struct timeval tv = p->ts;

    HashListTableBucket *next = HashListTableGetListHead(dc->frag_table);
    DefragTracker *tracker;
    while (next != NULL) {
        tracker = HashListTableGetListData(next);

        if (timercmp(&tracker->timeout, &tv, <)) {
            /* Tracker has timeout out. */
            HashListTableRemove(dc->frag_table, tracker, sizeof(tracker));
            DefragTrackerReset(tracker);
            PoolReturn(dc->tracker_pool, tracker);
            return;
        }

        next = HashListTableGetListNext(next);
    }
}

/**
 * \brief Entry point for IPv4 fragments.
 *
 * \param tv ThreadVars for the calling decoder.
 * \param dc A DefragContext to use, may be NULL for the default.
 * \param p The packet fragment.
 *
 * \retval A new Packet resembling the re-assembled packet if the most
 *     recent fragment allowed the packet to be re-assembled, otherwise
 *     NULL is returned.
 */
Packet *
Defrag4(ThreadVars *tv, DefragContext *dc, Packet *p)
{
    uint16_t frag_offset;
    int more_frags;
    DefragTracker *tracker, lookup;

    /* If no DefragContext was passed in, use the global one.  Passing
     * one in is primarily useful for unit tests. */
    if (dc == NULL)
        dc = defrag_context;

    more_frags = IPV4_GET_MF(p);
    frag_offset = IPV4_GET_IPOFFSET(p);

    if (frag_offset == 0 && more_frags == 0) {
        return NULL;
    }

    /* Create a lookup key. */
    lookup.family = AF_INET;
    lookup.id = IPV4_GET_IPID(p);
    lookup.src_addr = p->src;
    lookup.dst_addr = p->dst;
    mutex_lock(&dc->frag_table_lock);
    tracker = HashListTableLookup(dc->frag_table, &lookup, sizeof(lookup));
    mutex_unlock(&dc->frag_table_lock);
    if (tracker == NULL) {
        mutex_lock(&dc->tracker_pool_lock);
        tracker = PoolGet(dc->tracker_pool);
        if (tracker == NULL) {
            /* Timeout trackers and try again. */
            DefragTimeoutTracker(dc, p);
            tracker = PoolGet(dc->tracker_pool);
        }
        mutex_unlock(&dc->tracker_pool_lock);
        if (tracker == NULL) {
            /* Report memory error - actually a pool allocation error. */
            SCLogError(SC_ERR_MEM_ALLOC, "Defrag: Failed to allocate tracker.");
            return NULL;
        }
        DefragTrackerReset(tracker);
        tracker->family = lookup.family;
        tracker->id = lookup.id;
        tracker->src_addr = lookup.src_addr;
        tracker->dst_addr = lookup.dst_addr;

        /* XXX Do policy lookup. */
        tracker->policy = dc->default_policy;

        mutex_lock(&dc->frag_table_lock);
        if (HashListTableAdd(dc->frag_table, tracker, sizeof(*tracker)) != 0) {
            /* Failed to add new tracker. */
            mutex_unlock(&dc->frag_table_lock);
            SCLogError(SC_ERR_MEM_ALLOC,
                "Defrag: Failed to add new tracker to hash table.");
            return NULL;
        }
        mutex_unlock(&dc->frag_table_lock);
    }

    if (!more_frags) {
        tracker->seen_last = 1;
    }
    Defrag4InsertFrag(dc, tracker, p);
    if (tracker->seen_last) {
        Packet *rp = Defrag4Reassemble(tv, dc, tracker, p);
        return rp;
    }

    return NULL;
}

/**
 * \brief Entry point for IPv4 fragments.
 *
 * \param tv ThreadVars for the calling decoder.
 * \param dc A DefragContext to use, may be NULL for the default.
 * \param p The packet fragment.
 *
 * \retval A new Packet resembling the re-assembled packet if the most
 *     recent fragment allowed the packet to be re-assembled, otherwise
 *     NULL is returned.
 */
Packet *
Defrag6(DefragContext *dc, Packet *p)
{
    /* If no DefragContext was passed in, use the global one.  Passing
     * one in is primarily useful for unit tests. */
    if (dc == NULL)
        dc = defrag_context;

    return NULL;
}

void
DefragInit(void)
{
    /* Initialize random value for hashing and hash table size. */
    defrag_hash_rand = rand();
    defrag_hash_size = DEFAULT_DEFRAG_HASH_SIZE;

    /* Allocate the DefragContext. */
    defrag_context = DefragContextNew();
    if (defrag_context == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate memory for the Defrag module.");
        exit(EXIT_FAILURE);
    }
}

void DefragDestroy(void) {
    DefragContextDestroy(defrag_context);
    defrag_context = NULL;
}

#ifdef UNITTESTS
#define IP_MF 0x2000

/**
 * Allocate a test packet.  Nothing to fancy, just a simple IP packet
 * with some payload of no particular protocol.
 */
static Packet *
BuildTestPacket(uint16_t id, uint16_t off, int mf, const char content,
    int content_len)
{
    Packet *p = NULL;
    int hlen = 20;
    int ttl = 64;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
        return NULL;
    gettimeofday(&p->ts, NULL);
    p->ip4h = (IPV4Hdr *)p->pkt;
    p->ip4h->ip_verhl = 4 << 4;
    p->ip4h->ip_verhl |= hlen >> 2;
    p->ip4h->ip_len = htons(hlen + content_len);
    p->ip4h->ip_id = htons(id);
    p->ip4h->ip_off = htons(off);
    if (mf)
        p->ip4h->ip_off = htons(IP_MF | off);
    else
        p->ip4h->ip_off = htons(off);
    p->ip4h->ip_ttl = ttl;
    p->ip4h->ip_proto = IPPROTO_ICMP;

    p->ip4h->ip_src.s_addr = 0x01010101; /* 1.1.1.1 */
    p->ip4h->ip_dst.s_addr = 0x02020202; /* 2.2.2.2 */
    SET_IPV4_SRC_ADDR(p, &p->src);
    SET_IPV4_DST_ADDR(p, &p->dst);
    memset(p->pkt + hlen, content, content_len);
    p->pktlen = hlen + content_len;

    p->ip4h->ip_csum = IPV4CalculateChecksum((uint16_t *)p->pkt, hlen);

    /* Self test. */
    IPV4_CACHE_INIT(p);
    if (IPV4_GET_VER(p) != 4)
        goto error;
    if (IPV4_GET_HLEN(p) != hlen)
        goto error;
    if (IPV4_GET_IPLEN(p) != hlen + content_len)
        goto error;
    if (IPV4_GET_IPID(p) != id)
        goto error;
    if (IPV4_GET_IPOFFSET(p) != off)
        goto error;
    if (IPV4_GET_MF(p) != mf)
        goto error;
    if (IPV4_GET_IPTTL(p) != ttl)
        goto error;
    if (IPV4_GET_IPPROTO(p) != IPPROTO_ICMP)
        goto error;

    return p;
error:
    if (p != NULL)
        free(p);
    return NULL;
}

/**
 * Test the simplest possible re-assembly scenario.  All packet in
 * order and no overlaps.
 */
static int
DefragInOrderSimpleTest(void)
{
    DefragContext *dc = NULL;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Packet *reassembled = NULL;
    int id = 12;
    int i;
    int ret = 0;

    DefragInit();

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;

    p1 = BuildTestPacket(id, 0, 1, 'A', 8);
    if (p1 == NULL)
        goto end;
    p2 = BuildTestPacket(id, 1, 1, 'B', 8);
    if (p2 == NULL)
        goto end;
    p3 = BuildTestPacket(id, 2, 0, 'C', 3);
    if (p3 == NULL)
        goto end;

    if (Defrag4(NULL, dc, p1) != NULL)
        goto end;
    if (Defrag4(NULL, dc, p2) != NULL)
        goto end;
    reassembled = Defrag4(NULL, dc, p3);
    if (reassembled == NULL)
        goto end;

    /* 20 bytes in we should find 8 bytes of A. */
    for (i = 20; i < 20 + 8; i++) {
        if (reassembled->pkt[i] != 'A')
            goto end;
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 28; i < 28 + 8; i++) {
        if (reassembled->pkt[i] != 'B')
            goto end;
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 36; i < 36 + 3; i++) {
        if (reassembled->pkt[i] != 'C')
            goto end;
    }

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p1 != NULL)
        free(p1);
    if (p2 != NULL)
        free(p2);
    if (p3 != NULL)
        free(p3);
    if (reassembled != NULL)
        free(reassembled);

    DefragDestroy();
    return ret;
}

static int
DefragDoSturgesNovakTest(int policy, u_char *expected, size_t expected_len)
{
    int i;
    int ret = 0;
    DefragContext *dc = NULL;

    DefragInit();

    /*
     * Build the packets.
     */

    int id = 1;
    Packet *packets[17];
    memset(packets, 0x00, sizeof(packets));

    /*
     * Original fragments.
     */

    /* A*24 at 0. */
    packets[0] = BuildTestPacket(id, 0, 1, 'A', 24);

    /* B*15 at 32. */
    packets[1] = BuildTestPacket(id, 32 >> 3, 1, 'B', 16);

    /* C*24 at 48. */
    packets[2] = BuildTestPacket(id, 48 >> 3, 1, 'C', 24);

    /* D*8 at 80. */
    packets[3] = BuildTestPacket(id, 80 >> 3, 1, 'D', 8);

    /* E*16 at 104. */
    packets[4] = BuildTestPacket(id, 104 >> 3, 1, 'E', 16);

    /* F*24 at 120. */
    packets[5] = BuildTestPacket(id, 120 >> 3, 1, 'F', 24);

    /* G*16 at 144. */
    packets[6] = BuildTestPacket(id, 144 >> 3, 1, 'G', 16);

    /* H*16 at 160. */
    packets[7] = BuildTestPacket(id, 160 >> 3, 1, 'H', 16);

    /* I*8 at 176. */
    packets[8] = BuildTestPacket(id, 176 >> 3, 1, 'I', 8);

    /*
     * Overlapping subsequent fragments.
     */

    /* J*32 at 8. */
    packets[9] = BuildTestPacket(id, 8 >> 3, 1, 'J', 32);

    /* K*24 at 48. */
    packets[10] = BuildTestPacket(id, 48 >> 3, 1, 'K', 24);

    /* L*24 at 72. */
    packets[11] = BuildTestPacket(id, 72 >> 3, 1, 'L', 24);

    /* M*24 at 96. */
    packets[12] = BuildTestPacket(id, 96 >> 3, 1, 'M', 24);

    /* N*8 at 128. */
    packets[13] = BuildTestPacket(id, 128 >> 3, 1, 'N', 8);

    /* O*8 at 152. */
    packets[14] = BuildTestPacket(id, 152 >> 3, 1, 'O', 8);

    /* P*8 at 160. */
    packets[15] = BuildTestPacket(id, 160 >> 3, 1, 'P', 8);

    /* Q*16 at 176. */
    packets[16] = BuildTestPacket(id, 176 >> 3, 0, 'Q', 16);

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;
    dc->default_policy = policy;

    /* Send all but the last. */
    for (i = 0; i < 16; i++) {
        Packet *tp = Defrag4(NULL, dc, packets[i]);
        if (tp != NULL) {
            free(tp);
            goto end;
        }
    }

    /* And now the last one. */
    Packet *reassembled = Defrag4(NULL, dc, packets[16]);
    if (reassembled == NULL)
        goto end;
    if (memcmp(reassembled->pkt + 20, expected, expected_len) != 0)
        goto end;
    free(reassembled);

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    for (i = 0; i < 17; i++) {
        free(packets[i]);
    }
    DefragDestroy();
    return ret;
}

static int
DefragSturgesNovakBsdTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "JJJJJJJJ"
        "JJJJJJJJ"
        "BBBBBBBB"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "LLLLLLLL"
        "LLLLLLLL"
        "LLLLLLLL"
        "MMMMMMMM"
        "MMMMMMMM"
        "MMMMMMMM"
        "FFFFFFFF"
        "FFFFFFFF"
        "FFFFFFFF"
        "GGGGGGGG"
        "GGGGGGGG"
        "HHHHHHHH"
        "HHHHHHHH"
        "IIIIIIII"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_BSD, expected, sizeof(expected));
}

static int
DefragSturgesNovakLinuxTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "JJJJJJJJ"
        "JJJJJJJJ"
        "BBBBBBBB"
        "KKKKKKKK"
        "KKKKKKKK"
        "KKKKKKKK"
        "LLLLLLLL"
        "LLLLLLLL"
        "LLLLLLLL"
        "MMMMMMMM"
        "MMMMMMMM"
        "MMMMMMMM"
        "FFFFFFFF"
        "FFFFFFFF"
        "FFFFFFFF"
        "GGGGGGGG"
        "GGGGGGGG"
        "PPPPPPPP"
        "HHHHHHHH"
        "QQQQQQQQ"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_LINUX, expected, sizeof(expected));
}

static int
DefragSturgesNovakWindowsTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "JJJJJJJJ"
        "BBBBBBBB"
        "BBBBBBBB"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "LLLLLLLL"
        "LLLLLLLL"
        "LLLLLLLL"
        "MMMMMMMM"
        "EEEEEEEE"
        "EEEEEEEE"
        "FFFFFFFF"
        "FFFFFFFF"
        "FFFFFFFF"
        "GGGGGGGG"
        "GGGGGGGG"
        "HHHHHHHH"
        "HHHHHHHH"
        "IIIIIIII"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_WINDOWS, expected, sizeof(expected));
}

static int
DefragSturgesNovakSolarisTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "JJJJJJJJ"
        "BBBBBBBB"
        "BBBBBBBB"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "LLLLLLLL"
        "LLLLLLLL"
        "LLLLLLLL"
        "MMMMMMMM"
        "MMMMMMMM"
        "MMMMMMMM"
        "FFFFFFFF"
        "FFFFFFFF"
        "FFFFFFFF"
        "GGGGGGGG"
        "GGGGGGGG"
        "HHHHHHHH"
        "HHHHHHHH"
        "IIIIIIII"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_SOLARIS, expected, sizeof(expected));
}

static int
DefragSturgesNovakFirstTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "JJJJJJJJ"
        "BBBBBBBB"
        "BBBBBBBB"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "LLLLLLLL"
        "DDDDDDDD"
        "LLLLLLLL"
        "MMMMMMMM"
        "EEEEEEEE"
        "EEEEEEEE"
        "FFFFFFFF"
        "FFFFFFFF"
        "FFFFFFFF"
        "GGGGGGGG"
        "GGGGGGGG"
        "HHHHHHHH"
        "HHHHHHHH"
        "IIIIIIII"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_FIRST, expected, sizeof(expected));
}

static int
DefragSturgesNovakLastTest(void)
{
    /* Expected data. */
    u_char expected[] = {
        "AAAAAAAA"
        "JJJJJJJJ"
        "JJJJJJJJ"
        "JJJJJJJJ"
        "JJJJJJJJ"
        "BBBBBBBB"
        "KKKKKKKK"
        "KKKKKKKK"
        "KKKKKKKK"
        "LLLLLLLL"
        "LLLLLLLL"
        "LLLLLLLL"
        "MMMMMMMM"
        "MMMMMMMM"
        "MMMMMMMM"
        "FFFFFFFF"
        "NNNNNNNN"
        "FFFFFFFF"
        "GGGGGGGG"
        "OOOOOOOO"
        "PPPPPPPP"
        "HHHHHHHH"
        "QQQQQQQQ"
        "QQQQQQQQ"
    };

    return DefragDoSturgesNovakTest(POLICY_LAST, expected, sizeof(expected));
}

static int
DefragTimeoutTest(void)
{
    int i;
    int ret = 0;
    DefragContext *dc = NULL;

    DefragInit();

    /* Setup a small numberr of trackers. */
    ConfSet("defrag.trackers", "16", 1);

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;

    /* Load in 16 packets. */
    for (i = 0; i < 16; i++) {
        Packet *p = BuildTestPacket(i, 0, 1, 'A' + i, 16);
        if (p == NULL)
            goto end;

        Packet *tp = Defrag4(NULL, dc, p);

        free(p);

        if (tp != NULL) {
            free(tp);
            goto end;
        }
    }

    /* Build a new packet but push the timestamp out by our timeout.
     * This should force our previous fragments to be timed out. */
    Packet *p = BuildTestPacket(99, 0, 1, 'A' + i, 16);
    if (p == NULL)
        goto end;

    p->ts.tv_sec += dc->timeout;
    Packet *tp = Defrag4(NULL, dc, p);

    free(p);

    if (tp != NULL) {
        free(tp);
        goto end;
    }

    /* Iterate our HashList and look for the trackerr with id 99. */
    int found = 0;
    HashListTableBucket *next = HashListTableGetListHead(dc->frag_table);
    if (next == NULL)
        goto end;
    for (;;) {
        if (next == NULL)
            break;
        DefragTracker *tracker = HashListTableGetListData(next);
        if (tracker->id == 99) {
            found = 1;
            break;
        }

        next = HashListTableGetListNext(next);
    }
    if (found == 0)
        goto end;

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    DefragDestroy();
    return ret;
}

#endif /* UNITTESTS */

void
DefragRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DefragInOrderSimpleTest",
        DefragInOrderSimpleTest, 1);
    UtRegisterTest("DefragSturgesNovakBsdTest",
        DefragSturgesNovakBsdTest, 1);
    UtRegisterTest("DefragSturgesNovakLinuxTest",
        DefragSturgesNovakLinuxTest, 1);
    UtRegisterTest("DefragSturgesNovakWindowsTest",
        DefragSturgesNovakWindowsTest, 1);
    UtRegisterTest("DefragSturgesNovakSolarisTest",
        DefragSturgesNovakSolarisTest, 1);
    UtRegisterTest("DefragSturgesNovakFirstTest",
        DefragSturgesNovakFirstTest, 1);
    UtRegisterTest("DefragSturgesNovakLastTest",
        DefragSturgesNovakLastTest, 1);
    UtRegisterTest("DefragTimeoutTest",
        DefragTimeoutTest, 1);
#endif /* UNITTESTS */
}

