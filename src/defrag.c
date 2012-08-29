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
 * \file
 *
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 *
 * Defragmentation module.
 * References:
 *   - RFC 815
 *   - OpenBSD PF's IP normalizaton (pf_norm.c)
 *
 * \todo pool for frag packet storage
 * \todo policy bsd-right
 * \todo profile hash function
 * \todo log anomalies
 */

#include "suricata-common.h"

#include "queue.h"

#include "suricata.h"
#include "threads.h"
#include "conf.h"
#include "decode-ipv6.h"
#include "util-hashlist.h"
#include "util-pool.h"
#include "util-time.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-fix_checksum.h"
#include "util-random.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "util-host-os-info.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif

#define DEFAULT_DEFRAG_HASH_SIZE 0xffff
#define DEFAULT_DEFRAG_POOL_SIZE 0xffff

/**
 * Default timeout (in seconds) before a defragmentation tracker will
 * be released.
 */
#define TIMEOUT_DEFAULT 60

/**
 * Maximum allowed timeout, 24 hours.
 */
#define TIMEOUT_MAX (60 * 60 * 24)

/**
 * Minimum allowed timeout, 1 second.
 */
#define TIMEOUT_MIN 1

/** Fragment reassembly policies. */
enum defrag_policies {
    DEFRAG_POLICY_FIRST = 1,
    DEFRAG_POLICY_LAST,
    DEFRAG_POLICY_BSD,
    DEFRAG_POLICY_BSD_RIGHT,
    DEFRAG_POLICY_LINUX,
    DEFRAG_POLICY_WINDOWS,
    DEFRAG_POLICY_SOLARIS,

    DEFRAG_POLICY_DEFAULT = DEFRAG_POLICY_BSD,
};

static int default_policy = DEFRAG_POLICY_BSD;

/**
 * A context for an instance of a fragmentation re-assembler, in case
 * we ever need more than one.
 */
typedef struct DefragContext_ {
    uint64_t ip4_frags; /**< Number of IPv4 fragments seen. */
    uint64_t ip6_frags; /**< Number of IPv6 fragments seen. */

    HashListTable *frag_table; /**< Hash (list) table of fragment trackers. */
    SCMutex frag_table_lock;

    Pool *tracker_pool; /**< Pool of trackers. */
    SCMutex tracker_pool_lock;

    Pool *frag_pool; /**< Pool of fragments. */
    SCMutex frag_pool_lock;

    time_t timeout; /**< Default timeout. */
} DefragContext;

/**
 * Storage for an individual fragment.
 */
typedef struct Frag_ {
    DefragContext *dc; /**< The defragmentation context this frag was
                        * allocated under. */

    uint16_t offset; /**< The offset of this fragment, already
                      * multiplied by 8. */

    uint16_t len; /**< The length of this fragment. */

    uint8_t hlen; /**< The length of this fragments IP header. */

    uint8_t more_frags; /**< More frags? */

    uint16_t ip_hdr_offset; /**< Offset in the packet where the IP
                               * header starts. */
    uint16_t frag_hdr_offset; /**< Offset in the packet where the frag
                               * header starts. */

    uint16_t data_offset; /**< Offset to the packet data. */
    uint16_t data_len; /**< Length of data. */

    uint8_t *pkt; /**< The actual packet. */

    uint16_t ltrim; /**< Number of leading bytes to trim when
                     * re-assembling the packet. */

    int8_t skip; /**< Skip this fragment during re-assembly. */

#ifdef DEBUG
    uint64_t pcap_cnt;  /* pcap_cnt of original packet */
#endif

    TAILQ_ENTRY(Frag_) next; /**< Pointer to next fragment for tailq. */
} Frag;

/** \brief Reset tracker fields except "dc" and "lock" */
#define DEFRAG_TRACKER_RESET(t) { \
    (t)->timeout = 0; \
    (t)->id = 0; \
    (t)->policy = 0; \
    (t)->af = 0; \
    (t)->seen_last = 0; \
    CLEAR_ADDR(&(t)->src_addr); \
    CLEAR_ADDR(&(t)->dst_addr); \
    (t)->frags.tqh_first = NULL; \
    (t)->frags.tqh_last = NULL; \
}

/**
 * A defragmentation tracker.  Used to track fragments that make up a
 * single packet.
 */
typedef struct DefragTracker_ {
    SCMutex lock; /**< Mutex for locking list operations on
                           * this tracker. */

    DefragContext *dc; /**< The defragmentation context this tracker
                        * was allocated under. */

    uint32_t timeout; /**< When this tracker will timeout. */

    uint32_t id; /**< IP ID for this tracker.  32 bits for IPv6, 16
                  * for IPv4. */

    uint8_t policy; /**< Reassembly policy this tracker will use. */

    uint8_t af; /**< Address family for this tracker, AF_INET or
                 * AF_INET6. */

    uint8_t seen_last; /**< Has this tracker seen the last fragment? */

    Address src_addr; /**< Source address for this tracker. */
    Address dst_addr; /**< Destination address for this tracker. */

    TAILQ_HEAD(frag_tailq, Frag_) frags; /**< Head of list of fragments. */
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
        printf("-> Frag: frag_offset=%d, frag_len=%d, data_len=%d, ltrim=%d, skip=%d\n", frag->offset, frag->len, frag->data_len, frag->ltrim, frag->skip);
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

    if (p->af == AF_INET) {
        key = (defrag_hash_rand + p->id +
            p->src_addr.addr_data32[0] + p->dst_addr.addr_data32[0]) %
            defrag_hash_size;
    }
    else if (p->af == AF_INET6) {
        key = (defrag_hash_rand + p->id +
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

    if (dta->af != dtb->af)
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
        SCFree(frag->pkt);
    memset(frag, 0, sizeof(*frag));
    frag->dc = dc;
}

/**
 * \brief Allocate a new frag for use in a pool.
 */
static int
DefragFragInit(void *data, void *initdata)
{
    DefragContext *dc = initdata;
    Frag *frag = data;

    memset(frag, 0, sizeof(*frag));
    frag->dc = dc;

    return 1;
}

/**
 * \brief Free all frags associated with a tracker.
 */
static void
DefragTrackerFreeFrags(DefragTracker *tracker)
{
    Frag *frag;

    /* Lock the frag pool as we'll be return items to it. */
    SCMutexLock(&tracker->dc->frag_pool_lock);

    while ((frag = TAILQ_FIRST(&tracker->frags)) != NULL) {
        TAILQ_REMOVE(&tracker->frags, frag, next);

        /* Don't SCFree the frag, just give it back to its pool. */
        DefragFragReset(frag);
        PoolReturn(frag->dc->frag_pool, frag);
    }

    SCMutexUnlock(&tracker->dc->frag_pool_lock);
}

/**
 * \brief Reset a tracker for reuse.
 */
static void
DefragTrackerReset(DefragTracker *tracker)
{
    DefragTrackerFreeFrags(tracker);
    DEFRAG_TRACKER_RESET(tracker);
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
static int
DefragTrackerInit(void *data, void *initdata)
{
    DefragContext *dc = initdata;
    DefragTracker *tracker = data;

    memset(tracker, 0, sizeof(*tracker));
    if (SCMutexInit(&tracker->lock, NULL) != 0) {
        return 0;
    }
    tracker->dc = dc;
    TAILQ_INIT(&tracker->frags);

    return 1;
}

/**
 * \brief Free a defragmentation tracker that is being removed from
 *     the pool.
 */
static void
DefragTrackerFree(void *arg)
{
    DefragTracker *tracker = arg;

    SCMutexDestroy(&tracker->lock);
    DefragTrackerFreeFrags(tracker);
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

    dc = SCCalloc(1, sizeof(*dc));
    if (dc == NULL)
        return NULL;

    /* Initialize the hash table. */
    dc->frag_table = HashListTableInit(defrag_hash_size, DefragHashFunc,
        DefragHashCompare, DefragHashFree);
    if (dc->frag_table == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize hash table.");
        exit(EXIT_FAILURE);
    }
    if (SCMutexInit(&dc->frag_table_lock, NULL) != 0) {
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
        sizeof(DefragTracker),
        NULL, DefragTrackerInit, dc, DefragTrackerFree);
    if (dc->tracker_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize tracker pool.");
        exit(EXIT_FAILURE);
    }
    if (SCMutexInit(&dc->tracker_pool_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX,
            "Defrag: Failed to initialize tracker pool mutex.");
        exit(EXIT_FAILURE);
    }

    /* Initialize the pool of frags. */
    intmax_t frag_pool_size;
    if (!ConfGetInt("defrag.max-frags", &frag_pool_size)) {
        frag_pool_size = DEFAULT_DEFRAG_POOL_SIZE;
    }
    intmax_t frag_pool_prealloc = frag_pool_size / 2;
    dc->frag_pool = PoolInit(frag_pool_size, frag_pool_prealloc,
        sizeof(Frag),
        NULL, DefragFragInit, dc, NULL);
    if (dc->frag_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Defrag: Failed to initialize fragment pool.");
        exit(EXIT_FAILURE);
    }
    if (SCMutexInit(&dc->frag_pool_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX,
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
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "defrag: Timeout less than minimum allowed value.");
            exit(EXIT_FAILURE);
        }
        else if (timeout > TIMEOUT_MAX) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "defrag: Tiemout greater than maximum allowed value.");
            exit(EXIT_FAILURE);
        }
        dc->timeout = timeout;
    }

    SCLogDebug("Defrag Initialized:");
    SCLogDebug("\tTimeout: %"PRIuMAX, (uintmax_t)dc->timeout);
    SCLogDebug("\tMaximum defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tPreallocated defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tMaximum fragments: %ld", frag_pool_size);
    SCLogDebug("\tPreallocated fragments: %ld", frag_pool_prealloc);

    return dc;
}

static void
DefragContextDestroy(DefragContext *dc)
{
    if (dc == NULL)
        return;

    HashListTableFree(dc->frag_table);
    PoolFree(dc->frag_pool);
    PoolFree(dc->tracker_pool);
    SCFree(dc);
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
    Packet *rp = NULL;

    /* Should not be here unless we have seen the last fragment. */
    if (!tracker->seen_last)
        return NULL;

    /* Check that we have all the data. Relies on the fact that
     * fragments are inserted if frag_offset order. */
    Frag *frag;
    int len = 0;
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag->skip)
            continue;

        if (frag == TAILQ_FIRST(&tracker->frags)) {
            if (frag->offset != 0) {
                goto done;
            }
            len = frag->data_len;
        }
        else {
            if (frag->offset > len) {
                /* This fragment starts after the end of the previous
                 * fragment.  We have a hole. */
                goto done;
            }
            else {
                len += frag->data_len;
            }
        }
    }

    /* Allocate a Packet for the reassembled packet.  On failure we
     * SCFree all the resources held by this tracker. */
    rp = PacketDefragPktSetup(p, NULL, 0, IPV4_GET_IPPROTO(p));
    if (rp == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for "
                   "fragmentation re-assembly, dumping fragments.");
        goto remove_tracker;
    }
    SCLogDebug("Packet rp %p, p %p, rp->root %p", rp, p, rp->root);
    rp->recursion_level = p->recursion_level;

    int fragmentable_offset = 0;
    int fragmentable_len = 0;
    int hlen = 0;
    int ip_hdr_offset = 0;
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        SCLogDebug("frag %p, data_len %u, offset %u, pcap_cnt %"PRIu64,
                frag, frag->data_len, frag->offset, frag->pcap_cnt);

        if (frag->skip)
            continue;
        if (frag->data_len - frag->ltrim <= 0)
            continue;
        if (frag->offset == 0) {

            if (PacketCopyData(rp, frag->pkt, frag->len) == -1)
                goto remove_tracker;

            hlen = frag->hlen;
            ip_hdr_offset = frag->ip_hdr_offset;

            /* This is the start of the fragmentable portion of the
             * first packet.  All fragment offsets are relative to
             * this. */
            fragmentable_offset = frag->ip_hdr_offset + frag->hlen;
            fragmentable_len = frag->data_len;
        }
        else {
            int pkt_end = fragmentable_offset + frag->offset + frag->data_len;
            if (pkt_end > (int)MAX_PAYLOAD_SIZE) {
                SCLogWarning(SC_ERR_REASSEMBLY, "Failed re-assemble "
                        "fragmented packet, exceeds size of packet buffer.");
                goto remove_tracker;
            }
            if (PacketCopyDataOffset(rp, fragmentable_offset + frag->offset + frag->ltrim,
                frag->pkt + frag->data_offset + frag->ltrim,
                frag->data_len - frag->ltrim) == -1) {
                goto remove_tracker;
            }
            if (frag->offset + frag->data_len > fragmentable_len)
                fragmentable_len = frag->offset + frag->data_len;
        }
    }

    SCLogDebug("ip_hdr_offset %u, hlen %u, fragmentable_len %u",
            ip_hdr_offset, hlen, fragmentable_len);

    rp->ip4h = (IPV4Hdr *)(GET_PKT_DATA(rp) + ip_hdr_offset);
    int old = rp->ip4h->ip_len + rp->ip4h->ip_off;
    rp->ip4h->ip_len = htons(fragmentable_len + hlen);
    rp->ip4h->ip_off = 0;
    rp->ip4h->ip_csum = FixChecksum(rp->ip4h->ip_csum,
        old, rp->ip4h->ip_len + rp->ip4h->ip_off);
    SET_PKT_LEN(rp, ip_hdr_offset + hlen + fragmentable_len);

remove_tracker:
    /* Remove the frag tracker. */
    SCMutexLock(&dc->frag_table_lock);
    HashListTableRemove(dc->frag_table, tracker, HASHLIST_NO_SIZE);
    SCMutexUnlock(&dc->frag_table_lock);
    DefragTrackerReset(tracker);
    SCMutexLock(&dc->tracker_pool_lock);
    PoolReturn(dc->tracker_pool, tracker);
    SCMutexUnlock(&dc->tracker_pool_lock);

done:
    return rp;
}

/**
 * Attempt to re-assemble a packet.
 *
 * \param tracker The defragmentation tracker to reassemble from.
 */
static Packet *
Defrag6Reassemble(ThreadVars *tv, DefragContext *dc, DefragTracker *tracker,
    Packet *p)
{
    Packet *rp = NULL;

    /* Should not be here unless we have seen the last fragment. */
    if (!tracker->seen_last)
        return NULL;

    /* Check that we have all the data. Relies on the fact that
     * fragments are inserted if frag_offset order. */
    Frag *frag;
    int len = 0;
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag->skip)
            continue;

        if (frag == TAILQ_FIRST(&tracker->frags)) {
            if (frag->offset != 0) {
                goto done;
            }
            len = frag->data_len;
        }
        else {
            if (frag->offset > len) {
                /* This fragment starts after the end of the previous
                 * fragment.  We have a hole. */
                goto done;
            }
            else {
                len += frag->data_len;
            }
        }
    }

    /* Allocate a Packet for the reassembled packet.  On failure we
     * SCFree all the resources held by this tracker. */
    rp = PacketDefragPktSetup(p, (uint8_t *)p->ip6h,
            IPV6_GET_PLEN(p) + sizeof(IPV6Hdr), 0);
    if (rp == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for "
                "fragmentation re-assembly, dumping fragments.");
        goto remove_tracker;
    }

    int fragmentable_offset = 0;
    int fragmentable_len = 0;
    int ip_hdr_offset = 0;
    uint8_t next_hdr = 0;
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag->skip)
            continue;
        if (frag->data_len - frag->ltrim <= 0)
            continue;
        if (frag->offset == 0) {
            IPV6FragHdr *frag_hdr = (IPV6FragHdr *)(frag->pkt +
                frag->frag_hdr_offset);
            next_hdr = frag_hdr->ip6fh_nxt;

            /* This is the first packet, we use this packets link and
             * IPv6 headers. We also copy in its data, but remove the
             * fragmentation header. */
            if (PacketCopyData(rp, frag->pkt, frag->frag_hdr_offset) == -1)
                goto remove_tracker;
            if (PacketCopyDataOffset(rp, frag->frag_hdr_offset,
                frag->pkt + frag->frag_hdr_offset + sizeof(IPV6FragHdr),
                frag->data_len) == -1)
                goto remove_tracker;
            ip_hdr_offset = frag->ip_hdr_offset;

            /* This is the start of the fragmentable portion of the
             * first packet.  All fragment offsets are relative to
             * this. */
            fragmentable_offset = frag->frag_hdr_offset;
            fragmentable_len = frag->data_len;
        }
        else {
            if (PacketCopyDataOffset(rp, fragmentable_offset + frag->offset + frag->ltrim,
                frag->pkt + frag->data_offset + frag->ltrim,
                frag->data_len - frag->ltrim) == -1)
                goto remove_tracker;
            if (frag->offset + frag->data_len > fragmentable_len)
                fragmentable_len = frag->offset + frag->data_len;
        }
    }

    rp->ip6h = (IPV6Hdr *)(GET_PKT_DATA(rp) + ip_hdr_offset);
    rp->ip6h->s_ip6_plen = htons(fragmentable_len);
    rp->ip6h->s_ip6_nxt = next_hdr;
    SET_PKT_LEN(rp, ip_hdr_offset + sizeof(IPV6Hdr) + fragmentable_len);

remove_tracker:
    /* Remove the frag tracker. */
    SCMutexLock(&dc->frag_table_lock);
    HashListTableRemove(dc->frag_table, tracker, HASHLIST_NO_SIZE);
    SCMutexUnlock(&dc->frag_table_lock);
    DefragTrackerReset(tracker);
    SCMutexLock(&dc->tracker_pool_lock);
    PoolReturn(dc->tracker_pool, tracker);
    SCMutexUnlock(&dc->tracker_pool_lock);

done:
    return rp;
}

/**
 * Insert a new IPv4/IPv6 fragment into a tracker.
 *
 * \todo Allocate packet buffers from a pool.
 */
static Packet *
DefragInsertFrag(ThreadVars *tv, DecodeThreadVars *dtv, DefragContext *dc,
    DefragTracker *tracker, Packet *p)
{
    Packet *r = NULL;
    int ltrim = 0;

    uint8_t more_frags;
    uint16_t frag_offset;

    /* IPv4 header length - IPv4 only. */
    uint16_t hlen = 0;

    /* This is the offset of the start of the data in the packet that
     * falls after the IP header. */
    uint16_t data_offset;

    /* The length of the (fragmented) data.  This is the length of the
     * data that falls after the IP header. */
    uint16_t data_len;

    /* Where the fragment ends. */
    uint16_t frag_end;

    /* Offset in the packet to the IPv6 header. */
    uint16_t ip_hdr_offset;

    /* Offset in the packet to the IPv6 frag header. IPv6 only. */
    uint16_t frag_hdr_offset = 0;

    /* Address family */
    int af = tracker->af;

#ifdef DEBUG
    uint64_t pcap_cnt = p->pcap_cnt;
#endif

    if (tracker->af == AF_INET) {
        more_frags = IPV4_GET_MF(p);
        frag_offset = IPV4_GET_IPOFFSET(p) << 3;
        hlen = IPV4_GET_HLEN(p);
        data_offset = (uint8_t *)p->ip4h + hlen - GET_PKT_DATA(p);
        data_len = IPV4_GET_IPLEN(p) - hlen;
        frag_end = frag_offset + data_len;
        ip_hdr_offset = (uint8_t *)p->ip4h - GET_PKT_DATA(p);

        /* Ignore fragment if the end of packet extends past the
         * maximum size of a packet. */
        if (IPV4_HEADER_LEN + frag_offset + data_len > IPV4_MAXPACKET_LEN) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_PKT_TOO_LARGE);
            return NULL;
        }
    }
    else if (tracker->af == AF_INET6) {
        more_frags = IPV6_EXTHDR_GET_FH_FLAG(p);
        frag_offset = IPV6_EXTHDR_GET_FH_OFFSET(p);
        data_offset = (uint8_t *)p->ip6eh.ip6fh + sizeof(IPV6FragHdr) - GET_PKT_DATA(p);
        data_len = IPV6_GET_PLEN(p) - (
            ((uint8_t *)p->ip6eh.ip6fh + sizeof(IPV6FragHdr)) -
                ((uint8_t *)p->ip6h + sizeof(IPV6Hdr)));
        frag_end = frag_offset + data_len;
        ip_hdr_offset = (uint8_t *)p->ip6h - GET_PKT_DATA(p);
        frag_hdr_offset = (uint8_t *)p->ip6eh.ip6fh - GET_PKT_DATA(p);

        /* Ignore fragment if the end of packet extends past the
         * maximum size of a packet. */
        if (frag_offset + data_len > IPV6_MAXPACKET) {
            ENGINE_SET_EVENT(p, IPV6_FRAG_PKT_TOO_LARGE);
            return NULL;
        }
    }
    else {
        /* Abort - should not happen. */
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid address family, aborting.");
        return NULL;
    }

    /* Lock this tracker as we'll be doing list operations on it. */
    SCMutexLock(&tracker->lock);

    /* Update timeout. */
    tracker->timeout = p->ts.tv_sec + dc->timeout;

    Frag *prev = NULL, *next;
    int overlap = 0;
    if (!TAILQ_EMPTY(&tracker->frags)) {
        TAILQ_FOREACH(prev, &tracker->frags, next) {
            ltrim = 0;
            next = TAILQ_NEXT(prev, next);

            switch (tracker->policy) {
            case DEFRAG_POLICY_BSD:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset >= prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                        overlap++;
                    }
                    if ((next != NULL) && (frag_end > next->offset)) {
                        next->ltrim = frag_end - next->offset;
                        overlap++;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end >= prev->offset + prev->data_len)) {
                        prev->skip = 1;
                        overlap++;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_LINUX:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset > prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                        overlap++;
                    }
                    if ((next != NULL) && (frag_end > next->offset)) {
                        next->ltrim = frag_end - next->offset;
                        overlap++;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end >= prev->offset + prev->data_len)) {
                        prev->skip = 1;
                        overlap++;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_WINDOWS:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset >= prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                        overlap++;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end > prev->offset + prev->data_len)) {
                        prev->skip = 1;
                        overlap++;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_SOLARIS:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset >= prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                        overlap++;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end >= prev->offset + prev->data_len)) {
                        prev->skip = 1;
                        overlap++;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_FIRST:
                if ((frag_offset >= prev->offset) &&
                    (frag_end <= prev->offset + prev->data_len)) {
                    overlap++;
                    goto done;
                }
                if (frag_offset < prev->offset) {
                    goto insert;
                }
                if (frag_offset < prev->offset + prev->data_len) {
                    ltrim = prev->offset + prev->data_len - frag_offset;
                    overlap++;
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_LAST:
                if (frag_offset <= prev->offset) {
                    if (frag_end > prev->offset) {
                        prev->ltrim = frag_end - prev->offset;
                        overlap++;
                    }
                    goto insert;
                }
                break;
            default:
                break;
            }
        }
    }

insert:
    if (data_len - ltrim <= 0) {
        if (af == AF_INET) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_TOO_LARGE);
        } else {
            ENGINE_SET_EVENT(p, IPV6_FRAG_TOO_LARGE);
        }
        goto done;
    }

    /* Allocate fragment and insert. */
    SCMutexLock(&dc->frag_pool_lock);
    Frag *new = PoolGet(dc->frag_pool);
    SCMutexUnlock(&dc->frag_pool_lock);
    if (new == NULL) {
        if (af == AF_INET) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_IGNORED);
        } else {
            ENGINE_SET_EVENT(p, IPV6_FRAG_IGNORED);
        }
        goto done;
    }
    new->pkt = SCMalloc(GET_PKT_LEN(p));
    if (new->pkt == NULL) {
        SCMutexLock(&dc->frag_pool_lock);
        PoolReturn(dc->frag_pool, new);
        SCMutexUnlock(&dc->frag_pool_lock);
        if (af == AF_INET) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_IGNORED);
        } else {
            ENGINE_SET_EVENT(p, IPV6_FRAG_IGNORED);
        }
        goto done;
    }
    memcpy(new->pkt, GET_PKT_DATA(p) + ltrim, GET_PKT_LEN(p) - ltrim);
    new->len = GET_PKT_LEN(p) - ltrim;
    new->hlen = hlen;
    new->offset = frag_offset + ltrim;
    new->data_offset = data_offset;
    new->data_len = data_len - ltrim;
    new->ip_hdr_offset = ip_hdr_offset;
    new->frag_hdr_offset = frag_hdr_offset;
#ifdef DEBUG
    new->pcap_cnt = pcap_cnt;
#endif

    Frag *frag;
    TAILQ_FOREACH(frag, &tracker->frags, next) {
        if (frag_offset < frag->offset)
            break;
    }
    if (frag == NULL) {
        TAILQ_INSERT_TAIL(&tracker->frags, new, next);
    }
    else {
        TAILQ_INSERT_BEFORE(frag, new, next);
    }

    if (!more_frags) {
        tracker->seen_last = 1;
    }

    if (tracker->seen_last) {
        if (tracker->af == AF_INET) {
            r = Defrag4Reassemble(tv, dc, tracker, p);
            if (r != NULL && tv != NULL && dtv != NULL) {
                SCPerfCounterIncr(dtv->counter_defrag_ipv4_reassembled,
                    tv->sc_perf_pca);
            }
        }
        else if (tracker->af == AF_INET6) {
            r = Defrag6Reassemble(tv, dc, tracker, p);
            if (r != NULL && tv != NULL && dtv != NULL) {
                SCPerfCounterIncr(dtv->counter_defrag_ipv6_reassembled,
                    tv->sc_perf_pca);
            }
        }
    }

done:
    if (overlap) {
        if (af == AF_INET) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_OVERLAP);
        }
        else {
            ENGINE_SET_EVENT(p, IPV6_FRAG_OVERLAP);
        }
    }
    SCMutexUnlock(&tracker->lock);
    return r;
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
DefragTimeoutTracker(ThreadVars *tv, DecodeThreadVars *dtv, DefragContext *dc,
    Packet *p)
{
    HashListTableBucket *next = HashListTableGetListHead(dc->frag_table);
    DefragTracker *tracker;
    while (next != NULL) {
        tracker = HashListTableGetListData(next);

        if (tracker->timeout < (unsigned int)p->ts.tv_sec) {
            /* Tracker has timeout out. */
            HashListTableRemove(dc->frag_table, tracker, HASHLIST_NO_SIZE);
            DefragTrackerReset(tracker);
            PoolReturn(dc->tracker_pool, tracker);
            if (tv != NULL && dtv != NULL) {
                if (tracker->af == AF_INET) {
                    SCPerfCounterIncr(dtv->counter_defrag_ipv4_timeouts,
                        tv->sc_perf_pca);
                }
                else if (tracker->af == AF_INET6) {
                    SCPerfCounterIncr(dtv->counter_defrag_ipv6_timeouts,
                        tv->sc_perf_pca);
                }
            }
            return;
        }

        next = HashListTableGetListNext(next);
    }
}

/**
 * \brief Get the defrag policy based on the destination address of
 * the packet.
 *
 * \param p The packet used to get the destination address.
 *
 * \retval The defrag policy to use.
 */
static uint8_t
DefragGetOsPolicy(Packet *p)
{
    int policy = -1;

    if (PKT_IS_IPV4(p)) {
        policy = SCHInfoGetIPv4HostOSFlavour((uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
    }
    else if (PKT_IS_IPV6(p)) {
        policy = SCHInfoGetIPv6HostOSFlavour((uint8_t *)GET_IPV6_DST_ADDR(p));
    }

    if (policy == -1) {
        return default_policy;
    }

    /* Map the OS policies returned from the configured host info to
     * defrag specific policies. */
    switch (policy) {
        /* BSD. */
    case OS_POLICY_BSD:
    case OS_POLICY_HPUX10:
    case OS_POLICY_IRIX:
        return DEFRAG_POLICY_BSD;

        /* BSD-Right. */
    case OS_POLICY_BSD_RIGHT:
        return DEFRAG_POLICY_BSD_RIGHT;

        /* Linux. */
    case OS_POLICY_OLD_LINUX:
    case OS_POLICY_LINUX:
        return DEFRAG_POLICY_LINUX;

        /* First. */
    case OS_POLICY_OLD_SOLARIS:
    case OS_POLICY_HPUX11:
    case OS_POLICY_MACOS:
    case OS_POLICY_FIRST:
        return DEFRAG_POLICY_FIRST;

        /* Solaris. */
    case OS_POLICY_SOLARIS:
        return DEFRAG_POLICY_SOLARIS;

        /* Windows. */
    case OS_POLICY_WINDOWS:
    case OS_POLICY_VISTA:
    case OS_POLICY_WINDOWS2K3:
        return DEFRAG_POLICY_WINDOWS;

        /* Last. */
    case OS_POLICY_LAST:
        return DEFRAG_POLICY_LAST;

    default:
        return default_policy;
    }
}

static DefragTracker *
DefragGetTracker(ThreadVars *tv, DecodeThreadVars *dtv, DefragContext *dc,
    DefragTracker *lookup_key, Packet *p)
{
    DefragTracker *tracker;

    SCMutexLock(&dc->frag_table_lock);
    tracker = HashListTableLookup(dc->frag_table, lookup_key,
        sizeof(*lookup_key));
    if (tracker == NULL) {
        SCMutexLock(&dc->tracker_pool_lock);
        tracker = PoolGet(dc->tracker_pool);
        if (tracker == NULL) {
            /* Timeout trackers and try again. */
            DefragTimeoutTracker(tv, dtv, dc, p);
            tracker = PoolGet(dc->tracker_pool);
        }
        SCMutexUnlock(&dc->tracker_pool_lock);
        if (tracker == NULL) {
            /* Report memory error - actually a pool allocation error. */
            SCLogError(SC_ERR_MEM_ALLOC, "Defrag: Failed to allocate tracker.");
            goto done;
        }
        DefragTrackerReset(tracker);
        tracker->af = lookup_key->af;
        tracker->id = lookup_key->id;
        tracker->src_addr = lookup_key->src_addr;
        tracker->dst_addr = lookup_key->dst_addr;
        tracker->policy = DefragGetOsPolicy(p);

        if (HashListTableAdd(dc->frag_table, tracker, HASHLIST_NO_SIZE) != 0) {
            /* Failed to add new tracker. */
            SCLogError(SC_ERR_MEM_ALLOC,
                "Defrag: Failed to add new tracker to hash table.");
            SCMutexLock(&dc->tracker_pool_lock);
            PoolReturn(dc->tracker_pool, tracker);
            SCMutexUnlock(&dc->tracker_pool_lock);
            goto done;
        }
    }

done:
    SCMutexUnlock(&dc->frag_table_lock);
    return tracker;
}

/**
 * \brief Entry point for IPv4 and IPv6 fragments.
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
Defrag(ThreadVars *tv, DecodeThreadVars *dtv, DefragContext *dc, Packet *p)
{
    uint16_t frag_offset;
    uint8_t more_frags;
    DefragTracker *tracker, lookup;
    uint32_t id;
    int af;

    /* If no DefragContext was passed in, use the global one.  Passing
     * one in is primarily useful for unit tests. */
    if (dc == NULL)
        dc = defrag_context;

    if (PKT_IS_IPV4(p)) {
        af = AF_INET;
        more_frags = IPV4_GET_MF(p);
        frag_offset = IPV4_GET_IPOFFSET(p);
        id = IPV4_GET_IPID(p);
    }
    else if (PKT_IS_IPV6(p)) {
        af = AF_INET6;
        frag_offset = IPV6_EXTHDR_GET_FH_OFFSET(p);
        more_frags = IPV6_EXTHDR_GET_FH_FLAG(p);
        id = IPV6_EXTHDR_GET_FH_ID(p);
    }
    else {
        return NULL;
    }

    if (frag_offset == 0 && more_frags == 0) {
        return NULL;
    }

    if (tv != NULL && dtv != NULL) {
        if (af == AF_INET) {
            SCPerfCounterIncr(dtv->counter_defrag_ipv4_fragments,
                tv->sc_perf_pca);
        }
        else if (af == AF_INET6) {
            SCPerfCounterIncr(dtv->counter_defrag_ipv6_fragments,
                tv->sc_perf_pca);
        }
    }

    /* Create a lookup key. */
    lookup.af = af;
    lookup.id = id;
    lookup.src_addr = p->src;
    lookup.dst_addr = p->dst;

    tracker = DefragGetTracker(tv, dtv, dc, &lookup, p);
    if (tracker == NULL)
        return NULL;

    return DefragInsertFrag(tv, dtv, dc, tracker, p);
}

void
DefragInit(void)
{
    /* Initialize random value for hashing and hash table size. */
    unsigned int seed = RandomTimePreseed();
    intmax_t tracker_pool_size;
    if (!ConfGetInt("defrag.trackers", &tracker_pool_size)) {
        tracker_pool_size = DEFAULT_DEFRAG_HASH_SIZE;
    }

    /* set defaults */
    defrag_hash_rand = (int)(tracker_pool_size * (rand_r(&seed) / RAND_MAX + 1.0));
    defrag_hash_size = tracker_pool_size;

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
    uint8_t *pcontent;
    IPV4Hdr ip4h;

    p = SCCalloc(1, sizeof(*p) + default_packet_size);
    if (p == NULL)
        return NULL;

    PACKET_INITIALIZE(p);

    gettimeofday(&p->ts, NULL);
    //p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    ip4h.ip_verhl = 4 << 4;
    ip4h.ip_verhl |= hlen >> 2;
    ip4h.ip_len = htons(hlen + content_len);
    ip4h.ip_id = htons(id);
    ip4h.ip_off = htons(off);
    if (mf)
        ip4h.ip_off = htons(IP_MF | off);
    else
        ip4h.ip_off = htons(off);
    ip4h.ip_ttl = ttl;
    ip4h.ip_proto = IPPROTO_ICMP;

    ip4h.s_ip_src.s_addr = 0x01010101; /* 1.1.1.1 */
    ip4h.s_ip_dst.s_addr = 0x02020202; /* 2.2.2.2 */

    /* copy content_len crap, we need full length */
    PacketCopyData(p, (uint8_t *)&ip4h, sizeof(ip4h) + content_len);
    p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    SET_IPV4_SRC_ADDR(p, &p->src);
    SET_IPV4_DST_ADDR(p, &p->dst);

    pcontent = SCCalloc(1, content_len);
    if (pcontent == NULL)
        return NULL;
    memset(pcontent, content, content_len);
    PacketCopyDataOffset(p, hlen, pcontent, content_len);
    SET_PKT_LEN(p, hlen + content_len);
    SCFree(pcontent);

    p->ip4h->ip_csum = IPV4CalculateChecksum((uint16_t *)GET_PKT_DATA(p), hlen);

    /* Self test. */
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
        SCFree(p);
    return NULL;
}

static Packet *
IPV6BuildTestPacket(uint32_t id, uint16_t off, int mf, const char content,
    int content_len)
{
    Packet *p = NULL;
    uint8_t *pcontent;
    IPV6Hdr ip6h;

    p = SCCalloc(1, sizeof(*p) + default_packet_size);
    if (p == NULL)
        return NULL;

    PACKET_INITIALIZE(p);

    gettimeofday(&p->ts, NULL);

    ip6h.s_ip6_nxt = 44;
    ip6h.s_ip6_hlim = 2;

    /* Source and dest address - very bogus addresses. */
    ip6h.s_ip6_src[0] = 0x01010101;
    ip6h.s_ip6_src[1] = 0x01010101;
    ip6h.s_ip6_src[2] = 0x01010101;
    ip6h.s_ip6_src[3] = 0x01010101;
    ip6h.s_ip6_dst[0] = 0x02020202;
    ip6h.s_ip6_dst[1] = 0x02020202;
    ip6h.s_ip6_dst[2] = 0x02020202;
    ip6h.s_ip6_dst[3] = 0x02020202;

    /* copy content_len crap, we need full length */
    PacketCopyData(p, (uint8_t *)&ip6h, sizeof(IPV6Hdr) + sizeof(IPV6FragHdr) + content_len);

    p->ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    IPV6_SET_RAW_VER(p->ip6h, 6);
    /* Fragmentation header. */
    p->ip6eh.ip6fh = (IPV6FragHdr *)(GET_PKT_DATA(p) + sizeof(IPV6Hdr));
    p->ip6eh.ip6fh->ip6fh_nxt = IPPROTO_ICMP;
    p->ip6eh.ip6fh->ip6fh_ident = htonl(id);
    p->ip6eh.ip6fh->ip6fh_offlg = htons((off << 3) | mf);

    pcontent = SCCalloc(1, content_len);
    if (pcontent == NULL)
        return NULL;
    memset(pcontent, content, content_len);
    PacketCopyDataOffset(p, sizeof(IPV6Hdr) + sizeof(IPV6FragHdr), pcontent, content_len);
    SET_PKT_LEN(p, sizeof(IPV6Hdr) + sizeof(IPV6FragHdr) + content_len);
    SCFree(pcontent);

    p->ip6h->s_ip6_plen = htons(sizeof(IPV6FragHdr) + content_len);

    SET_IPV6_SRC_ADDR(p, &p->src);
    SET_IPV6_DST_ADDR(p, &p->dst);

    /* Self test. */
    if (IPV6_GET_VER(p) != 6)
        goto error;
    if (IPV6_GET_NH(p) != 44)
        goto error;
    if (IPV6_GET_PLEN(p) != sizeof(IPV6FragHdr) + content_len)
        goto error;

    return p;
error:
    fprintf(stderr, "Error building test packet.\n");
    if (p != NULL)
        SCFree(p);
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

    if (Defrag(NULL, NULL, dc, p1) != NULL)
        goto end;
    if (Defrag(NULL, NULL, dc, p2) != NULL)
        goto end;

    reassembled = Defrag(NULL, NULL, dc, p3);
    if (reassembled == NULL)
        goto end;

    if (IPV4_GET_HLEN(reassembled) != 20)
        goto end;
    if (IPV4_GET_IPLEN(reassembled) != 39)
        goto end;

    /* 20 bytes in we should find 8 bytes of A. */
    for (i = 20; i < 20 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'A')
            goto end;
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 28; i < 28 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'B')
            goto end;
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 36; i < 36 + 3; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'C')
            goto end;
    }

    ret = 1;
end:

    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p1 != NULL)
        SCFree(p1);
    if (p2 != NULL)
        SCFree(p2);
    if (p3 != NULL)
        SCFree(p3);
    if (reassembled != NULL)
        SCFree(reassembled);

    DefragDestroy();
    return ret;
}

/**
 * Simple fragmented packet in reverse order.
 */
static int
DefragReverseSimpleTest(void)
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

    if (Defrag(NULL, NULL, dc, p3) != NULL)
        goto end;
    if (Defrag(NULL, NULL, dc, p2) != NULL)
        goto end;

    reassembled = Defrag(NULL, NULL, dc, p1);
    if (reassembled == NULL)
        goto end;

    if (IPV4_GET_HLEN(reassembled) != 20)
        goto end;
    if (IPV4_GET_IPLEN(reassembled) != 39)
        goto end;

    /* 20 bytes in we should find 8 bytes of A. */
    for (i = 20; i < 20 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'A')
            goto end;
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 28; i < 28 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'B')
            goto end;
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 36; i < 36 + 3; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'C')
            goto end;
    }

    ret = 1;
end:

    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p1 != NULL)
        SCFree(p1);
    if (p2 != NULL)
        SCFree(p2);
    if (p3 != NULL)
        SCFree(p3);
    if (reassembled != NULL)
        SCFree(reassembled);

    DefragDestroy();
    return ret;
}

/**
 * Test the simplest possible re-assembly scenario.  All packet in
 * order and no overlaps.
 */
static int
IPV6DefragInOrderSimpleTest(void)
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

    p1 = IPV6BuildTestPacket(id, 0, 1, 'A', 8);
    if (p1 == NULL)
        goto end;
    p2 = IPV6BuildTestPacket(id, 1, 1, 'B', 8);
    if (p2 == NULL)
        goto end;
    p3 = IPV6BuildTestPacket(id, 2, 0, 'C', 3);
    if (p3 == NULL)
        goto end;

    if (Defrag(NULL, NULL, dc, p1) != NULL)
        goto end;
    if (Defrag(NULL, NULL, dc, p2) != NULL)
        goto end;
    reassembled = Defrag(NULL, NULL, dc, p3);
    if (reassembled == NULL)
        goto end;

    if (IPV6_GET_PLEN(reassembled) != 19)
        goto end;

    /* 40 bytes in we should find 8 bytes of A. */
    for (i = 40; i < 40 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'A')
            goto end;
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 48; i < 48 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'B')
            goto end;
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 56; i < 56 + 3; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'C')
            goto end;
    }

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p1 != NULL)
        SCFree(p1);
    if (p2 != NULL)
        SCFree(p2);
    if (p3 != NULL)
        SCFree(p3);
    if (reassembled != NULL)
        SCFree(reassembled);

    DefragDestroy();
    return ret;
}

static int
IPV6DefragReverseSimpleTest(void)
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

    p1 = IPV6BuildTestPacket(id, 0, 1, 'A', 8);
    if (p1 == NULL)
        goto end;
    p2 = IPV6BuildTestPacket(id, 1, 1, 'B', 8);
    if (p2 == NULL)
        goto end;
    p3 = IPV6BuildTestPacket(id, 2, 0, 'C', 3);
    if (p3 == NULL)
        goto end;

    if (Defrag(NULL, NULL, dc, p3) != NULL)
        goto end;
    if (Defrag(NULL, NULL, dc, p2) != NULL)
        goto end;
    reassembled = Defrag(NULL, NULL, dc, p1);
    if (reassembled == NULL)
        goto end;

    /* 40 bytes in we should find 8 bytes of A. */
    for (i = 40; i < 40 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'A')
            goto end;
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 48; i < 48 + 8; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'B')
            goto end;
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 56; i < 56 + 3; i++) {
        if (GET_PKT_DATA(reassembled)[i] != 'C')
            goto end;
    }

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p1 != NULL)
        SCFree(p1);
    if (p2 != NULL)
        SCFree(p2);
    if (p3 != NULL)
        SCFree(p3);
    if (reassembled != NULL)
        SCFree(reassembled);

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
    default_policy = policy;

    /* Send all but the last. */
    for (i = 0; i < 9; i++) {
        Packet *tp = Defrag(NULL, NULL, dc, packets[i]);
        if (tp != NULL) {
            SCFree(tp);
            goto end;
        }
        if (ENGINE_ISSET_EVENT(packets[i], IPV4_FRAG_OVERLAP)) {
            goto end;
        }
    }
    int overlap = 0;
    for (; i < 16; i++) {
        Packet *tp = Defrag(NULL, NULL, dc, packets[i]);
        if (tp != NULL) {
            SCFree(tp);
            goto end;
        }
        if (ENGINE_ISSET_EVENT(packets[i], IPV4_FRAG_OVERLAP)) {
            overlap++;
        }
    }
    if (!overlap)
        goto end;

    /* And now the last one. */
    Packet *reassembled = Defrag(NULL, NULL, dc, packets[16]);
    if (reassembled == NULL)
        goto end;

    if (IPV4_GET_HLEN(reassembled) != 20)
        goto end;
    if (IPV4_GET_IPLEN(reassembled) != 20 + 192)
        goto end;

    if (memcmp(GET_PKT_DATA(reassembled) + 20, expected, expected_len) != 0)
        goto end;
    SCFree(reassembled);

    /* Make sure the tracker was released back to the pool. */
    if (dc->tracker_pool->outstanding != 0)
        return 0;

    /* Make sure all frags were returned back to the pool. */
    if (dc->frag_pool->outstanding != 0)
        return 0;

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    for (i = 0; i < 17; i++) {
        SCFree(packets[i]);
    }
    DefragDestroy();
    return ret;
}

static int
IPV6DefragDoSturgesNovakTest(int policy, u_char *expected, size_t expected_len)
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
    packets[0] = IPV6BuildTestPacket(id, 0, 1, 'A', 24);

    /* B*15 at 32. */
    packets[1] = IPV6BuildTestPacket(id, 32 >> 3, 1, 'B', 16);

    /* C*24 at 48. */
    packets[2] = IPV6BuildTestPacket(id, 48 >> 3, 1, 'C', 24);

    /* D*8 at 80. */
    packets[3] = IPV6BuildTestPacket(id, 80 >> 3, 1, 'D', 8);

    /* E*16 at 104. */
    packets[4] = IPV6BuildTestPacket(id, 104 >> 3, 1, 'E', 16);

    /* F*24 at 120. */
    packets[5] = IPV6BuildTestPacket(id, 120 >> 3, 1, 'F', 24);

    /* G*16 at 144. */
    packets[6] = IPV6BuildTestPacket(id, 144 >> 3, 1, 'G', 16);

    /* H*16 at 160. */
    packets[7] = IPV6BuildTestPacket(id, 160 >> 3, 1, 'H', 16);

    /* I*8 at 176. */
    packets[8] = IPV6BuildTestPacket(id, 176 >> 3, 1, 'I', 8);

    /*
     * Overlapping subsequent fragments.
     */

    /* J*32 at 8. */
    packets[9] = IPV6BuildTestPacket(id, 8 >> 3, 1, 'J', 32);

    /* K*24 at 48. */
    packets[10] = IPV6BuildTestPacket(id, 48 >> 3, 1, 'K', 24);

    /* L*24 at 72. */
    packets[11] = IPV6BuildTestPacket(id, 72 >> 3, 1, 'L', 24);

    /* M*24 at 96. */
    packets[12] = IPV6BuildTestPacket(id, 96 >> 3, 1, 'M', 24);

    /* N*8 at 128. */
    packets[13] = IPV6BuildTestPacket(id, 128 >> 3, 1, 'N', 8);

    /* O*8 at 152. */
    packets[14] = IPV6BuildTestPacket(id, 152 >> 3, 1, 'O', 8);

    /* P*8 at 160. */
    packets[15] = IPV6BuildTestPacket(id, 160 >> 3, 1, 'P', 8);

    /* Q*16 at 176. */
    packets[16] = IPV6BuildTestPacket(id, 176 >> 3, 0, 'Q', 16);

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;
    default_policy = policy;

    /* Send all but the last. */
    for (i = 0; i < 9; i++) {
        Packet *tp = Defrag(NULL, NULL, dc, packets[i]);
        if (tp != NULL) {
            SCFree(tp);
            goto end;
        }
        if (ENGINE_ISSET_EVENT(packets[i], IPV6_FRAG_OVERLAP)) {
            goto end;
        }
    }
    int overlap = 0;
    for (; i < 16; i++) {
        Packet *tp = Defrag(NULL, NULL, dc, packets[i]);
        if (tp != NULL) {
            SCFree(tp);
            goto end;
        }
        if (ENGINE_ISSET_EVENT(packets[i], IPV6_FRAG_OVERLAP)) {
            overlap++;
        }
    }
    if (!overlap)
        goto end;

    /* And now the last one. */
    Packet *reassembled = Defrag(NULL, NULL, dc, packets[16]);
    if (reassembled == NULL)
        goto end;
    if (memcmp(GET_PKT_DATA(reassembled) + 40, expected, expected_len) != 0)
        goto end;

    if (IPV6_GET_PLEN(reassembled) != 192)
        goto end;

    SCFree(reassembled);

    /* Make sure the tracker was released back to the pool. */
    if (dc->tracker_pool->outstanding != 0)
        return 0;

    /* Make sure all frags were returned to the pool. */
    if (dc->frag_pool->outstanding != 0)
        return 0;

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    for (i = 0; i < 17; i++) {
        SCFree(packets[i]);
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_BSD, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakBsdTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_BSD, expected, sizeof(expected));
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_LINUX, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakLinuxTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_LINUX, expected,
        sizeof(expected));
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_WINDOWS, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakWindowsTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_WINDOWS, expected,
        sizeof(expected));
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_SOLARIS, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakSolarisTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_SOLARIS, expected,
        sizeof(expected));
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_FIRST, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakFirstTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_FIRST, expected,
        sizeof(expected));
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

    return DefragDoSturgesNovakTest(DEFRAG_POLICY_LAST, expected, sizeof(expected));
}

static int
IPV6DefragSturgesNovakLastTest(void)
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

    return IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_LAST, expected,
        sizeof(expected));
}

static int
DefragTimeoutTest(void)
{
    int i;
    int ret = 0;
    DefragContext *dc = NULL;

    /* Setup a small numberr of trackers. */
    if (ConfSet("defrag.trackers", "16", 1) != 1) {
        printf("ConfSet failed: ");
        goto end;
    }

    DefragInit();

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;

    /* Load in 16 packets. */
    for (i = 0; i < 16; i++) {
        Packet *p = BuildTestPacket(i, 0, 1, 'A' + i, 16);
        if (p == NULL)
            goto end;

        Packet *tp = Defrag(NULL, NULL, dc, p);

        SCFree(p);

        if (tp != NULL) {
            SCFree(tp);
            goto end;
        }
    }

    /* Build a new packet but push the timestamp out by our timeout.
     * This should force our previous fragments to be timed out. */
    Packet *p = BuildTestPacket(99, 0, 1, 'A' + i, 16);
    if (p == NULL)
        goto end;

    p->ts.tv_sec += (dc->timeout + 1);
    Packet *tp = Defrag(NULL, NULL, dc, p);

    SCFree(p);

    if (tp != NULL) {
        SCFree(tp);
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

/**
 * QA found that if you send a packet where more frags is 0, offset is
 * > 0 and there is no data in the packet that the re-assembler will
 * fail.  The fix was simple, but this unit test is just to make sure
 * its not introduced.
 */
static int
DefragIPv4NoDataTest(void)
{
    DefragContext *dc = NULL;
    Packet *p = NULL;
    int id = 12;
    int ret = 0;

    DefragInit();

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;

    /* This packet has an offset > 0, more frags set to 0 and no data. */
    p = BuildTestPacket(id, 1, 0, 'A', 0);
    if (p == NULL)
        goto end;

    /* We do not expect a packet returned. */
    if (Defrag(NULL, NULL, dc, p) != NULL)
        goto end;

    /* The fragment should have been ignored so no fragments should
     * have been allocated from the pool. */
    if (dc->frag_pool->outstanding != 0)
        return 0;

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p != NULL)
        SCFree(p);

    DefragDestroy();
    return ret;
}

static int
DefragIPv4TooLargeTest(void)
{
    DefragContext *dc = NULL;
    Packet *p = NULL;
    int ret = 0;

    DefragInit();

    dc = DefragContextNew();
    if (dc == NULL)
        goto end;

    /* Create a fragment that would extend past the max allowable size
     * for an IPv4 packet. */
    p = BuildTestPacket(1, 8183, 0, 'A', 71);
    if (p == NULL)
        goto end;

    /* We do not expect a packet returned. */
    if (Defrag(NULL, NULL, dc, p) != NULL)
        goto end;
    if (!ENGINE_ISSET_EVENT(p, IPV4_FRAG_PKT_TOO_LARGE))
        goto end;

    /* The fragment should have been ignored so no fragments should have
     * been allocated from the pool. */
    if (dc->frag_pool->outstanding != 0)
        return 0;

    ret = 1;
end:
    if (dc != NULL)
        DefragContextDestroy(dc);
    if (p != NULL)
        SCFree(p);

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
    UtRegisterTest("DefragReverseSimpleTest",
        DefragReverseSimpleTest, 1);
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

    UtRegisterTest("DefragIPv4NoDataTest", DefragIPv4NoDataTest, 1);
    UtRegisterTest("DefragIPv4TooLargeTest", DefragIPv4TooLargeTest, 1);

    UtRegisterTest("IPV6DefragInOrderSimpleTest",
        IPV6DefragInOrderSimpleTest, 1);
    UtRegisterTest("IPV6DefragReverseSimpleTest",
        IPV6DefragReverseSimpleTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakBsdTest",
        IPV6DefragSturgesNovakBsdTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakLinuxTest",
        IPV6DefragSturgesNovakLinuxTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakWindowsTest",
        IPV6DefragSturgesNovakWindowsTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakSolarisTest",
        IPV6DefragSturgesNovakSolarisTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakFirstTest",
        IPV6DefragSturgesNovakFirstTest, 1);
    UtRegisterTest("IPV6DefragSturgesNovakLastTest",
        IPV6DefragSturgesNovakLastTest, 1);

    UtRegisterTest("DefragTimeoutTest",
        DefragTimeoutTest, 1);
#endif /* UNITTESTS */
}

