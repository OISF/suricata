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
#ifdef DEBUG
#include "decode.h"
#include "defrag-queue.h"
#include "stream-tcp-private.h"
#include "util-random.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-pool.h"
#include "util-hashlist.h"
#include "decode-ipv6.h"
#include "conf.h"
#include "threads.h"
#include "suricata.h"
#include "queue.h"
#endif

#include "util-time.h"
#include "util-fix_checksum.h"
#include "stream-tcp-reassemble.h"
#include "util-host-os-info.h"
#include "util-validate.h"

#include "defrag.h"
#include "defrag-hash.h"
#include "defrag-config.h"

#include "tmqh-packetpool.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif

#include "util-validate.h"

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

static uint8_t default_policy = DEFRAG_POLICY_BSD;

/** The global DefragContext so all threads operate from the same
 * context. */
static DefragContext *defrag_context;

RB_GENERATE(IP_FRAGMENTS, Frag_, rb, DefragRbFragCompare);

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
 * \brief Reset a frag for reuse in a pool.
 */
static void
DefragFragReset(Frag *frag)
{
    if (frag->pkt != NULL)
        SCFree(frag->pkt);
    memset(frag, 0, sizeof(*frag));
}

/**
 * \brief Allocate a new frag for use in a pool.
 */
static int
DefragFragInit(void *data, void *initdata)
{
    Frag *frag = data;

    memset(frag, 0, sizeof(*frag));
    return 1;
}

/**
 * \brief Free all frags associated with a tracker.
 */
void
DefragTrackerFreeFrags(DefragTracker *tracker)
{
    Frag *frag, *tmp;

    /* Lock the frag pool as we'll be return items to it. */
    SCMutexLock(&defrag_context->frag_pool_lock);

    RB_FOREACH_SAFE(frag, IP_FRAGMENTS, &tracker->fragment_tree, tmp) {
        RB_REMOVE(IP_FRAGMENTS, &tracker->fragment_tree, frag);
        DefragFragReset(frag);
        PoolReturn(defrag_context->frag_pool, frag);
    }

    SCMutexUnlock(&defrag_context->frag_pool_lock);
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
    if (unlikely(dc == NULL))
        return NULL;

    /* Initialize the pool of trackers. */
    intmax_t tracker_pool_size;
    if (!ConfGetInt("defrag.trackers", &tracker_pool_size) || tracker_pool_size == 0) {
        tracker_pool_size = DEFAULT_DEFRAG_HASH_SIZE;
    }

    /* Initialize the pool of frags. */
    intmax_t frag_pool_size;
    if (!ConfGetInt("defrag.max-frags", &frag_pool_size) || frag_pool_size == 0) {
        frag_pool_size = DEFAULT_DEFRAG_POOL_SIZE;
    }
    intmax_t frag_pool_prealloc = frag_pool_size / 2;
    dc->frag_pool = PoolInit(frag_pool_size, frag_pool_prealloc,
        sizeof(Frag),
        NULL, DefragFragInit, dc, NULL, NULL);
    if (dc->frag_pool == NULL) {
            FatalError(SC_ERR_FATAL,
                       "Defrag: Failed to initialize fragment pool.");
    }
    if (SCMutexInit(&dc->frag_pool_lock, NULL) != 0) {
            FatalError(SC_ERR_FATAL,
                       "Defrag: Failed to initialize frag pool mutex.");
    }

    /* Set the default timeout. */
    intmax_t timeout;
    if (!ConfGetInt("defrag.timeout", &timeout)) {
        dc->timeout = TIMEOUT_DEFAULT;
    }
    else {
        if (timeout < TIMEOUT_MIN) {
                FatalError(SC_ERR_FATAL,
                           "defrag: Timeout less than minimum allowed value.");
        }
        else if (timeout > TIMEOUT_MAX) {
                FatalError(SC_ERR_FATAL,
                           "defrag: Tiemout greater than maximum allowed value.");
        }
        dc->timeout = timeout;
    }

    SCLogDebug("Defrag Initialized:");
    SCLogDebug("\tTimeout: %"PRIuMAX, (uintmax_t)dc->timeout);
    SCLogDebug("\tMaximum defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tPreallocated defrag trackers: %"PRIuMAX, tracker_pool_size);
    SCLogDebug("\tMaximum fragments: %"PRIuMAX, (uintmax_t)frag_pool_size);
    SCLogDebug("\tPreallocated fragments: %"PRIuMAX, (uintmax_t)frag_pool_prealloc);

    return dc;
}

static void
DefragContextDestroy(DefragContext *dc)
{
    if (dc == NULL)
        return;

    PoolFree(dc->frag_pool);
    SCFree(dc);
}

/**
 * Attempt to re-assemble a packet.
 *
 * \param tracker The defragmentation tracker to reassemble from.
 */
static Packet *
Defrag4Reassemble(ThreadVars *tv, DefragTracker *tracker, Packet *p)
{
    Packet *rp = NULL;

    /* Should not be here unless we have seen the last fragment. */
    if (!tracker->seen_last) {
        return NULL;
    }

    /* Check that we have the first fragment and its of a valid size. */
    Frag *first = RB_MIN(IP_FRAGMENTS, &tracker->fragment_tree);
    if (first == NULL) {
        goto done;
    } else if (first->offset != 0) {
        /* Still waiting for the first fragment. */
        goto done;
    } else if (first->len < sizeof(IPV4Hdr)) {
        /* First fragment isn't enough for an IPv6 header. */
        goto error_remove_tracker;
    }

    /* Check that we have all the data. Relies on the fact that
     * fragments are inserted if frag_offset order. */
    Frag *frag = NULL;
    size_t len = 0;
    RB_FOREACH_FROM(frag, IP_FRAGMENTS, first) {
        if (frag->offset > len) {
            /* This fragment starts after the end of the previous
             * fragment.  We have a hole. */
            goto done;
        }
        else {
            len += frag->data_len;
        }
    }

    /* Allocate a Packet for the reassembled packet.  On failure we
     * SCFree all the resources held by this tracker. */
    rp = PacketDefragPktSetup(p, NULL, 0, IPV4_GET_IPPROTO(p));
    if (rp == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate packet for "
                   "fragmentation re-assembly, dumping fragments.");
        goto error_remove_tracker;
    }
    PKT_SET_SRC(rp, PKT_SRC_DEFRAG);
    rp->flags |= PKT_REBUILT_FRAGMENT;
    rp->recursion_level = p->recursion_level;

    int fragmentable_offset = 0;
    int fragmentable_len = 0;
    int hlen = 0;
    int ip_hdr_offset = 0;

    RB_FOREACH(frag, IP_FRAGMENTS, &tracker->fragment_tree) {
        SCLogDebug("frag %p, data_len %u, offset %u, pcap_cnt %"PRIu64,
                frag, frag->data_len, frag->offset, frag->pcap_cnt);

        if (frag->skip)
            continue;
        if (frag->ltrim >= frag->data_len)
            continue;
        if (frag->offset == 0) {

            if (PacketCopyData(rp, frag->pkt, frag->len) == -1)
                goto error_remove_tracker;

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
                goto error_remove_tracker;
            }
            if (PacketCopyDataOffset(rp,
                    fragmentable_offset + frag->offset + frag->ltrim,
                    frag->pkt + frag->data_offset + frag->ltrim,
                    frag->data_len - frag->ltrim) == -1) {
                goto error_remove_tracker;
            }
            if (frag->offset + frag->data_len > fragmentable_len)
                fragmentable_len = frag->offset + frag->data_len;
        }

        if (!frag->more_frags) {
            break;
        }
    }

    SCLogDebug("ip_hdr_offset %u, hlen %u, fragmentable_len %u",
            ip_hdr_offset, hlen, fragmentable_len);

    rp->ip4h = (IPV4Hdr *)(GET_PKT_DATA(rp) + ip_hdr_offset);
    uint16_t old = rp->ip4h->ip_len + rp->ip4h->ip_off;
    rp->ip4h->ip_len = htons(fragmentable_len + hlen);
    rp->ip4h->ip_off = 0;
    rp->ip4h->ip_csum = FixChecksum(rp->ip4h->ip_csum,
        old, rp->ip4h->ip_len + rp->ip4h->ip_off);
    SET_PKT_LEN(rp, ip_hdr_offset + hlen + fragmentable_len);

    tracker->remove = 1;
    DefragTrackerFreeFrags(tracker);
done:
    return rp;

error_remove_tracker:
    tracker->remove = 1;
    DefragTrackerFreeFrags(tracker);
    if (rp != NULL)
        PacketFreeOrRelease(rp);
    return NULL;
}

/**
 * Attempt to re-assemble a packet.
 *
 * \param tracker The defragmentation tracker to reassemble from.
 */
static Packet *
Defrag6Reassemble(ThreadVars *tv, DefragTracker *tracker, Packet *p)
{
    Packet *rp = NULL;

    /* Should not be here unless we have seen the last fragment. */
    if (!tracker->seen_last)
        return NULL;

    /* Check that we have the first fragment and its of a valid size. */
    Frag *first = RB_MIN(IP_FRAGMENTS, &tracker->fragment_tree);
    if (first == NULL) {
        goto done;
    } else if (first->offset != 0) {
        /* Still waiting for the first fragment. */
        goto done;
    } else if (first->len < sizeof(IPV6Hdr)) {
        /* First fragment isn't enough for an IPv6 header. */
        goto error_remove_tracker;
    }

    /* Check that we have all the data. Relies on the fact that
     * fragments are inserted if frag_offset order. */
    size_t len = 0;
    Frag *frag = NULL;
    RB_FOREACH_FROM(frag, IP_FRAGMENTS, first) {
        if (frag->skip) {
            continue;
        }

        if (frag == first) {
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
        goto error_remove_tracker;
    }
    PKT_SET_SRC(rp, PKT_SRC_DEFRAG);

    int unfragmentable_len = 0;
    int fragmentable_offset = 0;
    int fragmentable_len = 0;
    int ip_hdr_offset = 0;
    uint8_t next_hdr = 0;
    RB_FOREACH(frag, IP_FRAGMENTS, &tracker->fragment_tree) {
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
                goto error_remove_tracker;
            if (PacketCopyDataOffset(rp, frag->frag_hdr_offset,
                frag->pkt + frag->frag_hdr_offset + sizeof(IPV6FragHdr),
                frag->data_len) == -1)
                goto error_remove_tracker;
            ip_hdr_offset = frag->ip_hdr_offset;

            /* This is the start of the fragmentable portion of the
             * first packet.  All fragment offsets are relative to
             * this. */
            fragmentable_offset = frag->frag_hdr_offset;
            fragmentable_len = frag->data_len;

            /* unfragmentable part is the part between the ipv6 header
             * and the frag header. */
            unfragmentable_len = (fragmentable_offset - ip_hdr_offset) - IPV6_HEADER_LEN;
            if (unfragmentable_len >= fragmentable_offset)
                goto error_remove_tracker;
        }
        else {
            if (PacketCopyDataOffset(rp, fragmentable_offset + frag->offset + frag->ltrim,
                frag->pkt + frag->data_offset + frag->ltrim,
                frag->data_len - frag->ltrim) == -1)
                goto error_remove_tracker;
            if (frag->offset + frag->data_len > fragmentable_len)
                fragmentable_len = frag->offset + frag->data_len;
        }

        if (!frag->more_frags) {
            break;
        }
    }

    rp->ip6h = (IPV6Hdr *)(GET_PKT_DATA(rp) + ip_hdr_offset);
    rp->ip6h->s_ip6_plen = htons(fragmentable_len + unfragmentable_len);
    /* if we have no unfragmentable part, so no ext hdrs before the frag
     * header, we need to update the ipv6 headers next header field. This
     * points to the frag header, and we will make it point to the layer
     * directly after the frag header. */
    if (unfragmentable_len == 0)
        rp->ip6h->s_ip6_nxt = next_hdr;
    SET_PKT_LEN(rp, ip_hdr_offset + sizeof(IPV6Hdr) +
            unfragmentable_len + fragmentable_len);

    tracker->remove = 1;
    DefragTrackerFreeFrags(tracker);
done:
    return rp;

error_remove_tracker:
    tracker->remove = 1;
    DefragTrackerFreeFrags(tracker);
    if (rp != NULL)
        PacketFreeOrRelease(rp);
    return NULL;
}

/**
 * The RB_TREE compare function for fragments.
 *
 * When it comes to adding fragments, we want subsequent ones with the
 * same offset to be treated as greater than, so we don't have an
 * equal return value here.
 */
int DefragRbFragCompare(struct Frag_ *a, struct Frag_ *b) {
    if (a->offset < b->offset) {
        return -1;
    }
    return 1;
}

/**
 * Insert a new IPv4/IPv6 fragment into a tracker.
 *
 * \todo Allocate packet buffers from a pool.
 */
static Packet *
DefragInsertFrag(ThreadVars *tv, DecodeThreadVars *dtv, DefragTracker *tracker, Packet *p)
{
    Packet *r = NULL;
    uint16_t ltrim = 0;

    uint8_t more_frags;
    uint16_t frag_offset;

    /* IPv4 header length - IPv4 only. */
    uint8_t hlen = 0;

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

    /* settings for updating a payload when an ip6 fragment with
     * unfragmentable exthdrs are encountered. */
    uint32_t ip6_nh_set_offset = 0;
    uint8_t ip6_nh_set_value = 0;

#ifdef DEBUG
    uint64_t pcap_cnt = p->pcap_cnt;
#endif

    if (tracker->af == AF_INET) {
        more_frags = IPV4_GET_MF(p);
        frag_offset = (uint16_t)(IPV4_GET_IPOFFSET(p) << 3);
        hlen = IPV4_GET_HLEN(p);
        data_offset = (uint16_t)((uint8_t *)p->ip4h + hlen - GET_PKT_DATA(p));
        data_len = IPV4_GET_IPLEN(p) - hlen;
        frag_end = frag_offset + data_len;
        ip_hdr_offset = (uint16_t)((uint8_t *)p->ip4h - GET_PKT_DATA(p));

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
        data_offset = p->ip6eh.fh_data_offset;
        data_len = p->ip6eh.fh_data_len;
        frag_end = frag_offset + data_len;
        ip_hdr_offset = (uint16_t)((uint8_t *)p->ip6h - GET_PKT_DATA(p));
        frag_hdr_offset = p->ip6eh.fh_header_offset;

        SCLogDebug("mf %s frag_offset %u data_offset %u, data_len %u, "
                "frag_end %u, ip_hdr_offset %u, frag_hdr_offset %u",
                more_frags ? "true" : "false", frag_offset, data_offset,
                data_len, frag_end, ip_hdr_offset, frag_hdr_offset);

        /* handle unfragmentable exthdrs */
        if (ip_hdr_offset + IPV6_HEADER_LEN < frag_hdr_offset) {
            SCLogDebug("we have exthdrs before fraghdr %u bytes",
                    (uint32_t)(frag_hdr_offset - (ip_hdr_offset + IPV6_HEADER_LEN)));

            /* get the offset of the 'next' field in exthdr before the FH,
             * relative to the buffer start */

            /* store offset and FH 'next' value for updating frag buffer below */
            ip6_nh_set_offset = p->ip6eh.fh_prev_hdr_offset;
            ip6_nh_set_value = IPV6_EXTHDR_GET_FH_NH(p);
            SCLogDebug("offset %d, value %u", ip6_nh_set_offset, ip6_nh_set_value);
        }

        /* Ignore fragment if the end of packet extends past the
         * maximum size of a packet. */
        if (frag_offset + data_len > IPV6_MAXPACKET) {
            ENGINE_SET_EVENT(p, IPV6_FRAG_PKT_TOO_LARGE);
            return NULL;
        }
    }
    else {
        DEBUG_VALIDATE_BUG_ON(1);
        return NULL;
    }

    /* Update timeout. */
    tracker->timeout = TimevalWithSeconds(&p->ts, tracker->host_timeout);

    Frag *prev = NULL, *next = NULL;
    bool overlap = false;
    ltrim = 0;

    if (!RB_EMPTY(&tracker->fragment_tree)) {
        Frag key = {
            .offset = frag_offset - 1,
        };
        next = RB_NFIND(IP_FRAGMENTS, &tracker->fragment_tree, &key);
        if (next == NULL) {
            prev = RB_MIN(IP_FRAGMENTS, &tracker->fragment_tree);
            next = IP_FRAGMENTS_RB_NEXT(prev);
        } else {
            prev = IP_FRAGMENTS_RB_PREV(next);
            if (prev == NULL) {
                prev = next;
                next = IP_FRAGMENTS_RB_NEXT(prev);
            }
        }
        while (prev != NULL) {
            if (prev->skip) {
                goto next;
            }
            if (frag_offset < prev->offset + prev->data_len && prev->offset < frag_end) {
                overlap = true;
            }

            switch (tracker->policy) {
            case DEFRAG_POLICY_BSD:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset >= prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                    }
                    if ((next != NULL) && (frag_end > next->offset)) {
                        next->ltrim = frag_end - next->offset;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end >= prev->offset + prev->data_len)) {
                        prev->skip = 1;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_LINUX:
                /* Check if new fragment overlaps the end of previous
                 * fragment, if it does, trim the new fragment.
                 *
                 * Old: AAAAAAAA AAAAAAAA AAAAAAAA
                 * New:          BBBBBBBB BBBBBBBB BBBBBBBB
                 * Res: AAAAAAAA AAAAAAAA AAAAAAAA BBBBBBBB
                 */
                if (prev->offset + prev->ltrim < frag_offset + ltrim &&
                        prev->offset + prev->data_len > frag_offset + ltrim) {
                    ltrim += prev->offset + prev->data_len - frag_offset;
                }

                /* Check if new fragment overlaps the beginning of
                 * previous fragment, if it does, tim the previous
                 * fragment.
                 *
                 * Old:          AAAAAAAA AAAAAAAA
                 * New: BBBBBBBB BBBBBBBB BBBBBBBB
                 * Res: BBBBBBBB BBBBBBBB BBBBBBBB
                 */
                if (frag_offset + ltrim < prev->offset + prev->ltrim &&
                        frag_end > prev->offset + prev->ltrim) {
                    prev->ltrim += frag_end - (prev->offset + prev->ltrim);
                    goto insert;
                }

                /* If the new fragment completely overlaps the
                 * previous fragment, mark the previous to be
                 * skipped. Re-assembly would succeed without doing
                 * this, but this will prevent the bytes from being
                 * copied just to be overwritten. */
                if (frag_offset + ltrim <= prev->offset + prev->ltrim &&
                        frag_end >= prev->offset + prev->data_len) {
                    prev->skip = 1;
                    goto insert;
                }

                break;
            case DEFRAG_POLICY_WINDOWS:
                /* If new fragment fits inside a previous fragment, drop it. */
                if (frag_offset + ltrim >= prev->offset + ltrim &&
                        frag_end <= prev->offset + prev->data_len) {
                    goto done;
                }

                /* If new fragment starts before and ends after
                 * previous fragment, drop the previous fragment. */
                if (frag_offset + ltrim < prev->offset + ltrim &&
                        frag_end > prev->offset + prev->data_len) {
                    prev->skip = 1;
                    goto insert;
                }

                /* Check if new fragment overlaps the end of previous
                 * fragment, if it does, trim the new fragment.
                 *
                 * Old: AAAAAAAA AAAAAAAA AAAAAAAA
                 * New:          BBBBBBBB BBBBBBBB BBBBBBBB
                 * Res: AAAAAAAA AAAAAAAA AAAAAAAA BBBBBBBB
                 */
                if (frag_offset + ltrim > prev->offset + prev->ltrim &&
                        frag_offset + ltrim < prev->offset + prev->data_len) {
                    ltrim += prev->offset + prev->data_len - frag_offset;
                    goto insert;
                }

                /* If new fragment starts at same offset as an
                 * existing fragment, but ends after it, trim the new
                 * fragment. */
                if (frag_offset + ltrim == prev->offset + ltrim &&
                        frag_end > prev->offset + prev->data_len) {
                    ltrim += prev->offset + prev->data_len - frag_offset;
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_SOLARIS:
                if (frag_offset < prev->offset + prev->data_len) {
                    if (frag_offset >= prev->offset) {
                        ltrim = prev->offset + prev->data_len - frag_offset;
                    }
                    if ((frag_offset < prev->offset) &&
                        (frag_end >= prev->offset + prev->data_len)) {
                        prev->skip = 1;
                    }
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_FIRST:
                if ((frag_offset >= prev->offset) &&
                    (frag_end <= prev->offset + prev->data_len)) {
                    goto done;
                }
                if (frag_offset < prev->offset) {
                    goto insert;
                }
                if (frag_offset < prev->offset + prev->data_len) {
                    ltrim = prev->offset + prev->data_len - frag_offset;
                    goto insert;
                }
                break;
            case DEFRAG_POLICY_LAST:
                if (frag_offset <= prev->offset) {
                    if (frag_end > prev->offset) {
                        prev->ltrim = frag_end - prev->offset;
                    }
                    goto insert;
                }
                break;
            default:
                break;
            }

        next:
            prev = next;
            if (next != NULL) {
                next = IP_FRAGMENTS_RB_NEXT(next);
            }
            continue;

        insert:
            /* If existing fragment has been trimmed up completely
             * (complete overlap), remove it now instead of holding
             * onto it. */
            if (prev->skip || prev->ltrim >= prev->data_len) {
                RB_REMOVE(IP_FRAGMENTS, &tracker->fragment_tree, prev);
                DefragFragReset(prev);
                SCMutexLock(&defrag_context->frag_pool_lock);
                PoolReturn(defrag_context->frag_pool, prev);
                SCMutexUnlock(&defrag_context->frag_pool_lock);
            }
            break;
        }
    }

    if (ltrim > data_len) {
        /* Full packet has been trimmed due to the overlap policy. Overlap
         * already set. */
        goto done;
    }

    /* Allocate fragment and insert. */
    SCMutexLock(&defrag_context->frag_pool_lock);
    Frag *new = PoolGet(defrag_context->frag_pool);
    SCMutexUnlock(&defrag_context->frag_pool_lock);
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
        SCMutexLock(&defrag_context->frag_pool_lock);
        PoolReturn(defrag_context->frag_pool, new);
        SCMutexUnlock(&defrag_context->frag_pool_lock);
        if (af == AF_INET) {
            ENGINE_SET_EVENT(p, IPV4_FRAG_IGNORED);
        } else {
            ENGINE_SET_EVENT(p, IPV6_FRAG_IGNORED);
        }
        goto done;
    }
    memcpy(new->pkt, GET_PKT_DATA(p) + ltrim, GET_PKT_LEN(p) - ltrim);
    new->len = (GET_PKT_LEN(p) - ltrim);
    /* in case of unfragmentable exthdrs, update the 'next hdr' field
     * in the raw buffer so the reassembled packet will point to the
     * correct next header after stripping the frag header */
    if (ip6_nh_set_offset > 0 && frag_offset == 0 && ltrim == 0) {
        if (new->len > ip6_nh_set_offset) {
            SCLogDebug("updating frag to have 'correct' nh value: %u -> %u",
                    new->pkt[ip6_nh_set_offset], ip6_nh_set_value);
            new->pkt[ip6_nh_set_offset] = ip6_nh_set_value;
        }
    }

    new->hlen = hlen;
    new->offset = frag_offset + ltrim;
    new->data_offset = data_offset;
    new->data_len = data_len - ltrim;
    new->ip_hdr_offset = ip_hdr_offset;
    new->frag_hdr_offset = frag_hdr_offset;
    new->more_frags = more_frags;
#ifdef DEBUG
    new->pcap_cnt = pcap_cnt;
#endif

    IP_FRAGMENTS_RB_INSERT(&tracker->fragment_tree, new);

    if (!more_frags) {
        tracker->seen_last = 1;
    }

    if (tracker->seen_last) {
        if (tracker->af == AF_INET) {
            r = Defrag4Reassemble(tv, tracker, p);
            if (r != NULL && tv != NULL && dtv != NULL) {
                StatsIncr(tv, dtv->counter_defrag_ipv4_reassembled);
                if (DecodeIPV4(tv, dtv, r, (void *)r->ip4h,
                               IPV4_GET_IPLEN(r)) != TM_ECODE_OK) {

                    UNSET_TUNNEL_PKT(r);
                    r->root = NULL;
                    TmqhOutputPacketpool(tv, r);
                    r = NULL;
                } else {
                    PacketDefragPktSetupParent(p);
                }
            }
        }
        else if (tracker->af == AF_INET6) {
            r = Defrag6Reassemble(tv, tracker, p);
            if (r != NULL && tv != NULL && dtv != NULL) {
                StatsIncr(tv, dtv->counter_defrag_ipv6_reassembled);
                if (DecodeIPV6(tv, dtv, r, (uint8_t *)r->ip6h,
                               IPV6_GET_PLEN(r) + IPV6_HEADER_LEN)
                               != TM_ECODE_OK) {

                    UNSET_TUNNEL_PKT(r);
                    r->root = NULL;
                    TmqhOutputPacketpool(tv, r);
                    r = NULL;
                } else {
                    PacketDefragPktSetupParent(p);
                }
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
    return r;
}

/**
 * \brief Get the defrag policy based on the destination address of
 * the packet.
 *
 * \param p The packet used to get the destination address.
 *
 * \retval The defrag policy to use.
 */
uint8_t
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

/** \internal
 *
 *  \retval NULL or a *LOCKED* tracker */
static DefragTracker *
DefragGetTracker(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    return DefragGetTrackerFromHash(p);
}

/**
 * \brief Entry point for IPv4 and IPv6 fragments.
 *
 * \param tv ThreadVars for the calling decoder.
 * \param p The packet fragment.
 *
 * \retval A new Packet resembling the re-assembled packet if the most
 *     recent fragment allowed the packet to be re-assembled, otherwise
 *     NULL is returned.
 */
Packet *
Defrag(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    uint16_t frag_offset;
    uint8_t more_frags;
    DefragTracker *tracker;
    int af;

    if (PKT_IS_IPV4(p)) {
        af = AF_INET;
        more_frags = IPV4_GET_MF(p);
        frag_offset = IPV4_GET_IPOFFSET(p);
    }
    else if (PKT_IS_IPV6(p)) {
        af = AF_INET6;
        frag_offset = IPV6_EXTHDR_GET_FH_OFFSET(p);
        more_frags = IPV6_EXTHDR_GET_FH_FLAG(p);
    }
    else {
        return NULL;
    }

    if (frag_offset == 0 && more_frags == 0) {
        return NULL;
    }

    if (tv != NULL && dtv != NULL) {
        if (af == AF_INET) {
            StatsIncr(tv, dtv->counter_defrag_ipv4_fragments);
        }
        else if (af == AF_INET6) {
            StatsIncr(tv, dtv->counter_defrag_ipv6_fragments);
        }
    }

    /* return a locked tracker or NULL */
    tracker = DefragGetTracker(tv, dtv, p);
    if (tracker == NULL)
        return NULL;

    Packet *rp = DefragInsertFrag(tv, dtv, tracker, p);
    DefragTrackerRelease(tracker);

    return rp;
}

void
DefragInit(void)
{
    intmax_t tracker_pool_size;
    if (!ConfGetInt("defrag.trackers", &tracker_pool_size)) {
        tracker_pool_size = DEFAULT_DEFRAG_HASH_SIZE;
    }

    /* Load the defrag-per-host lookup. */
    DefragPolicyLoadFromConfig();

    /* Allocate the DefragContext. */
    defrag_context = DefragContextNew();
    if (defrag_context == NULL) {
            FatalError(SC_ERR_FATAL,
                       "Failed to allocate memory for the Defrag module.");
    }

    DefragSetDefaultTimeout(defrag_context->timeout);
    DefragInitConfig(false);
}

void DefragDestroy(void)
{
    DefragHashShutdown();
    DefragContextDestroy(defrag_context);
    defrag_context = NULL;
    DefragTreeDestroy();
}

#ifdef UNITTESTS
#define IP_MF 0x2000

/**
 * Allocate a test packet.  Nothing to fancy, just a simple IP packet
 * with some payload of no particular protocol.
 */
static Packet *BuildTestPacket(uint8_t proto, uint16_t id, uint16_t off, int mf,
        const char content, int content_len)
{
    Packet *p = NULL;
    int hlen = 20;
    int ttl = 64;
    uint8_t *pcontent;
    IPV4Hdr ip4h;

    p = SCCalloc(1, sizeof(*p) + default_packet_size);
    if (unlikely(p == NULL))
        return NULL;

    PACKET_INITIALIZE(p);

    gettimeofday(&p->ts, NULL);
    //p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    ip4h.ip_verhl = 4 << 4;
    ip4h.ip_verhl |= hlen >> 2;
    ip4h.ip_len = htons(hlen + content_len);
    ip4h.ip_id = htons(id);
    if (mf)
        ip4h.ip_off = htons(IP_MF | off);
    else
        ip4h.ip_off = htons(off);
    ip4h.ip_ttl = ttl;
    ip4h.ip_proto = proto;

    ip4h.s_ip_src.s_addr = 0x01010101; /* 1.1.1.1 */
    ip4h.s_ip_dst.s_addr = 0x02020202; /* 2.2.2.2 */

    /* copy content_len crap, we need full length */
    PacketCopyData(p, (uint8_t *)&ip4h, sizeof(ip4h));
    p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    SET_IPV4_SRC_ADDR(p, &p->src);
    SET_IPV4_DST_ADDR(p, &p->dst);

    pcontent = SCCalloc(1, content_len);
    if (unlikely(pcontent == NULL))
        return NULL;
    memset(pcontent, content, content_len);
    PacketCopyDataOffset(p, hlen, pcontent, content_len);
    SET_PKT_LEN(p, hlen + content_len);
    SCFree(pcontent);

    p->ip4h->ip_csum = IPV4Checksum((uint16_t *)GET_PKT_DATA(p), hlen, 0);

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
    if (IPV4_GET_IPPROTO(p) != proto)
        goto error;

    return p;
error:
    if (p != NULL)
        SCFree(p);
    return NULL;
}

static Packet *IPV6BuildTestPacket(uint8_t proto, uint32_t id, uint16_t off,
        int mf, const char content, int content_len)
{
    Packet *p = NULL;
    uint8_t *pcontent;
    IPV6Hdr ip6h;

    p = SCCalloc(1, sizeof(*p) + default_packet_size);
    if (unlikely(p == NULL))
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
    PacketCopyData(p, (uint8_t *)&ip6h, sizeof(IPV6Hdr));

    p->ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    IPV6_SET_RAW_VER(p->ip6h, 6);
    /* Fragmentation header. */
    IPV6FragHdr *fh = (IPV6FragHdr *)(GET_PKT_DATA(p) + sizeof(IPV6Hdr));
    fh->ip6fh_nxt = proto;
    fh->ip6fh_ident = htonl(id);
    fh->ip6fh_offlg = htons((off << 3) | mf);

    DecodeIPV6FragHeader(p, (uint8_t *)fh, 8, 8 + content_len, 0);

    pcontent = SCCalloc(1, content_len);
    if (unlikely(pcontent == NULL))
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
    if (p != NULL)
        SCFree(p);
    return NULL;
}

/**
 * Test the simplest possible re-assembly scenario.  All packet in
 * order and no overlaps.
 */
static int DefragInOrderSimpleTest(void)
{
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Packet *reassembled = NULL;
    int id = 12;
    int i;

    DefragInit();

    p1 = BuildTestPacket(IPPROTO_ICMP, id, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = BuildTestPacket(IPPROTO_ICMP, id, 1, 1, 'B', 8);
    FAIL_IF_NULL(p2);
    p3 = BuildTestPacket(IPPROTO_ICMP, id, 2, 0, 'C', 3);
    FAIL_IF_NULL(p3);

    FAIL_IF(Defrag(NULL, NULL, p1) != NULL);
    FAIL_IF(Defrag(NULL, NULL, p2) != NULL);

    reassembled = Defrag(NULL, NULL, p3);
    FAIL_IF_NULL(reassembled);

    FAIL_IF(IPV4_GET_HLEN(reassembled) != 20);
    FAIL_IF(IPV4_GET_IPLEN(reassembled) != 39);

    /* 20 bytes in we should find 8 bytes of A. */
    for (i = 20; i < 20 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'A');
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 28; i < 28 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'B');
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 36; i < 36 + 3; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'C');
    }

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(reassembled);

    DefragDestroy();
    PASS;
}

/**
 * Simple fragmented packet in reverse order.
 */
static int DefragReverseSimpleTest(void)
{
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Packet *reassembled = NULL;
    int id = 12;
    int i;

    DefragInit();

    p1 = BuildTestPacket(IPPROTO_ICMP, id, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = BuildTestPacket(IPPROTO_ICMP, id, 1, 1, 'B', 8);
    FAIL_IF_NULL(p2);
    p3 = BuildTestPacket(IPPROTO_ICMP, id, 2, 0, 'C', 3);
    FAIL_IF_NULL(p3);

    FAIL_IF(Defrag(NULL, NULL, p3) != NULL);
    FAIL_IF(Defrag(NULL, NULL, p2) != NULL);

    reassembled = Defrag(NULL, NULL, p1);
    FAIL_IF_NULL(reassembled);

    FAIL_IF(IPV4_GET_HLEN(reassembled) != 20);
    FAIL_IF(IPV4_GET_IPLEN(reassembled) != 39);

    /* 20 bytes in we should find 8 bytes of A. */
    for (i = 20; i < 20 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'A');
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 28; i < 28 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'B');
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 36; i < 36 + 3; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'C');
    }

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(reassembled);

    DefragDestroy();
    PASS;
}

/**
 * Test the simplest possible re-assembly scenario.  All packet in
 * order and no overlaps.
 */
static int IPV6DefragInOrderSimpleTest(void)
{
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Packet *reassembled = NULL;
    int id = 12;
    int i;

    DefragInit();

    p1 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 1, 1, 'B', 8);
    FAIL_IF_NULL(p2);
    p3 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 2, 0, 'C', 3);
    FAIL_IF_NULL(p3);

    FAIL_IF(Defrag(NULL, NULL, p1) != NULL);
    FAIL_IF(Defrag(NULL, NULL, p2) != NULL);
    reassembled = Defrag(NULL, NULL, p3);
    FAIL_IF_NULL(reassembled);

    FAIL_IF(IPV6_GET_PLEN(reassembled) != 19);

    /* 40 bytes in we should find 8 bytes of A. */
    for (i = 40; i < 40 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'A');
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 48; i < 48 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'B');
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 56; i < 56 + 3; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'C');
    }

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(reassembled);

    DefragDestroy();
    PASS;
}

static int IPV6DefragReverseSimpleTest(void)
{
    DefragContext *dc = NULL;
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    Packet *reassembled = NULL;
    int id = 12;
    int i;

    DefragInit();

    dc = DefragContextNew();
    FAIL_IF_NULL(dc);

    p1 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 1, 1, 'B', 8);
    FAIL_IF_NULL(p2);
    p3 = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 2, 0, 'C', 3);
    FAIL_IF_NULL(p3);

    FAIL_IF(Defrag(NULL, NULL, p3) != NULL);
    FAIL_IF(Defrag(NULL, NULL, p2) != NULL);
    reassembled = Defrag(NULL, NULL, p1);
    FAIL_IF_NULL(reassembled);

    /* 40 bytes in we should find 8 bytes of A. */
    for (i = 40; i < 40 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'A');
    }

    /* 28 bytes in we should find 8 bytes of B. */
    for (i = 48; i < 48 + 8; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'B');
    }

    /* And 36 bytes in we should find 3 bytes of C. */
    for (i = 56; i < 56 + 3; i++) {
        FAIL_IF(GET_PKT_DATA(reassembled)[i] != 'C');
    }

    DefragContextDestroy(dc);
    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(reassembled);

    DefragDestroy();
    PASS;
}

static int DefragDoSturgesNovakTest(int policy, u_char *expected,
        size_t expected_len)
{
    int i;

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
    packets[0] = BuildTestPacket(IPPROTO_ICMP, id, 0, 1, 'A', 24);

    /* B*15 at 32. */
    packets[1] = BuildTestPacket(IPPROTO_ICMP, id, 32 >> 3, 1, 'B', 16);

    /* C*24 at 48. */
    packets[2] = BuildTestPacket(IPPROTO_ICMP, id, 48 >> 3, 1, 'C', 24);

    /* D*8 at 80. */
    packets[3] = BuildTestPacket(IPPROTO_ICMP, id, 80 >> 3, 1, 'D', 8);

    /* E*16 at 104. */
    packets[4] = BuildTestPacket(IPPROTO_ICMP, id, 104 >> 3, 1, 'E', 16);

    /* F*24 at 120. */
    packets[5] = BuildTestPacket(IPPROTO_ICMP, id, 120 >> 3, 1, 'F', 24);

    /* G*16 at 144. */
    packets[6] = BuildTestPacket(IPPROTO_ICMP, id, 144 >> 3, 1, 'G', 16);

    /* H*16 at 160. */
    packets[7] = BuildTestPacket(IPPROTO_ICMP, id, 160 >> 3, 1, 'H', 16);

    /* I*8 at 176. */
    packets[8] = BuildTestPacket(IPPROTO_ICMP, id, 176 >> 3, 1, 'I', 8);

    /*
     * Overlapping subsequent fragments.
     */

    /* J*32 at 8. */
    packets[9] = BuildTestPacket(IPPROTO_ICMP, id, 8 >> 3, 1, 'J', 32);

    /* K*24 at 48. */
    packets[10] = BuildTestPacket(IPPROTO_ICMP, id, 48 >> 3, 1, 'K', 24);

    /* L*24 at 72. */
    packets[11] = BuildTestPacket(IPPROTO_ICMP, id, 72 >> 3, 1, 'L', 24);

    /* M*24 at 96. */
    packets[12] = BuildTestPacket(IPPROTO_ICMP, id, 96 >> 3, 1, 'M', 24);

    /* N*8 at 128. */
    packets[13] = BuildTestPacket(IPPROTO_ICMP, id, 128 >> 3, 1, 'N', 8);

    /* O*8 at 152. */
    packets[14] = BuildTestPacket(IPPROTO_ICMP, id, 152 >> 3, 1, 'O', 8);

    /* P*8 at 160. */
    packets[15] = BuildTestPacket(IPPROTO_ICMP, id, 160 >> 3, 1, 'P', 8);

    /* Q*16 at 176. */
    packets[16] = BuildTestPacket(IPPROTO_ICMP, id, 176 >> 3, 0, 'Q', 16);

    default_policy = policy;

    /* Send all but the last. */
    for (i = 0; i < 9; i++) {
        Packet *tp = Defrag(NULL, NULL, packets[i]);
        FAIL_IF_NOT_NULL(tp);
        FAIL_IF(ENGINE_ISSET_EVENT(packets[i], IPV4_FRAG_OVERLAP));
    }
    int overlap = 0;
    for (; i < 16; i++) {
        Packet *tp = Defrag(NULL, NULL, packets[i]);
        FAIL_IF_NOT_NULL(tp);
        if (ENGINE_ISSET_EVENT(packets[i], IPV4_FRAG_OVERLAP)) {
            overlap++;
        }
    }
    FAIL_IF_NOT(overlap);

    /* And now the last one. */
    Packet *reassembled = Defrag(NULL, NULL, packets[16]);
    FAIL_IF_NULL(reassembled);

    FAIL_IF(IPV4_GET_HLEN(reassembled) != 20);
    FAIL_IF(IPV4_GET_IPLEN(reassembled) != 20 + 192);

    FAIL_IF(memcmp(GET_PKT_DATA(reassembled) + 20, expected, expected_len) != 0);
    SCFree(reassembled);

    /* Make sure all frags were returned back to the pool. */
    FAIL_IF(defrag_context->frag_pool->outstanding != 0);

    for (i = 0; i < 17; i++) {
        SCFree(packets[i]);
    }
    DefragDestroy();
    PASS;
}

static int IPV6DefragDoSturgesNovakTest(int policy, u_char *expected,
        size_t expected_len)
{
    int i;

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
    packets[0] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 0, 1, 'A', 24);

    /* B*15 at 32. */
    packets[1] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 32 >> 3, 1, 'B', 16);

    /* C*24 at 48. */
    packets[2] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 48 >> 3, 1, 'C', 24);

    /* D*8 at 80. */
    packets[3] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 80 >> 3, 1, 'D', 8);

    /* E*16 at 104. */
    packets[4] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 104 >> 3, 1, 'E', 16);

    /* F*24 at 120. */
    packets[5] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 120 >> 3, 1, 'F', 24);

    /* G*16 at 144. */
    packets[6] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 144 >> 3, 1, 'G', 16);

    /* H*16 at 160. */
    packets[7] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 160 >> 3, 1, 'H', 16);

    /* I*8 at 176. */
    packets[8] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 176 >> 3, 1, 'I', 8);

    /*
     * Overlapping subsequent fragments.
     */

    /* J*32 at 8. */
    packets[9] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 8 >> 3, 1, 'J', 32);

    /* K*24 at 48. */
    packets[10] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 48 >> 3, 1, 'K', 24);

    /* L*24 at 72. */
    packets[11] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 72 >> 3, 1, 'L', 24);

    /* M*24 at 96. */
    packets[12] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 96 >> 3, 1, 'M', 24);

    /* N*8 at 128. */
    packets[13] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 128 >> 3, 1, 'N', 8);

    /* O*8 at 152. */
    packets[14] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 152 >> 3, 1, 'O', 8);

    /* P*8 at 160. */
    packets[15] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 160 >> 3, 1, 'P', 8);

    /* Q*16 at 176. */
    packets[16] = IPV6BuildTestPacket(IPPROTO_ICMPV6, id, 176 >> 3, 0, 'Q', 16);

    default_policy = policy;

    /* Send all but the last. */
    for (i = 0; i < 9; i++) {
        Packet *tp = Defrag(NULL, NULL, packets[i]);
        FAIL_IF_NOT_NULL(tp);
        FAIL_IF(ENGINE_ISSET_EVENT(packets[i], IPV6_FRAG_OVERLAP));
    }
    int overlap = 0;
    for (; i < 16; i++) {
        Packet *tp = Defrag(NULL, NULL, packets[i]);
        FAIL_IF_NOT_NULL(tp);
        if (ENGINE_ISSET_EVENT(packets[i], IPV6_FRAG_OVERLAP)) {
            overlap++;
        }
    }
    FAIL_IF_NOT(overlap);

    /* And now the last one. */
    Packet *reassembled = Defrag(NULL, NULL, packets[16]);
    FAIL_IF_NULL(reassembled);
    FAIL_IF(memcmp(GET_PKT_DATA(reassembled) + 40, expected, expected_len) != 0);

    FAIL_IF(IPV6_GET_PLEN(reassembled) != 192);

    SCFree(reassembled);

    /* Make sure all frags were returned to the pool. */
    FAIL_IF(defrag_context->frag_pool->outstanding != 0);

    for (i = 0; i < 17; i++) {
        SCFree(packets[i]);
    }
    DefragDestroy();
    PASS;
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_BSD, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakBsdTest(void)
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

    FAIL_IF_NOT(IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_BSD, expected,
                    sizeof(expected)));
    PASS;
}

static int DefragSturgesNovakLinuxIpv4Test(void)
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_LINUX, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakLinuxTest(void)
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

    FAIL_IF_NOT(IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_LINUX, expected,
            sizeof(expected)));
    PASS;
}

static int DefragSturgesNovakWindowsIpv4Test(void)
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_WINDOWS, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakWindowsTest(void)
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

    FAIL_IF_NOT(IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_WINDOWS, expected,
                    sizeof(expected)));
    PASS;
}

static int DefragSturgesNovakSolarisTest(void)
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_SOLARIS, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakSolarisTest(void)
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

    FAIL_IF_NOT(IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_SOLARIS, expected,
                    sizeof(expected)));
    PASS;
}

static int DefragSturgesNovakFirstTest(void)
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_FIRST, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakFirstTest(void)
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

    FAIL_IF_NOT(DefragDoSturgesNovakTest(DEFRAG_POLICY_LAST, expected,
                    sizeof(expected)));
    PASS;
}

static int IPV6DefragSturgesNovakLastTest(void)
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

    FAIL_IF_NOT(IPV6DefragDoSturgesNovakTest(DEFRAG_POLICY_LAST, expected,
                    sizeof(expected)));
    PASS;
}

static int DefragTimeoutTest(void)
{
    int i;

    /* Setup a small numberr of trackers. */
    FAIL_IF_NOT(ConfSet("defrag.trackers", "16"));

    DefragInit();

    /* Load in 16 packets. */
    for (i = 0; i < 16; i++) {
        Packet *p = BuildTestPacket(IPPROTO_ICMP,i, 0, 1, 'A' + i, 16);
        FAIL_IF_NULL(p);

        Packet *tp = Defrag(NULL, NULL, p);
        SCFree(p);
        FAIL_IF_NOT_NULL(tp);
    }

    /* Build a new packet but push the timestamp out by our timeout.
     * This should force our previous fragments to be timed out. */
    Packet *p = BuildTestPacket(IPPROTO_ICMP, 99, 0, 1, 'A' + i, 16);
    FAIL_IF_NULL(p);

    p->ts.tv_sec += (defrag_context->timeout + 1);
    Packet *tp = Defrag(NULL, NULL, p);
    FAIL_IF_NOT_NULL(tp);

    DefragTracker *tracker = DefragLookupTrackerFromHash(p);
    FAIL_IF_NULL(tracker);

    FAIL_IF(tracker->id != 99);

    SCMutexUnlock(&tracker->lock);
    SCFree(p);

    DefragDestroy();
    PASS;
}

/**
 * QA found that if you send a packet where more frags is 0, offset is
 * > 0 and there is no data in the packet that the re-assembler will
 * fail.  The fix was simple, but this unit test is just to make sure
 * its not introduced.
 */
static int DefragIPv4NoDataTest(void)
{
    DefragContext *dc = NULL;
    Packet *p = NULL;
    int id = 12;

    DefragInit();

    dc = DefragContextNew();
    FAIL_IF_NULL(dc);

    /* This packet has an offset > 0, more frags set to 0 and no data. */
    p = BuildTestPacket(IPPROTO_ICMP, id, 1, 0, 'A', 0);
    FAIL_IF_NULL(p);

    /* We do not expect a packet returned. */
    FAIL_IF(Defrag(NULL, NULL, p) != NULL);

    /* The fragment should have been ignored so no fragments should
     * have been allocated from the pool. */
    FAIL_IF(dc->frag_pool->outstanding != 0);

    DefragContextDestroy(dc);
    SCFree(p);

    DefragDestroy();
    PASS;
}

static int DefragIPv4TooLargeTest(void)
{
    DefragContext *dc = NULL;
    Packet *p = NULL;

    DefragInit();

    dc = DefragContextNew();
    FAIL_IF_NULL(dc);

    /* Create a fragment that would extend past the max allowable size
     * for an IPv4 packet. */
    p = BuildTestPacket(IPPROTO_ICMP, 1, 8183, 0, 'A', 71);
    FAIL_IF_NULL(p);

    /* We do not expect a packet returned. */
    FAIL_IF(Defrag(NULL, NULL, p) != NULL);

    /* We do expect an event. */
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, IPV4_FRAG_PKT_TOO_LARGE));

    /* The fragment should have been ignored so no fragments should have
     * been allocated from the pool. */
    FAIL_IF(dc->frag_pool->outstanding != 0);

    DefragContextDestroy(dc);
    SCFree(p);

    DefragDestroy();
    PASS;
}

/**
 * Test that fragments in different VLANs that would otherwise be
 * re-assembled, are not re-assembled.  Just use simple in-order
 * fragments.
 */
static int DefragVlanTest(void)
{
    Packet *p1 = NULL, *p2 = NULL, *r = NULL;

    DefragInit();

    p1 = BuildTestPacket(IPPROTO_ICMP, 1, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = BuildTestPacket(IPPROTO_ICMP, 1, 1, 0, 'B', 8);
    FAIL_IF_NULL(p2);

    /* With no VLAN IDs set, packets should re-assemble. */
    FAIL_IF((r = Defrag(NULL, NULL, p1)) != NULL);
    FAIL_IF((r = Defrag(NULL, NULL, p2)) == NULL);
    SCFree(r);

    /* With mismatched VLANs, packets should not re-assemble. */
    p1->vlan_id[0] = 1;
    p2->vlan_id[0] = 2;
    FAIL_IF((r = Defrag(NULL, NULL, p1)) != NULL);
    FAIL_IF((r = Defrag(NULL, NULL, p2)) != NULL);

    SCFree(p1);
    SCFree(p2);
    DefragDestroy();

    PASS;
}

/**
 * Like DefragVlanTest, but for QinQ, testing the second level VLAN ID.
 */
static int DefragVlanQinQTest(void)
{
    Packet *p1 = NULL, *p2 = NULL, *r = NULL;

    DefragInit();

    p1 = BuildTestPacket(IPPROTO_ICMP, 1, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = BuildTestPacket(IPPROTO_ICMP, 1, 1, 0, 'B', 8);
    FAIL_IF_NULL(p2);

    /* With no VLAN IDs set, packets should re-assemble. */
    FAIL_IF((r = Defrag(NULL, NULL, p1)) != NULL);
    FAIL_IF((r = Defrag(NULL, NULL, p2)) == NULL);
    SCFree(r);

    /* With mismatched VLANs, packets should not re-assemble. */
    p1->vlan_id[0] = 1;
    p2->vlan_id[0] = 1;
    p1->vlan_id[1] = 1;
    p2->vlan_id[1] = 2;
    FAIL_IF((r = Defrag(NULL, NULL, p1)) != NULL);
    FAIL_IF((r = Defrag(NULL, NULL, p2)) != NULL);

    SCFree(p1);
    SCFree(p2);
    DefragDestroy();

    PASS;
}

static int DefragTrackerReuseTest(void)
{
    int id = 1;
    Packet *p1 = NULL;
    DefragTracker *tracker1 = NULL, *tracker2 = NULL;

    DefragInit();

    /* Build a packet, its not a fragment but shouldn't matter for
     * this test. */
    p1 = BuildTestPacket(IPPROTO_ICMP, id, 0, 0, 'A', 8);
    FAIL_IF_NULL(p1);

    /* Get a tracker. It shouldn't look like its already in use. */
    tracker1 = DefragGetTracker(NULL, NULL, p1);
    FAIL_IF_NULL(tracker1);
    FAIL_IF(tracker1->seen_last);
    FAIL_IF(tracker1->remove);
    DefragTrackerRelease(tracker1);

    /* Get a tracker again, it should be the same one. */
    tracker2 = DefragGetTracker(NULL, NULL, p1);
    FAIL_IF_NULL(tracker2);
    FAIL_IF(tracker2 != tracker1);
    DefragTrackerRelease(tracker1);

    /* Now mark the tracker for removal. It should not be returned
     * when we get a tracker for a packet that may have the same
     * attributes. */
    tracker1->remove = 1;

    tracker2 = DefragGetTracker(NULL, NULL, p1);
    FAIL_IF_NULL(tracker2);
    FAIL_IF(tracker2 == tracker1);
    FAIL_IF(tracker2->remove);

    SCFree(p1);
    DefragDestroy();
    PASS;
}

/**
 * IPV4: Test the case where you have a packet fragmented in 3 parts
 * and send like:
 * - Offset: 2; MF: 1
 * - Offset: 0; MF: 1
 * - Offset: 1; MF: 0
 *
 * Only the fragments with offset 0 and 1 should be reassembled.
 */
static int DefragMfIpv4Test(void)
{
    int ip_id = 9;
    Packet *p = NULL;

    DefragInit();

    Packet *p1 = BuildTestPacket(IPPROTO_ICMP, ip_id, 2, 1, 'C', 8);
    Packet *p2 = BuildTestPacket(IPPROTO_ICMP, ip_id, 0, 1, 'A', 8);
    Packet *p3 = BuildTestPacket(IPPROTO_ICMP, ip_id, 1, 0, 'B', 8);
    FAIL_IF(p1 == NULL || p2 == NULL || p3 == NULL);

    p = Defrag(NULL, NULL, p1);
    FAIL_IF_NOT_NULL(p);

    p = Defrag(NULL, NULL, p2);
    FAIL_IF_NOT_NULL(p);

    /* This should return a packet as MF=0. */
    p = Defrag(NULL, NULL, p3);
    FAIL_IF_NULL(p);

    /* Expected IP length is 20 + 8 + 8 = 36 as only 2 of the
     * fragments should be in the re-assembled packet. */
    FAIL_IF(IPV4_GET_IPLEN(p) != 36);

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(p);
    DefragDestroy();
    PASS;
}

/**
 * IPV6: Test the case where you have a packet fragmented in 3 parts
 * and send like:
 * - Offset: 2; MF: 1
 * - Offset: 0; MF: 1
 * - Offset: 1; MF: 0
 *
 * Only the fragments with offset 0 and 1 should be reassembled.
 */
static int DefragMfIpv6Test(void)
{
    int ip_id = 9;
    Packet *p = NULL;

    DefragInit();

    Packet *p1 = IPV6BuildTestPacket(IPPROTO_ICMPV6, ip_id, 2, 1, 'C', 8);
    Packet *p2 = IPV6BuildTestPacket(IPPROTO_ICMPV6, ip_id, 0, 1, 'A', 8);
    Packet *p3 = IPV6BuildTestPacket(IPPROTO_ICMPV6, ip_id, 1, 0, 'B', 8);
    FAIL_IF(p1 == NULL || p2 == NULL || p3 == NULL);

    p = Defrag(NULL, NULL, p1);
    FAIL_IF_NOT_NULL(p);

    p = Defrag(NULL, NULL, p2);
    FAIL_IF_NOT_NULL(p);

    /* This should return a packet as MF=0. */
    p = Defrag(NULL, NULL, p3);
    FAIL_IF_NULL(p);

    /* For IPv6 the expected length is just the length of the payload
     * of 2 fragments, so 16. */
    FAIL_IF(IPV6_GET_PLEN(p) != 16);

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);
    SCFree(p);
    DefragDestroy();
    PASS;
}

/**
 * \brief Test that fragments that match other than the proto don't
 * actually get matched.
 */
static int DefragTestBadProto(void)
{
    Packet *p1 = NULL, *p2 = NULL, *p3 = NULL;
    int id = 12;

    DefragInit();

    p1 = BuildTestPacket(IPPROTO_ICMP, id, 0, 1, 'A', 8);
    FAIL_IF_NULL(p1);
    p2 = BuildTestPacket(IPPROTO_UDP, id, 1, 1, 'B', 8);
    FAIL_IF_NULL(p2);
    p3 = BuildTestPacket(IPPROTO_ICMP, id, 2, 0, 'C', 3);
    FAIL_IF_NULL(p3);

    FAIL_IF_NOT_NULL(Defrag(NULL, NULL, p1));
    FAIL_IF_NOT_NULL(Defrag(NULL, NULL, p2));
    FAIL_IF_NOT_NULL(Defrag(NULL, NULL, p3));

    SCFree(p1);
    SCFree(p2);
    SCFree(p3);

    DefragDestroy();
    PASS;
}

/**
 * \test Test a report Linux overlap issue that doesn't appear to be
 *     covered by the Sturges/Novak tests above.
 */
static int DefragTestJeremyLinux(void)
{
    char expected[] = "AAAAAAAA"
        "AAAAAAAA"
        "AAAAAAAA"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "CCCCCCCC"
        "BBBBBBBB"
        "BBBBBBBB"
        "DDDDDDDD"
        "DDDDDD";

    DefragInit();
    default_policy = DEFRAG_POLICY_LINUX;

    int id = 1;
    Packet *packets[4];
    int i = 0;

    packets[0] = BuildTestPacket(IPPROTO_ICMP, id, 0, 1, 'A', 24);
    packets[1] = BuildTestPacket(IPPROTO_ICMP, id, 40 >> 3, 1, 'B', 48);
    packets[2] = BuildTestPacket(IPPROTO_ICMP, id, 24 >> 3, 1, 'C', 48);
    packets[3] = BuildTestPacket(IPPROTO_ICMP, id, 88 >> 3, 0, 'D', 14);

    Packet *r = Defrag(NULL, NULL, packets[0]);
    FAIL_IF_NOT_NULL(r);

    r = Defrag(NULL, NULL, packets[1]);
    FAIL_IF_NOT_NULL(r);

    r = Defrag(NULL, NULL, packets[2]);
    FAIL_IF_NOT_NULL(r);

    r = Defrag(NULL, NULL, packets[3]);
    FAIL_IF_NULL(r);

    FAIL_IF(memcmp(expected, GET_PKT_DATA(r) + 20, sizeof(expected)) != 0);

    for (i = 0; i < 4; i++) {
        SCFree(packets[i]);
    }
    SCFree(r);

    DefragDestroy();
    PASS;
}

#endif /* UNITTESTS */

void DefragRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DefragInOrderSimpleTest", DefragInOrderSimpleTest);
    UtRegisterTest("DefragReverseSimpleTest", DefragReverseSimpleTest);
    UtRegisterTest("DefragSturgesNovakBsdTest", DefragSturgesNovakBsdTest);
    UtRegisterTest("DefragSturgesNovakLinuxIpv4Test",
            DefragSturgesNovakLinuxIpv4Test);
    UtRegisterTest("DefragSturgesNovakWindowsIpv4Test",
                   DefragSturgesNovakWindowsIpv4Test);
    UtRegisterTest("DefragSturgesNovakSolarisTest",
                   DefragSturgesNovakSolarisTest);
    UtRegisterTest("DefragSturgesNovakFirstTest", DefragSturgesNovakFirstTest);
    UtRegisterTest("DefragSturgesNovakLastTest", DefragSturgesNovakLastTest);

    UtRegisterTest("DefragIPv4NoDataTest", DefragIPv4NoDataTest);
    UtRegisterTest("DefragIPv4TooLargeTest", DefragIPv4TooLargeTest);

    UtRegisterTest("IPV6DefragInOrderSimpleTest", IPV6DefragInOrderSimpleTest);
    UtRegisterTest("IPV6DefragReverseSimpleTest", IPV6DefragReverseSimpleTest);
    UtRegisterTest("IPV6DefragSturgesNovakBsdTest",
                   IPV6DefragSturgesNovakBsdTest);
    UtRegisterTest("IPV6DefragSturgesNovakLinuxTest",
                   IPV6DefragSturgesNovakLinuxTest);
    UtRegisterTest("IPV6DefragSturgesNovakWindowsTest",
                   IPV6DefragSturgesNovakWindowsTest);
    UtRegisterTest("IPV6DefragSturgesNovakSolarisTest",
                   IPV6DefragSturgesNovakSolarisTest);
    UtRegisterTest("IPV6DefragSturgesNovakFirstTest",
                   IPV6DefragSturgesNovakFirstTest);
    UtRegisterTest("IPV6DefragSturgesNovakLastTest",
                   IPV6DefragSturgesNovakLastTest);

    UtRegisterTest("DefragVlanTest", DefragVlanTest);
    UtRegisterTest("DefragVlanQinQTest", DefragVlanQinQTest);
    UtRegisterTest("DefragTrackerReuseTest", DefragTrackerReuseTest);
    UtRegisterTest("DefragTimeoutTest", DefragTimeoutTest);
    UtRegisterTest("DefragMfIpv4Test", DefragMfIpv4Test);
    UtRegisterTest("DefragMfIpv6Test", DefragMfIpv6Test);
    UtRegisterTest("DefragTestBadProto", DefragTestBadProto);

    UtRegisterTest("DefragTestJeremyLinux", DefragTestJeremyLinux);
#endif /* UNITTESTS */
}
