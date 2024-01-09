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
 * \defgroup threshold Thresholding
 *
 * This feature is used to reduce the number of logged alerts for noisy rules.
 * This can be tuned to significantly reduce false alarms, and it can also be
 * used to write a newer breed of rules. Thresholding commands limit the number
 * of times a particular event is logged during a specified time interval.
 *
 * @{
 */

/**
 * \file
 *
 *  \author Breno Silva <breno.silva@gmail.com>
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Threshold part of the detection engine.
 */

#include "suricata-common.h"
#include "detect.h"
#include "flow.h"

#include "host.h"
#include "host-storage.h"

#include "ippair.h"
#include "ippair-storage.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"

#include "detect-engine.h"
#include "detect-engine-threshold.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-hash.h"
#include "util-time.h"
#include "util-error.h"
#include "util-debug.h"

#include "util-var-name.h"
#include "tm-threads.h"

#include "action-globals.h"
#include "util-validate.h"

static HostStorageId host_threshold_id = { .id = -1 };     /**< host storage id for thresholds */
static IPPairStorageId ippair_threshold_id = { .id = -1 }; /**< ip pair storage id for thresholds */

HostStorageId ThresholdHostStorageId(void)
{
    return host_threshold_id;
}

void ThresholdInit(void)
{
    host_threshold_id = HostStorageRegister("threshold", sizeof(void *), NULL, ThresholdListFree);
    if (host_threshold_id.id == -1) {
        FatalError("Can't initiate host storage for thresholding");
    }
    ippair_threshold_id = IPPairStorageRegister("threshold", sizeof(void *), NULL, ThresholdListFree);
    if (ippair_threshold_id.id == -1) {
        FatalError("Can't initiate IP pair storage for thresholding");
    }
}

int ThresholdHostHasThreshold(Host *host)
{
    return HostGetStorageById(host, host_threshold_id) ? 1 : 0;
}

int ThresholdIPPairHasThreshold(IPPair *pair)
{
    return IPPairGetStorageById(pair, ippair_threshold_id) ? 1 : 0;
}

#include "util-hash.h"

typedef struct ThresholdCacheItem {
    int8_t track; // by_src/by_dst
    int8_t ipv;
    int8_t retval;
    uint32_t addr;
    uint32_t sid;
    SCTime_t expires_at;
    RB_ENTRY(ThresholdCacheItem) rb;
} ThresholdCacheItem;

static thread_local HashTable *threshold_cache_ht = NULL;

thread_local uint64_t cache_lookup_cnt = 0;
thread_local uint64_t cache_lookup_notinit = 0;
thread_local uint64_t cache_lookup_nosupport = 0;
thread_local uint64_t cache_lookup_miss_expired = 0;
thread_local uint64_t cache_lookup_miss = 0;
thread_local uint64_t cache_lookup_hit = 0;
thread_local uint64_t cache_housekeeping_check = 0;
thread_local uint64_t cache_housekeeping_expired = 0;

static void DumpCacheStats(void)
{
    SCLogPerf("threshold thread cache stats: cnt:%" PRIu64 " notinit:%" PRIu64 " nosupport:%" PRIu64
              " miss_expired:%" PRIu64 " miss:%" PRIu64 " hit:%" PRIu64
              ", housekeeping: checks:%" PRIu64 ", expired:%" PRIu64,
            cache_lookup_cnt, cache_lookup_notinit, cache_lookup_nosupport,
            cache_lookup_miss_expired, cache_lookup_miss, cache_lookup_hit,
            cache_housekeeping_check, cache_housekeeping_expired);
}

/* rbtree for expiry handling */

static int ThresholdCacheTreeCompareFunc(ThresholdCacheItem *a, ThresholdCacheItem *b)
{
    if (SCTIME_CMP_GTE(a->expires_at, b->expires_at)) {
        return 1;
    } else {
        return -1;
    }
}

RB_HEAD(THRESHOLD_CACHE, ThresholdCacheItem);
RB_PROTOTYPE(THRESHOLD_CACHE, ThresholdCacheItem, rb, ThresholdCacheTreeCompareFunc);
RB_GENERATE(THRESHOLD_CACHE, ThresholdCacheItem, rb, ThresholdCacheTreeCompareFunc);
thread_local struct THRESHOLD_CACHE threshold_cache_tree;
thread_local uint64_t threshold_cache_housekeeping_ts = 0;

static void ThresholdCacheExpire(SCTime_t now)
{
    ThresholdCacheItem *iter, *safe = NULL;
    int cnt = 0;
    threshold_cache_housekeeping_ts = SCTIME_SECS(now);

    RB_FOREACH_SAFE (iter, THRESHOLD_CACHE, &threshold_cache_tree, safe) {
        cache_housekeeping_check++;

        if (SCTIME_CMP_LT(iter->expires_at, now)) {
            THRESHOLD_CACHE_RB_REMOVE(&threshold_cache_tree, iter);
            HashTableRemove(threshold_cache_ht, iter, 0);
            SCLogDebug("iter %p expired", iter);
            cache_housekeeping_expired++;
        }

        if (++cnt > 1)
            break;
    }
}

/* hash table for threshold look ups */

static uint32_t ThresholdCacheHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    ThresholdCacheItem *tci = data;
    int hash = tci->ipv * tci->track + tci->addr + tci->sid;
    hash = hash % ht->array_size;
    return hash;
}

static char ThresholdCacheHashCompareFunc(
        void *data1, uint16_t datalen1, void *data2, uint16_t datalen2)
{
    ThresholdCacheItem *tci1 = data1;
    ThresholdCacheItem *tci2 = data2;
    return tci1->ipv == tci2->ipv && tci1->track == tci2->track && tci1->addr == tci2->addr &&
           tci1->sid == tci2->sid;
}

static void ThresholdCacheHashFreeFunc(void *data)
{
    SCFree(data);
}

/// \brief Thread local cache
static int SetupCache(const Packet *p, const int8_t track, const int8_t retval, const uint32_t sid,
        SCTime_t expires)
{
    if (!threshold_cache_ht) {
        threshold_cache_ht = HashTableInit(256, ThresholdCacheHashFunc,
                ThresholdCacheHashCompareFunc, ThresholdCacheHashFreeFunc);
    }

    uint32_t addr;
    if (track == TRACK_SRC) {
        addr = p->src.addr_data32[0];
    } else if (track == TRACK_DST) {
        addr = p->dst.addr_data32[0];
    } else {
        return -1;
    }

    ThresholdCacheItem lookup = {
        .track = track,
        .ipv = 4,
        .retval = retval,
        .addr = addr,
        .sid = sid,
        .expires_at = expires,
    };
    ThresholdCacheItem *found = HashTableLookup(threshold_cache_ht, &lookup, 0);
    if (!found) {
        ThresholdCacheItem *n = SCCalloc(1, sizeof(*n));
        if (n) {
            n->track = track;
            n->ipv = 4;
            n->retval = retval;
            n->addr = addr;
            n->sid = sid;
            n->expires_at = expires;

            if (HashTableAdd(threshold_cache_ht, n, 0) == 0) {
                (void)THRESHOLD_CACHE_RB_INSERT(&threshold_cache_tree, n);
                return 1;
            }
            SCFree(n);
        }
        return -1;
    } else {
        found->expires_at = expires;
        found->retval = retval;

        THRESHOLD_CACHE_RB_REMOVE(&threshold_cache_tree, found);
        THRESHOLD_CACHE_RB_INSERT(&threshold_cache_tree, found);
        return 1;
    }
}

/** \brief Check Thread local thresholding cache
 *  \note only supports IPv4
 *  \retval -1 cache miss - not found
 *  \retval -2 cache miss - found but expired
 *  \retval -3 error - cache not initialized
 *  \retval -4 error - unsupported tracker
 *  \retval ret cached return code
 */
static int CheckCache(const Packet *p, const int8_t track, const uint32_t sid)
{
    cache_lookup_cnt++;

    if (!threshold_cache_ht) {
        cache_lookup_notinit++;
        return -3; // error cache initialized
    }

    uint32_t addr;
    if (track == TRACK_SRC) {
        addr = p->src.addr_data32[0];
    } else if (track == TRACK_DST) {
        addr = p->dst.addr_data32[0];
    } else {
        cache_lookup_nosupport++;
        return -4; // error tracker not unsupported
    }

    if (SCTIME_SECS(p->ts) > threshold_cache_housekeeping_ts) {
        ThresholdCacheExpire(p->ts);
    }

    ThresholdCacheItem lookup = {
        .track = track,
        .ipv = 4,
        .addr = addr,
        .sid = sid,
    };
    ThresholdCacheItem *found = HashTableLookup(threshold_cache_ht, &lookup, 0);
    if (found) {
        if (SCTIME_CMP_GT(p->ts, found->expires_at)) {
            THRESHOLD_CACHE_RB_REMOVE(&threshold_cache_tree, found);
            HashTableRemove(threshold_cache_ht, found, 0);
            cache_lookup_miss_expired++;
            return -2; // cache miss - found but expired
        }
        cache_lookup_hit++;
        return found->retval;
    }
    cache_lookup_miss++;
    return -1; // cache miss - not found
}

void ThresholdCacheThreadFree(void)
{
    if (threshold_cache_ht) {
        HashTableFree(threshold_cache_ht);
        threshold_cache_ht = NULL;
    }
    RB_INIT(&threshold_cache_tree);
    DumpCacheStats();
}

/**
 * \brief Return next DetectThresholdData for signature
 *
 * \param sig  Signature pointer
 * \param psm  Pointer to a Signature Match pointer
 * \param list List to return data from
 *
 * \retval tsh Return the threshold data from signature or NULL if not found
 */
const DetectThresholdData *SigGetThresholdTypeIter(
        const Signature *sig, const SigMatchData **psm, int list)
{
    const SigMatchData *smd = NULL;
    const DetectThresholdData *tsh = NULL;

    if (sig == NULL)
        return NULL;

    if (*psm == NULL) {
        smd = sig->sm_arrays[list];
    } else {
        /* Iteration in progress, using provided value */
        smd = *psm;
    }

    while (1) {
        if (smd->type == DETECT_THRESHOLD || smd->type == DETECT_DETECTION_FILTER) {
            tsh = (DetectThresholdData *)smd->ctx;

            if (smd->is_last) {
                *psm = NULL;
            } else {
                *psm = smd + 1;
            }
            return tsh;
        }

        if (smd->is_last) {
            break;
        }
        smd++;
    }
    *psm = NULL;
    return NULL;
}

/**
 * \brief Remove timeout threshold hash elements
 *
 * \param head Current head element of storage
 * \param tv Current time
 *
 * \retval DetectThresholdEntry Return new head element or NULL if all expired
 *
 */

static DetectThresholdEntry *ThresholdTimeoutCheck(DetectThresholdEntry *head, SCTime_t ts)
{
    DetectThresholdEntry *tmp = head;
    DetectThresholdEntry *prev = NULL;
    DetectThresholdEntry *new_head = head;

    while (tmp != NULL) {
        /* check if the 'check' timestamp is not before the creation ts.
         * This can happen due to the async nature of the host timeout
         * code that also calls this code from a management thread. */
        SCTime_t entry = SCTIME_ADD_SECS(tmp->tv1, (time_t)tmp->seconds);
        if (SCTIME_CMP_LTE(ts, entry)) {
            prev = tmp;
            tmp = tmp->next;
            continue;
        }

        /* timed out */

        DetectThresholdEntry *tde = tmp;
        if (prev != NULL) {
            prev->next = tmp->next;
        }
        else {
            new_head = tmp->next;
        }
        tmp = tde->next;
        SCFree(tde);
    }

    return new_head;
}

int ThresholdHostTimeoutCheck(Host *host, SCTime_t ts)
{
    DetectThresholdEntry* head = HostGetStorageById(host, host_threshold_id);
    DetectThresholdEntry *new_head = ThresholdTimeoutCheck(head, ts);
    if (new_head != head) {
        HostSetStorageById(host, host_threshold_id, new_head);
    }
    return new_head == NULL;
}

int ThresholdIPPairTimeoutCheck(IPPair *pair, SCTime_t ts)
{
    DetectThresholdEntry* head = IPPairGetStorageById(pair, ippair_threshold_id);
    DetectThresholdEntry *new_head = ThresholdTimeoutCheck(head, ts);
    if (new_head != head) {
        IPPairSetStorageById(pair, ippair_threshold_id, new_head);
    }
    return new_head == NULL;
}

static DetectThresholdEntry *DetectThresholdEntryAlloc(
        const DetectThresholdData *td, uint32_t sid, uint32_t gid)
{
    SCEnter();

    DetectThresholdEntry *ste = SCCalloc(1, sizeof(DetectThresholdEntry));
    if (unlikely(ste == NULL)) {
        SCReturnPtr(NULL, "DetectThresholdEntry");
    }

    ste->sid = sid;
    ste->gid = gid;
    ste->track = td->track;
    ste->seconds = td->seconds;

    SCReturnPtr(ste, "DetectThresholdEntry");
}

static DetectThresholdEntry *ThresholdHostLookupEntry(Host *h,
        uint32_t sid, uint32_t gid)
{
    DetectThresholdEntry *e;

    for (e = HostGetStorageById(h, host_threshold_id); e != NULL; e = e->next) {
        if (e->sid == sid && e->gid == gid)
            break;
    }

    return e;
}

/** struct for storing per flow thresholds. This will be stored in the Flow::flowvar list, so it
 * needs to follow the GenericVar header format. */
typedef struct FlowVarThreshold_ {
    uint8_t type;
    uint8_t pad[7];
    struct GenericVar_ *next;
    DetectThresholdEntry *thresholds;
} FlowVarThreshold;

void FlowThresholdVarFree(void *ptr)
{
    FlowVarThreshold *t = ptr;
    ThresholdListFree(t->thresholds);
    SCFree(t);
}

static FlowVarThreshold *FlowThresholdVarGet(Flow *f)
{
    if (f == NULL)
        return NULL;

    for (GenericVar *gv = f->flowvar; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_THRESHOLD)
            return (FlowVarThreshold *)gv;
    }

    return NULL;
}

static DetectThresholdEntry *ThresholdFlowLookupEntry(Flow *f, uint32_t sid, uint32_t gid)
{
    FlowVarThreshold *t = FlowThresholdVarGet(f);
    if (t == NULL)
        return NULL;

    for (DetectThresholdEntry *e = t->thresholds; e != NULL; e = e->next) {
        if (e->sid == sid && e->gid == gid) {
            return e;
        }
    }
    return NULL;
}

static int AddEntryToFlow(Flow *f, DetectThresholdEntry *e, SCTime_t packet_time)
{
    DEBUG_VALIDATE_BUG_ON(e == NULL);

    FlowVarThreshold *t = FlowThresholdVarGet(f);
    if (t == NULL) {
        t = SCCalloc(1, sizeof(*t));
        if (t == NULL) {
            return -1;
        }
        t->type = DETECT_THRESHOLD;
        GenericVarAppend(&f->flowvar, (GenericVar *)t);
    }

    e->current_count = 1;
    e->tv1 = packet_time;
    e->tv_timeout = 0;
    e->next = t->thresholds;
    t->thresholds = e;
    return 0;
}

static DetectThresholdEntry *ThresholdIPPairLookupEntry(IPPair *pair,
        uint32_t sid, uint32_t gid)
{
    DetectThresholdEntry *e;

    for (e = IPPairGetStorageById(pair, ippair_threshold_id); e != NULL; e = e->next) {
        if (e->sid == sid && e->gid == gid)
            break;
    }

    return e;
}

static int ThresholdHandlePacketSuppress(Packet *p,
        const DetectThresholdData *td, uint32_t sid, uint32_t gid)
{
    int ret = 0;
    DetectAddress *m = NULL;
    switch (td->track) {
        case TRACK_DST:
            m = DetectAddressLookupInHead(&td->addrs, &p->dst);
            SCLogDebug("TRACK_DST");
            break;
        case TRACK_SRC:
            m = DetectAddressLookupInHead(&td->addrs, &p->src);
            SCLogDebug("TRACK_SRC");
            break;
        /* suppress if either src or dst is a match on the suppress
         * address list */
        case TRACK_EITHER:
            m = DetectAddressLookupInHead(&td->addrs, &p->src);
            if (m == NULL) {
                m = DetectAddressLookupInHead(&td->addrs, &p->dst);
            }
            break;
        case TRACK_RULE:
        case TRACK_FLOW:
        default:
            SCLogError("track mode %d is not supported", td->track);
            break;
    }
    if (m == NULL)
        ret = 1;
    else
        ret = 2; /* suppressed but still need actions */

    return ret;
}

static inline void RateFilterSetAction(PacketAlert *pa, uint8_t new_action)
{
    switch (new_action) {
        case TH_ACTION_ALERT:
            pa->flags |= PACKET_ALERT_RATE_FILTER_MODIFIED;
            pa->action = ACTION_ALERT;
            break;
        case TH_ACTION_DROP:
            pa->flags |= PACKET_ALERT_RATE_FILTER_MODIFIED;
            pa->action = ACTION_DROP;
            break;
        case TH_ACTION_REJECT:
            pa->flags |= PACKET_ALERT_RATE_FILTER_MODIFIED;
            pa->action = (ACTION_REJECT | ACTION_DROP);
            break;
        case TH_ACTION_PASS:
            pa->flags |= PACKET_ALERT_RATE_FILTER_MODIFIED;
            pa->action = ACTION_PASS;
            break;
        default:
            /* Weird, leave the default action */
            break;
    }
}

/**
* \brief Check if the entry reached threshold count limit
*
* \param lookup_tsh Current threshold entry
* \param td Threshold settings
* \param packet_time used to compare against previous detection and to set timeouts
*
* \retval int 1 if threshold reached for this entry
*
*/
static int IsThresholdReached(
        DetectThresholdEntry *lookup_tsh, const DetectThresholdData *td, SCTime_t packet_time)
{
    int ret = 0;

    /* Check if we have a timeout enabled, if so,
    * we still matching (and enabling the new_action) */
    if (lookup_tsh->tv_timeout != 0) {
        if ((SCTIME_SECS(packet_time) - lookup_tsh->tv_timeout) > td->timeout) {
            /* Ok, we are done, timeout reached */
            lookup_tsh->tv_timeout = 0;
        } else {
            /* Already matching */
            ret = 1;
        } /* else - if ((packet_time - lookup_tsh->tv_timeout) > td->timeout) */

    }
    else {
        /* Update the matching state with the timeout interval */
        SCTime_t entry = SCTIME_ADD_SECS(lookup_tsh->tv1, td->seconds);
        if (SCTIME_CMP_LTE(packet_time, entry)) {
            lookup_tsh->current_count++;
            if (lookup_tsh->current_count > td->count) {
                /* Then we must enable the new action by setting a
                * timeout */
                lookup_tsh->tv_timeout = SCTIME_SECS(packet_time);
                ret = 1;
            }
        } else {
            lookup_tsh->tv1 = packet_time;
            lookup_tsh->current_count = 1;
        }
    } /* else - if (lookup_tsh->tv_timeout != 0) */

    return ret;
}

static void AddEntryToHostStorage(Host *h, DetectThresholdEntry *e, SCTime_t packet_time)
{
    if (h && e) {
        e->current_count = 1;
        e->tv1 = packet_time;
        e->tv_timeout = 0;
        e->next = HostGetStorageById(h, host_threshold_id);
        HostSetStorageById(h, host_threshold_id, e);
    }
}

static void AddEntryToIPPairStorage(IPPair *pair, DetectThresholdEntry *e, SCTime_t packet_time)
{
    if (pair && e) {
        e->current_count = 1;
        e->tv1 = packet_time;
        e->tv_timeout = 0;
        e->next = IPPairGetStorageById(pair, ippair_threshold_id);
        IPPairSetStorageById(pair, ippair_threshold_id, e);
    }
}

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 *
 *  If a new DetectThresholdEntry is generated to track the threshold
 *  for this rule, then it will be returned in new_tsh.
 */
static int ThresholdHandlePacket(Packet *p, DetectThresholdEntry *lookup_tsh,
        DetectThresholdEntry **new_tsh, const DetectThresholdData *td,
        uint32_t sid, uint32_t gid, PacketAlert *pa)
{
    int ret = 0;

    switch(td->type)   {
        case TYPE_LIMIT:
        {
            SCLogDebug("limit");

            if (lookup_tsh != NULL)  {
                SCTime_t entry = SCTIME_ADD_SECS(lookup_tsh->tv1, td->seconds);
                if (SCTIME_CMP_LTE(p->ts, entry)) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count <= td->count) {
                        ret = 1;
                    } else {
                        ret = 2;

                        if (PacketIsIPv4(p)) {
                            SetupCache(p, td->track, (int8_t)ret, sid, entry);
                        }
                    }
                } else {
                    lookup_tsh->tv1 = p->ts;
                    lookup_tsh->current_count = 1;

                    ret = 1;
                }
            } else {
                *new_tsh = DetectThresholdEntryAlloc(td, sid, gid);

                ret = 1;
            }
            break;
        }
        case TYPE_THRESHOLD:
        {
            SCLogDebug("threshold");

            if (lookup_tsh != NULL)  {
                SCTime_t entry = SCTIME_ADD_SECS(lookup_tsh->tv1, td->seconds);
                if (SCTIME_CMP_LTE(p->ts, entry)) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count >= td->count) {
                        ret = 1;
                        lookup_tsh->current_count = 0;
                    }
                } else {
                    lookup_tsh->tv1 = p->ts;
                    lookup_tsh->current_count = 1;
                }
            } else {
                if (td->count == 1)  {
                    ret = 1;
                } else {
                    *new_tsh = DetectThresholdEntryAlloc(td, sid, gid);
                }
            }
            break;
        }
        case TYPE_BOTH:
        {
            SCLogDebug("both");

            if (lookup_tsh != NULL) {
                SCTime_t entry = SCTIME_ADD_SECS(lookup_tsh->tv1, td->seconds);
                if (SCTIME_CMP_LTE(p->ts, entry)) {
                    /* within time limit */

                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count == td->count) {
                        ret = 1;
                    } else if (lookup_tsh->current_count > td->count) {
                        /* silent match */
                        ret = 2;

                        if (PacketIsIPv4(p)) {
                            SetupCache(p, td->track, (int8_t)ret, sid, entry);
                        }
                    }
                } else {
                    /* expired, so reset */
                    lookup_tsh->tv1 = p->ts;
                    lookup_tsh->current_count = 1;

                    /* if we have a limit of 1, this is a match */
                    if (lookup_tsh->current_count == td->count) {
                        ret = 1;
                    }
                }
            } else {
                *new_tsh = DetectThresholdEntryAlloc(td, sid, gid);

                /* for the first match we return 1 to
                 * indicate we should alert */
                if (td->count == 1)  {
                    ret = 1;
                }
            }
            break;
        }
        /* detection_filter */
        case TYPE_DETECTION:
        {
            SCLogDebug("detection_filter");

            if (lookup_tsh != NULL) {
                SCTime_t entry = SCTIME_ADD_SECS(lookup_tsh->tv1, td->seconds);
                if (SCTIME_CMP_LTE(p->ts, entry)) {
                    /* within timeout */
                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count > td->count) {
                        ret = 1;
                    }
                } else {
                    /* expired, reset */
                    lookup_tsh->tv1 = p->ts;
                    lookup_tsh->current_count = 1;
                }
            } else {
                *new_tsh = DetectThresholdEntryAlloc(td, sid, gid);
            }
            break;
        }
        /* rate_filter */
        case TYPE_RATE:
        {
            SCLogDebug("rate_filter");
            ret = 1;
            if (lookup_tsh && IsThresholdReached(lookup_tsh, td, p->ts)) {
                RateFilterSetAction(pa, td->new_action);
            } else if (!lookup_tsh) {
                *new_tsh = DetectThresholdEntryAlloc(td, sid, gid);
            }
            break;
        }
        /* case TYPE_SUPPRESS: is not handled here */
        default:
            SCLogError("type %d is not supported", td->type);
    }
    return ret;
}

static int ThresholdHandlePacketIPPair(IPPair *pair, Packet *p, const DetectThresholdData *td,
    uint32_t sid, uint32_t gid, PacketAlert *pa)
{
    int ret = 0;

    DetectThresholdEntry *lookup_tsh = ThresholdIPPairLookupEntry(pair, sid, gid);
    SCLogDebug("ippair lookup_tsh %p sid %u gid %u", lookup_tsh, sid, gid);

    DetectThresholdEntry *new_tsh = NULL;
    ret = ThresholdHandlePacket(p, lookup_tsh, &new_tsh, td, sid, gid, pa);
    if (new_tsh != NULL) {
        AddEntryToIPPairStorage(pair, new_tsh, p->ts);
    }

    return ret;
}

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 */
static int ThresholdHandlePacketHost(Host *h, Packet *p, const DetectThresholdData *td,
        uint32_t sid, uint32_t gid, PacketAlert *pa)
{
    int ret = 0;
    DetectThresholdEntry *lookup_tsh = ThresholdHostLookupEntry(h, sid, gid);
    SCLogDebug("lookup_tsh %p sid %u gid %u", lookup_tsh, sid, gid);

    DetectThresholdEntry *new_tsh = NULL;
    ret = ThresholdHandlePacket(p, lookup_tsh, &new_tsh, td, sid, gid, pa);
    if (new_tsh != NULL) {
        AddEntryToHostStorage(h, new_tsh, p->ts);
    }
    return ret;
}

static int ThresholdHandlePacketRule(DetectEngineCtx *de_ctx, Packet *p,
        const DetectThresholdData *td, const Signature *s, PacketAlert *pa)
{
    int ret = 0;

    DetectThresholdEntry* lookup_tsh = (DetectThresholdEntry *)de_ctx->ths_ctx.th_entry[s->num];
    SCLogDebug("by_rule lookup_tsh %p num %u", lookup_tsh, s->num);

    DetectThresholdEntry *new_tsh = NULL;
    ret = ThresholdHandlePacket(p, lookup_tsh, &new_tsh, td, s->id, s->gid, pa);
    if (new_tsh != NULL) {
        new_tsh->tv1 = p->ts;
        new_tsh->current_count = 1;
        new_tsh->tv_timeout = 0;
        de_ctx->ths_ctx.th_entry[s->num] = new_tsh;
    }

    return ret;
}

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 */
static int ThresholdHandlePacketFlow(Flow *f, Packet *p, const DetectThresholdData *td,
        uint32_t sid, uint32_t gid, PacketAlert *pa)
{
    int ret = 0;
    DetectThresholdEntry *lookup_tsh = ThresholdFlowLookupEntry(f, sid, gid);
    SCLogDebug("lookup_tsh %p sid %u gid %u", lookup_tsh, sid, gid);

    DetectThresholdEntry *new_tsh = NULL;
    ret = ThresholdHandlePacket(p, lookup_tsh, &new_tsh, td, sid, gid, pa);
    if (new_tsh != NULL) {
        if (AddEntryToFlow(f, new_tsh, p->ts) == -1) {
            SCFree(new_tsh);
        }
    }
    return ret;
}

/**
 * \brief Make the threshold logic for signatures
 *
 * \param de_ctx Detection Context
 * \param tsh_ptr Threshold element
 * \param p Packet structure
 * \param s Signature structure
 *
 * \retval 2 silent match (no alert but apply actions)
 * \retval 1 alert on this event
 * \retval 0 do not alert on this event
 */
int PacketAlertThreshold(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectThresholdData *td, Packet *p, const Signature *s, PacketAlert *pa)
{
    SCEnter();

    int ret = 0;
    if (td == NULL) {
        SCReturnInt(0);
    }

    if (td->type == TYPE_SUPPRESS) {
        ret = ThresholdHandlePacketSuppress(p,td,s->id,s->gid);
    } else if (td->track == TRACK_SRC) {
        if (PacketIsIPv4(p) && (td->type == TYPE_LIMIT || td->type == TYPE_BOTH)) {
            int cache_ret = CheckCache(p, td->track, s->id);
            if (cache_ret >= 0) {
                SCReturnInt(cache_ret);
            }
        }
        Host *src = HostGetHostFromHash(&p->src);
        if (src) {
            ret = ThresholdHandlePacketHost(src,p,td,s->id,s->gid,pa);
            HostRelease(src);
        }
    } else if (td->track == TRACK_DST) {
        if (PacketIsIPv4(p) && (td->type == TYPE_LIMIT || td->type == TYPE_BOTH)) {
            int cache_ret = CheckCache(p, td->track, s->id);
            if (cache_ret >= 0) {
                SCReturnInt(cache_ret);
            }
        }
        Host *dst = HostGetHostFromHash(&p->dst);
        if (dst) {
            ret = ThresholdHandlePacketHost(dst,p,td,s->id,s->gid,pa);
            HostRelease(dst);
        }
    } else if (td->track == TRACK_BOTH) {
        IPPair *pair = IPPairGetIPPairFromHash(&p->src, &p->dst);
        if (pair) {
            ret = ThresholdHandlePacketIPPair(pair, p, td, s->id, s->gid, pa);
            IPPairRelease(pair);
        }
    } else if (td->track == TRACK_RULE) {
        SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
        ret = ThresholdHandlePacketRule(de_ctx,p,td,s,pa);
        SCMutexUnlock(&de_ctx->ths_ctx.threshold_table_lock);
    } else if (td->track == TRACK_FLOW) {
        if (p->flow) {
            ret = ThresholdHandlePacketFlow(p->flow, p, td, s->id, s->gid, pa);
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Init threshold context hash tables
 *
 * \param de_ctx Detection Context
 *
 */
void ThresholdHashInit(DetectEngineCtx *de_ctx)
{
    if (SCMutexInit(&de_ctx->ths_ctx.threshold_table_lock, NULL) != 0) {
        FatalError("Threshold: Failed to initialize hash table mutex.");
    }
}

/**
 * \brief Allocate threshold context hash tables
 *
 * \param de_ctx Detection Context
 */
void ThresholdHashAllocate(DetectEngineCtx *de_ctx)
{
    const Signature *s = de_ctx->sig_list;
    bool has_by_rule_tracking = false;

    /* Find the signature with the highest signature number that is using
       thresholding with by_rule tracking. */
    uint32_t highest_signum = 0;
    while (s != NULL) {
        if (s->sm_arrays[DETECT_SM_LIST_SUPPRESS] != NULL) {
            const SigMatchData *smd = NULL;
            do {
                const DetectThresholdData *td =
                        SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_SUPPRESS);
                if (td == NULL) {
                    continue;
                }
                if (td->track != TRACK_RULE) {
                    continue;
                }
                if (s->num >= highest_signum) {
                    highest_signum = s->num;
                    has_by_rule_tracking = true;
                }
            } while (smd != NULL);
        }

        if (s->sm_arrays[DETECT_SM_LIST_THRESHOLD] != NULL) {
            const SigMatchData *smd = NULL;
            do {
                const DetectThresholdData *td =
                        SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_THRESHOLD);
                if (td == NULL) {
                    continue;
                }
                if (td->track != TRACK_RULE) {
                    continue;
                }
                if (s->num >= highest_signum) {
                    highest_signum = s->num;
                    has_by_rule_tracking = true;
                }
            } while (smd != NULL);
        }

        s = s->next;
    }

    /* Skip allocating if by_rule tracking is not used */
    if (has_by_rule_tracking == false) {
        return;
    }

    de_ctx->ths_ctx.th_size = highest_signum + 1;
    de_ctx->ths_ctx.th_entry = SCCalloc(de_ctx->ths_ctx.th_size, sizeof(DetectThresholdEntry *));
    if (de_ctx->ths_ctx.th_entry == NULL) {
        FatalError(
                "failed to allocate memory for \"by_rule\" thresholding (tried to allocate %" PRIu32
                " entries)",
                de_ctx->ths_ctx.th_size);
    }
}

/**
 * \brief Destroy threshold context hash tables
 *
 * \param de_ctx Detection Context
 *
 */
void ThresholdContextDestroy(DetectEngineCtx *de_ctx)
{
    if (de_ctx->ths_ctx.th_entry != NULL) {
        for (uint32_t i = 0; i < de_ctx->ths_ctx.th_size; i++) {
            if (de_ctx->ths_ctx.th_entry[i] != NULL) {
                SCFree(de_ctx->ths_ctx.th_entry[i]);
            }
        }
        SCFree(de_ctx->ths_ctx.th_entry);
    }
    SCMutexDestroy(&de_ctx->ths_ctx.threshold_table_lock);
}

/**
 * \brief this function will free all the entries of a list
 *        DetectTagDataEntry
 *
 * \param td pointer to DetectTagDataEntryList
 */
void ThresholdListFree(void *ptr)
{
    if (ptr != NULL) {
        DetectThresholdEntry *entry = ptr;

        while (entry != NULL) {
            DetectThresholdEntry *next_entry = entry->next;
            SCFree(entry);
            entry = next_entry;
        }
    }
}

/**
 * @}
 */
