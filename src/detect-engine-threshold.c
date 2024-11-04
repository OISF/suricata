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

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-threshold.h"
#include "detect-engine-address.h"
#include "detect-engine-address-ipv6.h"

#include "util-misc.h"
#include "util-time.h"
#include "util-error.h"
#include "util-debug.h"
#include "action-globals.h"
#include "util-validate.h"

#include "util-hash.h"
#include "util-thash.h"
#include "util-hash-lookup3.h"

struct Thresholds {
    THashTableContext *thash;
} ctx;

static int ThresholdsInit(struct Thresholds *t);
static void ThresholdsDestroy(struct Thresholds *t);

void ThresholdInit(void)
{
    ThresholdsInit(&ctx);
}

void ThresholdDestroy(void)
{
    ThresholdsDestroy(&ctx);
}

#define SID    0
#define GID    1
#define REV    2
#define TRACK  3
#define TENANT 4

typedef struct ThresholdEntry_ {
    uint32_t key[5];

    uint32_t tv_timeout;    /**< Timeout for new_action (for rate_filter)
                                 its not "seconds", that define the time interval */
    uint32_t seconds;       /**< Event seconds */
    uint32_t current_count; /**< Var for count control */

    union {
        struct {
            uint32_t next_value;
        } backoff;
        struct {
            SCTime_t tv1;  /**< Var for time control */
            Address addr;  /* used for src/dst/either tracking */
            Address addr2; /* used for both tracking */
        };
    };

} ThresholdEntry;

static int ThresholdEntrySet(void *dst, void *src)
{
    const ThresholdEntry *esrc = src;
    ThresholdEntry *edst = dst;
    memset(edst, 0, sizeof(*edst));
    *edst = *esrc;
    return 0;
}

static void ThresholdEntryFree(void *ptr)
{
    // nothing to free, base data is part of hash
}

static inline uint32_t HashAddress(const Address *a)
{
    uint32_t key;

    if (a->family == AF_INET) {
        key = a->addr_data32[0];
    } else if (a->family == AF_INET6) {
        key = hashword(a->addr_data32, 4, 0);
    } else
        key = 0;

    return key;
}

static inline int CompareAddress(const Address *a, const Address *b)
{
    if (a->family == b->family) {
        switch (a->family) {
            case AF_INET:
                return (a->addr_data32[0] == b->addr_data32[0]);
            case AF_INET6:
                return CMP_ADDR(a, b);
        }
    }
    return 0;
}

static uint32_t ThresholdEntryHash(uint32_t seed, void *ptr)
{
    const ThresholdEntry *e = ptr;
    uint32_t hash = hashword(e->key, sizeof(e->key) / sizeof(uint32_t), seed);
    switch (e->key[TRACK]) {
        case TRACK_BOTH:
            hash += HashAddress(&e->addr2);
            /* fallthrough */
        case TRACK_SRC:
        case TRACK_DST:
            hash += HashAddress(&e->addr);
            break;
    }
    return hash;
}

static bool ThresholdEntryCompare(void *a, void *b)
{
    const ThresholdEntry *e1 = a;
    const ThresholdEntry *e2 = b;
    SCLogDebug("sid1: %u sid2: %u", e1->key[SID], e2->key[SID]);

    if (memcmp(e1->key, e2->key, sizeof(e1->key)) != 0)
        return false;
    switch (e1->key[TRACK]) {
        case TRACK_BOTH:
            if (!(CompareAddress(&e1->addr2, &e2->addr2)))
                return false;
            /* fallthrough */
        case TRACK_SRC:
        case TRACK_DST:
            if (!(CompareAddress(&e1->addr, &e2->addr)))
                return false;
            break;
    }
    return true;
}

static bool ThresholdEntryExpire(void *data, const SCTime_t ts)
{
    const ThresholdEntry *e = data;
    const SCTime_t entry = SCTIME_ADD_SECS(e->tv1, e->seconds);
    if (SCTIME_CMP_GT(ts, entry)) {
        return true;
    }
    return false;
}

static int ThresholdsInit(struct Thresholds *t)
{
    uint32_t hashsize = 16384;
    uint64_t memcap = 16 * 1024 * 1024;

    const char *str;
    if (ConfGet("detect.thresholds.memcap", &str) == 1) {
        if (ParseSizeStringU64(str, &memcap) < 0) {
            SCLogError("Error parsing detect.thresholds.memcap from conf file - %s", str);
            return -1;
        }
    }

    intmax_t value = 0;
    if ((ConfGetInt("detect.thresholds.hash-size", &value)) == 1) {
        if (value < 256 || value > INT_MAX) {
            SCLogError("'detect.thresholds.hash-size' value %" PRIiMAX
                       " out of range. Valid range 256-2147483647.",
                    value);
            return -1;
        }
        hashsize = (uint32_t)value;
    }

    t->thash = THashInit("thresholds", sizeof(ThresholdEntry), ThresholdEntrySet,
            ThresholdEntryFree, ThresholdEntryHash, ThresholdEntryCompare, ThresholdEntryExpire,
            NULL, 0, memcap, hashsize);
    if (t->thash == NULL) {
        SCLogError("failed to initialize thresholds hash table");
        return -1;
    }
    return 0;
}

static void ThresholdsDestroy(struct Thresholds *t)
{
    if (t->thash) {
        THashShutdown(t->thash);
    }
}

uint32_t ThresholdsExpire(const SCTime_t ts)
{
    return THashExpire(ctx.thash, ts);
}

#define TC_ADDRESS 0
#define TC_SID     1
#define TC_GID     2
#define TC_REV     3
#define TC_TENANT  4

typedef struct ThresholdCacheItem {
    int8_t track; // by_src/by_dst
    int8_t ipv;
    int8_t retval;
    uint32_t key[5];
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
    ThresholdCacheItem *e = data;
    uint32_t hash = hashword(e->key, sizeof(e->key) / sizeof(uint32_t), 0) * (e->ipv + e->track);
    hash = hash % ht->array_size;
    return hash;
}

static char ThresholdCacheHashCompareFunc(
        void *data1, uint16_t datalen1, void *data2, uint16_t datalen2)
{
    ThresholdCacheItem *tci1 = data1;
    ThresholdCacheItem *tci2 = data2;
    return tci1->ipv == tci2->ipv && tci1->track == tci2->track &&
           memcmp(tci1->key, tci2->key, sizeof(tci1->key)) == 0;
}

static void ThresholdCacheHashFreeFunc(void *data)
{
    SCFree(data);
}

/// \brief Thread local cache
static int SetupCache(const Packet *p, const int8_t track, const int8_t retval, const uint32_t sid,
        const uint32_t gid, const uint32_t rev, SCTime_t expires)
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
        .key[TC_ADDRESS] = addr,
        .key[TC_SID] = sid,
        .key[TC_GID] = gid,
        .key[TC_REV] = rev,
        .key[TC_TENANT] = p->tenant_id,
        .expires_at = expires,
    };
    ThresholdCacheItem *found = HashTableLookup(threshold_cache_ht, &lookup, 0);
    if (!found) {
        ThresholdCacheItem *n = SCCalloc(1, sizeof(*n));
        if (n) {
            n->track = track;
            n->ipv = 4;
            n->retval = retval;
            n->key[TC_ADDRESS] = addr;
            n->key[TC_SID] = sid;
            n->key[TC_GID] = gid;
            n->key[TC_REV] = rev;
            n->key[TC_TENANT] = p->tenant_id;
            n->expires_at = expires;

            if (HashTableAdd(threshold_cache_ht, n, 0) == 0) {
                ThresholdCacheItem *r = THRESHOLD_CACHE_RB_INSERT(&threshold_cache_tree, n);
                DEBUG_VALIDATE_BUG_ON(r != NULL); // duplicate; should be impossible
                (void)r;                          // only used by DEBUG_VALIDATE_BUG_ON
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
static int CheckCache(const Packet *p, const int8_t track, const uint32_t sid, const uint32_t gid,
        const uint32_t rev)
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
        .key[TC_ADDRESS] = addr,
        .key[TC_SID] = sid,
        .key[TC_GID] = gid,
        .key[TC_REV] = rev,
        .key[TC_TENANT] = p->tenant_id,
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

typedef struct FlowThresholdEntryList_ {
    struct FlowThresholdEntryList_ *next;
    ThresholdEntry threshold;
} FlowThresholdEntryList;

static void FlowThresholdEntryListFree(FlowThresholdEntryList *list)
{
    for (FlowThresholdEntryList *i = list; i != NULL;) {
        FlowThresholdEntryList *next = i->next;
        SCFree(i);
        i = next;
    }
}

/** struct for storing per flow thresholds. This will be stored in the Flow::flowvar list, so it
 * needs to follow the GenericVar header format. */
typedef struct FlowVarThreshold_ {
    uint8_t type;
    uint8_t pad[7];
    struct GenericVar_ *next;
    FlowThresholdEntryList *thresholds;
} FlowVarThreshold;

void FlowThresholdVarFree(void *ptr)
{
    FlowVarThreshold *t = ptr;
    FlowThresholdEntryListFree(t->thresholds);
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

static ThresholdEntry *ThresholdFlowLookupEntry(
        Flow *f, uint32_t sid, uint32_t gid, uint32_t rev, uint32_t tenant_id)
{
    FlowVarThreshold *t = FlowThresholdVarGet(f);
    if (t == NULL)
        return NULL;

    for (FlowThresholdEntryList *e = t->thresholds; e != NULL; e = e->next) {
        if (e->threshold.key[SID] == sid && e->threshold.key[GID] == gid &&
                e->threshold.key[REV] == rev && e->threshold.key[TENANT] == tenant_id) {
            return &e->threshold;
        }
    }
    return NULL;
}

static int AddEntryToFlow(Flow *f, FlowThresholdEntryList *e, SCTime_t packet_time)
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

    e->next = t->thresholds;
    t->thresholds = e;
    return 0;
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

/** \internal
 *  \brief Apply the multiplier and return the new value.
 *  If it would overflow the uint32_t we return UINT32_MAX.
 */
static uint32_t BackoffCalcNextValue(const uint32_t cur, const uint32_t m)
{
    /* goal is to see if cur * m would overflow uint32_t */
    if (unlikely(UINT32_MAX / m < cur)) {
        return UINT32_MAX;
    }
    return cur * m;
}

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 */
static int ThresholdSetup(const DetectThresholdData *td, ThresholdEntry *te,
        const SCTime_t packet_time, const uint32_t sid, const uint32_t gid, const uint32_t rev,
        const uint32_t tenant_id)
{
    te->key[SID] = sid;
    te->key[GID] = gid;
    te->key[REV] = rev;
    te->key[TRACK] = td->track;
    te->key[TENANT] = tenant_id;

    te->seconds = td->seconds;
    te->current_count = 1;

    switch (td->type) {
        case TYPE_BACKOFF:
            te->backoff.next_value = td->count;
            break;
        default:
            te->tv1 = packet_time;
            te->tv_timeout = 0;
            break;
    }

    switch (td->type) {
        case TYPE_LIMIT:
        case TYPE_RATE:
            return 1;
        case TYPE_THRESHOLD:
        case TYPE_BOTH:
            if (td->count == 1)
                return 1;
            return 0;
        case TYPE_BACKOFF:
            if (td->count == 1) {
                te->backoff.next_value =
                        BackoffCalcNextValue(te->backoff.next_value, td->multiplier);
                return 1;
            }
            return 0;
        case TYPE_DETECTION:
            return 0;
    }
    return 0;
}

static int ThresholdCheckUpdate(const DetectThresholdData *td, ThresholdEntry *te,
        const Packet *p, // ts only? - cache too
        const uint32_t sid, const uint32_t gid, const uint32_t rev, PacketAlert *pa)
{
    int ret = 0;
    const SCTime_t packet_time = p->ts;
    const SCTime_t entry = SCTIME_ADD_SECS(te->tv1, td->seconds);
    switch (td->type) {
        case TYPE_LIMIT:
            SCLogDebug("limit");

            if (SCTIME_CMP_LTE(p->ts, entry)) {
                te->current_count++;

                if (te->current_count <= td->count) {
                    ret = 1;
                } else {
                    ret = 2;

                    if (PacketIsIPv4(p)) {
                        SetupCache(p, td->track, (int8_t)ret, sid, gid, rev, entry);
                    }
                }
            } else {
                /* entry expired, reset */
                te->tv1 = p->ts;
                te->current_count = 1;
                ret = 1;
            }
            break;
        case TYPE_THRESHOLD:
            if (SCTIME_CMP_LTE(p->ts, entry)) {
                te->current_count++;

                if (te->current_count >= td->count) {
                    ret = 1;
                    te->current_count = 0;
                }
            } else {
                te->tv1 = p->ts;
                te->current_count = 1;
            }
            break;
        case TYPE_BOTH:
            if (SCTIME_CMP_LTE(p->ts, entry)) {
                /* within time limit */

                te->current_count++;
                if (te->current_count == td->count) {
                    ret = 1;
                } else if (te->current_count > td->count) {
                    /* silent match */
                    ret = 2;

                    if (PacketIsIPv4(p)) {
                        SetupCache(p, td->track, (int8_t)ret, sid, gid, rev, entry);
                    }
                }
            } else {
                /* expired, so reset */
                te->tv1 = p->ts;
                te->current_count = 1;

                /* if we have a limit of 1, this is a match */
                if (te->current_count == td->count) {
                    ret = 1;
                }
            }
            break;
        case TYPE_DETECTION:
            SCLogDebug("detection_filter");

            if (SCTIME_CMP_LTE(p->ts, entry)) {
                /* within timeout */
                te->current_count++;
                if (te->current_count > td->count) {
                    ret = 1;
                }
            } else {
                /* expired, reset */
                te->tv1 = p->ts;
                te->current_count = 1;
            }
            break;
        case TYPE_RATE:
            SCLogDebug("rate_filter");
            ret = 1;
            /* Check if we have a timeout enabled, if so,
             * we still matching (and enabling the new_action) */
            if (te->tv_timeout != 0) {
                if ((SCTIME_SECS(packet_time) - te->tv_timeout) > td->timeout) {
                    /* Ok, we are done, timeout reached */
                    te->tv_timeout = 0;
                } else {
                    /* Already matching */
                    RateFilterSetAction(pa, td->new_action);
                }
            } else {
                /* Update the matching state with the timeout interval */
                if (SCTIME_CMP_LTE(packet_time, entry)) {
                    te->current_count++;
                    if (te->current_count > td->count) {
                        /* Then we must enable the new action by setting a
                         * timeout */
                        te->tv_timeout = SCTIME_SECS(packet_time);
                        RateFilterSetAction(pa, td->new_action);
                    }
                } else {
                    te->tv1 = packet_time;
                    te->current_count = 1;
                }
            }
            break;
        case TYPE_BACKOFF:
            SCLogDebug("backoff");

            if (te->current_count < UINT32_MAX) {
                te->current_count++;
                if (te->backoff.next_value == te->current_count) {
                    te->backoff.next_value =
                            BackoffCalcNextValue(te->backoff.next_value, td->multiplier);
                    SCLogDebug("te->backoff.next_value %u", te->backoff.next_value);
                    ret = 1;
                } else {
                    ret = 2;
                }
            } else {
                /* if count reaches UINT32_MAX, we just silent match on the rest of the flow */
                ret = 2;
            }
            break;
    }
    return ret;
}

static int ThresholdGetFromHash(struct Thresholds *tctx, const Packet *p, const Signature *s,
        const DetectThresholdData *td, PacketAlert *pa)
{
    /* fast track for count 1 threshold */
    if (td->count == 1 && td->type == TYPE_THRESHOLD) {
        return 1;
    }

    ThresholdEntry lookup;
    memset(&lookup, 0, sizeof(lookup));
    lookup.key[SID] = s->id;
    lookup.key[GID] = s->gid;
    lookup.key[REV] = s->rev;
    lookup.key[TRACK] = td->track;
    lookup.key[TENANT] = p->tenant_id;
    if (td->track == TRACK_SRC) {
        COPY_ADDRESS(&p->src, &lookup.addr);
    } else if (td->track == TRACK_DST) {
        COPY_ADDRESS(&p->dst, &lookup.addr);
    } else if (td->track == TRACK_BOTH) {
        /* make sure lower ip address is first */
        if (PacketIsIPv4(p)) {
            if (SCNtohl(p->src.addr_data32[0]) < SCNtohl(p->dst.addr_data32[0])) {
                COPY_ADDRESS(&p->src, &lookup.addr);
                COPY_ADDRESS(&p->dst, &lookup.addr2);
            } else {
                COPY_ADDRESS(&p->dst, &lookup.addr);
                COPY_ADDRESS(&p->src, &lookup.addr2);
            }
        } else {
            if (AddressIPv6Lt(&p->src, &p->dst)) {
                COPY_ADDRESS(&p->src, &lookup.addr);
                COPY_ADDRESS(&p->dst, &lookup.addr2);
            } else {
                COPY_ADDRESS(&p->dst, &lookup.addr);
                COPY_ADDRESS(&p->src, &lookup.addr2);
            }
        }
    }

    struct THashDataGetResult res = THashGetFromHash(tctx->thash, &lookup);
    if (res.data) {
        SCLogDebug("found %p, is_new %s", res.data, BOOL2STR(res.is_new));
        int r;
        ThresholdEntry *te = res.data->data;
        if (res.is_new) {
            // new threshold, set up
            r = ThresholdSetup(td, te, p->ts, s->id, s->gid, s->rev, p->tenant_id);
        } else {
            // existing, check/update
            r = ThresholdCheckUpdate(td, te, p, s->id, s->gid, s->rev, pa);
        }

        (void)THashDecrUsecnt(res.data);
        THashDataUnlock(res.data);
        return r;
    }
    return 0; // TODO error?
}

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 */
static int ThresholdHandlePacketFlow(Flow *f, Packet *p, const DetectThresholdData *td,
        uint32_t sid, uint32_t gid, uint32_t rev, PacketAlert *pa)
{
    int ret = 0;
    ThresholdEntry *found = ThresholdFlowLookupEntry(f, sid, gid, rev, p->tenant_id);
    SCLogDebug("found %p sid %u gid %u rev %u", found, sid, gid, rev);

    if (found == NULL) {
        FlowThresholdEntryList *new = SCCalloc(1, sizeof(*new));
        if (new == NULL)
            return 0;

        // new threshold, set up
        ret = ThresholdSetup(td, &new->threshold, p->ts, sid, gid, rev, p->tenant_id);

        if (AddEntryToFlow(f, new, p->ts) == -1) {
            SCFree(new);
            return 0;
        }
    } else {
        // existing, check/update
        ret = ThresholdCheckUpdate(td, found, p, sid, gid, rev, pa);
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
            int cache_ret = CheckCache(p, td->track, s->id, s->gid, s->rev);
            if (cache_ret >= 0) {
                SCReturnInt(cache_ret);
            }
        }

        ret = ThresholdGetFromHash(&ctx, p, s, td, pa);
    } else if (td->track == TRACK_DST) {
        if (PacketIsIPv4(p) && (td->type == TYPE_LIMIT || td->type == TYPE_BOTH)) {
            int cache_ret = CheckCache(p, td->track, s->id, s->gid, s->rev);
            if (cache_ret >= 0) {
                SCReturnInt(cache_ret);
            }
        }

        ret = ThresholdGetFromHash(&ctx, p, s, td, pa);
    } else if (td->track == TRACK_BOTH) {
        ret = ThresholdGetFromHash(&ctx, p, s, td, pa);
    } else if (td->track == TRACK_RULE) {
        ret = ThresholdGetFromHash(&ctx, p, s, td, pa);
    } else if (td->track == TRACK_FLOW) {
        if (p->flow) {
            ret = ThresholdHandlePacketFlow(p->flow, p, td, s->id, s->gid, s->rev, pa);
        }
    }

    SCReturnInt(ret);
}

/**
 * @}
 */
