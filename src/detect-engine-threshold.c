/* Copyright (C) 2007-2021 Open Information Security Foundation
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

// ACTION_DROP
#include "action-globals.h"

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
        FatalError(SC_ERR_FATAL,
                   "Can't initiate host storage for thresholding");
    }
    ippair_threshold_id = IPPairStorageRegister("threshold", sizeof(void *), NULL, ThresholdListFree);
    if (ippair_threshold_id.id == -1) {
        FatalError(SC_ERR_FATAL,
                   "Can't initiate IP pair storage for thresholding");
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

static DetectThresholdEntry* ThresholdTimeoutCheck(DetectThresholdEntry *head, struct timeval *tv)
{
    DetectThresholdEntry *tmp = head;
    DetectThresholdEntry *prev = NULL;
    DetectThresholdEntry *new_head = head;

    while (tmp != NULL) {
        /* check if the 'check' timestamp is not before the creation ts.
         * This can happen due to the async nature of the host timeout
         * code that also calls this code from a management thread. */
        struct timeval entry = TimevalWithSeconds(&tmp->tv1, (time_t)tmp->seconds);
        if (TimevalEarlier(tv, &entry)) {
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

int ThresholdHostTimeoutCheck(Host *host, struct timeval *tv)
{
    DetectThresholdEntry* head = HostGetStorageById(host, host_threshold_id);
    DetectThresholdEntry* new_head = ThresholdTimeoutCheck(head, tv);
    if (new_head != head) {
        HostSetStorageById(host, host_threshold_id, new_head);
    }
    return new_head == NULL;
}


int ThresholdIPPairTimeoutCheck(IPPair *pair, struct timeval *tv)
{
    DetectThresholdEntry* head = IPPairGetStorageById(pair, ippair_threshold_id);
    DetectThresholdEntry* new_head = ThresholdTimeoutCheck(head, tv);
    if (new_head != head) {
        IPPairSetStorageById(pair, ippair_threshold_id, new_head);
    }
    return new_head == NULL;
}

static DetectThresholdEntry *
DetectThresholdEntryAlloc(const DetectThresholdData *td, Packet *p,
                          uint32_t sid, uint32_t gid)
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
        default:
            SCLogError(SC_ERR_INVALID_VALUE,
                    "track mode %d is not supported", td->track);
            break;
    }
    if (m == NULL)
        ret = 1;
    else
        ret = 2; /* suppressed but still need actions */

    return ret;
}

static inline void RateFilterSetAction(Packet *p, PacketAlert *pa, uint8_t new_action)
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
static int IsThresholdReached(DetectThresholdEntry* lookup_tsh, const DetectThresholdData *td, struct timeval packet_time)
{
    int ret = 0;

    /* Check if we have a timeout enabled, if so,
    * we still matching (and enabling the new_action) */
    if (lookup_tsh->tv_timeout != 0) {
        if ((packet_time.tv_sec - lookup_tsh->tv_timeout) > td->timeout) {
            /* Ok, we are done, timeout reached */
            lookup_tsh->tv_timeout = 0;
        }
        else {
            /* Already matching */
            ret = 1;
        } /* else - if ((packet_time - lookup_tsh->tv_timeout) > td->timeout) */

    }
    else {
        /* Update the matching state with the timeout interval */
        struct timeval entry = TimevalWithSeconds(&lookup_tsh->tv1, (time_t)td->seconds);
        if (TimevalEarlier(&packet_time, &entry)) {
            lookup_tsh->current_count++;
            if (lookup_tsh->current_count > td->count) {
                /* Then we must enable the new action by setting a
                * timeout */
                lookup_tsh->tv_timeout = packet_time.tv_sec;
                ret = 1;
            }
        } else {
            lookup_tsh->tv1 = packet_time;
            lookup_tsh->current_count = 1;
        }
    } /* else - if (lookup_tsh->tv_timeout != 0) */

    return ret;
}

static void AddEntryToHostStorage(Host *h, DetectThresholdEntry *e, struct timeval packet_time)
{
    if (h && e) {
        e->current_count = 1;
        e->tv1 = packet_time;
        e->tv_timeout = 0;
        e->next = HostGetStorageById(h, host_threshold_id);
        HostSetStorageById(h, host_threshold_id, e);
    }
}

static void AddEntryToIPPairStorage(IPPair *pair, DetectThresholdEntry *e, struct timeval packet_time)
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
                struct timeval entry = TimevalWithSeconds(&lookup_tsh->tv1, (time_t)td->seconds);
                if (TimevalEarlier(&p->ts, &entry)) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count <= td->count) {
                        ret = 1;
                    } else {
                        ret = 2;
                    }
                } else {
                    lookup_tsh->tv1 = p->ts;
                    lookup_tsh->current_count = 1;

                    ret = 1;
                }
            } else {
                *new_tsh = DetectThresholdEntryAlloc(td, p, sid, gid);

                ret = 1;
            }
            break;
        }
        case TYPE_THRESHOLD:
        {
            SCLogDebug("threshold");

            if (lookup_tsh != NULL)  {
                struct timeval entry = TimevalWithSeconds(&lookup_tsh->tv1, (time_t)td->seconds);
                if (TimevalEarlier(&p->ts, &entry)) {
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
                    *new_tsh = DetectThresholdEntryAlloc(td, p, sid, gid);
                }
            }
            break;
        }
        case TYPE_BOTH:
        {
            SCLogDebug("both");

            if (lookup_tsh != NULL) {
                struct timeval entry = TimevalWithSeconds(&lookup_tsh->tv1, (time_t)td->seconds);
                if (TimevalEarlier(&p->ts, &entry)) {
                    /* within time limit */

                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count == td->count) {
                        ret = 1;
                    } else if (lookup_tsh->current_count > td->count) {
                        /* silent match */
                        ret = 2;
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
                *new_tsh = DetectThresholdEntryAlloc(td, p, sid, gid);

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
                struct timeval entry = TimevalWithSeconds(&lookup_tsh->tv1, (time_t)td->seconds);
                if (TimevalEarlier(&p->ts, &entry)) {
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
                *new_tsh = DetectThresholdEntryAlloc(td, p, sid, gid);
            }
            break;
        }
        /* rate_filter */
        case TYPE_RATE:
        {
            SCLogDebug("rate_filter");
            ret = 1;
            if (lookup_tsh && IsThresholdReached(lookup_tsh, td, p->ts)) {
                RateFilterSetAction(p, pa, td->new_action);
            } else if (!lookup_tsh) {
                *new_tsh = DetectThresholdEntryAlloc(td, p, sid, gid);
            }
            break;
        }
        /* case TYPE_SUPPRESS: is not handled here */
        default:
            SCLogError(SC_ERR_INVALID_VALUE, "type %d is not supported", td->type);
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
 * \brief Make the threshold logic for signatures
 *
 * \param de_ctx Dectection Context
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
        Host *src = HostGetHostFromHash(&p->src);
        if (src) {
            ret = ThresholdHandlePacketHost(src,p,td,s->id,s->gid,pa);
            HostRelease(src);
        }
    } else if (td->track == TRACK_DST) {
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
    }

    SCReturnInt(ret);
}

/**
 * \brief Init threshold context hash tables
 *
 * \param de_ctx Dectection Context
 *
 */
void ThresholdHashInit(DetectEngineCtx *de_ctx)
{
    if (SCMutexInit(&de_ctx->ths_ctx.threshold_table_lock, NULL) != 0) {
                FatalError(SC_ERR_FATAL,
                           "Threshold: Failed to initialize hash table mutex.");
    }
}

/**
 * \brief Allocate threshold context hash tables
 *
 * \param de_ctx Detection Context
 */
void ThresholdHashAllocate(DetectEngineCtx *de_ctx)
{
    Signature *s = de_ctx->sig_list;
    bool has_by_rule_tracking = false;
    const DetectThresholdData *td = NULL;
    const SigMatchData *smd;

    /* Find the signature with the highest signature number that is using
       thresholding with by_rule tracking. */
    uint32_t highest_signum = 0;
    while (s != NULL) {
        if (s->sm_arrays[DETECT_SM_LIST_SUPPRESS] != NULL) {
            smd = NULL;
            do {
                td = SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_SUPPRESS);
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
            smd = NULL;
            do {
                td = SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_THRESHOLD);
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
        FatalError(SC_ERR_MEM_ALLOC,
                "Error allocating memory for rule "
                "thresholds (tried to allocate %" PRIu32 " th_entrys for "
                "rule tracking)",
                de_ctx->ths_ctx.th_size);
    }
}

/**
 * \brief Destroy threshold context hash tables
 *
 * \param de_ctx Dectection Context
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
