/* Copyright (C) 2007-2015 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "host.h"
#include "host-storage.h"

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

static int threshold_id = -1; /**< host storage id for thresholds */

int ThresholdHostStorageId(void)
{
    return threshold_id;
}

void ThresholdInit(void)
{
    threshold_id = HostStorageRegister("threshold", sizeof(void *), NULL, ThresholdListFree);
    if (threshold_id == -1) {
        SCLogError(SC_ERR_HOST_INIT, "Can't initiate host storage for thresholding");
        exit(EXIT_FAILURE);
    }
}

int ThresholdHostHasThreshold(Host *host)
{
    return HostGetStorageById(host, threshold_id) ? 1 : 0;
}

/**
 * \brief Return next DetectThresholdData for signature
 *
 * \param sig Signature pointer
 * \param p Packet structure
 * \param sm Pointer to a Signature Match pointer
 *
 * \retval tsh Return the threshold data from signature or NULL if not found
 *
 *
 */
DetectThresholdData *SigGetThresholdTypeIter(Signature *sig, Packet *p, SigMatch **psm, int list)
{
    SigMatch *sm = NULL;
    DetectThresholdData *tsh = NULL;

    if (sig == NULL)
        return NULL;

    if (*psm == NULL) {
        sm = sig->sm_lists_tail[list];
    } else {
        /* Iteration in progress, using provided value */
        sm = *psm;
    }

    if (p == NULL)
        return NULL;

    while (sm != NULL) {
        if (sm->type == DETECT_THRESHOLD || sm->type == DETECT_DETECTION_FILTER) {
            tsh = (DetectThresholdData *)sm->ctx;
            *psm = sm->prev;
            return tsh;
        }

        sm = sm->prev;
    }
    *psm = NULL;

    return NULL;
}

/**
 * \brief Remove timeout threshold hash elements
 *
 * \param de_ctx Dectection Context
 *
 */

int ThresholdTimeoutCheck(Host *host, struct timeval *tv)
{
    DetectThresholdEntry *tde = NULL;
    DetectThresholdEntry *tmp = NULL;
    DetectThresholdEntry *prev = NULL;
    int retval = 1;

    tmp = HostGetStorageById(host, threshold_id);
    if (tmp == NULL)
         return 1;

    prev = NULL;
    while (tmp != NULL) {
        if ((tv->tv_sec - tmp->tv_sec1) <= tmp->seconds) {
            prev = tmp;
            tmp = tmp->next;
            retval = 0;
            continue;
        }

        /* timed out */

        if (prev != NULL) {
            prev->next = tmp->next;

            tde = tmp;
            tmp = tde->next;

            SCFree(tde);
        } else {
            HostSetStorageById(host, threshold_id, tmp->next);
            tde = tmp;
            tmp = tde->next;

            SCFree(tde);
        }
    }

    return retval;
}

static inline DetectThresholdEntry *DetectThresholdEntryAlloc(DetectThresholdData *td, Packet *p, uint32_t sid, uint32_t gid)
{
    SCEnter();

    DetectThresholdEntry *ste = SCMalloc(sizeof(DetectThresholdEntry));
    if (unlikely(ste == NULL)) {
        SCReturnPtr(NULL, "DetectThresholdEntry");
    }

    ste->sid = sid;
    ste->gid = gid;

    ste->track = td->track;
    ste->seconds = td->seconds;
    ste->tv_timeout = 0;

    SCReturnPtr(ste, "DetectThresholdEntry");
}

static DetectThresholdEntry *ThresholdHostLookupEntry(Host *h, uint32_t sid, uint32_t gid)
{
    DetectThresholdEntry *e;

    for (e = HostGetStorageById(h, threshold_id); e != NULL; e = e->next) {
        if (e->sid == sid && e->gid == gid)
            break;
    }

    return e;
}

int ThresholdHandlePacketSuppress(Packet *p, DetectThresholdData *td, uint32_t sid, uint32_t gid)
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

/**
 *  \retval 2 silent match (no alert but apply actions)
 *  \retval 1 normal match
 *  \retval 0 no match
 */
int ThresholdHandlePacketHost(Host *h, Packet *p, DetectThresholdData *td, uint32_t sid, uint32_t gid)
{
    int ret = 0;

    DetectThresholdEntry *lookup_tsh = ThresholdHostLookupEntry(h, sid, gid);
    SCLogDebug("lookup_tsh %p sid %u gid %u", lookup_tsh, sid, gid);

    switch(td->type)   {
        case TYPE_LIMIT:
        {
            SCLogDebug("limit");

            if (lookup_tsh != NULL)  {
                if ((p->ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count <= td->count) {
                        ret = 1;
                    } else {
                        ret = 2;
                    }
                } else    {
                    lookup_tsh->tv_sec1 = p->ts.tv_sec;
                    lookup_tsh->current_count = 1;

                    ret = 1;
                }
            } else {
                DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, sid, gid);
                if (e == NULL) {
                    break;
                }

                e->tv_sec1 = p->ts.tv_sec;
                e->current_count = 1;

                ret = 1;

                e->next = HostGetStorageById(h, threshold_id);
                HostSetStorageById(h, threshold_id, e);
            }
            break;
        }
        case TYPE_THRESHOLD:
        {
            SCLogDebug("threshold");

            if (lookup_tsh != NULL)  {
                if ((p->ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count >= td->count) {
                        ret = 1;
                        lookup_tsh->current_count = 0;
                    }
                } else {
                    lookup_tsh->tv_sec1 = p->ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else {
                if (td->count == 1)  {
                    ret = 1;
                } else {
                    DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, sid, gid);
                    if (e == NULL) {
                        break;
                    }

                    e->current_count = 1;
                    e->tv_sec1 = p->ts.tv_sec;

                    e->next = HostGetStorageById(h, threshold_id);
                    HostSetStorageById(h, threshold_id, e);
                }
            }
            break;
        }
        case TYPE_BOTH:
        {
            SCLogDebug("both");

            if (lookup_tsh != NULL) {
                if ((p->ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
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
                    lookup_tsh->tv_sec1 = p->ts.tv_sec;
                    lookup_tsh->current_count = 1;

                    /* if we have a limit of 1, this is a match */
                    if (lookup_tsh->current_count == td->count) {
                        ret = 1;
                    }
                }
            } else {
                DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, sid, gid);
                if (e == NULL) {
                    break;
                }

                e->current_count = 1;
                e->tv_sec1 = p->ts.tv_sec;

                e->next = HostGetStorageById(h, threshold_id);
                HostSetStorageById(h, threshold_id, e);

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
                long double time_diff = ((p->ts.tv_sec + p->ts.tv_usec/1000000.0) -
                                         (lookup_tsh->tv_sec1 + lookup_tsh->tv_usec1/1000000.0));

                if (time_diff < td->seconds) {
                    /* within timeout */

                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count > td->count) {
                        ret = 1;
                    }
                } else {
                    /* expired, reset */

                    lookup_tsh->tv_sec1 = p->ts.tv_sec;
                    lookup_tsh->tv_usec1 = p->ts.tv_usec;
                    lookup_tsh->current_count = 1;
                }
            } else {
                DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, sid, gid);
                if (e == NULL) {
                    break;
                }

                e->current_count = 1;
                e->tv_sec1 = p->ts.tv_sec;
                e->tv_usec1 = p->ts.tv_usec;

                e->next = HostGetStorageById(h, threshold_id);
                HostSetStorageById(h, threshold_id, e);
            }
            break;
        }
        /* rate_filter */
        case TYPE_RATE:
        {
            SCLogDebug("rate_filter");

            ret = 1;

            if (lookup_tsh != NULL) {
                /* Check if we have a timeout enabled, if so,
                 * we still matching (and enabling the new_action) */
                if (lookup_tsh->tv_timeout != 0) {
                    if ((p->ts.tv_sec - lookup_tsh->tv_timeout) > td->timeout) {
                        /* Ok, we are done, timeout reached */
                        lookup_tsh->tv_timeout = 0;
                    } else {
                        /* Already matching */
                        /* Take the action to perform */
                        switch (td->new_action) {
                            case TH_ACTION_ALERT:
                                PACKET_ALERT(p);
                                break;
                            case TH_ACTION_DROP:
                                PACKET_DROP(p);
                                break;
                            case TH_ACTION_REJECT:
                                PACKET_REJECT(p);
                                break;
                            case TH_ACTION_PASS:
                                PACKET_PASS(p);
                                break;
                            default:
                                /* Weird, leave the default action */
                                break;
                        }
                        ret = 1;
                    } /* else - if ((p->ts.tv_sec - lookup_tsh->tv_timeout) > td->timeout) */

                } else {
                    /* Update the matching state with the timeout interval */
                    if ( (p->ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                        lookup_tsh->current_count++;
                        if (lookup_tsh->current_count > td->count) {
                            /* Then we must enable the new action by setting a
                             * timeout */
                            lookup_tsh->tv_timeout = p->ts.tv_sec;
                            /* Take the action to perform */
                            switch (td->new_action) {
                                case TH_ACTION_ALERT:
                                    PACKET_ALERT(p);
                                    break;
                                case TH_ACTION_DROP:
                                    PACKET_DROP(p);
                                    break;
                                case TH_ACTION_REJECT:
                                    PACKET_REJECT(p);
                                    break;
                                case TH_ACTION_PASS:
                                    PACKET_PASS(p);
                                    break;
                                default:
                                    /* Weird, leave the default action */
                                    break;
                            }
                            ret = 1;
                        }
                    } else {
                        lookup_tsh->tv_sec1 = p->ts.tv_sec;
                        lookup_tsh->current_count = 1;
                    }
                } /* else - if (lookup_tsh->tv_timeout != 0) */
            } else {
                if (td->count == 1) {
                    ret = 1;
                }

                DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, sid, gid);
                if (e == NULL) {
                    break;
                }

                e->current_count = 1;
                e->tv_sec1 = p->ts.tv_sec;
                e->tv_timeout = 0;

                e->next = HostGetStorageById(h, threshold_id);
                HostSetStorageById(h, threshold_id, e);
            }
            break;
        }
        /* case TYPE_SUPPRESS: is not handled here */
        default:
            SCLogError(SC_ERR_INVALID_VALUE, "type %d is not supported", td->type);
    }

    return ret;
}

static int ThresholdHandlePacketRule(DetectEngineCtx *de_ctx, Packet *p, DetectThresholdData *td, Signature *s)
{
    int ret = 0;

    if (td->type != TYPE_RATE)
        return 1;

    DetectThresholdEntry* lookup_tsh = (DetectThresholdEntry *)de_ctx->ths_ctx.th_entry[s->num];
    if (lookup_tsh != NULL) {
        /* Check if we have a timeout enabled, if so,
         * we still matching (and enabling the new_action) */
        if ( (p->ts.tv_sec - lookup_tsh->tv_timeout) > td->timeout) {
            /* Ok, we are done, timeout reached */
            td->timeout = 0;
        } else {
            /* Already matching */
            /* Take the action to perform */
            switch (td->new_action) {
                case TH_ACTION_ALERT:
                    PACKET_ALERT(p);
                    break;
                case TH_ACTION_DROP:
                    PACKET_DROP(p);
                    break;
                case TH_ACTION_REJECT:
                    PACKET_REJECT(p);
                    break;
                case TH_ACTION_PASS:
                    PACKET_PASS(p);
                    break;
                default:
                    /* Weird, leave the default action */
                    break;
            }
            ret = 1;
        }

        /* Update the matching state with the timeout interval */
        if ( (p->ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
            lookup_tsh->current_count++;
            if (lookup_tsh->current_count >= td->count) {
                /* Then we must enable the new action by setting a
                 * timeout */
                lookup_tsh->tv_timeout = p->ts.tv_sec;
                /* Take the action to perform */
                switch (td->new_action) {
                    case TH_ACTION_ALERT:
                        PACKET_ALERT(p);
                        break;
                    case TH_ACTION_DROP:
                        PACKET_DROP(p);
                        break;
                    case TH_ACTION_REJECT:
                        PACKET_REJECT(p);
                        break;
                    case TH_ACTION_PASS:
                        PACKET_PASS(p);
                        break;
                    default:
                        /* Weird, leave the default action */
                        break;
                }
                ret = 1;
            }
        } else {
            lookup_tsh->tv_sec1 = p->ts.tv_sec;
            lookup_tsh->current_count = 1;
        }
    } else {
        if (td->count == 1) {
            ret = 1;
        }

        DetectThresholdEntry *e = DetectThresholdEntryAlloc(td, p, s->id, s->gid);
        if (e != NULL) {
            e->current_count = 1;
            e->tv_sec1 = p->ts.tv_sec;
            e->tv_timeout = 0;

            de_ctx->ths_ctx.th_entry[s->num] = e;
        }
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
        DetectThresholdData *td, Packet *p, Signature *s)
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
            ret = ThresholdHandlePacketHost(src,p,td,s->id,s->gid);
            HostRelease(src);
        }
    } else if (td->track == TRACK_DST) {
        Host *dst = HostGetHostFromHash(&p->dst);
        if (dst) {
            ret = ThresholdHandlePacketHost(dst,p,td,s->id,s->gid);
            HostRelease(dst);
        }
    } else if (td->track == TRACK_RULE) {
        SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
        ret = ThresholdHandlePacketRule(de_ctx,p,td,s);
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
        SCLogError(SC_ERR_MEM_ALLOC,
                "Threshold: Failed to initialize hash table mutex.");
        exit(EXIT_FAILURE);
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
    if (de_ctx->ths_ctx.th_entry != NULL)
        SCFree(de_ctx->ths_ctx.th_entry);
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
