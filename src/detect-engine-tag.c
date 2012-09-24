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
 * \file detect-engine-tag.c
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements a global context to store data related to hosts flagged
 * tag keyword
 */

#include "suricata-common.h"
#include "util-hash.h"
#include "util-atomic.h"
#include "util-time.h"
#include "util-hashlist.h"
#include "detect-engine-tag.h"
#include "detect-tag.h"
#include "host.h"

SC_ATOMIC_DECLARE(unsigned int, num_tags);  /**< Atomic counter, to know if we
                                                 have tagged hosts/sessions,
                                                 to avoid locking */

void TagInitCtx(void) {
    SC_ATOMIC_INIT(num_tags);
}

/**
 * \brief Destroy tag context hash tables
 *
 * \param tag_ctx Tag Context
 *
 */
void TagDestroyCtx(void)
{
#ifdef DEBUG
    BUG_ON(SC_ATOMIC_GET(num_tags) != 0);
#endif
    SC_ATOMIC_DESTROY(num_tags);
}

/** \brief Reset the tagging engine context
 */
void TagRestartCtx() {
    TagDestroyCtx();
    TagInitCtx();
}

static DetectTagDataEntry *DetectTagDataCopy(DetectTagDataEntry *dtd) {
    DetectTagDataEntry *tde = SCMalloc(sizeof(DetectTagDataEntry));
    if (unlikely(tde == NULL)) {
        return NULL;
    }
    memset(tde, 0, sizeof(DetectTagDataEntry));

    tde->sid = dtd->sid;
    tde->gid = dtd->gid;
    tde->flags = dtd->flags;
    tde->metric = dtd->metric;
    tde->count = dtd->count;

    tde->first_ts = dtd->first_ts;
    tde->last_ts = dtd->last_ts;
    return tde;
}

/**
 * \brief This function is used to add a tag to a session (type session)
 *        or update it if it's already installed. The number of times to
 *        allow an update is limited by DETECT_TAG_MATCH_LIMIT. This way
 *        repetitive matches to the same rule are limited of setting tags,
 *        to avoid DOS attacks
 *
 * \param p pointer to the current packet
 * \param tde pointer to the new DetectTagDataEntry
 *
 * \retval 0 if the tde was added succesfuly
 * \retval 1 if an entry of this sid/gid already exist and was updated
 */
int TagFlowAdd(Packet *p, DetectTagDataEntry *tde) {
    uint8_t updated = 0;
    uint16_t num_tags = 0;
    DetectTagDataEntry *iter = NULL;

    if (p->flow == NULL)
        return 1;

    FLOWLOCK_WRLOCK(p->flow);

    if (p->flow->tag_list != NULL) {
        iter = p->flow->tag_list;

        /* First iterate installed entries searching a duplicated sid/gid */
        for (; iter != NULL; iter = iter->next) {
            num_tags++;

            if (iter->sid == tde->sid && iter->gid == tde->gid) {
                iter->cnt_match++;

                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_TAG_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts = iter->last_ts = tde->first_ts;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }
    }

    /* If there was no entry of this rule, prepend the new tde */
    if (updated == 0 && num_tags < DETECT_TAG_MAX_TAGS) {
        DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
        if (new_tde != NULL) {
            new_tde->next = p->flow->tag_list;
            p->flow->tag_list = new_tde;
            (void) SC_ATOMIC_ADD(num_tags, 1);
        }
    } else if (num_tags == DETECT_TAG_MAX_TAGS) {
        SCLogDebug("Max tags for sessions reached (%"PRIu16")", num_tags);
    }

    FLOWLOCK_UNLOCK(p->flow);
    return updated;
}

/**
 * \brief Add a tag entry for a host. If it already exist, update it.
 *
 * \param tag_ctx Tag context for hosts
 * \param tde Tag data
 * \param p packet
 *
 * \retval 0 if it was added, 1 if it was updated
 */
int TagHashAddTag(DetectTagDataEntry *tde, Packet *p)
{
    SCEnter();

    uint8_t updated = 0;
    uint16_t num_tags = 0;
    Host *host = NULL;

    /* Lookup host in the hash. If it doesn't exist yet it's
     * created. */
    if (tde->flags & TAG_ENTRY_FLAG_DIR_SRC) {
        host = HostGetHostFromHash(&p->src);
    } else if (tde->flags & TAG_ENTRY_FLAG_DIR_DST) {
        host = HostGetHostFromHash(&p->dst);
    }
    /* no host for us */
    if (host == NULL) {
        return -1;
    }

    if (host->tag == NULL) {
        /* get a new tde as the one we have is on the stack */
        DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
        if (new_tde != NULL) {
            host->tag = new_tde;
            (void) SC_ATOMIC_ADD(num_tags, 1);
        }
    } else {
        /* Append the tag to the list of this host */

        /* First iterate installed entries searching a duplicated sid/gid */
        DetectTagDataEntry *iter = NULL;

        for (iter = host->tag; iter != NULL; iter = iter->next) {
            num_tags++;
            if (iter->sid == tde->sid && iter->gid == tde->gid) {
                iter->cnt_match++;
                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_TAG_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts = iter->last_ts = tde->first_ts;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }

        /* If there was no entry of this rule, append the new tde */
        if (updated == 0 && num_tags < DETECT_TAG_MAX_TAGS) {
            /* get a new tde as the one we have is on the stack */
            DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
            if (new_tde != NULL) {
                (void) SC_ATOMIC_ADD(num_tags, 1);

                new_tde->next = host->tag;
                host->tag = new_tde;
            }
        } else if (num_tags == DETECT_TAG_MAX_TAGS) {
            SCLogDebug("Max tags for sessions reached (%"PRIu16")", num_tags);
        }
    }

    HostRelease(host);
    SCReturnInt(updated);
}

static void TagHandlePacketFlow(Flow *f, Packet *p) {
    if (f->tag_list == NULL)
        return;

    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *prev = NULL;
    DetectTagDataEntry *iter = f->tag_list;
    uint8_t flag_added = 0;

    while (iter != NULL) {
        /* update counters */
        iter->last_ts = p->ts.tv_sec;
        switch (iter->metric) {
            case DETECT_TAG_METRIC_PACKET:
                iter->packets++;
                break;
            case DETECT_TAG_METRIC_BYTES:
                iter->bytes += GET_PKT_LEN(p);
                break;
        }

        /* If this packet triggered the rule with tag, we dont need
         * to log it (the alert will log it) */
        if (!(iter->flags & TAG_ENTRY_FLAG_SKIPPED_FIRST)) {
            iter->flags |= TAG_ENTRY_FLAG_SKIPPED_FIRST;
        } else {
            /* Update metrics; remove if tag expired; and set alerts */
            switch (iter->metric) {
                case DETECT_TAG_METRIC_PACKET:
                    if (iter->packets > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            p->flow->tag_list = iter->next;
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
                case DETECT_TAG_METRIC_BYTES:
                    if (iter->bytes > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            p->flow->tag_list = iter->next;
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
                case DETECT_TAG_METRIC_SECONDS:
                    /* last_ts handles this metric, but also a generic time based
                     * expiration to prevent dead sessions/hosts */
                    if (iter->last_ts - iter->first_ts > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            p->flow->tag_list = iter->next;
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
            }

        }

        prev = iter;
        iter = iter->next;
    }
}

void TagHandlePacketHost(Host *host, Packet *p) {
    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *prev = NULL;
    DetectTagDataEntry *iter;
    uint8_t flag_added = 0;

    iter = host->tag;
    prev = NULL;
    while (iter != NULL) {
        /* update counters */
        iter->last_ts = p->ts.tv_sec;
        switch (iter->metric) {
            case DETECT_TAG_METRIC_PACKET:
                iter->packets++;
                break;
            case DETECT_TAG_METRIC_BYTES:
                iter->bytes += GET_PKT_LEN(p);
                break;
        }

        /* If this packet triggered the rule with tag, we dont need
         * to log it (the alert will log it) */
        if (!(iter->flags & TAG_ENTRY_FLAG_SKIPPED_FIRST)) {
            iter->flags |= TAG_ENTRY_FLAG_SKIPPED_FIRST;
        } else {
            /* Update metrics; remove if tag expired; and set alerts */
            switch (iter->metric) {
                case DETECT_TAG_METRIC_PACKET:
                    if (iter->packets > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            host->tag = iter;
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
                case DETECT_TAG_METRIC_BYTES:
                    if (iter->bytes > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            host->tag = iter;
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
                case DETECT_TAG_METRIC_SECONDS:
                    /* last_ts handles this metric, but also a generic time based
                     * expiration to prevent dead sessions/hosts */
                    if (iter->last_ts - iter->first_ts > iter->count) {
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            tde = iter;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            host->tag = iter;
                            continue;
                        }
                    } else if (flag_added == 0) {
                        /* It's matching the tag. Add it to be logged and
                         * update "flag_added" to add the packet once. */
                        p->flags |= PKT_HAS_TAG;
                        flag_added++;
                    }
                    break;
            }

        }

        prev = iter;
        iter = iter->next;
    }
}

/**
 * \brief Search tags for src and dst. Update entries of the tag, remove if necessary
 *
 * \param de_ctx Detect context
 * \param det_ctx Detect thread context
 * \param p packet
 *
 */
void TagHandlePacket(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p)
{
    /* If there's no tag, get out of here */
    unsigned int current_tags = SC_ATOMIC_GET(num_tags);
    if (current_tags == 0)
        return;

    /* First update and get session tags */
    if (p->flow != NULL) {
        FLOWLOCK_WRLOCK(p->flow);
        TagHandlePacketFlow(p->flow, p);
        FLOWLOCK_UNLOCK(p->flow);
    }

    Host *src = HostLookupHostFromHash(&p->src);
    if (src) {
        if (src->tag != NULL) {
            TagHandlePacketHost(src,p);
        }
        HostRelease(src);
    }
    Host *dst = HostLookupHostFromHash(&p->dst);
    if (dst) {
        if (dst->tag != NULL) {
            TagHandlePacketHost(dst,p);
        }
        HostRelease(dst);
    }
}

/**
 * \brief Removes the entries exceding the max timeout value
 *
 * \param tag_ctx Tag context
 * \param ts the current time
 *
 * \retval 1 no tags or tags removed -- host is free to go (from tag perspective)
 * \retval 0 still active tags
 */
int TagTimeoutCheck(Host *host, struct timeval *tv)
{
    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *tmp = NULL;
    DetectTagDataEntry *prev = NULL;
    int retval = 1;

    if (host->tag == NULL)
        return 1;

    tmp = host->tag;

    prev = NULL;
    while (tmp != NULL) {
        if ((tv->tv_sec - tmp->last_ts) <= TAG_MAX_LAST_TIME_SEEN) {
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
            (void) SC_ATOMIC_SUB(num_tags, 1);
        } else {
            host->tag = tmp->next;

            tde = tmp;
            tmp = tde->next;

            SCFree(tde);
            (void) SC_ATOMIC_SUB(num_tags, 1);
        }
    }
    return retval;
}

