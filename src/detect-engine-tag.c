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
 * \file detect-engine-tag.c
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements a global context to store data related to hosts flagged
 * tag keyword
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "util-hash.h"
#include "util-atomic.h"
#include "util-time.h"
#include "util-hashlist.h"
#include "detect-engine-tag.h"
#include "detect-tag.h"
#include "host.h"
#include "host-storage.h"
#include "flow-storage.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"
#include "stream-tcp-private.h"

SC_ATOMIC_DECLARE(unsigned int, num_tags);  /**< Atomic counter, to know if we
                                                 have tagged hosts/sessions,
                                                 to avoid locking */
static HostStorageId host_tag_id = { .id = -1 }; /**< Host storage id for tags */
static FlowStorageId flow_tag_id = { .id = -1 }; /**< Flow storage id for tags */

void TagInitCtx(void)
{
    SC_ATOMIC_INIT(num_tags);

    host_tag_id = HostStorageRegister("tag", sizeof(void *), NULL, DetectTagDataListFree);
    if (host_tag_id.id == -1) {
        FatalError(SC_ERR_FATAL, "Can't initiate host storage for tag");
    }
    flow_tag_id = FlowStorageRegister("tag", sizeof(void *), NULL, DetectTagDataListFree);
    if (flow_tag_id.id == -1) {
        FatalError(SC_ERR_FATAL, "Can't initiate flow storage for tag");
    }
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
}

/** \brief Reset the tagging engine context
 */
void TagRestartCtx()
{
    TagDestroyCtx();
    TagInitCtx();
}

int TagHostHasTag(Host *host)
{
    return HostGetStorageById(host, host_tag_id) ? 1 : 0;
}

static DetectTagDataEntry *DetectTagDataCopy(DetectTagDataEntry *dtd)
{
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
 * \retval 0 if the tde was added successfully
 * \retval 1 if an entry of this sid/gid already exist and was updated
 */
int TagFlowAdd(Packet *p, DetectTagDataEntry *tde)
{
    uint8_t updated = 0;
    uint16_t tag_cnt = 0;
    DetectTagDataEntry *iter = NULL;

    if (p->flow == NULL)
        return 1;

    iter = FlowGetStorageById(p->flow, flow_tag_id);
    if (iter != NULL) {
        /* First iterate installed entries searching a duplicated sid/gid */
        for (; iter != NULL; iter = iter->next) {
            tag_cnt++;

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
    if (updated == 0 && tag_cnt < DETECT_TAG_MAX_TAGS) {
        DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
        if (new_tde != NULL) {
            new_tde->next = FlowGetStorageById(p->flow, flow_tag_id);
            FlowSetStorageById(p->flow, flow_tag_id, new_tde);
            SCLogDebug("adding tag with first_ts %u", new_tde->first_ts);
            (void) SC_ATOMIC_ADD(num_tags, 1);
        }
    } else if (tag_cnt == DETECT_TAG_MAX_TAGS) {
        SCLogDebug("Max tags for sessions reached (%"PRIu16")", tag_cnt);
    }

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
    uint16_t ntags = 0;
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
        SCLogDebug("host tag not added: no host");
        return -1;
    }

    void *tag = HostGetStorageById(host, host_tag_id);
    if (tag == NULL) {
        /* get a new tde as the one we have is on the stack */
        DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
        if (new_tde != NULL) {
            HostSetStorageById(host, host_tag_id, new_tde);
            (void) SC_ATOMIC_ADD(num_tags, 1);
            SCLogDebug("host tag added");
        }
    } else {
        /* Append the tag to the list of this host */
        SCLogDebug("updating existing host");

        /* First iterate installed entries searching a duplicated sid/gid */
        DetectTagDataEntry *iter = NULL;

        for (iter = tag; iter != NULL; iter = iter->next) {
            ntags++;
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
        if (updated == 0 && ntags < DETECT_TAG_MAX_TAGS) {
            /* get a new tde as the one we have is on the stack */
            DetectTagDataEntry *new_tde = DetectTagDataCopy(tde);
            if (new_tde != NULL) {
                (void) SC_ATOMIC_ADD(num_tags, 1);

                new_tde->next = tag;
                HostSetStorageById(host, host_tag_id, new_tde);
            }
        } else if (ntags == DETECT_TAG_MAX_TAGS) {
            SCLogDebug("Max tags for sessions reached (%"PRIu16")", ntags);
        }
    }

    HostRelease(host);
    SCReturnInt(updated);
}

static void TagHandlePacketFlow(Flow *f, Packet *p)
{
    if (FlowGetStorageById(f, flow_tag_id) == NULL)
        return;

    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *prev = NULL;
    DetectTagDataEntry *iter = FlowGetStorageById(f, flow_tag_id);
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
            p->flags |= PKT_FIRST_TAG;
        } else {
            /* Update metrics; remove if tag expired; and set alerts */
            switch (iter->metric) {
                case DETECT_TAG_METRIC_PACKET:
                    if (iter->packets > iter->count) {
                        SCLogDebug("flow tag expired: packets %u > %u",
                            iter->packets, iter->count);
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            FlowSetStorageById(p->flow, flow_tag_id, iter->next);
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
                        SCLogDebug("flow tag expired: bytes %u > %u",
                            iter->bytes, iter->count);
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            FlowSetStorageById(p->flow, flow_tag_id, iter->next);
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
                        SCLogDebug("flow tag expired: %u - %u = %u > %u",
                            iter->last_ts, iter->first_ts,
                            (iter->last_ts - iter->first_ts), iter->count);
                        /* tag expired */
                        if (prev != NULL) {
                            tde = iter;
                            prev->next = iter->next;
                            iter = iter->next;
                            SCFree(tde);
                            (void) SC_ATOMIC_SUB(num_tags, 1);
                            continue;
                        } else {
                            FlowSetStorageById(p->flow, flow_tag_id, iter->next);
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

static void TagHandlePacketHost(Host *host, Packet *p)
{
    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *prev = NULL;
    DetectTagDataEntry *iter;
    uint8_t flag_added = 0;

    iter = HostGetStorageById(host, host_tag_id);
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
                        SCLogDebug("host tag expired: packets %u > %u", iter->packets, iter->count);
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
                            HostSetStorageById(host, host_tag_id, iter);
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
                        SCLogDebug("host tag expired: bytes %u > %u", iter->bytes, iter->count);
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
                            HostSetStorageById(host, host_tag_id, iter);
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
                        SCLogDebug("host tag expired: %u - %u = %u > %u",
                            iter->last_ts, iter->first_ts,
                            (iter->last_ts - iter->first_ts), iter->count);
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
                            HostSetStorageById(host, host_tag_id, iter);
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
    SCEnter();

    /* If there's no tag, get out of here */
    unsigned int current_tags = SC_ATOMIC_GET(num_tags);
    if (current_tags == 0)
        SCReturn;

    /* First update and get session tags */
    if (p->flow != NULL) {
        TagHandlePacketFlow(p->flow, p);
    }

    Host *src = HostLookupHostFromHash(&p->src);
    if (src) {
        if (TagHostHasTag(src)) {
            TagHandlePacketHost(src,p);
        }
        HostRelease(src);
    }
    Host *dst = HostLookupHostFromHash(&p->dst);
    if (dst) {
        if (TagHostHasTag(dst)) {
            TagHandlePacketHost(dst,p);
        }
        HostRelease(dst);
    }
    SCReturn;
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

    tmp = HostGetStorageById(host, host_tag_id);
    if (tmp == NULL)
        return 1;

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
            HostSetStorageById(host, host_tag_id, tmp->next);

            tde = tmp;
            tmp = tde->next;

            SCFree(tde);
            (void) SC_ATOMIC_SUB(num_tags, 1);
        }
    }
    return retval;
}

#ifdef UNITTESTS

/**
 * \test host tagging: packets
 */
static int DetectTagTestPacket01 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:host,3,packets,src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"Hi all\"; tag:host,4,packets,dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };
    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);

    SCLogDebug("running tests");
    result = UTHGenericTest(p, 7, sigs, sid, (uint32_t *) results, 5);
    SCLogDebug("running tests done");

    Host *src = HostLookupHostFromHash(&p[1]->src);
    if (src) {
        void *tag = HostGetStorageById(src, host_tag_id);
        if (tag != NULL) {
            printf("tag should have been expired: ");
            result = 0;
        }

        HostRelease(src);
    }
    Host *dst = HostLookupHostFromHash(&p[1]->dst);
    if (dst) {
        void *tag = HostGetStorageById(dst, host_tag_id);
        BUG_ON(tag == NULL);

        DetectTagDataEntry *iter = tag;

        /* check internal state */
        if (!(iter->gid == 1 && iter->sid == 2 && iter->packets == 4 && iter->count == 4)) {
            printf("gid %u sid %u packets %u count %u: ", iter->gid, iter->sid, iter->packets, iter->count);
            result = 0;
        }

        HostRelease(dst);
    }
    BUG_ON(src == NULL || dst == NULL);

    UTHFreePackets(p, 7);

    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test host tagging: seconds
 */
static int DetectTagTestPacket02 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:host,3,seconds,src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"Hi all\"; tag:host,8,seconds,dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    //de_ctx->flags |= DE_QUIET;

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        SCLogDebug("packet %d", i);
        TimeGet(&p[i]->ts);
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);
        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        TimeSetIncrementTime(2);
        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");

        /* see if the PKT_HAS_TAG is set on the packet if needed */
        bool expect;
        if (i == 0 || i == 2 || i == 3 || i == 5 || i == 6)
            expect = false;
        else
            expect = true;
        if (((p[i]->flags & PKT_HAS_TAG) ? true : false) != expect)
            goto cleanup;
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
end:
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test host tagging: bytes
 */
static int DetectTagTestPacket03 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:host, 150, bytes, src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"Hi all\"; tag:host, 150, bytes, dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");

        /* see if the PKT_HAS_TAG is set on the packet if needed */
        bool expect;
        if (i == 0 || i == 3 || i == 5 || i == 6)
            expect = false;
        else
            expect = true;
        if (((p[i]->flags & PKT_HAS_TAG) ? true : false) != expect)
            goto cleanup;
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
end:
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test session tagging: packets
 */
static int DetectTagTestPacket04 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);

    f = FlowAlloc();
    BUG_ON(f == NULL);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    if (inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1)
        goto end;
    if (inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1)
        goto end;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:session,4,packets; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");
        /* see if the PKT_HAS_TAG is set on the packet if needed */
        bool expect;
        if (i == 0 || i == 4 || i == 5 || i == 6)
            expect = false;
        else
            expect = true;
        if (((p[i]->flags & PKT_HAS_TAG) ? true : false) != expect)
            goto cleanup;
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);
end:
    FlowShutdown();
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test session tagging: seconds
 */
static int DetectTagTestPacket05 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);

    f = FlowAlloc();
    BUG_ON(f == NULL);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    if (inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1)
        goto end;
    if (inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1)
        goto end;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:session,8,seconds; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;

        SCLogDebug("packet %d", i);
        TimeGet(&p[i]->ts);
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        TimeSetIncrementTime(2);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");
        /* see if the PKT_HAS_TAG is set on the packet if needed */
        bool expect;
        if (i == 0 || i == 5 || i == 6)
            expect = false;
        else
            expect = true;
        if (((p[i]->flags & PKT_HAS_TAG) ? true : false) != expect)
            goto cleanup;
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);
end:
    FlowShutdown();
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test session tagging: bytes
 */
static int DetectTagTestPacket06 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);

    f = FlowAlloc();
    BUG_ON(f == NULL);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    if (inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1)
        goto end;
    if (inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1)
        goto end;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:session,150,bytes; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");

        /* see if the PKT_HAS_TAG is set on the packet if needed */
        int expect;
        if (i == 0 || i == 3 || i == 4 || i == 5 || i == 6)
            expect = FALSE;
        else
            expect = TRUE;
        if (((p[i]->flags & PKT_HAS_TAG) ? TRUE : FALSE) != expect)
            goto cleanup;
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);
end:
    FlowShutdown();
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

/**
 * \test session tagging: bytes, where a 2nd match makes us tag more
 */
static int DetectTagTestPacket07 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    TagInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);

    f = FlowAlloc();
    BUG_ON(f == NULL);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    if (inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1)
        goto end;
    if (inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1)
        goto end;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing tag 1\"; content:\"Hi all\"; tag:session,150,bytes; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing tag 2\"; content:\"no match\"; sid:5;)";

    /* Please, Notice that tagged data goes with sig_id = 1 and tag sig generator = 2 */
    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        if (UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0)
            goto cleanup;

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_TAG ? "true" : "false");
#if 1
        /* see if the PKT_HAS_TAG is set on the packet if needed */
        int expect;
        if (i == 0 || i == 6)
            expect = FALSE;
        else
            expect = TRUE;
        if (((p[i]->flags & PKT_HAS_TAG) ? TRUE : FALSE) != expect)
            goto cleanup;
#endif
    }

    result = 1;

cleanup:
    UTHFreePackets(p, 7);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);
end:
    FlowShutdown();
    HostShutdown();
    TagDestroyCtx();
    StorageCleanup();
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTag
 */
void DetectEngineTagRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTagTestPacket01", DetectTagTestPacket01);
    UtRegisterTest("DetectTagTestPacket02", DetectTagTestPacket02);
    UtRegisterTest("DetectTagTestPacket03", DetectTagTestPacket03);
    UtRegisterTest("DetectTagTestPacket04", DetectTagTestPacket04);
    UtRegisterTest("DetectTagTestPacket05", DetectTagTestPacket05);
    UtRegisterTest("DetectTagTestPacket06", DetectTagTestPacket06);
    UtRegisterTest("DetectTagTestPacket07", DetectTagTestPacket07);
#endif /* UNITTESTS */
}

