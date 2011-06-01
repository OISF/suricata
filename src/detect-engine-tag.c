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
 * \file detect-engine-tag.c
 *
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

static void TagTimeoutRemove(DetectTagHostCtx *tag_ctx, struct timeval *tv);

SC_ATOMIC_DECLARE(unsigned int, num_tags);  /**< Atomic counter, to know if we
                                                have tagged hosts/sessions,
                                                to avoid locking */

/* Global Ctx for tagging hosts */
DetectTagHostCtx *tag_ctx = NULL;

void TagFreeFunc(void *data)
{
    DetectTagDataListFree(data);
    return;
}

/**
 * \brief Compare elements into the hash table
 *
 * \param data1 First element to compare
 * \param len1 length of first element
 * \param data2 Second element to compare
 * \param len2 length of second element
 *
 * \retval 1 Match or 0 No Match
 */
char TagCompareFunc(void *data1, uint16_t len1, void *data2,uint16_t len2)
{
    SCEnter();

    DetectTagDataEntryList *a = (DetectTagDataEntryList *)data1;
    DetectTagDataEntryList *b = (DetectTagDataEntryList *)data2;

    if (CMP_ADDR(&a->addr,&b->addr)) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 * \brief Create the hash for tag tables
 *
 * \param ht Hash Table
 * \param data DataEntry that will be used to create the hash
 * \param datalen DataEntry length
 *
 * \retval hash the hash
 */
uint32_t TagHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SCEnter();

    if (data == NULL) return 0;
    DetectTagDataEntryList *dt = (DetectTagDataEntryList *)data;
    uint32_t hash = 0;

    if (dt->ipv == 4)
        hash = (dt->addr.addr_data32[0]);
    else if (dt->ipv == 6)
        hash = (dt->addr.addr_data32[0] +
                dt->addr.addr_data32[1] +
                dt->addr.addr_data32[2] +
                dt->addr.addr_data32[3]);
    else {
        SCLogDebug("no dt->ipv");
    }

    SCReturnInt(hash % TAG_HASH_SIZE);
}

void TagInitCtx(void) {
    tag_ctx = SCMalloc(sizeof(DetectTagHostCtx));
    if (tag_ctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for the tagging context");
        exit(EXIT_FAILURE);
    }
    memset(tag_ctx, 0, sizeof(DetectTagHostCtx));

    TimeGet(&tag_ctx->last_ts);

    if (SCMutexInit(&tag_ctx->lock, NULL) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Tag: Failed to initialize hash table mutex.");
        exit(EXIT_FAILURE);
    }

    TagHashInit(tag_ctx);
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
    HashListTableFree(tag_ctx->tag_hash_table_ipv4);
    tag_ctx->tag_hash_table_ipv4 = NULL;

    HashListTableFree(tag_ctx->tag_hash_table_ipv6);
    tag_ctx->tag_hash_table_ipv6 = NULL;

    SCMutexDestroy(&tag_ctx->lock);
    SC_ATOMIC_DESTROY(num_tags);

    SCFree(tag_ctx);
    tag_ctx = NULL;
}

/** \brief Reset the tagging engine context
 */
void TagRestartCtx() {
    TagDestroyCtx();
    TagInitCtx();
}

/**
 * \brief Init tag context hash tables
 *
 * \param det_ctx Dectection Thread Context
 *
 */
void TagHashInit(DetectTagHostCtx *tag_ctx)
{
    tag_ctx->tag_hash_table_ipv4 = HashListTableInit(TAG_HASH_SIZE, TagHashFunc, TagCompareFunc, TagFreeFunc);
    if(tag_ctx->tag_hash_table_ipv4 == NULL)    {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Tag: Failed to initialize ipv4 dst hash table.");
        exit(EXIT_FAILURE);
    }

    tag_ctx->tag_hash_table_ipv6 = HashListTableInit(TAG_HASH_SIZE, TagHashFunc, TagCompareFunc, TagFreeFunc);
    if(tag_ctx->tag_hash_table_ipv6 == NULL)    {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Tag: Failed to initialize ipv4 src hash table.");
        exit(EXIT_FAILURE);
    }
}

/**
 * \brief Search for a tag data into tag hash table
 *
 * \param de_ctx Dectection Context
 * \param dtde Tag element
 * \param p Packet structure
 *
 * \retval lookup_tde Return the tag element
 */
DetectTagDataEntryList *TagHashSearch(DetectTagHostCtx *tag_ctx, DetectTagDataEntryList *dtde,
                                  Packet *p)
{
    SCEnter();

    DetectTagDataEntryList *lookup_tde = NULL;

    if (PKT_IS_IPV4(p)) {
        SCLogDebug("ipv4 search");
        lookup_tde = HashListTableLookup(tag_ctx->tag_hash_table_ipv4, dtde, sizeof(DetectTagDataEntryList));
    } else if (PKT_IS_IPV6(p)) {
        SCLogDebug("ipv6 search");
        lookup_tde = HashListTableLookup(tag_ctx->tag_hash_table_ipv6, dtde, sizeof(DetectTagDataEntryList));
    }

    SCReturnPtr(lookup_tde, "DetectTagDataEntryList");
}

/**
 * \brief Add tag element into hash table
 *
 * \param de_ctx Dectection Context
 * \param dtde Tag element
 * \param p Packet structure
 *
 */
void TagHashAdd(DetectTagHostCtx *tag_ctx, DetectTagDataEntryList *dtde, Packet *p)
{
    SCEnter();

    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        dtde->ipv = 4;
        ret = HashListTableAdd(tag_ctx->tag_hash_table_ipv4,
                               dtde, sizeof(DetectTagDataEntry));
    } else if (PKT_IS_IPV6(p)) {
        dtde->ipv = 6;
        ret = HashListTableAdd(tag_ctx->tag_hash_table_ipv6,
                               dtde, sizeof(DetectTagDataEntry));
    }

    SCReturn;
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
int TagHashAddTag(DetectTagHostCtx *tag_ctx, DetectTagDataEntry *tde, Packet *p)
{
    uint8_t updated = 0;
    uint16_t num_tags = 0;

    /* local, just for searching */
    DetectTagDataEntryList tdl;

    tdl.header_entry = NULL;
    tdl.header_entry = tde;

    SCEnter();
    SCMutexLock(&tag_ctx->lock);

    /* first search if we already have an entry of this host */
    DetectTagDataEntryList *entry = NULL;
    if (PKT_IS_IPV4(p)) {
        tdl.ipv = 4;
        if (tde->td->direction == DETECT_TAG_DIR_SRC) {
            SET_IPV4_SRC_ADDR(p, &tdl.addr);
        } else if (tde->td->direction == DETECT_TAG_DIR_DST) {
            SET_IPV4_DST_ADDR(p, &tdl.addr);
        }
    } else if (PKT_IS_IPV6(p)) {
        tdl.ipv = 6;
        if (tde->td->direction == DETECT_TAG_DIR_SRC) {
            SET_IPV6_SRC_ADDR(p, &tdl.addr);
        } else if (tde->td->direction == DETECT_TAG_DIR_DST) {
            SET_IPV6_DST_ADDR(p, &tdl.addr);
        }
    }

    entry = TagHashSearch(tag_ctx, &tdl, p);
    if (entry == NULL) {
        DetectTagDataEntryList *new = SCMalloc(sizeof(DetectTagDataEntryList));
        if (new == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate a new session");
        } else {
            memcpy(new, &tdl, sizeof(DetectTagDataEntryList));
            TagHashAdd(tag_ctx, new, p);
        }
    } else {
        /* Append the tag to the list of this host */

        /* First iterate installed entries searching a duplicated sid/gid */
        DetectTagDataEntry *iter = NULL;

        for (iter = entry->header_entry; iter != NULL; iter = iter->next) {
            num_tags++;
            if (iter->sid == tde->sid && iter->gid == tde->gid) {
                iter->cnt_match++;
                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_TAG_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts.tv_sec = iter->last_ts.tv_sec = tde->first_ts.tv_sec;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }

        /* If there was no entry of this rule, append the new tde */
        if (updated == 0 && num_tags < DETECT_TAG_MAX_TAGS) {
            tde->next = entry->header_entry;
            entry->header_entry = tde;
        } else if (num_tags == DETECT_TAG_MAX_TAGS) {
            SCLogDebug("Max tags for sessions reached (%"PRIu16")", num_tags);
        }

    }

    SCMutexUnlock(&tag_ctx->lock);
    SCReturnInt(updated);
}

/**
 * \brief Search tags for src and dst. Update entries of the tag, remove if necessary
 *
 * \param de_ctx Detect context
 * \param det_ctx Detect thread context
 * \param p packet
 *
 */
void TagHandlePacket(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                     Packet *p) {

    DetectTagDataEntry *tde = NULL;
    DetectTagDataEntry *prev = NULL;
    DetectTagDataEntry *iter = NULL;
    DetectTagDataEntryList tdl;
    DetectTagDataEntryList *tde_src = NULL;
    DetectTagDataEntryList *tde_dst = NULL;

    unsigned int current_tags = SC_ATOMIC_GET(num_tags);
    /* If there's no tag, get out of here */
    if (current_tags == 0)
        return;

    uint8_t flag_added = 0;
    struct timeval ts = { 0, 0 };
    TimeGet(&ts);

    /* First update and get session tags */
    if (p->flow != NULL) {
        SCMutexLock(&p->flow->m);
        if (p->flow->tag_list != NULL) {
            iter = p->flow->tag_list->header_entry;
            prev = NULL;
            while (iter != NULL) {
                /* update counters */
                iter->last_ts.tv_sec = ts.tv_sec;
                iter->packets++;
                iter->bytes += p->pktlen;

                /* If this packet triggered the rule with tag, we dont need
                 * to log it (the alert will log it) */
                if (iter->first_time++ > 0) {
                    /* Update metrics; remove if tag expired; and set alerts */
                    switch (iter->td->metric) {
                        case DETECT_TAG_METRIC_PACKET:
                            if (iter->packets > iter->td->count) {
                                /* tag expired */
                                if (prev != NULL) {
                                    tde = iter;
                                    prev->next = iter->next;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
                                    continue;
                                } else {
                                    p->flow->tag_list->header_entry = iter->next;
                                    tde = iter;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
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
                            if (iter->bytes > iter->td->count) {
                                /* tag expired */
                                if (prev != NULL) {
                                    tde = iter;
                                    prev->next = iter->next;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
                                    continue;
                                } else {
                                    p->flow->tag_list->header_entry = iter->next;
                                    tde = iter;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
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
                            if (iter->last_ts.tv_sec - iter->first_ts.tv_sec > (int)iter->td->count) {
                                /* tag expired */
                                if (prev != NULL) {
                                    tde = iter;
                                    prev->next = iter->next;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
                                    continue;
                                } else {
                                    p->flow->tag_list->header_entry = iter->next;
                                    tde = iter;
                                    iter = iter->next;
                                    SCFree(tde);
                                    SC_ATOMIC_SUB(num_tags, 1);
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

            iter = NULL;
        }
        SCMutexUnlock(&p->flow->m);
    }

    /* Then search the src and dst hosts at the ctx */
    SCMutexLock(&tag_ctx->lock);

    /* Check for timeout tags if we reached the interval for checking it */
    if (ts.tv_sec - tag_ctx->last_ts.tv_sec > TAG_TIMEOUT_CHECK_INTERVAL) {
        TagTimeoutRemove(tag_ctx, &ts);
        tag_ctx->last_ts.tv_sec = ts.tv_sec;
    }

    if (PKT_IS_IPV4(p)) {
        tdl.ipv = 4;
        /* search tags for source */
        SET_IPV4_SRC_ADDR(p, &tdl.addr);
        tde_src = TagHashSearch(tag_ctx, &tdl, p);

        /* search tags for dest */
        SET_IPV4_DST_ADDR(p, &tdl.addr);
        tde_dst = TagHashSearch(tag_ctx, &tdl, p);
    } else if (PKT_IS_IPV6(p)) {
        tdl.ipv = 6;
        /* search tags for source */
        SET_IPV6_SRC_ADDR(p, &tdl.addr);
        tde_src = TagHashSearch(tag_ctx, &tdl, p);

        /* search tags for dest */
        SET_IPV6_DST_ADDR(p, &tdl.addr);
        tde_dst = TagHashSearch(tag_ctx, &tdl, p);
    }

    if (tde_src != NULL) {
        iter = tde_src->header_entry;
        prev = NULL;
        while (iter != NULL) {
            /* update counters */
            iter->last_ts.tv_sec = ts.tv_sec;
            iter->packets++;
            iter->bytes += p->pktlen;

            /* If this packet triggered the rule with tag, we dont need
             * to log it (the alert will log it) */
            if (iter->first_time++ > 0 && iter->td != NULL) {
                /* Update metrics; remove if tag expired; and set alerts */
                switch (iter->td->metric) {
                    case DETECT_TAG_METRIC_PACKET:
                        if (iter->packets > iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_src->header_entry = NULL;
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
                        if (iter->bytes > iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_src->header_entry = NULL;
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
                        if (iter->last_ts.tv_sec - iter->first_ts.tv_sec > (int)iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_src->header_entry = NULL;
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

    if (tde_dst != NULL) {
        iter = tde_dst->header_entry;
        prev = NULL;
        while (iter != NULL) {
            /* update counters */
            iter->last_ts.tv_sec = ts.tv_sec;
            iter->packets++;
            iter->bytes += p->pktlen;

            /* If this packet triggered the rule with tag, we dont need
             * to log it (the alert will log it) */
            if (iter->first_time++ > 0 && iter->td != NULL) {
                /* Update metrics; remove if tag expired; and set alerts */
                switch (iter->td->metric) {
                    case DETECT_TAG_METRIC_PACKET:
                        if (iter->packets > iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_dst->header_entry = NULL;
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
                        if (iter->bytes > iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_dst->header_entry = NULL;
                                continue;
                            }
                        }  else if (flag_added == 0) {
                            /* It's matching the tag. Add it to be logged and
                             * update "flag_added" to add the packet once. */
                            p->flags |= PKT_HAS_TAG;
                            flag_added++;
                        }
                        break;
                    case DETECT_TAG_METRIC_SECONDS:
                        /* last_ts handles this metric, but also a generic time based
                         * expiration to prevent dead sessions/hosts */
                        if (iter->last_ts.tv_sec - iter->first_ts.tv_sec > (int)iter->td->count) {
                            /* tag expired */
                            if (prev != NULL) {
                                tde = iter;
                                prev->next = iter->next;
                                iter = iter->next;
                                DetectTagDataEntryFree(tde);
                                continue;
                            } else {
                                tde = iter;
                                iter = iter->next;
                                SCFree(tde);
                                SC_ATOMIC_SUB(num_tags, 1);
                                tde_dst->header_entry = NULL;
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
    SCMutexUnlock(&tag_ctx->lock);
}

/**
 * \brief Removes the entries exceding the max timeout value
 *
 * \param tag_ctx Tag context
 * \param ts the current time
 *
 */
static void TagTimeoutRemove(DetectTagHostCtx *tag_ctx, struct timeval *tv)
{
    HashListTableBucket *next = NULL;
    HashListTableBucket *buck = NULL;

    DetectTagDataEntry *tde= NULL;
    DetectTagDataEntry *tmp = NULL;
    DetectTagDataEntry *prev= NULL;

    DetectTagDataEntryList *tdl = NULL;

    buck = HashListTableGetListHead(tag_ctx->tag_hash_table_ipv4);

    while (buck != NULL) {
        /* get the next before we free "buck" */
        next = HashListTableGetListNext(buck);
        tdl = HashListTableGetListData(buck);

        if (tdl != NULL && tdl->header_entry != NULL) {
            tmp = tdl->header_entry;

            prev = NULL;
            while (tmp != NULL) {

                if ((tv->tv_sec - tmp->last_ts.tv_sec) <= TAG_MAX_LAST_TIME_SEEN) {
                    prev = tmp;
                    tmp = tmp->next;
                    continue;
                }

                if (prev != NULL) {
                    prev->next = tmp->next;

                    tde = tmp;
                    tmp = tmp->next;

                    SCFree(tde);
                    SC_ATOMIC_SUB(num_tags, 1);
                } else {
                    tdl->header_entry = tmp->next;

                    tde = tmp;
                    tmp = tmp->next;

                    SCFree(tde);
                    SC_ATOMIC_SUB(num_tags, 1);
                }
            }
        }
        buck = next;
    }

    buck = HashListTableGetListHead(tag_ctx->tag_hash_table_ipv6);

    while (buck != NULL) {
        /* get the next before we free "buck" */
        next = HashListTableGetListNext(buck);
        tdl = HashListTableGetListData(buck);

        if (tdl != NULL && tdl->header_entry != NULL) {
            tmp = tdl->header_entry;

            prev = NULL;
            while (tmp != NULL) {

                if ((tv->tv_sec - tmp->last_ts.tv_sec) <= TAG_MAX_LAST_TIME_SEEN) {
                    prev = tmp;
                    tmp = tmp->next;
                    continue;
                }

                if (prev != NULL) {
                    prev->next = tmp->next;

                    tde = tmp;
                    tmp = tmp->next;

                    SCFree(tde);
                    SC_ATOMIC_SUB(num_tags, 1);
                } else {
                    tdl->header_entry = tmp->next;

                    tde = tmp;
                    tmp = tmp->next;

                    SCFree(tde);
                    SC_ATOMIC_SUB(num_tags, 1);
                }
            }
        }
        buck = next;
    }

    return;
}

