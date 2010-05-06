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
 *  \author Breno Silva <breno.silva@gmail.com>
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Threshold part of the detection engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

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
#include "tm-modules.h"

/**
 * \brief Handle a packet and check if needs a threshold logic
 *
 * \param de_ctx Detection Context
 * \param sig Signature pointer
 * \param p Packet structure
 *
 */
int PacketAlertHandle(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                       Signature *s, Packet *p, uint16_t pos)
{
    SCEnter();
    int ret = 0;

    /* retrieve the sig match data */
    DetectThresholdData *td = SigGetThresholdType(s,p);

    SCLogDebug("td %p", td);

    /* if have none just alert, otherwise handle thresholding */
    if (td == NULL) {
        //PacketAlertAppend(det_ctx, s, p);
        /* Already inserted so get out */
        ret = 1;
    } else {
        ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s);
        if (ret == 0) {
            /* It doesn't match threshold, remove it */
            PacketAlertRemove(p, pos);
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Check if a certain signature has threshold option
 *
 * \param sig Signature pointer
 * \param p Packet structure
 *
 * \retval tsh Return the threshold data from signature or NULL if not found
 */
DetectThresholdData *SigGetThresholdType(Signature *sig, Packet *p)
{
    SigMatch *sm = sig->match;
    DetectThresholdData *tsh = NULL;

    if(p == NULL)
        return NULL;

    while (sm != NULL) {
        if (sm->type == DETECT_THRESHOLD  || sm->type == DETECT_DETECTION_FILTER) {
            tsh = (DetectThresholdData *)sm->ctx;
            return tsh;
        }

        sm = sm->next;
    }

    return NULL;
}

/**
 * \brief Search for a threshold data into threshold hash table
 *
 * \param de_ctx Dectection Context
 * \param tsh_ptr Threshold element
 * \param p Packet structure
 *
 * \retval lookup_tsh Return the threshold element
 */
DetectThresholdEntry *ThresholdHashSearch(DetectEngineCtx *de_ctx, DetectThresholdEntry *tsh_ptr, Packet *p)
{
    SCEnter();

    DetectThresholdEntry *lookup_tsh = NULL;

    SCLogDebug("tsh_ptr->track %u", tsh_ptr->track);

    if (tsh_ptr->track == TRACK_DST) {
        if (PKT_IS_IPV4(p)) {
            SCLogDebug("ipv4 dst");
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_dst, tsh_ptr, sizeof(DetectThresholdEntry));
        } else if (PKT_IS_IPV6(p)) {
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh_ptr, sizeof(DetectThresholdEntry));
        }
    } else if (tsh_ptr->track == TRACK_SRC) {
        if (PKT_IS_IPV4(p)) {
            SCLogDebug("ipv4 src");
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_src, tsh_ptr, sizeof(DetectThresholdEntry));
        } else if (PKT_IS_IPV6(p))
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh_ptr, sizeof(DetectThresholdEntry));
    } else {
        SCLogDebug("no track, weird");
    }

    SCReturnPtr(lookup_tsh, "DetectThresholdEntry");
}

/**
 * \brief Remove timeout threshold hash elements
 *
 * \param de_ctx Dectection Context
 *
 */

/** \todo In some conditions HashListtableRemove returns at dt->array = NULL
 *  Must need to check it
 **/

void ThresholdTimeoutRemove(DetectEngineCtx *de_ctx)
{
    struct timeval tv;
    DetectThresholdEntry *tsh = NULL;
    HashListTableBucket *next = NULL;

    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
    next = HashListTableGetListHead(de_ctx->ths_ctx.threshold_hash_table_src);

    while (next != NULL) {
        tsh = HashListTableGetListData(next);

        if (tsh && ((tv.tv_sec - tsh->tv_sec1) > tsh->seconds)) {
            if (tsh->ipv == 4) {
                if (tsh->type == TRACK_SRC) {
                    HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_src, tsh, sizeof(DetectThresholdEntry));
                } else if (tsh->type == TRACK_DST) {
                    HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_dst, tsh, sizeof(DetectThresholdEntry));
                }
            } else if (tsh->ipv == 6) {
                if (tsh->type == TRACK_SRC) {
                    HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh, sizeof(DetectThresholdEntry));
                } else if (tsh->type == TRACK_DST) {
                    HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh, sizeof(DetectThresholdEntry));
                }
            }
        }

        next = HashListTableGetListNext(next);
    }

    SCMutexUnlock(&de_ctx->ths_ctx.threshold_table_lock);

    return;
}

/**
 * \brief Add threshold element into hash table
 *
 * \param de_ctx Dectection Context
 * \param tsh_ptr Threshold element
 * \param p Packet structure
 *
 */
void ThresholdHashAdd(DetectEngineCtx *de_ctx, DetectThresholdEntry *tsh_ptr, Packet *p)
{
    SCEnter();

    int ret = 0;

    if (tsh_ptr->ipv == 4) {
        SCLogDebug("ipv4");
        if (tsh_ptr->track == TRACK_DST) {
            SCLogDebug("dst");
            ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_dst, tsh_ptr, sizeof(DetectThresholdEntry));
        } else if (tsh_ptr->track == TRACK_SRC) {
            SCLogDebug("src");
            ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_src, tsh_ptr, sizeof(DetectThresholdEntry));
        }
    } else if (tsh_ptr->ipv == 6) {
        if (tsh_ptr->track == TRACK_DST)
           ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh_ptr, sizeof(DetectThresholdEntry));
        else if (tsh_ptr->track == TRACK_SRC)
           ret =  HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh_ptr, sizeof(DetectThresholdEntry));
    }

    if(ret == -1)   {
        SCLogError(SC_ERR_THRESHOLD_HASH_ADD,
                "failed to add element into the hash table");
    }

    SCReturn;
    return;
}

/**
 * \brief Make the threshold logic for signatures
 *
 * \param de_ctx Dectection Context
 * \param tsh_ptr Threshold element
 * \param p Packet structure
 * \param s Signature structure
 *
 */
int PacketAlertThreshold(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                          DetectThresholdData *td, Packet *p, Signature *s)
{
    SCEnter();
    int ret = 0;

    struct timeval ts;
    DetectThresholdEntry *lookup_tsh = NULL;
    DetectThresholdEntry *ste = NULL;

    if (td == NULL)
        SCReturnInt(ret);

    /* setup the Entry we use to search our hash with */
    ste = SCMalloc(sizeof(DetectThresholdEntry));
    if (ste == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s", strerror(errno));
        SCReturnInt(ret);
    }
    memset(ste, 0x00, sizeof(ste));

    if (PKT_IS_IPV4(p))
        ste->ipv = 4;
    else if (PKT_IS_IPV6(p))
        ste->ipv = 6;

    ste->sid = s->id;
    ste->gid = s->gid;

    if (td->track == TRACK_DST) {
        COPY_ADDRESS(&p->dst, &ste->addr);
    } else if (td->track == TRACK_SRC) {
        COPY_ADDRESS(&p->src, &ste->addr);
    }

    ste->track = td->track;
    ste->seconds = td->seconds;

    SCLogDebug("ste %p", ste);

    memset(&ts, 0x00, sizeof(ts));
    TimeGet(&ts);

    SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
    switch(td->type)   {
        case TYPE_LIMIT:
        {
            SCLogDebug("limit");

            lookup_tsh = ThresholdHashSearch(de_ctx, ste, p);
            SCLogDebug("lookup_tsh %p", lookup_tsh);

            if (lookup_tsh != NULL)  {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    if (lookup_tsh->current_count < td->count) {
                        ret = 1;
                    }
                    lookup_tsh->current_count++;
                } else    {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;

                    ret = 1;
                }
            } else {
                ste->tv_sec1 = ts.tv_sec;
                ste->current_count = 1;

                ret = 1;

                ThresholdHashAdd(de_ctx, ste, p);
                ste = NULL;
            }
            break;
        }
        case TYPE_THRESHOLD:
        {
            SCLogDebug("threshold");

            lookup_tsh = ThresholdHashSearch(de_ctx, ste, p);
            if (lookup_tsh != NULL)  {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count >= td->count) {
                        ret = 1;
                        lookup_tsh->current_count = 0;
                    }
                } else {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else {
                ste->current_count = 1;
                ste->tv_sec1 = ts.tv_sec;

                if (td->count == 1)  {
                    ret = 1;
                    ste->current_count = 0;
                } else {
                    ThresholdHashAdd(de_ctx,ste,p);
                    ste = NULL;
                }
            }
            break;
        }
        case TYPE_BOTH:
        {
            SCLogDebug("both");

            lookup_tsh = ThresholdHashSearch(de_ctx,ste,p);
            if (lookup_tsh != NULL) {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count == td->count)    {
                        ret = 1;
                    }
                } else    {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else {
                ste->current_count = 1;
                ste->tv_sec1 = ts.tv_sec;

                if (td->count == 1)  {
                    ret = 1;
                    ste->current_count = 0;
                } else {
                    ThresholdHashAdd(de_ctx,ste,p);
                    ste = NULL;
                }
            }
            break;
        }
        /* detection_filter */
        case TYPE_DETECTION:
        {
            SCLogDebug("detection_filter");

            lookup_tsh = ThresholdHashSearch(de_ctx,ste,p);
            if (lookup_tsh != NULL) {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < td->seconds) {
                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count >= td->count) {
                        ret = 1;
                    }
                } else {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else {
                ste->current_count = 1;
                ste->tv_sec1 = ts.tv_sec;

                if (td->count == 1) {
                    ret = 1;
                }
                ThresholdHashAdd(de_ctx, ste, p);
                ste = NULL;
            }
            break;
        }
    }
    SCMutexUnlock(&de_ctx->ths_ctx.threshold_table_lock);

    if (ste != NULL)
        SCFree(ste);

    ThresholdTimeoutRemove(de_ctx);
    SCReturnInt(ret);
}

void ThresholdFreeFunc(void *data)
{
    if (data != NULL)
        SCFree(data);
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
char ThresholdCompareFunc(void *data1, uint16_t len1, void *data2,uint16_t len2)
{
    SCEnter();

    DetectThresholdEntry *a = (DetectThresholdEntry *)data1;
    DetectThresholdEntry *b = (DetectThresholdEntry *)data2;

    if ((a->sid == b->sid) && (a->gid == b->gid) && (CMP_ADDR(&a->addr,&b->addr))) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 * \brief Create the hash for threshold tables
 *
 * \param ht Hash Table
 * \param data Data that will be used to create the hash
 * \param datalen Data length
 *
 * \retval hash the hash
 */
uint32_t ThresholdHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SCEnter();

    DetectThresholdEntry *dt = (DetectThresholdEntry *)data;
    uint32_t hash = 0;

    if (dt->ipv == 4)
        hash = (dt->sid + dt->gid + dt->addr.addr_data32[0]);
    else if (dt->ipv == 6)
        hash = (dt->sid + dt->gid + dt->addr.addr_data32[0] + dt->addr.addr_data32[1] + dt->addr.addr_data32[2] + dt->addr.addr_data32[3]);
    else {
        SCLogDebug("no dt->ipv");
    }

    SCReturnInt(hash % THRESHOLD_HASH_SIZE);
}

/**
 * \brief Init threshold context hash tables
 *
 * \param de_ctx Dectection Context
 *
 */
void ThresholdHashInit(DetectEngineCtx *de_ctx)
{
    if (de_ctx->ths_ctx.threshold_hash_table_dst == NULL ||
        de_ctx->ths_ctx.threshold_hash_table_src == NULL ||
        de_ctx->ths_ctx.threshold_hash_table_src_ipv6 == NULL ||
        de_ctx->ths_ctx.threshold_hash_table_dst_ipv6 == NULL) {

        de_ctx->ths_ctx.threshold_hash_table_dst = HashListTableInit(THRESHOLD_HASH_SIZE, ThresholdHashFunc, ThresholdCompareFunc, ThresholdFreeFunc);
        if(de_ctx->ths_ctx.threshold_hash_table_dst == NULL)    {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Threshold: Failed to initialize ipv4 dst hash table.");
            exit(EXIT_FAILURE);
        }

        de_ctx->ths_ctx.threshold_hash_table_src = HashListTableInit(THRESHOLD_HASH_SIZE, ThresholdHashFunc, ThresholdCompareFunc, ThresholdFreeFunc);
        if(de_ctx->ths_ctx.threshold_hash_table_dst == NULL)    {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Threshold: Failed to initialize ipv4 src hash table.");
            exit(EXIT_FAILURE);
        }

        de_ctx->ths_ctx.threshold_hash_table_src_ipv6 = HashListTableInit(THRESHOLD_HASH_SIZE, ThresholdHashFunc, ThresholdCompareFunc, ThresholdFreeFunc);
        if(de_ctx->ths_ctx.threshold_hash_table_dst == NULL)    {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Threshold: Failed to initialize ipv6 src hash table.");
            exit(EXIT_FAILURE);
        }

        de_ctx->ths_ctx.threshold_hash_table_dst_ipv6 = HashListTableInit(THRESHOLD_HASH_SIZE, ThresholdHashFunc, ThresholdCompareFunc, ThresholdFreeFunc);
        if(de_ctx->ths_ctx.threshold_hash_table_dst == NULL)    {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Threshold: Failed to initialize ipv6 dst hash table.");
            exit(EXIT_FAILURE);
        }

        if (SCMutexInit(&de_ctx->ths_ctx.threshold_table_lock, NULL) != 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Threshold: Failed to initialize hash table mutex.");
            exit(EXIT_FAILURE);
        }
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
    HashListTableFree(de_ctx->ths_ctx.threshold_hash_table_dst);
    HashListTableFree(de_ctx->ths_ctx.threshold_hash_table_src);
    HashListTableFree(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6);
    HashListTableFree(de_ctx->ths_ctx.threshold_hash_table_src_ipv6);
}
