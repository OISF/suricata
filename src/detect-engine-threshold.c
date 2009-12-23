/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
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
void PacketAlertHandle(DetectEngineCtx *de_ctx, Signature *sig, Packet *p)
{
    DetectThresholdData *tsh = NULL;

    tsh = SigGetThresholdType(sig,p);

    if (tsh == NULL) {
        PacketAlertAppend(p, sig->gid, sig->id, sig->rev, sig->prio, sig->msg);
    } else    {
        PacketAlertThreshold(de_ctx,tsh,p,sig);
    }

    return;
}
/**
 * \brief Check if a certain signature has threshold option
 *
 * \param sig Signature pointer
 * \param p Packet structure
 *
 * \retval tsh Return the threshold options from signature or NULL if not found
 */
DetectThresholdData *SigGetThresholdType(Signature *sig, Packet *p)
{
    SigMatch *sm = sig->match;
    DetectThresholdData *tsh = NULL;

    if(p == NULL)
        return NULL;

    while (sm != NULL) {
        if (sm->type == DETECT_THRESHOLD) {
            tsh = (DetectThresholdData *)sm->ctx;
            if (tsh != NULL) {
                if (PKT_IS_IPV4(p))
                    tsh->ipv = 4;
                else if (PKT_IS_IPV6(p))
                    tsh->ipv = 6;
                tsh->sid = sig->id;
                tsh->gid = sig->gid;
                if (tsh->track == TRACK_DST )
                    tsh->addr = p->dst;
                else if (tsh->track == TRACK_SRC )
                    tsh->addr = p->src;
            }
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
DetectThresholdData *ThresholdHashSearch(DetectEngineCtx *de_ctx, DetectThresholdData *tsh_ptr, Packet *p)
{
    DetectThresholdData *lookup_tsh = NULL;

    if (tsh_ptr->track == TRACK_DST) {
        if (PKT_IS_IPV4(p))
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_dst, tsh_ptr, sizeof(DetectThresholdData));
        else if (PKT_IS_IPV6(p))
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh_ptr, sizeof(DetectThresholdData));
    } else if (tsh_ptr->track == TRACK_SRC) {
        if (PKT_IS_IPV4(p))
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_src, tsh_ptr, sizeof(DetectThresholdData));
        else if (PKT_IS_IPV6(p))
            lookup_tsh = HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh_ptr, sizeof(DetectThresholdData));
    }

    return lookup_tsh;
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
    DetectThresholdData *tsh = NULL;
    HashListTableBucket *next = NULL;

    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
    next = HashListTableGetListHead(de_ctx->ths_ctx.threshold_hash_table_src);

    while (next != NULL) {

        tsh = HashListTableGetListData(next);

        if (tsh && ((tv.tv_sec - tsh->tv_sec1) > tsh->seconds))   {
            HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_src, tsh, sizeof(DetectThresholdData));
            HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_dst, tsh, sizeof(DetectThresholdData));
            HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh, sizeof(DetectThresholdData));
            HashListTableRemove(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh, sizeof(DetectThresholdData));
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
void ThresholdHashAdd(DetectEngineCtx *de_ctx, DetectThresholdData *tsh_ptr, Packet *p)
{
    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        if (tsh_ptr->track == TRACK_DST)
            ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_dst, tsh_ptr, sizeof(DetectThresholdData));
        else if (tsh_ptr->track == TRACK_SRC)
            ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_src, tsh_ptr, sizeof(DetectThresholdData));
    } else if (PKT_IS_IPV6(p)) {
        if (tsh_ptr->track == TRACK_DST)
           ret = HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_dst_ipv6, tsh_ptr, sizeof(DetectThresholdData));
        else if (tsh_ptr->track == TRACK_SRC)
           ret =  HashListTableAdd(de_ctx->ths_ctx.threshold_hash_table_src_ipv6, tsh_ptr, sizeof(DetectThresholdData));
    }

    if(ret == -1)   {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Threshold: Failed to Add element into the hash table.");
    }

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
void PacketAlertThreshold(DetectEngineCtx *de_ctx, DetectThresholdData *tsh_ptr, Packet *p, Signature *s)
{
    struct timeval ts;
    DetectThresholdData *lookup_tsh = NULL;

    if (tsh_ptr == NULL)
        return;

    memset(&ts, 0x00, sizeof(ts));
    TimeGet(&ts);

    SCMutexLock(&de_ctx->ths_ctx.threshold_table_lock);
    switch(tsh_ptr->type)   {
        case TYPE_LIMIT:

            lookup_tsh = ThresholdHashSearch(de_ctx,tsh_ptr,p);

            if (lookup_tsh != NULL)  {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < lookup_tsh->seconds)    {

                    if (lookup_tsh->current_count < lookup_tsh->count)    {
                        PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                    }

                    lookup_tsh->current_count++;
                } else    {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                    PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                }
            } else    {
                tsh_ptr->tv_sec1 = ts.tv_sec;
                tsh_ptr->current_count = 1;
                PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);

                if (tsh_ptr->count == 1)  {
                    tsh_ptr->current_count = 0;
                } else {
                    ThresholdHashAdd(de_ctx,tsh_ptr,p);
                }
            }
            break;

        case TYPE_THRESHOLD:

            lookup_tsh = ThresholdHashSearch(de_ctx,tsh_ptr,p);

            if (lookup_tsh != NULL)  {
                if ((ts.tv_sec - lookup_tsh->tv_sec1) < lookup_tsh->seconds)    {

                    lookup_tsh->current_count++;

                    if (lookup_tsh->current_count >= lookup_tsh->count)    {
                        PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                        lookup_tsh->current_count = 0;
                    }
                } else    {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else    {
                tsh_ptr->current_count = 1;
                tsh_ptr->tv_sec1 = ts.tv_sec;

                if (tsh_ptr->count == 1)  {
                    PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                    tsh_ptr->current_count = 0;
                } else {
                    ThresholdHashAdd(de_ctx,tsh_ptr,p);
                }
            }
            break;

        case TYPE_BOTH:

            lookup_tsh = ThresholdHashSearch(de_ctx,tsh_ptr,p);

            if (lookup_tsh != NULL)  {

                if ((ts.tv_sec - lookup_tsh->tv_sec1) < lookup_tsh->seconds)    {

                    lookup_tsh->current_count++;
                    if (lookup_tsh->current_count == lookup_tsh->count)    {
                        PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                    }
                } else    {
                    lookup_tsh->tv_sec1 = ts.tv_sec;
                    lookup_tsh->current_count = 1;
                }
            } else    {
                tsh_ptr->current_count = 1;
                tsh_ptr->tv_sec1 = ts.tv_sec;

                if (tsh_ptr->count == 1)  {
                    PacketAlertAppend(p, s->gid, s->id, s->rev, s->prio, s->msg);
                    tsh_ptr->current_count = 0;
                } else {
                    ThresholdHashAdd(de_ctx,tsh_ptr,p);
                }

            }
            break;
    }
    SCMutexUnlock(&de_ctx->ths_ctx.threshold_table_lock);

    ThresholdTimeoutRemove(de_ctx);
}

void ThresholdFreeFunc(void *data)
{
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
    DetectThresholdData *a = (DetectThresholdData *)data1;
    DetectThresholdData *b = (DetectThresholdData *)data2;

    if ((a->sid == b->sid) && (a->gid == b->gid) && (CMP_ADDR(&a->addr,&b->addr)))
        return 1;

    return 0;
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
    DetectThresholdData *dt = (DetectThresholdData *)data;
    uint32_t hash = 0;

    if (dt->ipv == 4)
        hash = (dt->sid + dt->gid + dt->addr.addr_data32[0]) % THRESHOLD_HASH_SIZE;
    else if (dt->ipv == 6)
        hash = (dt->sid + dt->gid + dt->addr.addr_data32[0] + dt->addr.addr_data32[1] + dt->addr.addr_data32[2] + dt->addr.addr_data32[3]) % THRESHOLD_HASH_SIZE;

    return hash;
}

/**
 * \brief Init threshold context hash tables
 *
 * \param de_ctx Dectection Context
 *
 */
void ThresholdHashInit(DetectEngineCtx *de_ctx)
{
    if (de_ctx->ths_ctx.threshold_hash_table_dst == NULL || de_ctx->ths_ctx.threshold_hash_table_src == NULL || de_ctx->ths_ctx.threshold_hash_table_src_ipv6 == NULL || de_ctx->ths_ctx.threshold_hash_table_dst_ipv6 == NULL) {
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
