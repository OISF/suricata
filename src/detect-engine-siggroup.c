/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Signature grouping part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"

#include "flow-var.h"

#include "app-layer-protos.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-mpm.h"
#include "detect-engine-siggroup.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-hash.h"
#include "util-hashlist.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"

/* prototypes */
int SigGroupHeadClearSigs(SigGroupHead *);

static uint32_t detect_siggroup_head_memory = 0;
static uint32_t detect_siggroup_head_init_cnt = 0;
static uint32_t detect_siggroup_head_free_cnt = 0;
static uint32_t detect_siggroup_head_initdata_memory = 0;
static uint32_t detect_siggroup_head_initdata_init_cnt = 0;
static uint32_t detect_siggroup_head_initdata_free_cnt = 0;
static uint32_t detect_siggroup_sigarray_memory = 0;
static uint32_t detect_siggroup_sigarray_init_cnt = 0;
static uint32_t detect_siggroup_sigarray_free_cnt = 0;
static uint32_t detect_siggroup_matcharray_memory = 0;
static uint32_t detect_siggroup_matcharray_init_cnt = 0;
static uint32_t detect_siggroup_matcharray_free_cnt = 0;

void SigGroupHeadInitDataFree(SigGroupHeadInitData *sghid)
{
    if (sghid->content_array != NULL) {
        SCFree(sghid->content_array);
        sghid->content_array = NULL;
        sghid->content_size = 0;
    }
    if (sghid->uri_content_array != NULL) {
        SCFree(sghid->uri_content_array);
        sghid->uri_content_array = NULL;
        sghid->uri_content_size = 0;
    }
    if (sghid->sig_array != NULL) {
        SCFree(sghid->sig_array);
        sghid->sig_array = NULL;

        detect_siggroup_sigarray_free_cnt++;
        detect_siggroup_sigarray_memory -= sghid->sig_size;
    }
    SCFree(sghid);

    detect_siggroup_head_initdata_free_cnt++;
    detect_siggroup_head_initdata_memory -= sizeof(SigGroupHeadInitData);
}

static SigGroupHeadInitData *SigGroupHeadInitDataAlloc(uint32_t size)
{
    SigGroupHeadInitData *sghid = SCMalloc(sizeof(SigGroupHeadInitData));
    if (unlikely(sghid == NULL))
        return NULL;

    memset(sghid, 0x00, sizeof(SigGroupHeadInitData));

    detect_siggroup_head_initdata_init_cnt++;
    detect_siggroup_head_initdata_memory += sizeof(SigGroupHeadInitData);

    /* initialize the signature bitarray */
    sghid->sig_size = size;
    if ( (sghid->sig_array = SCMalloc(sghid->sig_size)) == NULL)
        goto error;

    memset(sghid->sig_array, 0, sghid->sig_size);

    detect_siggroup_sigarray_init_cnt++;
    detect_siggroup_sigarray_memory += sghid->sig_size;

    return sghid;
error:
    SigGroupHeadInitDataFree(sghid);
    return NULL;
}

void SigGroupHeadStore(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    void *ptmp;
    //printf("de_ctx->sgh_array_cnt %u, de_ctx->sgh_array_size %u, de_ctx->sgh_array %p\n", de_ctx->sgh_array_cnt, de_ctx->sgh_array_size, de_ctx->sgh_array);
    if (de_ctx->sgh_array_cnt < de_ctx->sgh_array_size) {
        de_ctx->sgh_array[de_ctx->sgh_array_cnt] = sgh;
    } else {
        int increase = 16;
        ptmp = SCRealloc(de_ctx->sgh_array,
                         sizeof(SigGroupHead *) * (increase + de_ctx->sgh_array_size));
        if (ptmp == NULL) {
            SCFree(de_ctx->sgh_array);
            de_ctx->sgh_array = NULL;
            return;
        }
        de_ctx->sgh_array = ptmp;

        de_ctx->sgh_array_size += increase;
        de_ctx->sgh_array[de_ctx->sgh_array_cnt] = sgh;
    }
    de_ctx->sgh_array_cnt++;
}

/**
 * \brief Alloc a SigGroupHead and its signature bit_array.
 *
 * \param size Size of the sig_array that has to be created for this
 *             SigGroupHead.
 *
 * \retval sgh Pointer to the newly init SigGroupHead on success; or NULL in
 *             case of error.
 */
static SigGroupHead *SigGroupHeadAlloc(DetectEngineCtx *de_ctx, uint32_t size)
{
    SigGroupHead *sgh = SCMalloc(sizeof(SigGroupHead));
    if (unlikely(sgh == NULL))
        return NULL;
    memset(sgh, 0, sizeof(SigGroupHead));

    sgh->init = SigGroupHeadInitDataAlloc(size);
    if (sgh->init == NULL)
        goto error;

    detect_siggroup_head_init_cnt++;
    detect_siggroup_head_memory += sizeof(SigGroupHead);

    return sgh;

error:
    SigGroupHeadFree(sgh);
    return NULL;
}

/**
 * \brief Free a SigGroupHead and its members.
 *
 * \param sgh Pointer to the SigGroupHead that has to be freed.
 */
void SigGroupHeadFree(SigGroupHead *sgh)
{
    if (sgh == NULL)
        return;

    SCLogDebug("sgh %p", sgh);

    PatternMatchDestroyGroup(sgh);

    if (sgh->match_array != NULL) {
        detect_siggroup_matcharray_free_cnt++;
        detect_siggroup_matcharray_memory -= (sgh->sig_cnt * sizeof(Signature *));
        SCFree(sgh->match_array);
        sgh->match_array = NULL;
    }

    if (sgh->non_mpm_store_array != NULL) {
        SCFree(sgh->non_mpm_store_array);
        sgh->non_mpm_store_array = NULL;
        sgh->non_mpm_store_cnt = 0;
    }

    sgh->sig_cnt = 0;

    if (sgh->init != NULL) {
        SigGroupHeadInitDataFree(sgh->init);
        sgh->init = NULL;
    }

    SCFree(sgh);

    detect_siggroup_head_free_cnt++;
    detect_siggroup_head_memory -= sizeof(SigGroupHead);

    return;
}

/**
 * \brief The hash function to be the used by the mpm SigGroupHead hash table -
 *        DetectEngineCtx->sgh_mpm_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the SigGroupHead.
 * \param datalen Not used in our case.
 *
 * \retval hash The generated hash value.
 */
uint32_t SigGroupHeadMpmHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigGroupHead *sgh = (SigGroupHead *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    for (b = 0; b < sgh->init->content_size; b++)
        hash += sgh->init->content_array[b];

    return hash % ht->array_size;
}

/**
 * \brief The Compare function to be used by the mpm SigGroupHead hash table -
 *        DetectEngineCtx->sgh_mpm_hash_table.
 *
 * \param data1 Pointer to the first SigGroupHead.
 * \param len1  Not used.
 * \param data2 Pointer to the second SigGroupHead.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 SigGroupHeads sent as args match.
 * \retval 0 If the 2 SigGroupHeads sent as args do not match.
 */
char SigGroupHeadMpmCompareFunc(void *data1, uint16_t len1, void *data2,
                                uint16_t len2)
{
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->init->content_size != sgh2->init->content_size)
        return 0;

    if (SCMemcmp(sgh1->init->content_array, sgh2->init->content_array,
               sgh1->init->content_size) != 0) {
        return 0;
    }

    return 1;
}

/**
 * \brief Initializes the SigGroupHead mpm hash table to be used by the detection
 *        engine context.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadMpmHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_mpm_hash_table = HashListTableInit(4096, SigGroupHeadMpmHashFunc,
                                                   SigGroupHeadMpmCompareFunc,
                                                   NULL);

    if (de_ctx->sgh_mpm_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context SigGroupHead
 *        mpm hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the argument sgh; -1 on failure.
 */
int SigGroupHeadMpmHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_mpm_hash_table, (void *)sgh, 0);

    return ret;
}

/**
 * \brief Used to lookup a SigGroupHead from the detection engine context
 *        SigGroupHead mpm hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadMpmHashLookup(DetectEngineCtx *de_ctx,
                                        SigGroupHead *sgh)
{
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_mpm_hash_table,
                                             (void *)sgh, 0);

    return rsgh;
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_mpm_hash_table, allocated by
 *        SigGroupHeadMpmHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadMpmHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_mpm_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_mpm_hash_table);
    de_ctx->sgh_mpm_hash_table = NULL;

    return;
}

/**
 * \brief The hash function to be the used by the mpm uri SigGroupHead hash
 *        table - DetectEngineCtx->sgh_mpm_uri_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the SigGroupHead.
 * \param datalen Not used in our case.
 *
 * \retval hash The generated hash value.
 */
uint32_t SigGroupHeadMpmUriHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigGroupHead *sgh = (SigGroupHead *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    for (b = 0; b < sgh->init->uri_content_size; b++)
        hash += sgh->init->uri_content_array[b];

    return hash % ht->array_size;
}

/**
 * \brief The Compare function to be used by the mpm uri SigGroupHead hash
 *        table - DetectEngineCtx->sgh_mpm_uri_hash_table.
 *
 * \param data1 Pointer to the first SigGroupHead.
 * \param len1  Not used.
 * \param data2 Pointer to the second SigGroupHead.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 SigGroupHeads sent as args match.
 * \retval 0 If the 2 SigGroupHeads sent as args do not match.
 */
char SigGroupHeadMpmUriCompareFunc(void *data1, uint16_t len1, void *data2,
                                   uint16_t len2)
{
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->init->uri_content_size != sgh2->init->uri_content_size)
        return 0;

    if (SCMemcmp(sgh1->init->uri_content_array, sgh2->init->uri_content_array,
               sgh1->init->uri_content_size) != 0) {
        return 0;
    }

    return 1;
}

/**
 * \brief Initializes the mpm uri hash table to be used by the detection engine
 *        context.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadMpmUriHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_mpm_uri_hash_table = HashListTableInit(4096,
                                                       SigGroupHeadMpmUriHashFunc,
                                                       SigGroupHeadMpmUriCompareFunc,
                                                       NULL);
    if (de_ctx->sgh_mpm_uri_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context SigGroupHead
 *        mpm uri hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the argument sgh and -1 on failure.
 */
int SigGroupHeadMpmUriHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_mpm_uri_hash_table, (void *)sgh, 0);

    return ret;
}

/**
 * \brief Used to lookup a SigGroupHead from the detection engine context
 *        SigGroupHead mpm uri hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadMpmUriHashLookup(DetectEngineCtx *de_ctx,
                                           SigGroupHead *sgh)
{
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_mpm_uri_hash_table,
                                             (void *)sgh, 0);

    return rsgh;
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_mpm_uri_hash_table,
 *        allocated by SigGroupHeadMpmUriHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadMpmUriHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_mpm_uri_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_mpm_uri_hash_table);
    de_ctx->sgh_mpm_uri_hash_table = NULL;

    return;
}

/**
 * \brief The hash function to be the used by the mpm uri SigGroupHead hash
 *        table - DetectEngineCtx->sgh_mpm_uri_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the SigGroupHead.
 * \param datalen Not used in our case.
 *
 * \retval hash The generated hash value.
 */
uint32_t SigGroupHeadMpmStreamHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigGroupHead *sgh = (SigGroupHead *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    for (b = 0; b < sgh->init->stream_content_size; b++)
        hash += sgh->init->stream_content_array[b];

    return hash % ht->array_size;
}

/**
 * \brief The Compare function to be used by the mpm uri SigGroupHead hash
 *        table - DetectEngineCtx->sgh_mpm_uri_hash_table.
 *
 * \param data1 Pointer to the first SigGroupHead.
 * \param len1  Not used.
 * \param data2 Pointer to the second SigGroupHead.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 SigGroupHeads sent as args match.
 * \retval 0 If the 2 SigGroupHeads sent as args do not match.
 */
char SigGroupHeadMpmStreamCompareFunc(void *data1, uint16_t len1, void *data2,
                                   uint16_t len2)
{
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->init->stream_content_size != sgh2->init->stream_content_size)
        return 0;

    if (SCMemcmp(sgh1->init->stream_content_array, sgh2->init->stream_content_array,
               sgh1->init->stream_content_size) != 0) {
        return 0;
    }

    return 1;
}

/**
 * \brief Initializes the mpm uri hash table to be used by the detection engine
 *        context.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadMpmStreamHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_mpm_stream_hash_table = HashListTableInit(4096,
            SigGroupHeadMpmStreamHashFunc, SigGroupHeadMpmStreamCompareFunc, NULL);
    if (de_ctx->sgh_mpm_stream_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context SigGroupHead
 *        mpm uri hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the argument sgh and -1 on failure.
 */
int SigGroupHeadMpmStreamHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_mpm_stream_hash_table, (void *)sgh, 0);

    return ret;
}

/**
 * \brief Used to lookup a SigGroupHead from the detection engine context
 *        SigGroupHead mpm uri hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadMpmStreamHashLookup(DetectEngineCtx *de_ctx,
                                           SigGroupHead *sgh)
{
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_mpm_stream_hash_table,
                                             (void *)sgh, 0);

    return rsgh;
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_mpm_uri_hash_table,
 *        allocated by SigGroupHeadMpmUriHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadMpmStreamHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_mpm_stream_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_mpm_stream_hash_table);
    de_ctx->sgh_mpm_stream_hash_table = NULL;

    return;
}

/**
 * \brief The hash function to be the used by the hash table -
 *        DetectEngineCtx->sgh_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the SigGroupHead.
 * \param datalen Not used in our case.
 *
 * \retval hash The generated hash value.
 */
uint32_t SigGroupHeadHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigGroupHead *sgh = (SigGroupHead *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    SCLogDebug("hashing sgh %p (mpm_content_minlen %u)", sgh, sgh->mpm_content_minlen);

    for (b = 0; b < sgh->init->sig_size; b++)
        hash += sgh->init->sig_array[b];

    hash %= ht->array_size;
    SCLogDebug("hash %"PRIu32" (sig_size %"PRIu32")", hash, sgh->init->sig_size);
    return hash;
}

/**
 * \brief The Compare function to be used by the SigGroupHead hash table -
 *        DetectEngineCtx->sgh_hash_table.
 *
 * \param data1 Pointer to the first SigGroupHead.
 * \param len1  Not used.
 * \param data2 Pointer to the second SigGroupHead.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 SigGroupHeads sent as args match.
 * \retval 0 If the 2 SigGroupHeads sent as args do not match.
 */
char SigGroupHeadCompareFunc(void *data1, uint16_t len1, void *data2,
                             uint16_t len2)
{
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (data1 == NULL || data2 == NULL)
        return 0;

    if (sgh1->init->sig_size != sgh2->init->sig_size)
        return 0;

    if (SCMemcmp(sgh1->init->sig_array, sgh2->init->sig_array, sgh1->init->sig_size) != 0)
        return 0;

    return 1;
}

/**
 * \brief Initializes the hash table in the detection engine context to hold the
 *        SigGroupHeads.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_hash_table = HashListTableInit(4096, SigGroupHeadHashFunc,
                                               SigGroupHeadCompareFunc, NULL);
    if (de_ctx->sgh_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context SigGroupHead
 *        hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the SigGroupHead; -1 on failure.
 */
int SigGroupHeadHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_hash_table, (void *)sgh, 0);

    return ret;
}

int SigGroupHeadHashRemove(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return HashListTableRemove(de_ctx->sgh_hash_table, (void *)sgh, 0);
}

/**
 * \brief Used to lookup a SigGroupHead hash from the detection engine context
 *        SigGroupHead hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    SCEnter();

    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_hash_table,
                                             (void *)sgh, 0);

    SCReturnPtr(rsgh, "SigGroupHead");
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_hash_table, allocated by
 *        SigGroupHeadHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_hash_table);
    de_ctx->sgh_hash_table = NULL;

    return;
}

/**
 * \brief Initializes the dport based SigGroupHead hash table to hold the
 *        SigGroupHeads.  The hash table that would be initialized is
 *        DetectEngineCtx->sgh_dport_hash_table.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadDPortHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_dport_hash_table = HashListTableInit(4096, SigGroupHeadHashFunc,
                                                     SigGroupHeadCompareFunc,
                                                     NULL);
    if (de_ctx->sgh_dport_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context dport based
 *        SigGroupHead hash table(DetectEngineCtx->sgh_dport_hash_table).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the argument sgh and -1 on failure.
 */
int SigGroupHeadDPortHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_dport_hash_table, (void *)sgh, 0);

    return ret;
}

/**
 * \brief Used to lookup a SigGroupHead hash from the detection engine ctx dport
 *        based SigGroupHead hash table(DetectEngineCtx->sgh_dport_hash_table).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadDPortHashLookup(DetectEngineCtx *de_ctx,
                                          SigGroupHead *sgh)
{
    SCEnter();

    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_dport_hash_table,
                                             (void *)sgh, 0);

    SCReturnPtr(rsgh,"SigGroupHead");
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_dport_hash_table,
 *        allocated by the SigGroupHeadDPortHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadDPortHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_dport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_dport_hash_table);
    de_ctx->sgh_dport_hash_table = NULL;

    return;
}

/**
 * \brief Initializes the sport based SigGroupHead hash table to hold the
 *        SigGroupHeads.  The hash table that would be initialized is
 *        DetectEngineCtx->sgh_sport_hash_table.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadSPortHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_sport_hash_table = HashListTableInit(4096,
                                                     SigGroupHeadHashFunc,
                                                     SigGroupHeadCompareFunc,
                                                     NULL);
    if (de_ctx->sgh_sport_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a SigGroupHead to the detection engine context dport based
 *        SigGroupHead hash table(DetectEngineCtx->sgh_sport_hash_table).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval ret 0 on Successfully adding the argument sgh and -1 on failure.
 */
int SigGroupHeadSPortHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int ret = HashListTableAdd(de_ctx->sgh_sport_hash_table, (void *)sgh, 0);

    return ret;
}

int SigGroupHeadSPortHashRemove(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return HashListTableRemove(de_ctx->sgh_sport_hash_table, (void *)sgh, 0);
}

/**
 * \brief Used to lookup a SigGroupHead hash from the detection engine ctx sport
 *        based SigGroupHead hash table(DetectEngineCtx->sgh_dport_hash_table).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval rsgh On success a pointer to the SigGroupHead if the SigGroupHead is
 *              found in the hash table; NULL on failure.
 */
SigGroupHead *SigGroupHeadSPortHashLookup(DetectEngineCtx *de_ctx,
                                          SigGroupHead *sgh)
{
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_sport_hash_table,
                                             (void *)sgh, 0);

    return rsgh;
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_sport_hash_table,
 *        allocated by the SigGroupHeadSPortHashInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadSPortHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_sport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_sport_hash_table);
    de_ctx->sgh_sport_hash_table = NULL;

    return;
}

/**
 * \brief Used to free the signature array, content_array and uri_content_array
 *        members from the SigGroupHeads in the HashListTable.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param ht     Pointer to the HashListTable
 */
static void SigGroupHeadFreeSigArraysHash2(DetectEngineCtx *de_ctx,
                                           HashListTable *ht)
{
    HashListTableBucket *htb = NULL;
    SigGroupHead *sgh = NULL;

    for (htb = HashListTableGetListHead(ht);
         htb != NULL;
         htb = HashListTableGetListNext(htb))
    {
        sgh = (SigGroupHead *)HashListTableGetListData(htb);
        if (sgh == NULL) {
            continue;
        }

        if (sgh->init->sig_array != NULL) {
            detect_siggroup_sigarray_free_cnt++;
            detect_siggroup_sigarray_memory -= sgh->init->sig_size;

            SCFree(sgh->init->sig_array);
            sgh->init->sig_array = NULL;
            sgh->init->sig_size = 0;
        }

        SigGroupHeadInitDataFree(sgh->init);
        sgh->init = NULL;
    }

    return;
}

/**
 * \brief Used to free the sig_array member of the SigGroupHeads present
 *        in the HashListTable.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param ht     Pointer to the HashListTable
 */
static void SigGroupHeadFreeSigArraysHash(DetectEngineCtx *de_ctx,
                                          HashListTable *ht)
{
    HashListTableBucket *htb = NULL;
    SigGroupHead *sgh = NULL;

    for (htb = HashListTableGetListHead(ht);
         htb != NULL;
         htb = HashListTableGetListNext(htb)) {
        sgh = (SigGroupHead *)HashListTableGetListData(htb);

        if (sgh->init != NULL) {
            SigGroupHeadInitDataFree(sgh->init);
            sgh->init = NULL;
        }
    }

    return;
}

/**
 * \brief Free the sigarrays in the sgh's. Those are only used during the init
 *        stage.
 *
 * \param de_ctx Pointer to the detection engine context whose sigarrays have to
 *               be freed.
 */
void SigGroupHeadFreeSigArrays(DetectEngineCtx *de_ctx)
{
    SigGroupHeadFreeSigArraysHash2(de_ctx, de_ctx->sgh_hash_table);
    SigGroupHeadFreeSigArraysHash(de_ctx, de_ctx->sgh_dport_hash_table);
    SigGroupHeadFreeSigArraysHash(de_ctx, de_ctx->sgh_sport_hash_table);

    return;
}

/**
 * \brief Free the mpm arrays that are only used during the init stage.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void SigGroupHeadFreeMpmArrays(DetectEngineCtx *de_ctx)
{
    HashListTableBucket *htb = NULL;
    SigGroupHead *sgh = NULL;

    for (htb = HashListTableGetListHead(de_ctx->sgh_dport_hash_table); htb != NULL; htb = HashListTableGetListNext(htb)) {
        sgh = (SigGroupHead *)HashListTableGetListData(htb);
        if (sgh->init != NULL) {
            SigGroupHeadInitDataFree(sgh->init);
            sgh->init = NULL;
        }
    }

    for (htb = HashListTableGetListHead(de_ctx->sgh_sport_hash_table); htb != NULL; htb = HashListTableGetListNext(htb)) {
        sgh = (SigGroupHead *)HashListTableGetListData(htb);
        if (sgh->init != NULL) {
            SigGroupHeadInitDataFree(sgh->init);
            sgh->init = NULL;
        }
    }

    return;
}

static uint16_t SignatureGetMpmPatternLen(Signature *s, int list)
{
    if (s->sm_lists[list] != NULL && s->mpm_sm != NULL &&
        SigMatchListSMBelongsTo(s, s->mpm_sm) == list)
    {
        DetectContentData *cd = (DetectContentData *)s->mpm_sm->ctx;
        return cd->content_len;
    }
    return 0;
}

/**
 * \brief Add a Signature to a SigGroupHead.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to a SigGroupHead.  Can be NULL also.
 * \param s      Pointer to the Signature that has to be added to the
 *               SigGroupHead.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadAppendSig(DetectEngineCtx *de_ctx, SigGroupHead **sgh,
                          Signature *s)
{
    if (de_ctx == NULL)
        return 0;

    /* see if we have a head already */
    if (*sgh == NULL) {
        *sgh = SigGroupHeadAlloc(de_ctx, DetectEngineGetMaxSigId(de_ctx) / 8 + 1);
        if (*sgh == NULL)
            goto error;
    }

    /* enable the sig in the bitarray */
    (*sgh)->init->sig_array[s->num / 8] |= 1 << (s->num % 8);

    /* update minlen for mpm */
    if (s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        /* check with the precalculated values from the sig */
        uint16_t mpm_content_minlen = SignatureGetMpmPatternLen(s, DETECT_SM_LIST_PMATCH);
        if (mpm_content_minlen > 0) {
            if ((*sgh)->mpm_content_minlen == 0)
                (*sgh)->mpm_content_minlen = mpm_content_minlen;

            if ((*sgh)->mpm_content_minlen > mpm_content_minlen)
                (*sgh)->mpm_content_minlen = mpm_content_minlen;

            SCLogDebug("(%p)->mpm_content_minlen %u", *sgh, (*sgh)->mpm_content_minlen);
        }
    }
    return 0;

error:
    return -1;
}

/**
 * \brief Clears the bitarray holding the sids for this SigGroupHead.
 *
 * \param sgh Pointer to the SigGroupHead.
 *
 * \retval 0 Always.
 */
int SigGroupHeadClearSigs(SigGroupHead *sgh)
{
    if (sgh == NULL)
        return 0;

    if (sgh->init->sig_array != NULL)
        memset(sgh->init->sig_array, 0, sgh->init->sig_size);

    sgh->sig_cnt = 0;

    return 0;
}

/**
 * \brief Copies the bitarray holding the sids from the source SigGroupHead to
 *        the destination SigGroupHead.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param src    Pointer to the source SigGroupHead.
 * \param dst    Pointer to the destination SigGroupHead.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SigGroupHeadCopySigs(DetectEngineCtx *de_ctx, SigGroupHead *src, SigGroupHead **dst)
{
    uint32_t idx = 0;

    if (src == NULL || de_ctx == NULL)
        return 0;

    if (*dst == NULL) {
        *dst = SigGroupHeadAlloc(de_ctx, DetectEngineGetMaxSigId(de_ctx) / 8 + 1);
        if (*dst == NULL)
            goto error;
    }

    /* do the copy */
    for (idx = 0; idx < src->init->sig_size; idx++)
        (*dst)->init->sig_array[idx] = (*dst)->init->sig_array[idx] | src->init->sig_array[idx];

    if (src->mpm_content_minlen != 0) {
        if ((*dst)->mpm_content_minlen == 0)
            (*dst)->mpm_content_minlen = src->mpm_content_minlen;

        if ((*dst)->mpm_content_minlen > src->mpm_content_minlen)
            (*dst)->mpm_content_minlen = src->mpm_content_minlen;

        SCLogDebug("src (%p)->mpm_content_minlen %u", src, src->mpm_content_minlen);
        SCLogDebug("dst (%p)->mpm_content_minlen %u", (*dst), (*dst)->mpm_content_minlen);
        BUG_ON((*dst)->mpm_content_minlen == 0);
    }
    return 0;

error:
    return -1;
}

/**
 * \brief Updates the SigGroupHead->sig_cnt with the total count of all the
 *        Signatures present in this SigGroupHead.
 *
 * \param sgh     Pointer to the SigGroupHead.
 * \param max_idx Maximum sid of the all the Signatures present in this
 *                SigGroupHead.
 */
void SigGroupHeadSetSigCnt(SigGroupHead *sgh, uint32_t max_idx)
{
    uint32_t sig;

    sgh->sig_cnt = 0;
    for (sig = 0; sig < max_idx + 1; sig++) {
        if (sgh->init->sig_array[sig / 8] & (1 << (sig % 8)))
            sgh->sig_cnt++;
    }

    return;
}

/**
 * \brief Prints the memory statistics for the detect-engine-siggroup.[ch] module.
 */
void DetectSigGroupPrintMemory(void)
{
    SCLogDebug(" * Sig group head memory stats (SigGroupHead %" PRIuMAX "):",
               (uintmax_t)sizeof(SigGroupHead));
    SCLogDebug("  - detect_siggroup_head_memory %" PRIu32,
               detect_siggroup_head_memory);
    SCLogDebug("  - detect_siggroup_head_init_cnt %" PRIu32,
               detect_siggroup_head_init_cnt);
    SCLogDebug("  - detect_siggroup_head_free_cnt %" PRIu32,
               detect_siggroup_head_free_cnt);
    SCLogDebug("  - outstanding sig group heads %" PRIu32,
               detect_siggroup_head_init_cnt - detect_siggroup_head_free_cnt);
    SCLogDebug(" * Sig group head memory stats done");
    SCLogDebug(" * Sig group head initdata memory stats (SigGroupHeadInitData %" PRIuMAX "):",
               (uintmax_t)sizeof(SigGroupHeadInitData));
    SCLogDebug("  - detect_siggroup_head_initdata_memory %" PRIu32,
               detect_siggroup_head_initdata_memory);
    SCLogDebug("  - detect_siggroup_head_initdata_init_cnt %" PRIu32,
               detect_siggroup_head_initdata_init_cnt);
    SCLogDebug("  - detect_siggroup_head_initdata_free_cnt %" PRIu32,
               detect_siggroup_head_initdata_free_cnt);
    SCLogDebug("  - outstanding sig group head initdatas %" PRIu32,
               detect_siggroup_head_initdata_init_cnt - detect_siggroup_head_initdata_free_cnt);
    SCLogDebug(" * Sig group head memory initdata stats done");
    SCLogDebug(" * Sig group sigarray memory stats:");
    SCLogDebug("  - detect_siggroup_sigarray_memory %" PRIu32,
               detect_siggroup_sigarray_memory);
    SCLogDebug("  - detect_siggroup_sigarray_init_cnt %" PRIu32,
               detect_siggroup_sigarray_init_cnt);
    SCLogDebug("  - detect_siggroup_sigarray_free_cnt %" PRIu32,
               detect_siggroup_sigarray_free_cnt);
    SCLogDebug("  - outstanding sig group sigarrays %" PRIu32,
               (detect_siggroup_sigarray_init_cnt -
                detect_siggroup_sigarray_free_cnt));
    SCLogDebug(" * Sig group sigarray memory stats done");
    SCLogDebug(" * Sig group matcharray memory stats:");
    SCLogDebug("  - detect_siggroup_matcharray_memory %" PRIu32,
               detect_siggroup_matcharray_memory);
    SCLogDebug("  - detect_siggroup_matcharray_init_cnt %" PRIu32,
               detect_siggroup_matcharray_init_cnt);
    SCLogDebug("  - detect_siggroup_matcharray_free_cnt %" PRIu32,
               detect_siggroup_matcharray_free_cnt);
    SCLogDebug("  - outstanding sig group matcharrays %" PRIu32,
               (detect_siggroup_matcharray_init_cnt -
                detect_siggroup_matcharray_free_cnt));
    SCLogDebug(" * Sig group sigarray memory stats done");
    SCLogDebug(" X Total %" PRIu32,
               (detect_siggroup_head_memory + detect_siggroup_sigarray_memory +
                detect_siggroup_matcharray_memory));

    return;
}

/**
 * \brief Helper function used to print the list of sids for the Signatures
 *        present in this SigGroupHead.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 */
void SigGroupHeadPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    SCEnter();

    if (sgh == NULL) {
        SCReturn;
    }

    uint32_t u;

    SCLogDebug("The Signatures present in this SigGroupHead are: ");
    for (u = 0; u < (sgh->init->sig_size * 8); u++) {
        if (sgh->init->sig_array[u / 8] & (1 << (u % 8))) {
            SCLogDebug("%" PRIu32, u);
            printf("s->num %"PRIu32" ", u);
        }
    }

    SCReturn;
}

/**
 * \brief Helper function used to print the content ids of all the contents that
 *        have been added to the bitarray of this SigGroupHead.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 */
void SigGroupHeadPrintContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    SCEnter();

    uint32_t i = 0;

    SCLogDebug("Contents with the following content ids are present in this "
               "SigGroupHead - ");
    for (i = 0; i < DetectContentMaxId(de_ctx); i++) {
        if (sgh->init->content_array[i / 8] & (1 << (i % 8)))
            SCLogDebug("%" PRIu32, i);
    }

    SCReturn;
}

/**
 * \brief Helper function used to print the total no of contents that have
 *        been added to the bitarray for this SigGroupHead.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 */
void SigGroupHeadPrintContentCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    SCEnter();

    uint32_t i = 0;
    uint32_t cnt = 0;

    for (i = 0; i < DetectContentMaxId(de_ctx); i++) {
        if (sgh->init->content_array[i / 8] & (1 << (i % 8)))
            cnt++;
    }

    SCLogDebug("Total contents added to the SigGroupHead content bitarray: "
               "%" PRIu32, cnt);

    SCReturn;
}

/**
 * \brief Loads all the content ids from all the contents belonging to all the
 *        Signatures in this SigGroupHead, into a bitarray.  A fast and an
 *        efficient way of comparing pattern sets.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval  0 On success, i.e. on either the detection engine context being NULL
 *            or on successfully allocating memory and updating it with relevant
 *            data.
 * \retval -1 On failure.
 */
int SigGroupHeadLoadContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    uint32_t sig = 0;
    DetectContentData *co = NULL;

    if (sgh == NULL)
        return 0;

    if (DetectContentMaxId(de_ctx) == 0)
        return 0;

    BUG_ON(sgh->init == NULL);

    sgh->init->content_size = (DetectContentMaxId(de_ctx) / 8) + 1;
    sgh->init->content_array = SCMalloc(sgh->init->content_size);
    if (sgh->init->content_array == NULL)
        return -1;

    memset(sgh->init->content_array,0, sgh->init->content_size);

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (s->alproto != ALPROTO_UNKNOWN)
            continue;

        sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
        if (sm == NULL)
            continue;

        for ( ;sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co = (DetectContentData *)sm->ctx;

                sgh->init->content_array[co->id / 8] |= 1 << (co->id % 8);
            }
        }
    }

    return 0;
}

/**
 * \brief Clears the memory allocated by SigGroupHeadLoadContent() for the
 *        bitarray to hold the content ids for a SigGroupHead.
 *
 * \param Pointer to the SigGroupHead whose content_array would to be cleared.
 *
 * \ret 0 Always.
 */
int SigGroupHeadClearContent(SigGroupHead *sh)
{
    if (sh == NULL)
        return 0;

    if (sh->init->content_array != NULL) {
        SCFree(sh->init->content_array);
        sh->init->content_array = NULL;
        sh->init->content_size = 0;
    }
    return 0;
}

/**
 * \brief Loads all the uri content ids from all the uri contents belonging to
 *        all the Signatures in this SigGroupHead, into a bitarray.  A fast and
 *        an efficient way of comparing pattern sets.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval  0 On success, i.e. on either the detection engine context being NULL
 *            or on successfully allocating memory and updating it with relevant
 *            data.
 * \retval -1 On failure.
 */
int SigGroupHeadLoadUricontent(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    uint32_t sig = 0;
    DetectContentData *co = NULL;

    if (sgh == NULL)
        return 0;

    if (DetectUricontentMaxId(de_ctx) == 0)
        return 0;

    BUG_ON(sgh->init == NULL);

    sgh->init->uri_content_size = (DetectUricontentMaxId(de_ctx) / 8) + 1;
    sgh->init->uri_content_array = SCMalloc(sgh->init->uri_content_size);
    if (sgh->init->uri_content_array == NULL)
        return -1;

    memset(sgh->init->uri_content_array, 0, sgh->init->uri_content_size);

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];

        if (s == NULL)
            continue;

        sm = s->sm_lists[DETECT_SM_LIST_UMATCH];
        if (sm == NULL)
            continue;

        for ( ;sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co = (DetectContentData *)sm->ctx;

                sgh->init->uri_content_array[co->id / 8] |= 1 << (co->id % 8);
            }
        }
    }

    return 0;
}

/**
 * \brief Clears the memory allocated by SigGroupHeadLoadUriContent() for the
 *        bitarray to hold the uri content ids for a SigGroupHead.
 *
 * \param Pointer to the SigGroupHead whose uri_content_array would to be
 *        cleared.
 *
 * \retval 0 Always.
 */
int SigGroupHeadClearUricontent(SigGroupHead *sh)
{
    if (sh == NULL)
        return 0;

    if (sh->init->uri_content_array != NULL) {
        SCFree(sh->init->uri_content_array);
        sh->init->uri_content_array = NULL;
        sh->init->uri_content_size = 0;
    }

    return 0;
}

/**
 * \brief Loads all the content ids from all the contents belonging to all the
 *        Signatures in this SigGroupHead, into a bitarray.  A fast and an
 *        efficient way of comparing pattern sets.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead.
 *
 * \retval  0 On success, i.e. on either the detection engine context being NULL
 *            or on successfully allocating memory and updating it with relevant
 *            data.
 * \retval -1 On failure.
 */
int SigGroupHeadLoadStreamContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    SCEnter();

    Signature *s = NULL;
    SigMatch *sm = NULL;
    uint32_t sig = 0;
    DetectContentData *co = NULL;

    if (sgh == NULL) {
        SCReturnInt(0);
    }

    if (DetectContentMaxId(de_ctx) == 0) {
        SCReturnInt(0);
    }

    BUG_ON(sgh->init == NULL);

    sgh->init->stream_content_size = (DetectContentMaxId(de_ctx) / 8) + 1;
    sgh->init->stream_content_array = SCMalloc(sgh->init->stream_content_size);
    if (sgh->init->stream_content_array == NULL) {
        SCReturnInt(-1);
    }

    memset(sgh->init->stream_content_array,0, sgh->init->stream_content_size);

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];

        SCLogDebug("s %"PRIu32, s->id);

        if (s == NULL)
            continue;

        if (SignatureHasPacketContent(s)) {
            SCLogDebug("Sig has packet content");
            continue;
        }

        sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
        if (sm == NULL)
            continue;

        for ( ;sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co = (DetectContentData *)sm->ctx;

                sgh->init->stream_content_array[co->id / 8] |= 1 << (co->id % 8);
            }
        }
    }

    SCReturnInt(0);
}

/**
 * \brief Clears the memory allocated by SigGroupHeadLoadContent() for the
 *        bitarray to hold the content ids for a SigGroupHead.
 *
 * \param Pointer to the SigGroupHead whose content_array would to be cleared.
 *
 * \ret 0 Always.
 */
int SigGroupHeadClearStreamContent(SigGroupHead *sh)
{
    if (sh == NULL)
        return 0;

    if (sh->init->stream_content_array != NULL) {
        SCFree(sh->init->stream_content_array);
        sh->init->stream_content_array = NULL;
        sh->init->stream_content_size = 0;
    }
    return 0;
}

/**
 * \brief Create an array with all the internal ids of the sigs that this
 *        sig group head will check for.
 *
 * \param de_ctx  Pointer to the detection engine context.
 * \param sgh     Pointer to the SigGroupHead.
 * \param max_idx The maximum value of the sid in the SigGroupHead arg.
 *
 * \retval  0 success
 * \retval -1 error
 */
int SigGroupHeadBuildMatchArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                                uint32_t max_idx)
{
    Signature *s = NULL;
    uint32_t idx = 0;
    uint32_t sig = 0;

    if (sgh == NULL)
        return 0;

    BUG_ON(sgh->match_array != NULL);

    sgh->match_array = SCMalloc(sgh->sig_cnt * sizeof(Signature *));
    if (sgh->match_array == NULL)
        return -1;

    memset(sgh->match_array,0, sgh->sig_cnt * sizeof(Signature *));

    detect_siggroup_matcharray_init_cnt++;
    detect_siggroup_matcharray_memory += (sgh->sig_cnt * sizeof(Signature *));

    for (sig = 0; sig < max_idx + 1; sig++) {
        if (!(sgh->init->sig_array[(sig / 8)] & (1 << (sig % 8))) )
            continue;

        s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        sgh->match_array[idx] = s;
        idx++;
    }

    return 0;
}

/**
 *  \brief Set the need md5 flag in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 */
void SigGroupHeadSetFilemagicFlag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFilemagicInspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILEMAGIC;
            break;
        }
    }

    return;
}

/**
 *  \brief Get size of the shortest mpm pattern.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 *  \param list sm_list to consider
 */
uint16_t SigGroupHeadGetMinMpmSize(DetectEngineCtx *de_ctx,
                                   SigGroupHead *sgh, int list)
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint16_t min = USHRT_MAX;

    if (sgh == NULL)
        return 0;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        uint16_t mpm_content_minlen = SignatureGetMpmPatternLen(s, DETECT_SM_LIST_PMATCH);
        if (mpm_content_minlen > 0) {
            if (mpm_content_minlen < min)
                min = mpm_content_minlen;
            SCLogDebug("mpm_content_minlen %u", mpm_content_minlen);
        }
    }

    if (min == USHRT_MAX)
        min = 0;
    SCLogDebug("min mpm size %u", min);
    return min;
}

/**
 *  \brief Set the need size flag in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 */
void SigGroupHeadSetFilesizeFlag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFilesizeInspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILESIZE;
            break;
        }
    }

    return;
}

/**
 *  \brief Set the need magic flag in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 */
void SigGroupHeadSetFileMd5Flag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFileMd5Inspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILEMD5;
            SCLogDebug("sgh %p has filemd5", sgh);
            break;
        }
    }

    return;
}

/**
 *  \brief Set the filestore_cnt in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the counter in
 */
void SigGroupHeadSetFilestoreCount(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFilestoring(s)) {
            sgh->filestore_cnt++;
        }
    }

    return;
}

/** \brief build an array of rule id's for sigs with no mpm
 *  Also updated de_ctx::non_mpm_store_cnt_max to track the highest cnt
 */
int SigGroupHeadBuildNonMpmArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint32_t non_mpm = 0;

    if (sgh == NULL)
        return 0;

    BUG_ON(sgh->non_mpm_store_array != NULL);

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (s->mpm_sm == NULL)
            non_mpm++;
        else if (s->flags & (SIG_FLAG_MPM_PACKET_NEG|SIG_FLAG_MPM_STREAM_NEG|SIG_FLAG_MPM_APPLAYER_NEG))
            non_mpm++;
    }

    if (non_mpm == 0) {
        sgh->non_mpm_store_array = NULL;
        return 0;
    }

    sgh->non_mpm_store_array = SCMalloc(non_mpm * sizeof(SignatureNonMpmStore));
    BUG_ON(sgh->non_mpm_store_array == NULL);
    memset(sgh->non_mpm_store_array, 0, non_mpm * sizeof(SignatureNonMpmStore));

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (s->mpm_sm == NULL) {
            BUG_ON(sgh->non_mpm_store_cnt >= non_mpm);
            sgh->non_mpm_store_array[sgh->non_mpm_store_cnt].id = s->num;
            sgh->non_mpm_store_array[sgh->non_mpm_store_cnt].mask = s->mask;
            sgh->non_mpm_store_cnt++;
        } else if (s->flags & (SIG_FLAG_MPM_PACKET_NEG|SIG_FLAG_MPM_STREAM_NEG|SIG_FLAG_MPM_APPLAYER_NEG)) {
            BUG_ON(sgh->non_mpm_store_cnt >= non_mpm);
            sgh->non_mpm_store_array[sgh->non_mpm_store_cnt].id = s->num;
            sgh->non_mpm_store_array[sgh->non_mpm_store_cnt].mask = s->mask;
            sgh->non_mpm_store_cnt++;
        }
    }

    /* track highest cnt for any sgh in our de_ctx */
    if (sgh->non_mpm_store_cnt > de_ctx->non_mpm_store_cnt_max)
        de_ctx->non_mpm_store_cnt_max = sgh->non_mpm_store_cnt;

    return 0;
}

/**
 * \brief Check if a SigGroupHead contains a Signature, whose sid is sent as an
 *        argument.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the SigGroupHead that has to be checked for the
 *               presence of a Signature.
 * \param sid    The Signature id(sid) that has to be checked in the SigGroupHead.
 *
 * \retval 1 On successfully finding the sid in the SigGroupHead.
 * \retval 0 If the sid is not found in the SigGroupHead
 */
int SigGroupHeadContainsSigId(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                              uint32_t sid)
{
    SCEnter();

    uint32_t sig = 0;
    Signature *s = NULL;
    uint32_t max_sid = DetectEngineGetMaxSigId(de_ctx);

    if (sgh == NULL) {
        SCReturnInt(0);
    }

    for (sig = 0; sig < max_sid; sig++) {
        if (sgh->init->sig_array == NULL) {
            SCReturnInt(0);
        }

        /* Check if the SigGroupHead has an entry for the sid */
        if ( !(sgh->init->sig_array[sig / 8] & (1 << (sig % 8))) )
            continue;

        /* If we have reached here, we have an entry for sid in the SigGrouHead.
         * Retrieve the Signature from the detection engine context */
        s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        /* If the retrieved Signature matches the sid arg, we have a match */
        if (s->id == sid) {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/*----------------------------------Unittests---------------------------------*/

#ifdef UNITTESTS

int SigAddressPrepareStage1(DetectEngineCtx *);

/**
 * \test Check if a SigGroupHead mpm hash table is properly allocated and
 *       deallocated when calling SigGroupHeadMpmHashInit() and
 *       SigGroupHeadMpmHashFree() respectively.
 */
static int SigGroupHeadTest01(void)
{
    int result = 1;

    DetectEngineCtx de_ctx;

    SigGroupHeadMpmHashInit(&de_ctx);

    result &= (de_ctx.sgh_mpm_hash_table != NULL);

    SigGroupHeadMpmHashFree(&de_ctx);

    result &= (de_ctx.sgh_mpm_hash_table == NULL);

    return result;
}

/**
 * \test Check if a SigGroupHead mpm uri hash table is properly allocated and
 *       deallocated when calling SigGroupHeadMpmUriHashInit() and
 *       SigGroupHeadMpmUriHashFree() respectively.
 */
static int SigGroupHeadTest02(void)
{
    int result = 1;

    DetectEngineCtx de_ctx;

    SigGroupHeadMpmUriHashInit(&de_ctx);

    result &= (de_ctx.sgh_mpm_uri_hash_table != NULL);

    SigGroupHeadMpmUriHashFree(&de_ctx);

    result &= (de_ctx.sgh_mpm_uri_hash_table == NULL);

    return result;
}

/**
 * \test Check if a SigGroupHead hash table is properly allocated and
 *       deallocated when calling SigGroupHeadHashInit() and
 *       SigGroupHeadHashFree() respectively.
 */
static int SigGroupHeadTest03(void)
{
    int result = 1;

    DetectEngineCtx de_ctx;

    SigGroupHeadHashInit(&de_ctx);

    result &= (de_ctx.sgh_hash_table != NULL);

    SigGroupHeadHashFree(&de_ctx);

    result &= (de_ctx.sgh_hash_table == NULL);

    return result;
}

/**
 * \test Check if a SigGroupHead dport hash table is properly allocated and
 *       deallocated when calling SigGroupHeadDPortHashInit() and
 *       SigGroupHeadDportHashFree() respectively.
 */
static int SigGroupHeadTest04(void)
{
    int result = 1;

    DetectEngineCtx de_ctx;

    SigGroupHeadDPortHashInit(&de_ctx);

    result &= (de_ctx.sgh_dport_hash_table != NULL);

    SigGroupHeadDPortHashFree(&de_ctx);

    result &= (de_ctx.sgh_dport_hash_table == NULL);

    return result;
}

/**
 * \test Check if a SigGroupHead dport hash table is properly allocated and
 *       deallocated when calling SigGroupHeadSPortHashInit() and
 *       SigGroupHeadSportHashFree() respectively.
 */
static int SigGroupHeadTest05(void)
{
    int result = 1;

    DetectEngineCtx de_ctx;

    SigGroupHeadSPortHashInit(&de_ctx);

    result &= (de_ctx.sgh_sport_hash_table != NULL);

    SigGroupHeadSPortHashFree(&de_ctx);

    result &= (de_ctx.sgh_sport_hash_table == NULL);

    return result;
}

/**
 * \test Check if a SigGroupHeadAppendSig() correctly appends a sid to a
 *       SigGroupHead() and SigGroupHeadContainsSigId() correctly indicates
 *       the presence of a sid.
 */
static int SigGroupHeadTest06(void)
{
    int result = 1;
    SigGroupHead *sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *prev_sig = NULL;

    if (de_ctx == NULL)
        return 0;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                               "content:\"test2\"; content:\"test3\"; sid:0;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = de_ctx->sig_list;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:1;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:2;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:3;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:4;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);

    result &= (sh->sig_cnt == 3);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 0) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 1) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 2) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 3) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 4) == 1);

    SigGroupHeadFree(sh);

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if a SigGroupHeadAppendSig(), correctly appends a sid to a
 *       SigGroupHead() and SigGroupHeadContainsSigId(), correctly indicates
 *       the presence of a sid and SigGroupHeadClearSigs(), correctly clears
 *       the SigGroupHead->sig_array and SigGroupHead->sig_cnt.
 */
static int SigGroupHeadTest07(void)
{
    int result = 1;
    SigGroupHead *sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *prev_sig = NULL;

    if (de_ctx == NULL)
        return 0;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                               "content:\"test2\"; content:\"test3\"; sid:0;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = de_ctx->sig_list;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:1;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:2;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:3;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:4;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);

    result &= (sh->sig_cnt == 3);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 0) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 1) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 2) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 3) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 4) == 1);

    SigGroupHeadClearSigs(sh);

    result &= (sh->sig_cnt == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 0) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 1) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 2) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 3) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, sh, 4) == 0);

    SigGroupHeadFree(sh);

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if SigGroupHeadCopySigs(), correctly copies the sig_array from
 *       the source to the destination SigGroupHead.
 */
static int SigGroupHeadTest08(void)
{
    int result = 1;
    SigGroupHead *src_sh = NULL;
    SigGroupHead *dst_sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *prev_sig = NULL;

    if (de_ctx == NULL)
        return 0;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                               "content:\"test2\"; content:\"test3\"; sid:0;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = de_ctx->sig_list;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:1;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:2;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:3;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:4;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(src_sh, 4);

    result &= (src_sh->sig_cnt == 3);
    result &= (SigGroupHeadContainsSigId(de_ctx, src_sh, 0) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, src_sh, 1) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, src_sh, 2) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, src_sh, 3) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, src_sh, 4) == 1);

    SigGroupHeadCopySigs(de_ctx, src_sh, &dst_sh);

    SigGroupHeadSetSigCnt(dst_sh, 4);

    result &= (dst_sh->sig_cnt == 3);
    result &= (SigGroupHeadContainsSigId(de_ctx, dst_sh, 0) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, dst_sh, 1) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, dst_sh, 2) == 1);
    result &= (SigGroupHeadContainsSigId(de_ctx, dst_sh, 3) == 0);
    result &= (SigGroupHeadContainsSigId(de_ctx, dst_sh, 4) == 1);

    SigGroupHeadFree(src_sh);
    SigGroupHeadFree(dst_sh);

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if SigGroupHeadBuildMatchArray(), correctly updates the
 *       match array with the sids.
 */
static int SigGroupHeadTest09(void)
{
    int result = 1;
    SigGroupHead *sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *prev_sig = NULL;

    if (de_ctx == NULL)
        return 0;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                               "content:\"test2\"; content:\"test3\"; sid:0;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = de_ctx->sig_list;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:1;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:2;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:3;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    prev_sig->next = SigInit(de_ctx, "alert tcp any any -> any any "
                             "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                             "content:\"test2\"; content:\"test3\"; sid:4;)");
    if (prev_sig->next == NULL) {
        result = 0;
        goto end;
    }
    prev_sig = prev_sig->next;

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);
    SigGroupHeadBuildMatchArray(de_ctx, sh, 4);

    result &= (sh->match_array[0] == de_ctx->sig_list);
    result &= (sh->match_array[1] == de_ctx->sig_list->next->next);
    result &= (sh->match_array[2] == de_ctx->sig_list->next->next->next->next);

    SigGroupHeadFree(sh);

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test ICMP(?) sig grouping bug.
 */
static int SigGroupHeadTest10(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *s = NULL;
    Packet *p = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;

    memset(&th_v, 0, sizeof(ThreadVars));

    p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_ICMP, "192.168.1.1", "1.2.3.4");
    p->icmpv4h->type = 5;
    p->icmpv4h->code = 1;

    /* originally ip's were
    p.src.addr_data32[0] = 0xe08102d3;
    p.dst.addr_data32[0] = 0x3001a8c0;
    */

    if (de_ctx == NULL)
        return 0;

    s = DetectEngineAppendSig(de_ctx, "alert icmp 192.168.0.0/16 any -> any any (icode:>1; itype:11; sid:1; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> 192.168.0.0/16 any (icode:1; itype:5; sid:2; rev:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    AddressDebugPrint(&p->dst);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        goto end;
    }

    result = 1;
end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test sig grouping bug.
 */
static int SigGroupHeadTest11(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature *s = NULL;
    Packet *p = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;

    memset(&th_v, 0, sizeof(ThreadVars));

    p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "192.168.1.1", "1.2.3.4", 60000, 80);

    if (de_ctx == NULL || p == NULL)
        return 0;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any 1024: -> any 1024: (content:\"abc\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"def\"; http_client_body; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    AddressDebugPrint(&p->dst);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        goto end;
    }

    /* check if hcbd flag is set in sgh */
    if (!(sgh->flags & SIG_GROUP_HEAD_MPM_HCBD)) {
        printf("sgh has not SIG_GROUP_HEAD_MPM_HCBD flag set: ");
        goto end;
    }

    /* check if sig 2 is part of the sgh */

    result = 1;
end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);
    return result;
}
#endif

void SigGroupHeadRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SigGroupHeadTest01", SigGroupHeadTest01, 1);
    UtRegisterTest("SigGroupHeadTest02", SigGroupHeadTest02, 1);
    UtRegisterTest("SigGroupHeadTest03", SigGroupHeadTest03, 1);
    UtRegisterTest("SigGroupHeadTest04", SigGroupHeadTest04, 1);
    UtRegisterTest("SigGroupHeadTest05", SigGroupHeadTest05, 1);
    UtRegisterTest("SigGroupHeadTest06", SigGroupHeadTest06, 1);
    UtRegisterTest("SigGroupHeadTest07", SigGroupHeadTest07, 1);
    UtRegisterTest("SigGroupHeadTest08", SigGroupHeadTest08, 1);
    UtRegisterTest("SigGroupHeadTest09", SigGroupHeadTest09, 1);
    UtRegisterTest("SigGroupHeadTest10", SigGroupHeadTest10, 1);
    UtRegisterTest("SigGroupHeadTest11", SigGroupHeadTest11, 1);
#endif
}
