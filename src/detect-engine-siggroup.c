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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Signature grouping part of the detection engine.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "util-cidr.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-hashlist.h"
#include "util-hash.h"
#include "detect-uricontent.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"
#include "detect-engine-address.h"
#include "detect-parse.h"
#include "detect.h"
#include "app-layer-protos.h"
#include "flow-var.h"
#include "decode.h"
#endif

#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-prefilter.h"

#include "detect-tcp-flags.h"

#include "util-memcmp.h"

/* prototypes */
int SigGroupHeadClearSigs(SigGroupHead *);

void SigGroupHeadInitDataFree(SigGroupHeadInitData *sghid)
{
    if (sghid->match_array != NULL) {
        SCFree(sghid->match_array);
        sghid->match_array = NULL;
    }
    if (sghid->sig_array != NULL) {
        SCFree(sghid->sig_array);
        sghid->sig_array = NULL;
    }
    if (sghid->app_mpms != NULL) {
        SCFree(sghid->app_mpms);
    }
    if (sghid->pkt_mpms != NULL) {
        SCFree(sghid->pkt_mpms);
    }
    if (sghid->frame_mpms != NULL) {
        SCFree(sghid->frame_mpms);
    }

    PrefilterFreeEnginesList(sghid->tx_engines);
    PrefilterFreeEnginesList(sghid->pkt_engines);
    PrefilterFreeEnginesList(sghid->payload_engines);
    PrefilterFreeEnginesList(sghid->frame_engines);

    SCFree(sghid);
}

static SigGroupHeadInitData *SigGroupHeadInitDataAlloc(uint32_t size)
{
    SigGroupHeadInitData *sghid = SCMalloc(sizeof(SigGroupHeadInitData));
    if (unlikely(sghid == NULL))
        return NULL;

    memset(sghid, 0x00, sizeof(SigGroupHeadInitData));

    /* initialize the signature bitarray */
    sghid->sig_size = size;
    if ( (sghid->sig_array = SCMalloc(sghid->sig_size)) == NULL)
        goto error;

    memset(sghid->sig_array, 0, sghid->sig_size);

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
static SigGroupHead *SigGroupHeadAlloc(const DetectEngineCtx *de_ctx, uint32_t size)
{
    SigGroupHead *sgh = SCMalloc(sizeof(SigGroupHead));
    if (unlikely(sgh == NULL))
        return NULL;
    memset(sgh, 0, sizeof(SigGroupHead));

    sgh->init = SigGroupHeadInitDataAlloc(size);
    if (sgh->init == NULL)
        goto error;

    return sgh;

error:
    SigGroupHeadFree(de_ctx, sgh);
    return NULL;
}

/**
 * \brief Free a SigGroupHead and its members.
 *
 * \param sgh Pointer to the SigGroupHead that has to be freed.
 */
void SigGroupHeadFree(const DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL)
        return;

    SCLogDebug("sgh %p", sgh);

    if (sgh->non_pf_other_store_array != NULL) {
        SCFree(sgh->non_pf_other_store_array);
        sgh->non_pf_other_store_array = NULL;
        sgh->non_pf_other_store_cnt = 0;
    }

    if (sgh->non_pf_syn_store_array != NULL) {
        SCFree(sgh->non_pf_syn_store_array);
        sgh->non_pf_syn_store_array = NULL;
        sgh->non_pf_syn_store_cnt = 0;
    }

    if (sgh->init != NULL) {
        SigGroupHeadInitDataFree(sgh->init);
        sgh->init = NULL;
    }

    PrefilterCleanupRuleGroup(de_ctx, sgh);
    SCFree(sgh);

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
static uint32_t SigGroupHeadHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigGroupHead *sgh = (SigGroupHead *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    SCLogDebug("hashing sgh %p", sgh);

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
static char SigGroupHeadCompareFunc(void *data1, uint16_t len1, void *data2,
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
int SigGroupHeadAppendSig(const DetectEngineCtx *de_ctx, SigGroupHead **sgh,
                          const Signature *s)
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

    sgh->init->sig_cnt = 0;

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

    if (src->init->whitelist)
        (*dst)->init->whitelist = MAX((*dst)->init->whitelist, src->init->whitelist);

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

    sgh->init->sig_cnt = 0;
    for (sig = 0; sig < max_idx + 1; sig++) {
        if (sgh->init->sig_array[sig / 8] & (1 << (sig % 8)))
            sgh->init->sig_cnt++;
    }

    return;
}

void SigGroupHeadSetProtoAndDirection(SigGroupHead *sgh,
                                      uint8_t ipproto, int dir)
{
    if (sgh && sgh->init) {
        SCLogDebug("setting proto %u and dir %d on sgh %p", ipproto, dir, sgh);
        sgh->init->protos[ipproto] = 1;
        sgh->init->direction |= dir;
    }
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

    BUG_ON(sgh->init->match_array != NULL);

    sgh->init->match_array = SCMalloc(sgh->init->sig_cnt * sizeof(Signature *));
    if (sgh->init->match_array == NULL)
        return -1;

    memset(sgh->init->match_array, 0, sgh->init->sig_cnt * sizeof(Signature *));

    for (sig = 0; sig < max_idx + 1; sig++) {
        if (!(sgh->init->sig_array[(sig / 8)] & (1 << (sig % 8))) )
            continue;

        s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        sgh->init->match_array[idx] = s;
        idx++;
    }

    return 0;
}

/**
 *  \brief Set the need magic flag in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 */
void SigGroupHeadSetFilemagicFlag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
#ifdef HAVE_MAGIC
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFilemagicInspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILEMAGIC;
            break;
        }
    }
#endif
    return;
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

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
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
 *  \brief Set the need hash flag in the sgh.
 *
 *  \param de_ctx detection engine ctx for the signatures
 *  \param sgh sig group head to set the flag in
 */
void SigGroupHeadSetFileHashFlag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return;

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFileMd5Inspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILEMD5;
            SCLogDebug("sgh %p has filemd5", sgh);
            break;
        }

        if (SignatureIsFileSha1Inspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILESHA1;
            SCLogDebug("sgh %p has filesha1", sgh);
            break;
        }

        if (SignatureIsFileSha256Inspecting(s)) {
            sgh->flags |= SIG_GROUP_HEAD_HAVEFILESHA256;
            SCLogDebug("sgh %p has filesha256", sgh);
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

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureIsFilestoring(s)) {
            sgh->filestore_cnt++;
        }
    }

    return;
}

/** \brief build an array of rule id's for sigs with no prefilter
 *  Also updated de_ctx::non_pf_store_cnt_max to track the highest cnt
 */
int SigGroupHeadBuildNonPrefilterArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint32_t non_pf = 0;
    uint32_t non_pf_syn = 0;

    if (sgh == NULL)
        return 0;

    BUG_ON(sgh->non_pf_other_store_array != NULL);

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (!(s->flags & SIG_FLAG_PREFILTER) || (s->flags & SIG_FLAG_MPM_NEG)) {
            if (!(DetectFlagsSignatureNeedsSynPackets(s))) {
                non_pf++;
            }
            non_pf_syn++;
        }
    }

    if (non_pf == 0 && non_pf_syn == 0) {
        sgh->non_pf_other_store_array = NULL;
        sgh->non_pf_syn_store_array = NULL;
        return 0;
    }

    if (non_pf > 0) {
        sgh->non_pf_other_store_array = SCMalloc(non_pf * sizeof(SignatureNonPrefilterStore));
        BUG_ON(sgh->non_pf_other_store_array == NULL);
        memset(sgh->non_pf_other_store_array, 0, non_pf * sizeof(SignatureNonPrefilterStore));
    }

    if (non_pf_syn > 0) {
        sgh->non_pf_syn_store_array = SCMalloc(non_pf_syn * sizeof(SignatureNonPrefilterStore));
        BUG_ON(sgh->non_pf_syn_store_array == NULL);
        memset(sgh->non_pf_syn_store_array, 0, non_pf_syn * sizeof(SignatureNonPrefilterStore));
    }

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (!(s->flags & SIG_FLAG_PREFILTER) || (s->flags & SIG_FLAG_MPM_NEG)) {
            if (!(DetectFlagsSignatureNeedsSynPackets(s))) {
                BUG_ON(sgh->non_pf_other_store_cnt >= non_pf);
                BUG_ON(sgh->non_pf_other_store_array == NULL);
                sgh->non_pf_other_store_array[sgh->non_pf_other_store_cnt].id = s->num;
                sgh->non_pf_other_store_array[sgh->non_pf_other_store_cnt].mask = s->mask;
                sgh->non_pf_other_store_array[sgh->non_pf_other_store_cnt].alproto = s->alproto;
                sgh->non_pf_other_store_cnt++;
            }

            BUG_ON(sgh->non_pf_syn_store_cnt >= non_pf_syn);
            BUG_ON(sgh->non_pf_syn_store_array == NULL);
            sgh->non_pf_syn_store_array[sgh->non_pf_syn_store_cnt].id = s->num;
            sgh->non_pf_syn_store_array[sgh->non_pf_syn_store_cnt].mask = s->mask;
            sgh->non_pf_syn_store_array[sgh->non_pf_syn_store_cnt].alproto = s->alproto;
            sgh->non_pf_syn_store_cnt++;
        }
    }

    /* track highest cnt for any sgh in our de_ctx */
    uint32_t max = MAX(sgh->non_pf_other_store_cnt, sgh->non_pf_syn_store_cnt);
    if (max > de_ctx->non_pf_store_cnt_max)
        de_ctx->non_pf_store_cnt_max = max;

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
 * \test Check if a SigGroupHead hash table is properly allocated and
 *       deallocated when calling SigGroupHeadHashInit() and
 *       SigGroupHeadHashFree() respectively.
 */
static int SigGroupHeadTest01(void)
{
    DetectEngineCtx de_ctx;

    SigGroupHeadHashInit(&de_ctx);
    FAIL_IF_NULL(de_ctx.sgh_hash_table);

    SigGroupHeadHashFree(&de_ctx);
    FAIL_IF_NOT_NULL(de_ctx.sgh_hash_table);

    PASS;
}

/**
 * \test Check if a SigGroupHeadAppendSig() correctly appends a sid to a
 *       SigGroupHead() and SigGroupHeadContainsSigId() correctly indicates
 *       the presence of a sid.
 */
static int SigGroupHeadTest02(void)
{
    SigGroupHead *sh = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                                 "content:\"test2\"; content:\"test3\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:5;)");
    FAIL_IF_NULL(s);

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);

    FAIL_IF_NOT(sh->init->sig_cnt == 3);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 1) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 2) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 3) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 4) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 5) == 1);

    SigGroupHeadFree(de_ctx, sh);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Check if a SigGroupHeadAppendSig(), correctly appends a sid to a
 *       SigGroupHead() and SigGroupHeadContainsSigId(), correctly indicates
 *       the presence of a sid and SigGroupHeadClearSigs(), correctly clears
 *       the SigGroupHead->sig_array and SigGroupHead->sig_cnt.
 */
static int SigGroupHeadTest03(void)
{
    SigGroupHead *sh = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                                 "content:\"test2\"; content:\"test3\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:5;)");
    FAIL_IF_NULL(s);

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);

    FAIL_IF_NOT(sh->init->sig_cnt == 3);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 1) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 2) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 3) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 4) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 5) == 1);

    SigGroupHeadClearSigs(sh);

    FAIL_IF_NOT(sh->init->sig_cnt == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 1) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 2) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 3) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 4) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, sh, 5) == 0);

    SigGroupHeadFree(de_ctx, sh);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Check if SigGroupHeadCopySigs(), correctly copies the sig_array from
 *       the source to the destination SigGroupHead.
 */
static int SigGroupHeadTest04(void)
{
    SigGroupHead *src_sh = NULL;
    SigGroupHead *dst_sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                                 "content:\"test2\"; content:\"test3\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:5;)");
    FAIL_IF_NULL(s);

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &src_sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(src_sh, 4);

    FAIL_IF_NOT(src_sh->init->sig_cnt == 3);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, src_sh, 1) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, src_sh, 2) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, src_sh, 3) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, src_sh, 4) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, src_sh, 5) == 1);

    SigGroupHeadCopySigs(de_ctx, src_sh, &dst_sh);

    SigGroupHeadSetSigCnt(dst_sh, 4);

    FAIL_IF_NOT(dst_sh->init->sig_cnt == 3);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, dst_sh, 1) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, dst_sh, 2) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, dst_sh, 3) == 1);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, dst_sh, 4) == 0);
    FAIL_IF_NOT(SigGroupHeadContainsSigId(de_ctx, dst_sh, 5) == 1);

    SigGroupHeadFree(de_ctx, src_sh);
    SigGroupHeadFree(de_ctx, dst_sh);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Check if SigGroupHeadBuildMatchArray(), correctly updates the
 *       match array with the sids.
 */
static int SigGroupHeadTest05(void)
{
    SigGroupHead *sh = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                                 "content:\"test2\"; content:\"test3\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"SigGroupHead tests\"; content:\"test1\"; "
                                      "content:\"test2\"; content:\"test3\"; sid:5;)");
    FAIL_IF_NULL(s);

    SigAddressPrepareStage1(de_ctx);

    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next);
    SigGroupHeadAppendSig(de_ctx, &sh, de_ctx->sig_list->next->next->next->next);

    SigGroupHeadSetSigCnt(sh, 4);
    SigGroupHeadBuildMatchArray(de_ctx, sh, 4);

    /* matching an array to a queue structure (sig_list) constructed by SigInit()

    FAIL_IF_NOT(sh->init->match_array[0] == de_ctx->sig_list);
    FAIL_IF_NOT(sh->init->match_array[1] == de_ctx->sig_list->next->next);
    FAIL_IF_NOT(sh->init->match_array[2] == de_ctx->sig_list->next->next->next->next);
    */

    // matching an array to a stack structure (sig_list) constructed by DetectEngineAppendSig()
    FAIL_IF_NOT(sh->init->match_array[0] == de_ctx->sig_list->next->next->next->next);
    FAIL_IF_NOT(sh->init->match_array[1] == de_ctx->sig_list->next->next);
    FAIL_IF_NOT(sh->init->match_array[2] == de_ctx->sig_list);

    SigGroupHeadFree(de_ctx, sh);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test ICMP(?) sig grouping bug.
 */
static int SigGroupHeadTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;

    memset(&th_v, 0, sizeof(ThreadVars));

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_ICMP, "192.168.1.1", "1.2.3.4");
    FAIL_IF_NULL(p);

    p->icmpv4h->type = 5;
    p->icmpv4h->code = 1;

    /* originally ip's were
    p.src.addr_data32[0] = 0xe08102d3;
    p.dst.addr_data32[0] = 0x3001a8c0;
    */

    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert icmp 192.168.0.0/16 any -> any any "
                                                 "(icode:>1; itype:11; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> 192.168.0.0/16 any "
                                      "(icode:1; itype:5; sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    AddressDebugPrint(&p->dst);

    const SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, p);
    FAIL_IF_NULL(sgh);

    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);

    PASS;
}
#endif

void SigGroupHeadRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SigGroupHeadTest01", SigGroupHeadTest01);
    UtRegisterTest("SigGroupHeadTest02", SigGroupHeadTest02);
    UtRegisterTest("SigGroupHeadTest03", SigGroupHeadTest03);
    UtRegisterTest("SigGroupHeadTest04", SigGroupHeadTest04);
    UtRegisterTest("SigGroupHeadTest05", SigGroupHeadTest05);
    UtRegisterTest("SigGroupHeadTest06", SigGroupHeadTest06);
#endif
}
