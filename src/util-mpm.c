/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * Pattern matcher utility Functions
 */

#include "suricata-common.h"
#include "util-mpm.h"
#include "util-debug.h"

/* include pattern matchers */
#include "util-mpm-wumanber.h"
#include "util-mpm-b2g.h"
#include "util-mpm-b3g.h"
#include "util-mpm-ac.h"
#include "util-mpm-ac-gfbs.h"
#include "util-mpm-ac-bs.h"
#include "util-mpm-ac-tile.h"
#include "util-hashlist.h"

#include "detect-engine.h"
#include "util-cuda.h"
#include "util-misc.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "queue.h"
#include "util-unittest.h"
#ifdef __SC_CUDA_SUPPORT__
#include "util-cuda-handlers.h"
#include "detect-engine-mpm.h"
#endif

/**
 * \brief Register a new Mpm Context.
 *
 * \param name A new profile to be registered to store this MpmCtx.
 *
 * \retval id Return the id created for the new MpmCtx profile.
 */
int32_t MpmFactoryRegisterMpmCtxProfile(DetectEngineCtx *de_ctx, const char *name, uint8_t flags)
{
    void *ptmp;
    /* the very first entry */
    if (de_ctx->mpm_ctx_factory_container == NULL) {
        de_ctx->mpm_ctx_factory_container = SCMalloc(sizeof(MpmCtxFactoryContainer));
        if (de_ctx->mpm_ctx_factory_container == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(de_ctx->mpm_ctx_factory_container, 0, sizeof(MpmCtxFactoryContainer));

        MpmCtxFactoryItem *item = SCMalloc(sizeof(MpmCtxFactoryItem));
        if (unlikely(item == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        item[0].name = SCStrdup(name);
        if (item[0].name == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        /* toserver */
        item[0].mpm_ctx_ts = SCMalloc(sizeof(MpmCtx));
        if (item[0].mpm_ctx_ts == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(item[0].mpm_ctx_ts, 0, sizeof(MpmCtx));
        item[0].mpm_ctx_ts->global = 1;

        /* toclient */
        item[0].mpm_ctx_tc = SCMalloc(sizeof(MpmCtx));
        if (item[0].mpm_ctx_tc == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(item[0].mpm_ctx_tc, 0, sizeof(MpmCtx));
        item[0].mpm_ctx_tc->global = 1;

        /* our id starts from 0 always.  Helps us with the ctx retrieval from
         * the array */
        item[0].id = 0;

        /* store the flag */
        item[0].flags = flags;

        /* store the newly created item */
        de_ctx->mpm_ctx_factory_container->items = item;
        de_ctx->mpm_ctx_factory_container->no_of_items++;

        /* the first id is always 0 */
        return item[0].id;
    } else {
        int i;
        MpmCtxFactoryItem *items = de_ctx->mpm_ctx_factory_container->items;
        for (i = 0; i < de_ctx->mpm_ctx_factory_container->no_of_items; i++) {
            if (items[i].name != NULL && strcmp(items[i].name, name) == 0) {
                /* looks like we have this mpm_ctx freed */
                if (items[i].mpm_ctx_ts == NULL) {
                    items[i].mpm_ctx_ts = SCMalloc(sizeof(MpmCtx));
                    if (items[i].mpm_ctx_ts == NULL) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                        exit(EXIT_FAILURE);
                    }
                    memset(items[i].mpm_ctx_ts, 0, sizeof(MpmCtx));
                    items[i].mpm_ctx_ts->global = 1;
                }
                if (items[i].mpm_ctx_tc == NULL) {
                    items[i].mpm_ctx_tc = SCMalloc(sizeof(MpmCtx));
                    if (items[i].mpm_ctx_tc == NULL) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                        exit(EXIT_FAILURE);
                    }
                    memset(items[i].mpm_ctx_tc, 0, sizeof(MpmCtx));
                    items[i].mpm_ctx_tc->global = 1;
                }
                items[i].flags = flags;
                return items[i].id;
            }
        }

        /* let's make the new entry */
        ptmp = SCRealloc(items,
                         (de_ctx->mpm_ctx_factory_container->no_of_items + 1) * sizeof(MpmCtxFactoryItem));
        if (unlikely(ptmp == NULL)) {
            SCFree(items);
            items = NULL;
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        items = ptmp;

        de_ctx->mpm_ctx_factory_container->items = items;

        MpmCtxFactoryItem *new_item = &items[de_ctx->mpm_ctx_factory_container->no_of_items];
        new_item[0].name = SCStrdup(name);
        if (new_item[0].name == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        /* toserver */
        new_item[0].mpm_ctx_ts = SCMalloc(sizeof(MpmCtx));
        if (new_item[0].mpm_ctx_ts == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(new_item[0].mpm_ctx_ts, 0, sizeof(MpmCtx));
        new_item[0].mpm_ctx_ts->global = 1;

        /* toclient */
        new_item[0].mpm_ctx_tc = SCMalloc(sizeof(MpmCtx));
        if (new_item[0].mpm_ctx_tc == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(new_item[0].mpm_ctx_tc, 0, sizeof(MpmCtx));
        new_item[0].mpm_ctx_tc->global = 1;

        new_item[0].id = de_ctx->mpm_ctx_factory_container->no_of_items;
        new_item[0].flags = flags;
        de_ctx->mpm_ctx_factory_container->no_of_items++;

        /* the newly created id */
        return new_item[0].id;
    }
}

int32_t MpmFactoryIsMpmCtxAvailable(DetectEngineCtx *de_ctx, MpmCtx *mpm_ctx)
{
    if (mpm_ctx == NULL)
        return 0;

    if (de_ctx->mpm_ctx_factory_container == NULL) {
        return 0;
    } else {
        int i;
        for (i = 0; i < de_ctx->mpm_ctx_factory_container->no_of_items; i++) {
            if (mpm_ctx == de_ctx->mpm_ctx_factory_container->items[i].mpm_ctx_ts ||
                mpm_ctx == de_ctx->mpm_ctx_factory_container->items[i].mpm_ctx_tc) {
                return 1;
            }
        }
        return 0;
    }
}

MpmCtx *MpmFactoryGetMpmCtxForProfile(DetectEngineCtx *de_ctx, int32_t id, int direction)
{
    if (id == MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        MpmCtx *mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (unlikely(mpm_ctx == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(mpm_ctx, 0, sizeof(MpmCtx));
        return mpm_ctx;
    } else if (id < -1) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument - %d\n", id);
        return NULL;
    } else if (id >= de_ctx->mpm_ctx_factory_container->no_of_items) {
        /* this id does not exist */
        return NULL;
    } else {
        return (direction == 0) ?
            de_ctx->mpm_ctx_factory_container->items[id].mpm_ctx_ts :
            de_ctx->mpm_ctx_factory_container->items[id].mpm_ctx_tc;
    }
}

void MpmFactoryReClaimMpmCtx(DetectEngineCtx *de_ctx, MpmCtx *mpm_ctx)
{
    if (mpm_ctx == NULL)
        return;

    if (!MpmFactoryIsMpmCtxAvailable(de_ctx, mpm_ctx)) {
        if (mpm_ctx->mpm_type != MPM_NOTSET)
            mpm_table[mpm_ctx->mpm_type].DestroyCtx(mpm_ctx);
        SCFree(mpm_ctx);
    }

    return;
}

void MpmFactoryDeRegisterAllMpmCtxProfiles(DetectEngineCtx *de_ctx)
{
    if (de_ctx->mpm_ctx_factory_container == NULL)
        return;

    int i = 0;
    MpmCtxFactoryItem *items = de_ctx->mpm_ctx_factory_container->items;
    for (i = 0; i < de_ctx->mpm_ctx_factory_container->no_of_items; i++) {
        if (items[i].name != NULL)
            SCFree(items[i].name);
        if (items[i].mpm_ctx_ts != NULL) {
            if (items[i].mpm_ctx_ts->mpm_type != MPM_NOTSET)
                mpm_table[items[i].mpm_ctx_ts->mpm_type].DestroyCtx(items[i].mpm_ctx_ts);
            SCFree(items[i].mpm_ctx_ts);
        }
        if (items[i].mpm_ctx_tc != NULL) {
            if (items[i].mpm_ctx_tc->mpm_type != MPM_NOTSET)
                mpm_table[items[i].mpm_ctx_tc->mpm_type].DestroyCtx(items[i].mpm_ctx_tc);
            SCFree(items[i].mpm_ctx_tc);
        }
    }

    SCFree(de_ctx->mpm_ctx_factory_container->items);
    SCFree(de_ctx->mpm_ctx_factory_container);
    de_ctx->mpm_ctx_factory_container = NULL;

    return;
}

#ifdef __SC_CUDA_SUPPORT__

static void MpmCudaConfFree(void *conf)
{
    SCFree(conf);
    return;
}

static void *MpmCudaConfParse(ConfNode *node)
{
    const char *value;

    MpmCudaConf *conf = SCMalloc(sizeof(MpmCudaConf));
    if (unlikely(conf == NULL))
        exit(EXIT_FAILURE);
    memset(conf, 0, sizeof(*conf));

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "data-buffer-size-min-limit");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->data_buffer_size_min_limit = UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MIN_LIMIT_DEFAULT;
    } else if (ParseSizeStringU16(value, &conf->data_buffer_size_min_limit) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "data-buffer-size-min-limit - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "data-buffer-size-max-limit");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->data_buffer_size_max_limit = UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MAX_LIMIT_DEFAULT;
    } else if (ParseSizeStringU16(value, &conf->data_buffer_size_max_limit) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "data-buffer-size-max-limit - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "cudabuffer-buffer-size");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->cb_buffer_size = UTIL_MPM_CUDA_CUDA_BUFFER_DBUFFER_SIZE_DEFAULT;
    } else if (ParseSizeStringU32(value, &conf->cb_buffer_size) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "cb-buffer-size - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "gpu-transfer-size");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->gpu_transfer_size = UTIL_MPM_CUDA_GPU_TRANSFER_SIZE;
    } else if (ParseSizeStringU32(value, &conf->gpu_transfer_size) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "gpu-transfer-size - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "batching-timeout");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->batching_timeout = UTIL_MPM_CUDA_BATCHING_TIMEOUT_DEFAULT;
    } else if ((conf->batching_timeout = atoi(value)) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "batching-timeout - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "device-id");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->device_id = UTIL_MPM_CUDA_DEVICE_ID_DEFAULT;
    } else if ((conf->device_id = atoi(value)) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "device-id - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    if (node != NULL)
        value = ConfNodeLookupChildValue(node, "cuda-streams");
    else
        value = NULL;
    if (value == NULL) {
        /* default */
        conf->cuda_streams = UTIL_MPM_CUDA_CUDA_STREAMS_DEFAULT;
    } else if ((conf->cuda_streams = atoi(value)) < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for %s."
                   "cuda-streams - \"%s\"", node->name, value);
        exit(EXIT_FAILURE);
    }

    return conf;
}

void MpmCudaEnvironmentSetup()
{
    if (PatternMatchDefaultMatcher() != MPM_AC_CUDA)
        return;

    CudaHandlerAddCudaProfileFromConf("mpm", MpmCudaConfParse, MpmCudaConfFree);

    MpmCudaConf *conf = CudaHandlerGetCudaProfile("mpm");
    if (conf == NULL) {
        SCLogError(SC_ERR_AC_CUDA_ERROR, "Error obtaining cuda mpm "
                       "profile.");
        exit(EXIT_FAILURE);
    }

    if (MpmCudaBufferSetup() < 0) {
        SCLogError(SC_ERR_AC_CUDA_ERROR, "Error setting up env for ac "
                   "cuda");
        exit(EXIT_FAILURE);
    }

    return;
}

#endif

/**
 *  \brief Setup a pmq
 *
 *  \param pmq Pattern matcher queue to be initialized
 *  \param maxid Max sig id to be matched on
 *  \param patmaxid Max pattern id to be matched on
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int PmqSetup(PatternMatcherQueue *pmq, uint32_t patmaxid)
{
    SCEnter();
    SCLogDebug("patmaxid %u", patmaxid);

    if (pmq == NULL) {
        SCReturnInt(-1);
    }

    memset(pmq, 0, sizeof(PatternMatcherQueue));

    if (patmaxid > 0) {
        pmq->pattern_id_array_size = 32; /* Intial size, TODO Make this configure option */
        pmq->pattern_id_array_cnt = 0;

        pmq->pattern_id_array = SCCalloc(pmq->pattern_id_array_size, sizeof(uint32_t));
        if (pmq->pattern_id_array == NULL) {
            SCReturnInt(-1);
        }

        /* lookup bitarray */
        pmq->pattern_id_bitarray_size = (patmaxid / 8) + 1;

        pmq->pattern_id_bitarray = SCMalloc(pmq->pattern_id_bitarray_size);
        if (pmq->pattern_id_bitarray == NULL) {
            SCReturnInt(-1);
        }
        memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);

        SCLogDebug("pmq->pattern_id_array %p, pmq->pattern_id_bitarray %p",
                pmq->pattern_id_array, pmq->pattern_id_bitarray);

        pmq->rule_id_array_size = 128; /* Initial size, TODO: Make configure option. */
        pmq->rule_id_array_cnt = 0;

        size_t bytes = pmq->rule_id_array_size * sizeof(SigIntId);
        pmq->rule_id_array = (SigIntId*)SCMalloc(bytes);
        if (pmq->rule_id_array == NULL) {
            pmq->rule_id_array_size = 0;
            SCReturnInt(-1);
        }
        // Don't need to zero memory since it is always written first.
    }

    SCReturnInt(0);
}

/** \brief Add array of Signature IDs to rule ID array.
 *
 *   Checks size of the array first
 *
 *  \param pmq storage for match results
 *  \param new_size number of Signature IDs needing to be stored.
 *
 */
int
MpmAddSidsResize(PatternMatcherQueue *pmq, uint32_t new_size)
{
    /* Need to make the array bigger. Double the size needed to
     * also handle the case that sids_size might still be
     * larger than the old size.
     */
    new_size = new_size * 2;
    SigIntId *new_array = (SigIntId*)SCRealloc(pmq->rule_id_array,
                                               new_size * sizeof(SigIntId));
    if (unlikely(new_array == NULL)) {
        /* Try again just big enough. */
        new_size = new_size / 2;
        new_array = (SigIntId*)SCRealloc(pmq->rule_id_array,
                                         new_size * sizeof(SigIntId));
        if (unlikely(new_array == NULL)) {

            SCLogError(SC_ERR_MEM_ALLOC, "Failed to realloc PatternMatchQueue"
                       " rule ID array. Some signature ID matches lost");
            return 0;
        }
    }
    pmq->rule_id_array = new_array;
    pmq->rule_id_array_size = new_size;

    return new_size;
}

/** \brief Increase the size of the Pattern rule ID array.
 *
 *  \param pmq storage for match results
 *  \param new_size number of Signature IDs needing to be stored.
 *
 *  \return 0 on failure.
 */
int
MpmAddPidResize(PatternMatcherQueue *pmq, uint32_t new_size)
{
    /* Need to make the array bigger. Double the size needed to
     * also handle the case that sids_size might still be
     * larger than the old size.
     */
    new_size = new_size * 2;
    uint32_t *new_array = (uint32_t*)SCRealloc(pmq->pattern_id_array,
                                               new_size * sizeof(uint32_t));
    if (unlikely(new_array == NULL)) {
        // Failed to allocate 2x, so try 1x.
        new_size = new_size / 2;
        new_array = (uint32_t*)SCRealloc(pmq->pattern_id_array,
                                         new_size * sizeof(uint32_t));
        if (unlikely(new_array == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to realloc PatternMatchQueue"
                       " pattern ID array. Some new Pattern ID matches were lost.");
            return 0;
        }
    }
    pmq->pattern_id_array = new_array;
    pmq->pattern_id_array_size = new_size;

    return new_size;
}

/** \brief Verify and store a match
 *
 *   used at search runtime
 *
 *  \param thread_ctx mpm thread ctx
 *  \param pmq storage for match results
 *  \param patid pattern ID being checked
 *  \param bitarray Array of bits for patterns IDs found in current search
 *  \param sids pointer to array of Signature IDs
 *  \param sids_size number of Signature IDs in sids array.
 *
 *  \retval 0 no match after all
 *  \retval 1 (new) match
 */
int
MpmVerifyMatch(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, uint32_t patid,
               uint8_t *bitarray, SigIntId *sids, uint32_t sids_size)
{
    SCEnter();

    /* Handle pattern id storage */
    if (pmq != NULL && pmq->pattern_id_bitarray != NULL) {
        SCLogDebug("using pattern id arrays, storing %"PRIu32, patid);

        if ((bitarray[(patid / 8)] & (1<<(patid % 8))) == 0) {
            bitarray[(patid / 8)] |= (1<<(patid % 8));
            /* flag this pattern id as being added now */
            pmq->pattern_id_bitarray[(patid / 8)] |= (1<<(patid % 8));
            /* append the pattern_id to the array with matches */
            MpmAddPid(pmq, patid);
            MpmAddSids(pmq, sids, sids_size);
        }
    }

    SCReturnInt(1);
}

/**
 *  \brief Merge two pmq's bitarrays
 *
 *  \param src source pmq
 *  \param dst destination pmq to merge into
 */
void PmqMerge(PatternMatcherQueue *src, PatternMatcherQueue *dst)
{
    uint32_t u;

    if (src->pattern_id_array_cnt == 0)
        return;

    for (u = 0; u < src->pattern_id_bitarray_size && u < dst->pattern_id_bitarray_size; u++) {
        dst->pattern_id_bitarray[u] |= src->pattern_id_bitarray[u];
    }

    /** \todo now set merged flag? */

    if (src->rule_id_array && dst->rule_id_array) {
        MpmAddSids(dst, src->rule_id_array, src->rule_id_array_cnt);
    }
}

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 *  \todo memset is expensive, but we need it as we merge pmq's. We might use
 *        a flag so we can clear pmq's the old way if we can.
 */
void PmqReset(PatternMatcherQueue *pmq)
{
    if (pmq == NULL)
        return;

    memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);

    pmq->pattern_id_array_cnt = 0;

    pmq->rule_id_array_cnt = 0;
    /* TODO: Realloc the rule id array smaller at some size? */
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PatternMatcherQueue *pmq)
{
    if (pmq == NULL)
        return;

    if (pmq->pattern_id_array != NULL) {
        SCFree(pmq->pattern_id_array);
        pmq->pattern_id_array = NULL;
    }

    if (pmq->pattern_id_bitarray != NULL) {
        SCFree(pmq->pattern_id_bitarray);
        pmq->pattern_id_bitarray = NULL;
    }

    if (pmq->rule_id_array != NULL) {
        SCFree(pmq->rule_id_array);
        pmq->rule_id_array = NULL;
    }

    pmq->pattern_id_array_cnt = 0;
    pmq->pattern_id_array_size = 0;
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PatternMatcherQueue *pmq)
{
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher, uint32_t max_id)
{
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx, max_id);
}

void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher)
{
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx);
}

void MpmTableSetup(void)
{
    memset(mpm_table, 0, sizeof(mpm_table));

    MpmWuManberRegister();
    MpmB2gRegister();
    MpmB3gRegister();
    MpmACRegister();
    MpmACBSRegister();
    MpmACGfbsRegister();
    MpmACTileRegister();
#ifdef __SC_CUDA_SUPPORT__
    MpmACCudaRegister();
#endif /* __SC_CUDA_SUPPORT__ */
}

/** \brief  Function to return the default hash size for the mpm algorithm,
 *          which has been defined by the user in the config file
 *
 *  \param  conf_val    pointer to the string value of hash size
 *  \retval hash_value  returns the hash value as defined by user, otherwise
 *                      default low size value
 */
uint32_t MpmGetHashSize(const char *conf_val)
{
    SCEnter();
    uint32_t hash_value = HASHSIZE_LOW;

    if(strcmp(conf_val, "lowest") == 0) {
        hash_value = HASHSIZE_LOWEST;
    } else if(strcmp(conf_val, "low") == 0) {
        hash_value = HASHSIZE_LOW;
    } else if(strcmp(conf_val, "medium") == 0) {
        hash_value = HASHSIZE_MEDIUM;
    } else if(strcmp(conf_val, "high") == 0) {
        hash_value = HASHSIZE_HIGH;
    /* "highest" is supported in 1.0 to 1.0.2, so we keep supporting
     * it for backwards compatibility */
    } else if(strcmp(conf_val, "highest") == 0) {
        hash_value = HASHSIZE_HIGHER;
    } else if(strcmp(conf_val, "higher") == 0) {
        hash_value = HASHSIZE_HIGHER;
    } else if(strcmp(conf_val, "max") == 0) {
        hash_value = HASHSIZE_MAX;
    }

    SCReturnInt(hash_value);
}

/** \brief  Function to return the default bloomfilter size for the mpm algorithm,
 *          which has been defined by the user in the config file
 *
 *  \param  conf_val    pointer to the string value of bloom filter size
 *  \retval bloom_value returns the bloom filter value as defined by user,
 *                      otherwise default medium size value
 */
uint32_t MpmGetBloomSize(const char *conf_val)
{
    SCEnter();
    uint32_t bloom_value = BLOOMSIZE_MEDIUM;

    if(strncmp(conf_val, "low", 3) == 0) {
        bloom_value = BLOOMSIZE_LOW;
    } else if(strncmp(conf_val, "medium", 6) == 0) {
        bloom_value = BLOOMSIZE_MEDIUM;
    } else if(strncmp(conf_val, "high", 4) == 0) {
        bloom_value = BLOOMSIZE_HIGH;
    }

    SCReturnInt(bloom_value);
}

int MpmAddPatternCS(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags)
{
    return mpm_table[mpm_ctx->mpm_type].AddPattern(mpm_ctx, pat, patlen,
                                                   offset, depth,
                                                   pid, sid, flags);
}

int MpmAddPatternCI(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags)
{
    return mpm_table[mpm_ctx->mpm_type].AddPatternNocase(mpm_ctx, pat, patlen,
                                                         offset, depth,
                                                         pid, sid, flags);
}



/************************************Unittests*********************************/

#ifdef UNITTESTS
#endif /* UNITTESTS */

void MpmRegisterTests(void)
{
#ifdef UNITTESTS
    uint16_t i;

    for (i = 0; i < MPM_TABLE_SIZE; i++) {
        if (i == MPM_NOTSET)
            continue;

        g_ut_modules++;

        if (mpm_table[i].RegisterUnittests != NULL) {
            g_ut_covered++;
            mpm_table[i].RegisterUnittests();
        } else {
            if (coverage_unittests)
                SCLogWarning(SC_WARN_NO_UNITTESTS, "mpm module %s has no "
                        "unittest registration function.", mpm_table[i].name);
        }
    }

#endif
}
