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
#include "util-mpm-b2g-cuda.h"
#include "util-mpm-b3g.h"
#include "util-mpm-b2gc.h"
#include "util-mpm-b2gm.h"
#include "util-mpm-ac.h"
#include "util-mpm-ac-gfbs.h"
#include "util-hashlist.h"

#include "detect-engine.h"
#include "util-cuda-handlers.h"
#include "util-cuda.h"
#include "util-misc.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "queue.h"
#include "util-unittest.h"

MpmCtxFactoryContainer *mpm_ctx_factory_container = NULL;

/**
 * \brief Register a new Mpm Context.
 *
 * \param name A new profile to be registered to store this MpmCtx.
 *
 * \retval id Return the id created for the new MpmCtx profile.
 */
int32_t MpmFactoryRegisterMpmCtxProfile(const char *name, uint8_t flags)
{
    /* the very first entry */
    if (mpm_ctx_factory_container == NULL) {
        mpm_ctx_factory_container = SCMalloc(sizeof(MpmCtxFactoryContainer));
        if (mpm_ctx_factory_container == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(mpm_ctx_factory_container, 0, sizeof(MpmCtxFactoryContainer));

        MpmCtxFactoryItem *item = SCMalloc(sizeof(MpmCtxFactoryItem));
        if (item == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        item[0].name = SCStrdup(name);
        if (item[0].name == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        item[0].mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (item[0].mpm_ctx == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(item[0].mpm_ctx, 0, sizeof(MpmCtx));

        /* our id starts from 0 always.  Helps us with the ctx retrieval from
         * the array */
        item[0].id = 0;

        /* store the flag */
        item[0].flags = flags;

        /* store the newly created item */
        mpm_ctx_factory_container->items = item;
        mpm_ctx_factory_container->no_of_items++;

        /* the first id is always 0 */
        return item[0].id;
    } else {
        int i;
        MpmCtxFactoryItem *items = mpm_ctx_factory_container->items;
        for (i = 0; i < mpm_ctx_factory_container->no_of_items; i++) {
            if (items[i].name != NULL && strcmp(items[i].name, name) == 0) {
                /* looks like we have this mpm_ctx freed */
                if (items[i].mpm_ctx == NULL) {
                    items[i].mpm_ctx = SCMalloc(sizeof(MpmCtx));
                    if (items[i].mpm_ctx == NULL) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                        exit(EXIT_FAILURE);
                    }
                    memset(items[i].mpm_ctx, 0, sizeof(MpmCtx));
                }
                items[i].flags = flags;
                return items[i].id;
            }
        }

        /* let's make the new entry */
        items = SCRealloc(items,
                          (mpm_ctx_factory_container->no_of_items + 1) * sizeof(MpmCtxFactoryItem));
        if (items == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        mpm_ctx_factory_container->items = items;

        MpmCtxFactoryItem *new_item = &items[mpm_ctx_factory_container->no_of_items];
        new_item[0].name = SCStrdup(name);
        if (new_item[0].name == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        new_item[0].mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (new_item[0].mpm_ctx == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(new_item[0].mpm_ctx, 0, sizeof(MpmCtx));

        new_item[0].id = mpm_ctx_factory_container->no_of_items;
        new_item[0].flags = flags;
        mpm_ctx_factory_container->no_of_items++;

        /* the newly created id */
        return new_item[0].id;
    }
}

int32_t MpmFactoryIsMpmCtxAvailable(MpmCtx *mpm_ctx)
{
    if (mpm_ctx == NULL)
        return 0;

    if (mpm_ctx_factory_container == NULL) {
        return 0;
    } else {
        int i;
        for (i = 0; i < mpm_ctx_factory_container->no_of_items; i++) {
            if (mpm_ctx == mpm_ctx_factory_container->items[i].mpm_ctx)
                return 1;
        }
        return 0;
    }
}

MpmCtx *MpmFactoryGetMpmCtxForProfile(int32_t id)
{
    if (id == MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        MpmCtx *mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (mpm_ctx == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memset(mpm_ctx, 0, sizeof(MpmCtx));
        return mpm_ctx;
    } else if (id < -1) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument - %d\n", id);
        return NULL;
    } else if (id >= mpm_ctx_factory_container->no_of_items) {
        /* this id does not exist */
        return NULL;
    } else {
        return mpm_ctx_factory_container->items[id].mpm_ctx;
    }
}

void MpmFactoryReClaimMpmCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx == NULL)
        return;

    if (!MpmFactoryIsMpmCtxAvailable(mpm_ctx))
        SCFree(mpm_ctx);

    return;
}

void MpmFactoryDeRegisterAllMpmCtxProfiles(void)
{
    if (mpm_ctx_factory_container == NULL)
        return;

    int i = 0;
    MpmCtxFactoryItem *items = mpm_ctx_factory_container->items;
    for (i = 0; i < mpm_ctx_factory_container->no_of_items; i++) {
        if (items[i].name != NULL)
            SCFree(items[i].name);
        if (items[i].mpm_ctx != NULL)
            SCFree(items[i].mpm_ctx);
    }

    SCFree(mpm_ctx_factory_container->items);
    SCFree(mpm_ctx_factory_container);
    mpm_ctx_factory_container = NULL;

    return;
}

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
int PmqSetup(PatternMatcherQueue *pmq, uint32_t sig_maxid, uint32_t patmaxid) {
    SCEnter();
    SCLogDebug("sig_maxid %u, patmaxid %u", sig_maxid, patmaxid);

    if (pmq == NULL) {
        SCReturnInt(-1);
    }

    memset(pmq, 0, sizeof(PatternMatcherQueue));

    if (patmaxid > 0) {
        pmq->pattern_id_array_size = patmaxid * sizeof(uint32_t);

        pmq->pattern_id_array = SCMalloc(pmq->pattern_id_array_size);
        if (pmq->pattern_id_array == NULL) {
            SCReturnInt(-1);
        }
        memset(pmq->pattern_id_array, 0, pmq->pattern_id_array_size);
        pmq->pattern_id_array_cnt = 0;

        /* lookup bitarray */
        pmq->pattern_id_bitarray_size = (patmaxid / 8) + 1;

        pmq->pattern_id_bitarray = SCMalloc(pmq->pattern_id_bitarray_size);
        if (pmq->pattern_id_bitarray == NULL) {
            SCReturnInt(-1);
        }
        memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);

        SCLogDebug("pmq->pattern_id_array %p, pmq->pattern_id_bitarray %p",
                pmq->pattern_id_array, pmq->pattern_id_bitarray);
    }

    SCReturnInt(0);
}

/** \brief Verify and store a match
 *
 *   used at search runtime
 *
 *  \param thread_ctx mpm thread ctx
 *  \param pmq storage for match results
 *  \param list end match to check against (entire list will be checked)
 *  \param offset match offset in the buffer
 *  \param patlen length of the pattern we're checking
 *
 *  \retval 0 no match after all
 *  \retval 1 (new) match
 */
int
MpmVerifyMatch(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, uint32_t patid)
{
    SCEnter();

    /* Handle pattern id storage */
    if (pmq != NULL && pmq->pattern_id_bitarray != NULL) {
        SCLogDebug("using pattern id arrays, storing %"PRIu32, patid);

        if (!(pmq->pattern_id_bitarray[(patid / 8)] & (1<<(patid % 8)))) {
            /* flag this pattern id as being added now */
            pmq->pattern_id_bitarray[(patid / 8)] |= (1<<(patid % 8));
            /* append the pattern_id to the array with matches */
            pmq->pattern_id_array[pmq->pattern_id_array_cnt] = patid;
            pmq->pattern_id_array_cnt++;
            SCLogDebug("pattern_id_array_cnt %u", pmq->pattern_id_array_cnt);
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
void PmqMerge(PatternMatcherQueue *src, PatternMatcherQueue *dst) {
    uint32_t u;

    if (src->pattern_id_array_cnt == 0)
        return;

    for (u = 0; u < src->pattern_id_bitarray_size && u < dst->pattern_id_bitarray_size; u++) {
        dst->pattern_id_bitarray[u] |= src->pattern_id_bitarray[u];
    }

    /** \todo now set merged flag? */
}

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 *  \todo memset is expensive, but we need it as we merge pmq's. We might use
 *        a flag so we can clear pmq's the old way if we can.
 */
void PmqReset(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);
    //memset(pmq->pattern_id_array, 0, pmq->pattern_id_array_size);
    pmq->pattern_id_array_cnt = 0;
/*
    uint32_t u;
    for (u = 0; u < pmq->pattern_id_array_cnt; u++) {
        pmq->pattern_id_bitarray[(pmq->pattern_id_array[u] / 8)] &= ~(1<<(pmq->pattern_id_array[u] % 8));
    }
    pmq->pattern_id_array_cnt = 0;
*/
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PatternMatcherQueue *pmq) {
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

    pmq->pattern_id_array_cnt = 0;
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
}

/**
 * \brief Return the pattern max length of a registered matcher
 * \retval 0 if it has no limit
 * \retval max_pattern_length of the specified matcher type
 * \retval -1 if the type is not registered return -1
 */
int32_t MpmMatcherGetMaxPatternLength(uint16_t matcher) {
    if (matcher < MPM_TABLE_SIZE)
        return mpm_table[matcher].max_pattern_length;
    else
        return -1;
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher, uint32_t max_id) {
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx, max_id);
}

void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher, int module_handle) {
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx, module_handle);
}

void MpmTableSetup(void) {
    memset(mpm_table, 0, sizeof(mpm_table));

    MpmWuManberRegister();
    MpmB2gRegister();
#ifdef __SC_CUDA_SUPPORT__
    MpmB2gCudaRegister();
#endif
    MpmB3gRegister();
    MpmB2gcRegister();
    MpmB2gmRegister();
    MpmACRegister();
    MpmACGfbsRegister();
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


#ifdef __SC_CUDA_SUPPORT__

/**
 * \brief Parse the "mpm" profile under the cuda subsection of our conf file.
 *
 * \retval profile Pointer to a struct containing the parsed data.
 */
MpmCudaConf *MpmCudaConfParse(void)
{
    ConfNode *cuda_node = NULL;
    ConfNode *seq_node = NULL;

    MpmCudaConf *profile = NULL;

    const char *packet_buffer_limit = NULL;
    const char *packet_size_limit = NULL;
    const char *packet_buffers = NULL;
    const char *batching_timeout = NULL;
    const char *page_locked = NULL;
    const char *device_id = NULL;
    const char *cuda_streams = NULL;

    if ((profile = SCMalloc(sizeof(MpmCudaConf))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(profile, 0, sizeof(MpmCudaConf));
    profile->packet_buffer_limit = MPM_PACKET_BUFFER_LIMIT;
    profile->packet_size_limit = MPM_PACKET_SIZE_LIMIT;
    profile->packet_buffers = MPM_PACKET_BUFFERS;
    profile->batching_timeout = MPM_BATCHING_TIMEOUT;
    profile->page_locked = MPM_PAGE_LOCKED;
    profile->device_id = SC_CUDA_DEFAULT_DEVICE;
    profile->cuda_streams = MPM_CUDA_STREAMS;

    cuda_node = ConfGetNode("cuda");
    if (cuda_node == NULL) {
        SCLogInfo("No conf found for \"cuda\" in yaml file.  Use default conf");
        goto end;
    }

    TAILQ_FOREACH(seq_node, &cuda_node->head, next) {
        if (strcasecmp(seq_node->val, "mpm") == 0) {
            packet_buffer_limit = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "packet_buffer_limit");
            packet_size_limit = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "packet_size_limit");
            packet_buffers = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "packet_buffers");
            batching_timeout = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "batching_timeout");
            page_locked = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "page_locked");
            device_id = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "device_id");
            cuda_streams = ConfNodeLookupChildValue
                (seq_node->head.tqh_first, "cuda_streams");

            /* packet_buffer_size */
            if (packet_buffer_limit == NULL || strcasecmp(packet_buffer_limit, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.packet_buffer_limit.  Either NULL or empty");
            } else {
                profile->packet_buffer_limit = atoi(packet_buffer_limit);
                if (profile->packet_buffer_limit <= 0) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.packet_buffer_limit - %s", packet_buffer_limit);
                    profile->packet_buffer_limit = MPM_PACKET_BUFFER_LIMIT;
                }
            }

            /* packet_size_limit */
            if (packet_size_limit == NULL || strcasecmp(packet_size_limit, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.packet_size_limit.  Either NULL or empty");
            } else {
                if (ParseSizeStringU16(packet_size_limit, &profile->packet_size_limit) < 0) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.packet_size_limit - %s", packet_size_limit);
                    exit(EXIT_FAILURE);
                }

                if (profile->packet_size_limit <= 0) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.packet_size_limit - %s", packet_size_limit);
                    profile->packet_size_limit = MPM_PACKET_SIZE_LIMIT;
                }
            }

            /* packet_buffers */
            if (packet_buffers == NULL || strcasecmp(packet_buffers, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.packet_buffers.  Either NULL or empty");
            } else {
                profile->packet_buffers = atoi(packet_buffers);
                if (profile->packet_buffers <= 0) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.packet_buffers - %s", packet_buffers);
                    profile->packet_buffers = MPM_PACKET_BUFFERS;
                }
            }

            /* batching_timeout */
            if (batching_timeout == NULL || strcasecmp(batching_timeout, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.batching_timeout.  Either NULL or empty");
            } else {
                profile->batching_timeout = atof(batching_timeout);
                if (profile->batching_timeout < 0.000001) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.batching_timeout - %s", batching_timeout);
                    profile->batching_timeout = MPM_BATCHING_TIMEOUT;
                }
            }

            /* page_locked */
            if (page_locked == NULL || strcasecmp(page_locked, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.page_locked.  Either NULL or empty");
            } else {
                if (strcasecmp(page_locked, "enabled") == 0) {
                    profile->page_locked = MPM_PAGE_LOCKED;
                } else if (strcasecmp(page_locked, "disabled") == 0) {
                    profile->page_locked = !MPM_PAGE_LOCKED;
                } else {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.page_locked - %s", page_locked);
                }
            }

            /* device_id */
            if (device_id == NULL || strcasecmp(device_id, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                           "cuda.mpm.device_id  Either NULL or empty");
                profile->device_id = SC_CUDA_DEFAULT_DEVICE;
                continue;
            } else {
                profile->device_id = atoi(device_id);
                if (profile->device_id < 0) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                               "cuda.mpm.device_id - %s", device_id);
                    profile->device_id = SC_CUDA_DEFAULT_DEVICE;
                    continue;
                }
            }

            /* cuda_streams */
            if (cuda_streams == NULL || strcasecmp(cuda_streams, "") == 0) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                        "cuda.mpm.cuda_streams  Either NULL or empty");
                profile->cuda_streams = MPM_CUDA_STREAMS;
                continue;
            } else {
                profile->cuda_streams = atoi(cuda_streams);
                if (profile->cuda_streams < 1) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                            "cuda.mpm.cuda_streams - %s", cuda_streams);
                    profile->cuda_streams = MPM_CUDA_STREAMS;
                    continue;
                }
            }
        } /* if (strcasecmp(seq_node->val, "mpm") == 0) */
    } /* TAILQ_FOREACH(seq_node, &cuda_node->head, next) */

 end:
    SCLogDebug("Configuration for \"cuda.mpm\"\n"
               "packet_buffer_size: %u\n"
               "packet_size_limit: %d\n"
               "packet_buffers: %d\n"
               "batching_timeout: %d\n"
               "page_locked: %d\n"
               "device_id: %d\n",
               profile->packet_buffer_limit, profile->packet_size_limit,
               profile->packet_buffers, profile->batching_timeout,
               profile->page_locked, profile->device_id);

    return profile;
}

/**
 * \brief Cleanup the parsed "mpm" profile cuda conf.
 */
void MpmCudaConfCleanup(MpmCudaConf *conf)
{
    if (conf != NULL)
        SCFree(conf);

    return;
}

#endif /* __SC_CUDA_SUPPORT */

/************************************Unittests*********************************/

#ifdef UNITTESTS
#ifdef __SC_CUDA_SUPPORT__

static int MpmInitYamlConf(char *conf)
{
    ConfCreateContextBackup();
    ConfInit();
    return ConfYamlLoadString(conf, strlen(conf));
}

static void MpmDeInitYamlConf(void)
{
    ConfDeInit();
    ConfRestoreContextBackup();

    return;
}

static int MpmTest01(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit: 4000\n"
        "      packet_size_limit: 1500\n"
        "      packet_buffers: 10\n"
        "      batching_timeout: 1\n"
        "      page_locked: enabled\n"
        "      device_id: 0\n"
        "      cuda_streams: 2\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == 4000);
    result &= (profile->packet_size_limit == 1500);
    result &= (profile->packet_buffers == 10);
    result &= (profile->batching_timeout == 1);
    result &= (profile->page_locked == 1);
    result &= (profile->device_id == 0);
    result &= (profile->cuda_streams == 2);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest02(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit: 4001\n"
        "      packet_size_limit: 1500\n"
        "      packet_buffers: 12\n"
        "      batching_timeout: 10\n"
        "      page_locked: disabled\n"
        "      device_id: 5\n"
        "      cuda_streams: 4\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == 4001);
    result &= (profile->packet_size_limit == 1500);
    result &= (profile->packet_buffers == 12);
    result &= (profile->batching_timeout == 10);
    result &= (profile->page_locked == 0);
    result &= (profile->device_id == 5);
    result &= (profile->cuda_streams == 4);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest03(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit: 0\n"
        "      packet_size_limit: 0\n"
        "      packet_buffers: 0\n"
        "      batching_timeout: 0\n"
        "      page_locked: enbled\n"
        "      device_id: -1\n"
        "      cuda_streams: -1\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest04(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit: -1\n"
        "      packet_size_limit: -1\n"
        "      packet_buffers: -1\n"
        "      batching_timeout: -1\n"
        "      page_locked: enbled\n"
        "      device_id: -1\n"
        "      cuda_streams: -1\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest05(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit:\n"
        "      packet_size_limit:\n"
        "      packet_buffers:\n"
        "      batching_timeout: 2\n"
        "      page_locked: enabled\n"
        "      device_id: 1\n"
        "      cuda_streams: 0\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == 2);
    result &= (profile->page_locked == 1);
    result &= (profile->device_id == 1);
    result &= (profile->cuda_streams == 0);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest06(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit: \n"
        "      packet_size_limit: \n"
        "      packet_buffers: \n"
        "      batching_timeout: \n"
        "      page_locked: \n"
        "      device_id: \n"
        "      cuda_streams: \n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest07(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_buffer_limit:\n"
        "      packet_size_limit:\n"
        "      packet_buffers:\n"
        "      batching_timeout:\n"
        "      page_locked:\n"
        "      device_id:\n"
        "      cuda_streams:\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest08(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n"
        "      packet_size_limit: 2000\n"
        "      page_locked: disabled\n"
        "      device_id: 4\n"
        "      cuda_streams: 8\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == 2000);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == !MPM_PAGE_LOCKED);
    result &= (profile->device_id == 4);
    result &= (profile->cuda_streams == 8);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest09(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n"
        "  - mpm:\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest10(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "cuda:\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

static int MpmTest11(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (MpmInitYamlConf(conf) == -1)
        return 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCCudaHlBackupRegisteredProfiles();
    SCCudaHlGetYamlConf();
    MpmCudaConf *profile = SCCudaHlGetProfile("mpm");
    if (profile == NULL) {
        printf("Error retrieving mpm profile\n");
        goto end;
    }

    result = (profile->packet_buffer_limit == MPM_PACKET_BUFFER_LIMIT);
    result &= (profile->packet_size_limit == MPM_PACKET_SIZE_LIMIT);
    result &= (profile->packet_buffers == MPM_PACKET_BUFFERS);
    result &= (profile->batching_timeout == MPM_BATCHING_TIMEOUT);
    result &= (profile->page_locked == MPM_PAGE_LOCKED);
    result &= (profile->device_id == SC_CUDA_DEFAULT_DEVICE);
    result &= (profile->cuda_streams == MPM_CUDA_STREAMS);

 end:
    SCCudaHlCleanProfiles();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    MpmDeInitYamlConf();
    SCCudaHlRestoreBackupRegisteredProfiles();

    return result;
}

#endif /* __SC_CUDA_SUPPORT__ */
#endif /* UNITTESTS */

void MpmRegisterTests(void) {
#ifdef UNITTESTS
    uint16_t i;

    for (i = 0; i < MPM_TABLE_SIZE; i++) {
        if (mpm_table[i].RegisterUnittests != NULL) {
            mpm_table[i].RegisterUnittests();
        } else {
            printf("Warning: mpm %s has no unittest registration function...", mpm_table[i].name);
        }
    }

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("MpmTest01", MpmTest01, 1);
    UtRegisterTest("MpmTest02", MpmTest02, 1);
    UtRegisterTest("MpmTest03", MpmTest03, 1);
    UtRegisterTest("MpmTest04", MpmTest04, 1);
    UtRegisterTest("MpmTest05", MpmTest05, 1);
    UtRegisterTest("MpmTest06", MpmTest06, 1);
    UtRegisterTest("MpmTest07", MpmTest07, 1);
    UtRegisterTest("MpmTest08", MpmTest08, 1);
    UtRegisterTest("MpmTest09", MpmTest09, 1);
    UtRegisterTest("MpmTest10", MpmTest10, 1);
    UtRegisterTest("MpmTest11", MpmTest11, 1);
#endif /* __SC_CUDA_SUPPORT__ */

#endif
}
