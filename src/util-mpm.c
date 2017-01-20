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
#include "util-mpm-ac.h"
#include "util-mpm-ac-bs.h"
#include "util-mpm-ac-tile.h"
#include "util-mpm-hs.h"
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
#include "util-memcpy.h"
#ifdef BUILD_HYPERSCAN
#include "hs.h"
#endif

/**
 * \brief Register a new Mpm Context.
 *
 * \param name A new profile to be registered to store this MpmCtx.
 *
 * \retval id Return the id created for the new MpmCtx profile.
 */
int32_t MpmFactoryRegisterMpmCtxProfile(DetectEngineCtx *de_ctx, const char *name)
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

        item[0].name = name;

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
        new_item[0].name = name;

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
        de_ctx->mpm_ctx_factory_container->no_of_items++;

        /* the newly created id */
        return new_item[0].id;
    }
}

int32_t MpmFactoryIsMpmCtxAvailable(const DetectEngineCtx *de_ctx, const MpmCtx *mpm_ctx)
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

MpmCtx *MpmFactoryGetMpmCtxForProfile(const DetectEngineCtx *de_ctx, int32_t id, int direction)
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

void MpmFactoryReClaimMpmCtx(const DetectEngineCtx *de_ctx, MpmCtx *mpm_ctx)
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

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher)
{
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx);
}

void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher)
{
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx);
}

/* MPM matcher to use by default, i.e. when "mpm-algo" is set to "auto".
 * If Hyperscan is available, use it. Otherwise, use AC. */
#ifdef BUILD_HYPERSCAN
# define DEFAULT_MPM     MPM_HS
# ifdef __tile__
#  define DEFAULT_MPM_AC MPM_AC_TILE
# else
#  define DEFAULT_MPM_AC MPM_AC
# endif
#else
# ifdef __tile__
#  define DEFAULT_MPM    MPM_AC_TILE
# else
#  define DEFAULT_MPM    MPM_AC
# endif
#endif

void MpmTableSetup(void)
{
    memset(mpm_table, 0, sizeof(mpm_table));
    mpm_default_matcher = DEFAULT_MPM;

    MpmACRegister();
    MpmACBSRegister();
    MpmACTileRegister();
#ifdef BUILD_HYPERSCAN
    #ifdef HAVE_HS_VALID_PLATFORM
    /* Enable runtime check for SSSE3. Do not use Hyperscan MPM matcher if
     * check is not successful. */
        if (hs_valid_platform() != HS_SUCCESS) {
            SCLogInfo("SSSE3 support not detected, disabling Hyperscan for "
                      "MPM");
            /* Fall back to best Aho-Corasick variant. */
            mpm_default_matcher = DEFAULT_MPM_AC;
        } else {
            MpmHSRegister();
        }
    #else
        MpmHSRegister();
    #endif /* HAVE_HS_VALID_PLATFORM */
#endif /* BUILD_HYPERSCAN */
#ifdef __SC_CUDA_SUPPORT__
    MpmACCudaRegister();
#endif /* __SC_CUDA_SUPPORT__ */
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


/**
 * \internal
 * \brief Creates a hash of the pattern.  We use it for the hashing process
 *        during the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline uint32_t MpmInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % MPM_INIT_HASH_SIZE);
}

/**
 * \internal
 * \brief Looks up a pattern.  We use it for the hashing process during the
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param ctx    Pointer to the AC ctx.
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline MpmPattern *MpmInitHashLookup(MpmCtx *ctx, uint8_t *pat,
                                                  uint16_t patlen, char flags,
                                                  uint32_t pid)
{
    uint32_t hash = MpmInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL) {
        return NULL;
    }

    MpmPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (!(flags & MPM_PATTERN_CTX_OWNS_ID)) {
            if (t->id == pid)
                return t;
        } else {
            if (t->len == patlen &&
                    memcmp(pat, t->original_pat, patlen) == 0 &&
                    t->flags == flags)
            {
                return t;
            }
        }
    }

    return NULL;
}

/**
 * \internal
 * \brief Allocs a new pattern instance.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval p Pointer to the newly created pattern.
 */
static inline MpmPattern *MpmAllocPattern(MpmCtx *mpm_ctx)
{
    MpmPattern *p = SCMalloc(sizeof(MpmPattern));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(MpmPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(MpmPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free MpmPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the MpmPattern instance to be freed.
 */
void MpmFreePattern(MpmCtx *mpm_ctx, MpmPattern *p)
{
    if (p != NULL && p->cs != NULL && p->cs != p->ci) {
        SCFree(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->ci != NULL) {
        SCFree(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->original_pat != NULL) {
        SCFree(p->original_pat);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(MpmPattern);
    }
    return;
}

static inline uint32_t MpmInitHash(MpmPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % MPM_INIT_HASH_SIZE);
}

static inline int MpmInitHashAdd(MpmCtx *ctx, MpmPattern *p)
{
    uint32_t hash = MpmInitHash(p);

    if (ctx->init_hash == NULL) {
        return 0;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    MpmPattern *tt = NULL;
    MpmPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}

/**
 * \internal
 * \brief Add a pattern to the mpm-ac context.
 *
 * \param mpm_ctx Mpm context.
 * \param pat     Pointer to the pattern.
 * \param patlen  Length of the pattern.
 * \param pid     Pattern id
 * \param sid     Signature id (internal id).
 * \param flags   Pattern's MPM_PATTERN_* flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int MpmAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                            uint16_t offset, uint16_t depth, uint32_t pid,
                            SigIntId sid, uint8_t flags)
{
    SCLogDebug("Adding pattern for ctx %p, patlen %"PRIu16" and pid %" PRIu32,
               mpm_ctx, patlen, pid);

    if (patlen == 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "pattern length 0");
        return 0;
    }

    if (flags & MPM_PATTERN_CTX_OWNS_ID)
        pid = UINT_MAX;

    /* check if we have already inserted this pattern */
    MpmPattern *p = MpmInitHashLookup(mpm_ctx, pat, patlen, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = MpmAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        if (flags & MPM_PATTERN_CTX_OWNS_ID)
            p->id = mpm_ctx->max_pat_id++;
        else
            p->id = pid;

        p->original_pat = SCMalloc(patlen);
        if (p->original_pat == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->original_pat, pat, patlen);

        p->ci = SCMalloc(patlen);
        if (p->ci == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci, pat, p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL)
                    goto error;
                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;
                memcpy(p->cs, pat, patlen);
            }
        }

        /* put in the pattern hash */
        MpmInitHashAdd(mpm_ctx, p);

        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0) {
            mpm_ctx->minlen = patlen;
        } else {
            if (mpm_ctx->minlen > patlen)
                mpm_ctx->minlen = patlen;
        }

        /* we need the max pat id */
        if (p->id > mpm_ctx->max_pat_id)
            mpm_ctx->max_pat_id = p->id;

        p->sids_size = 1;
        p->sids = SCMalloc(p->sids_size * sizeof(SigIntId));
        BUG_ON(p->sids == NULL);
        p->sids[0] = sid;
    } else {
        /* we can be called multiple times for the same sid in the case
         * of the 'single' modus. Here multiple rule groups share the
         * same mpm ctx and might be adding the same pattern to the
         * mpm_ctx */
        int found = 0;
        uint32_t x = 0;
        for (x = 0; x < p->sids_size; x++) {
            if (p->sids[x] == sid) {
                found = 1;
                break;
            }
        }

        if (!found) {
            SigIntId *sids = SCRealloc(p->sids, (sizeof(SigIntId) * (p->sids_size + 1)));
            BUG_ON(sids == NULL);
            p->sids = sids;
            p->sids[p->sids_size] = sid;
            p->sids_size++;
        }
    }

    return 0;

error:
    MpmFreePattern(mpm_ctx, p);
    return -1;
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
