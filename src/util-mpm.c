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
 * Pattern matcher utility Functions
 */

#include "suricata-common.h"
#include "util-mpm.h"
#include "util-debug.h"

/* include pattern matchers */
#include "util-mpm-ac.h"
#include "util-mpm-ac-bs.h"
#include "util-mpm-ac-ks.h"
#include "util-mpm-hs.h"
#include "util-hashlist.h"

#include "detect-engine.h"
#include "util-misc.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "queue.h"
#include "util-unittest.h"
#include "util-memcpy.h"
#ifdef BUILD_HYPERSCAN
#include "hs.h"
#endif

MpmTableElmt mpm_table[MPM_TABLE_SIZE];
uint8_t mpm_default_matcher;

/**
 * \brief Register a new Mpm Context.
 *
 * \param name A new profile to be registered to store this MpmCtx.
 * \param sm_list sm_list for this name (might be variable with xforms)
 *
 * \retval id Return the id created for the new MpmCtx profile.
 */
int32_t MpmFactoryRegisterMpmCtxProfile(
        DetectEngineCtx *de_ctx, const char *name, const int sm_list)
{
    /* the very first entry */
    if (de_ctx->mpm_ctx_factory_container == NULL) {
        de_ctx->mpm_ctx_factory_container = SCCalloc(1, sizeof(MpmCtxFactoryContainer));
        if (de_ctx->mpm_ctx_factory_container == NULL) {
            FatalError(SC_ERR_FATAL, "Error allocating memory");
        }
        de_ctx->mpm_ctx_factory_container->max_id = ENGINE_SGH_MPM_FACTORY_CONTEXT_START_ID_RANGE;
    }

    MpmCtxFactoryItem *item = de_ctx->mpm_ctx_factory_container->items;
    MpmCtxFactoryItem *pitem = NULL;
    while (item) {
        if (item->sm_list == sm_list && item->name != NULL && strcmp(item->name, name) == 0) {
            return item->id;
        }
        pitem = item;
        item = item->next;
    }

    MpmCtxFactoryItem *nitem = SCCalloc(1, sizeof(MpmCtxFactoryItem));
    if (unlikely(nitem == NULL)) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    nitem->name = name;
    nitem->sm_list = sm_list;
    nitem->id = de_ctx->mpm_ctx_factory_container->max_id++;

    /* toserver */
    nitem->mpm_ctx_ts = SCCalloc(1, sizeof(MpmCtx));
    if (nitem->mpm_ctx_ts == NULL) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    nitem->mpm_ctx_ts->flags |= MPMCTX_FLAGS_GLOBAL;

    /* toclient */
    nitem->mpm_ctx_tc = SCCalloc(1, sizeof(MpmCtx));
    if (nitem->mpm_ctx_tc == NULL) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
    }
    nitem->mpm_ctx_tc->flags |= MPMCTX_FLAGS_GLOBAL;

    /* store the newly created item */
    if (pitem == NULL)
        de_ctx->mpm_ctx_factory_container->items = nitem;
    else
        pitem->next = nitem;

    de_ctx->mpm_ctx_factory_container->no_of_items++;
    return nitem->id;
}

int32_t MpmFactoryIsMpmCtxAvailable(const DetectEngineCtx *de_ctx, const MpmCtx *mpm_ctx)
{
    if (mpm_ctx == NULL)
        return 0;

    if (de_ctx->mpm_ctx_factory_container == NULL) {
        return 0;
    }

    for (MpmCtxFactoryItem *i = de_ctx->mpm_ctx_factory_container->items; i != NULL; i = i->next) {
        if (mpm_ctx == i->mpm_ctx_ts || mpm_ctx == i->mpm_ctx_tc) {
            return 1;
        }
    }
    return 0;
}

MpmCtx *MpmFactoryGetMpmCtxForProfile(const DetectEngineCtx *de_ctx, int32_t id, int direction)
{
    if (id == MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        MpmCtx *mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (unlikely(mpm_ctx == NULL)) {
            FatalError(SC_ERR_FATAL, "Error allocating memory");
        }
        memset(mpm_ctx, 0, sizeof(MpmCtx));
        return mpm_ctx;
    } else if (id < -1) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument - %d\n", id);
        return NULL;
    } else if (id >= de_ctx->mpm_ctx_factory_container->max_id) {
        /* this id does not exist */
        return NULL;
    } else {
        for (MpmCtxFactoryItem *i = de_ctx->mpm_ctx_factory_container->items; i != NULL;
                i = i->next) {
            if (id == i->id) {
                return (direction == 0) ? i->mpm_ctx_ts : i->mpm_ctx_tc;
            }
        }
        return NULL;
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
}

void MpmFactoryDeRegisterAllMpmCtxProfiles(DetectEngineCtx *de_ctx)
{
    if (de_ctx->mpm_ctx_factory_container == NULL)
        return;

    MpmCtxFactoryItem *item = de_ctx->mpm_ctx_factory_container->items;
    while (item) {
        if (item->mpm_ctx_ts != NULL) {
            if (item->mpm_ctx_ts->mpm_type != MPM_NOTSET)
                mpm_table[item->mpm_ctx_ts->mpm_type].DestroyCtx(item->mpm_ctx_ts);
            SCFree(item->mpm_ctx_ts);
        }
        if (item->mpm_ctx_tc != NULL) {
            if (item->mpm_ctx_tc->mpm_type != MPM_NOTSET)
                mpm_table[item->mpm_ctx_tc->mpm_type].DestroyCtx(item->mpm_ctx_tc);
            SCFree(item->mpm_ctx_tc);
        }

        MpmCtxFactoryItem *next = item->next;
        SCFree(item);
        item = next;
    }

    SCFree(de_ctx->mpm_ctx_factory_container);
    de_ctx->mpm_ctx_factory_container = NULL;
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint8_t matcher)
{
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx);
}

void MpmInitCtx(MpmCtx *mpm_ctx, uint8_t matcher)
{
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx);
}

/* MPM matcher to use by default, i.e. when "mpm-algo" is set to "auto".
 * If Hyperscan is available, use it. Otherwise, use AC. */
#ifdef BUILD_HYPERSCAN
# define DEFAULT_MPM    MPM_HS
# define DEFAULT_MPM_AC MPM_AC
#else
# define DEFAULT_MPM    MPM_AC
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
static inline MpmPattern *MpmInitHashLookup(MpmCtx *ctx,
        uint8_t *pat, uint16_t patlen,
        uint16_t offset, uint16_t depth,
        uint8_t flags, uint32_t pid)
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
            if (t->len == patlen && t->offset == offset && t->depth == depth &&
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
        return -1;
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
    MpmPattern *p = MpmInitHashLookup(mpm_ctx, pat, patlen,
            offset, depth, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = MpmAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        p->offset = offset;
        p->depth = depth;
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
        if (MpmInitHashAdd(mpm_ctx, p) != 0)
            goto error;

        mpm_ctx->pattern_cnt++;

        if (!(mpm_ctx->flags & MPMCTX_FLAGS_NODEPTH)) {
            if (depth) {
                mpm_ctx->maxdepth = MAX(mpm_ctx->maxdepth, depth);
                SCLogDebug("%p: depth %u max %u", mpm_ctx, depth, mpm_ctx->maxdepth);
            } else {
                mpm_ctx->flags |= MPMCTX_FLAGS_NODEPTH;
                mpm_ctx->maxdepth = 0;
                SCLogDebug("%p: alas, no depth for us", mpm_ctx);
            }
        }

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
