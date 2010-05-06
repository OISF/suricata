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
#include "util-hashlist.h"

/** \brief Setup a pmq
  * \param pmq Pattern matcher queue to be initialized
  * \param maxid Max id to be matched on
  * \retval -1 error
  * \retval 0 ok
  */
int PmqSetup(PatternMatcherQueue *pmq, uint32_t maxid) {
    SCEnter();
    SCLogDebug("maxid %u", maxid);

    if (pmq == NULL) {
        SCReturnInt(-1);
    }

    memset(pmq, 0, sizeof(PatternMatcherQueue));

    if (maxid == 0) {
        SCReturnInt(0);
    }

    pmq->sig_id_array = SCMalloc(maxid * sizeof(uint32_t));
    if (pmq->sig_id_array == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory alloc failed");
        SCReturnInt(-1);
    }
    memset(pmq->sig_id_array, 0, maxid * sizeof(uint32_t));
    pmq->sig_id_array_cnt = 0;

    /* lookup bitarray */
    pmq->sig_bitarray = SCMalloc(maxid / 8 + 1);
    if (pmq->sig_bitarray == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory alloc failed");
        SCReturnInt(-1);
    }
    memset(pmq->sig_bitarray, 0, maxid / 8 + 1);

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
MpmVerifyMatch(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, MpmEndMatch *list, uint16_t offset, uint16_t patlen)
{
    SCEnter();

    MpmEndMatch *em = list;
    int ret = 0;

    for ( ; em != NULL; em = em->next) {
        SCLogDebug("em->sig_id %u", em->sig_id);

        /* check offset */
        if (offset < em->offset)
            continue;

        /* check depth */
        if (em->depth && (offset+patlen) > em->depth)
            continue;

        if (pmq != NULL) {
            /* make sure we only append a sig with a matching pattern once,
             * so we won't inspect it more than once. For this we keep a
             * bitarray of sig internal id's and flag each sig that matched */
            if (!(pmq->sig_bitarray[(em->sig_id / 8)] & (1<<(em->sig_id % 8)))) {
                /* flag this sig_id as being added now */
                pmq->sig_bitarray[(em->sig_id / 8)] |= (1<<(em->sig_id % 8));
                /* append the sig_id to the array with matches */
                pmq->sig_id_array[pmq->sig_id_array_cnt] = em->sig_id;
                pmq->sig_id_array_cnt++;
            }

            /* nosearch flag */
            if (!(em->flags & MPM_ENDMATCH_NOSEARCH)) {
                pmq->searchable++;
            }
        }

        ret++;
    }

    SCReturnInt(ret);
}

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 */
void PmqReset(PatternMatcherQueue *pmq) {
    uint32_t u;
    for (u = 0; u < pmq->sig_id_array_cnt; u++) {
        pmq->sig_bitarray[(pmq->sig_id_array[u] / 8)] &= ~(1<<(pmq->sig_id_array[u] % 8));
    }
    pmq->sig_id_array_cnt = 0;
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    if (pmq->sig_id_array != NULL) {
        SCFree(pmq->sig_id_array);
        pmq->sig_id_array = NULL;
    }

    if (pmq->sig_bitarray != NULL) {
        SCFree(pmq->sig_bitarray);
        pmq->sig_bitarray = NULL;
    }

    pmq->sig_id_array_cnt = 0;
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
    SCFree(pmq);
}

/* allocate an endmatch
 *
 * Only used in the initialization phase */
MpmEndMatch *MpmAllocEndMatch (MpmCtx *ctx)
{
    MpmEndMatch *e = SCMalloc(sizeof(MpmEndMatch));
    if (e == NULL)
        return NULL;

    memset(e, 0, sizeof(MpmEndMatch));

    ctx->memory_cnt++;
    ctx->memory_size += sizeof(MpmEndMatch);
    ctx->endmatches++;
    return e;
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

void MpmEndMatchFree(MpmCtx *ctx, MpmEndMatch *em) {
    ctx->memory_cnt--;
    ctx->memory_size -= sizeof(MpmEndMatch);
    SCFree(em);
}

void MpmEndMatchFreeAll(MpmCtx *mpm_ctx, MpmEndMatch *em) {
    while(em) {
        MpmEndMatch *tem = em->next;
        MpmEndMatchFree(mpm_ctx, em);
        em = tem;
    }
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

    if(strncmp(conf_val, "lowest", 6) == 0) {
        hash_value = HASHSIZE_LOWEST;
    } else if(strncmp(conf_val, "low", 3) == 0) {
        hash_value = HASHSIZE_LOW;
    } else if(strncmp(conf_val, "medium", 6) == 0) {
        hash_value = HASHSIZE_MEDIUM;
    } else if(strncmp(conf_val, "high", 4) == 0) {
        hash_value = HASHSIZE_HIGH;
    } else if(strncmp(conf_val, "highest", 7) == 0) {
        hash_value = HASHSIZE_HIGHEST;
    } else if(strncmp(conf_val, "max", 3) == 0) {
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
#endif
}

