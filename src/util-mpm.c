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

