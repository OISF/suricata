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

/**
 *  \brief Setup a pmq
 *
 *  \param pmq Pattern matcher queue to be initialized
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int PmqSetup(PrefilterRuleStore *pmq)
{
    SCEnter();

    if (pmq == NULL) {
        SCReturnInt(-1);
    }

    memset(pmq, 0, sizeof(PrefilterRuleStore));

    pmq->rule_id_array_size = 128; /* Initial size, TODO: Make configure option. */
    pmq->rule_id_array_cnt = 0;

    size_t bytes = pmq->rule_id_array_size * sizeof(SigIntId);
    pmq->rule_id_array = (SigIntId*)SCMalloc(bytes);
    if (pmq->rule_id_array == NULL) {
        pmq->rule_id_array_size = 0;
        SCReturnInt(-1);
    }
    // Don't need to zero memory since it is always written first.

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
PrefilterAddSidsResize(PrefilterRuleStore *pmq, uint32_t new_size)
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

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 *  \todo memset is expensive, but we need it as we merge pmq's. We might use
 *        a flag so we can clear pmq's the old way if we can.
 */
void PmqReset(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;

    pmq->rule_id_array_cnt = 0;
    /* TODO: Realloc the rule id array smaller at some size? */
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;
    if (pmq->rule_id_array != NULL) {
        SCFree(pmq->rule_id_array);
        pmq->rule_id_array = NULL;
    }
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
}
