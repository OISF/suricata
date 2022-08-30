/* Copyright (C) 2016-2022 Open Information Security Foundation
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
 */

#ifndef __UTIL_PREFILTER_H__
#define __UTIL_PREFILTER_H__

/** \brief structure for storing potential rule matches
 *
 *  Helper structure for the prefilter engine. The Pattern Matchers
 *  and other prefilter engines will add rule id's for potential
 *  rule matches */
typedef struct PrefilterRuleStore_ {
    /* used for storing rule id's */

    /* Array of rule IDs found. */
    SigIntId *rule_id_array;
    /* Number of rule IDs in the array. */
    uint32_t rule_id_array_cnt;
    /* The number of slots allocated for storing rule IDs */
    uint32_t rule_id_array_size;

} PrefilterRuleStore;

#define PMQ_RESET(pmq) (pmq)->rule_id_array_cnt = 0

/* Resize Signature ID array. Only called from MpmAddSids(). */
int PrefilterAddSidsResize(PrefilterRuleStore *pmq, uint32_t new_size);

/** \brief Add array of Signature IDs to rule ID array.
 *
 *   Checks size of the array first. Calls PrefilterAddSidsResize to increase
 *   The size of the array, since that is the slow path.
 *
 *  \param pmq storage for match results
 *  \param sids pointer to array of Signature IDs
 *  \param sids_size number of Signature IDs in sids array.
 *
 */
static inline void
PrefilterAddSids(PrefilterRuleStore *pmq, SigIntId *sids, uint32_t sids_size)
{
    if (sids_size == 0)
        return;

    uint32_t new_size = pmq->rule_id_array_cnt + sids_size;
    if (new_size > pmq->rule_id_array_size) {
        if (PrefilterAddSidsResize(pmq, new_size) == 0) {
            // Failed to allocate larger memory for all the SIDS, but
            // keep as many as we can.
            sids_size = pmq->rule_id_array_size - pmq->rule_id_array_cnt;
        }
    }
    SCLogDebug("Adding %u sids", sids_size);
    // Add SIDs for this pattern to the end of the array
    SigIntId *ptr = pmq->rule_id_array + pmq->rule_id_array_cnt;
    SigIntId *end = ptr + sids_size;
    do {
        *ptr++ = *sids++;
    } while (ptr != end);
    pmq->rule_id_array_cnt += sids_size;
}
#endif /* __UTIL_PREFILTER_H__ */
