/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "suricata-common.h"
#include "decode.h"
#include "defrag.h"
#include "defrag-hash.h"
#include "defrag-timeout.h"

/** \internal
 *  \brief See if we can really discard this tracker. Check use_cnt reference.
 *
 *  \param dt tracker
 *  \param ts timestamp
 *
 *  \retval 0 not timed out just yet
 *  \retval 1 fully timed out, lets kill it
 */
static int DefragTrackerTimedOut(DefragTracker *dt, SCTime_t ts)
{
    /** never prune a trackers that is used by a packet
     *  we are currently processing in one of the threads */
    if (SC_ATOMIC_GET(dt->use_cnt) > 0) {
        return 0;
    }

    /* retain if remove is not set and not timed out */
    if (!dt->remove && SCTIME_CMP_GT(dt->timeout, ts))
        return 0;

    return 1;
}

/**
 *  \internal
 *
 *  \brief check all trackers in a hash row for timing out
 *
 *  \param hb tracker hash row *LOCKED*
 *  \param dt last tracker in the hash row
 *  \param ts timestamp
 *
 *  \retval cnt timed out tracker
 */
static uint32_t DefragTrackerHashRowTimeout(
        DefragTrackerHashRow *hb, DefragTracker *dt, SCTime_t ts)
{
    uint32_t cnt = 0;

    DefragTracker *prev_dt = NULL;
    do {
        if (SCMutexTrylock(&dt->lock) != 0) {
            prev_dt = dt;
            dt = dt->hnext;
            continue;
        }

        DefragTracker *next_dt = dt->hnext;

        /* check if the tracker is fully timed out and
         * ready to be discarded. */
        if (DefragTrackerTimedOut(dt, ts) == 0) {
            prev_dt = dt;
            SCMutexUnlock(&dt->lock);
            dt = next_dt;
            continue;
        }

        /* remove from the hash */
        if (prev_dt != NULL) {
            prev_dt->hnext = dt->hnext;
        } else {
            hb->head = dt->hnext;
        }

        dt->hnext = NULL;

        DefragTrackerClearMemory(dt);

        /* no one is referring to this tracker, use_cnt 0, removed from hash
         * so we can unlock it and move it back to the spare queue. */
        SCMutexUnlock(&dt->lock);

        /* move to spare list */
        DefragTrackerMoveToSpare(dt);

        cnt++;

        dt = next_dt;
    } while (dt != NULL);

    return cnt;
}

/**
 *  \brief time out tracker from the hash
 *
 *  \param ts timestamp
 *
 *  \retval cnt number of timed out tracker
 */
uint32_t DefragTimeoutHash(SCTime_t ts)
{
    uint32_t idx = 0;
    uint32_t cnt = 0;

    for (idx = 0; idx < defrag_config.hash_size; idx++) {
        DefragTrackerHashRow *hb = &defragtracker_hash[idx];

        if (DRLOCK_TRYLOCK(hb) != 0)
            continue;

        /* defrag hash bucket is now locked */

        if (hb->head == NULL) {
            DRLOCK_UNLOCK(hb);
            continue;
        }

        /* we have a tracker, or more than one */
        cnt += DefragTrackerHashRowTimeout(hb, hb->head, ts);
        DRLOCK_UNLOCK(hb);
    }

    return cnt;
}

