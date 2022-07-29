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
#include "ippair-bit.h"
#include "ippair-timeout.h"
#include "detect-engine-threshold.h"

uint32_t IPPairGetSpareCount(void)
{
    return IPPairSpareQueueGetSize();
}

uint32_t IPPairGetActiveCount(void)
{
    return SC_ATOMIC_GET(ippair_counter);
}

/** \internal
 *  \brief See if we can really discard this ippair. Check use_cnt reference.
 *
 *  \param h ippair
 *  \param ts timestamp
 *
 *  \retval 0 not timed out just yet
 *  \retval 1 fully timed out, lets kill it
 */
static int IPPairTimedOut(IPPair *h, struct timeval *ts)
{
    int vars = 0;
    int thresholds = 0;

    /** never prune a ippair that is used by a packet
     *  we are currently processing in one of the threads */
    if (SC_ATOMIC_GET(h->use_cnt) > 0) {
        return 0;
    }

    if (IPPairHasBits(h) && IPPairBitsTimedoutCheck(h, ts) == 0) {
        vars = 1;
    }

    if (ThresholdIPPairHasThreshold(h) && ThresholdIPPairTimeoutCheck(h, ts) == 0) {
        thresholds = 1;
    }

    if (vars || thresholds) {
        return 0;
    }

    SCLogDebug("ippair %p timed out", h);
    return 1;
}

/**
 *  \internal
 *
 *  \brief check all ippairs in a hash row for timing out
 *
 *  \param hb ippair hash row *LOCKED*
 *  \param h last ippair in the hash row
 *  \param ts timestamp
 *
 *  \retval cnt timed out ippairs
 */
static uint32_t IPPairHashRowTimeout(IPPairHashRow *hb, IPPair *h, struct timeval *ts)
{
    uint32_t cnt = 0;

    do {
        if (SCMutexTrylock(&h->m) != 0) {
            h = h->hprev;
            continue;
        }

        IPPair *next_ippair = h->hprev;

        /* check if the ippair is fully timed out and
         * ready to be discarded. */
        if (IPPairTimedOut(h, ts) == 1) {
            /* remove from the hash */
            if (h->hprev != NULL)
                h->hprev->hnext = h->hnext;
            if (h->hnext != NULL)
                h->hnext->hprev = h->hprev;
            if (hb->head == h)
                hb->head = h->hnext;
            if (hb->tail == h)
                hb->tail = h->hprev;

            h->hnext = NULL;
            h->hprev = NULL;

            IPPairClearMemory (h);

            /* no one is referring to this ippair, use_cnt 0, removed from hash
             * so we can unlock it and move it back to the spare queue. */
            SCMutexUnlock(&h->m);

            /* move to spare list */
            IPPairMoveToSpare(h);

            cnt++;
        } else {
            SCMutexUnlock(&h->m);
        }

        h = next_ippair;
    } while (h != NULL);

    return cnt;
}

/**
 *  \brief time out ippairs from the hash
 *
 *  \param ts timestamp
 *
 *  \retval cnt number of timed out ippair
 */
uint32_t IPPairTimeoutHash(struct timeval *ts)
{
    uint32_t idx = 0;
    uint32_t cnt = 0;

    for (idx = 0; idx < ippair_config.hash_size; idx++) {
        IPPairHashRow *hb = &ippair_hash[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        /* ippair hash bucket is now locked */

        if (hb->tail == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        /* we have a ippair, or more than one */
        cnt += IPPairHashRowTimeout(hb, hb->tail, ts);
        HRLOCK_UNLOCK(hb);
    }

    return cnt;
}
