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
#include "host.h"

#include "detect-engine-tag.h"

#include "host-bit.h"
#include "host-timeout.h"

#include "reputation.h"

/** \internal
 *  \brief See if we can really discard this host. Check use_cnt reference.
 *
 *  \param h host
 *  \param ts timestamp
 *
 *  \retval 0 not timed out just yet
 *  \retval 1 fully timed out, lets kill it
 */
static int HostHostTimedOut(Host *h, SCTime_t ts)
{
    int busy = 0;

    /** never prune a host that is used by a packet
     *  we are currently processing in one of the threads */
    if (SC_ATOMIC_GET(h->use_cnt) > 0) {
        return 0;
    }

    busy |= (h->iprep && SRepHostTimedOut(h) == 0);
    busy |= (TagHostHasTag(h) && TagTimeoutCheck(h, ts) == 0);
    busy |= (HostHasHostBits(h) && HostBitsTimedoutCheck(h, ts) == 0);
    SCLogDebug("host %p %s", h, busy ? "still active" : "timed out");
    return !busy;
}

/**
 *  \internal
 *
 *  \brief check all hosts in a hash row for timing out
 *
 *  \param hb host hash row *LOCKED*
 *  \param h last host in the hash row
 *  \param ts timestamp
 *
 *  \retval cnt timed out hosts
 */
static uint32_t HostHashRowTimeout(HostHashRow *hb, Host *h, SCTime_t ts)
{
    uint32_t cnt = 0;

    do {
        if (SCMutexTrylock(&h->m) != 0) {
            h = h->hprev;
            continue;
        }

        Host *next_host = h->hprev;

        /* check if the host is fully timed out and
         * ready to be discarded. */
        if (HostHostTimedOut(h, ts) == 1) {
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

            HostClearMemory (h);

            /* no one is referring to this host, use_cnt 0, removed from hash
             * so we can unlock it and move it back to the spare queue. */
            SCMutexUnlock(&h->m);

            /* move to spare list */
            HostMoveToSpare(h);

            cnt++;
        } else {
            SCMutexUnlock(&h->m);
        }

        h = next_host;
    } while (h != NULL);

    return cnt;
}

/**
 *  \brief time out hosts from the hash
 *
 *  \param ts timestamp
 *
 *  \retval cnt number of timed out host
 */
uint32_t HostTimeoutHash(SCTime_t ts)
{
    uint32_t idx = 0;
    uint32_t cnt = 0;

    for (idx = 0; idx < host_config.hash_size; idx++) {
        HostHashRow *hb = &host_hash[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        /* host hash bucket is now locked */

        if (hb->tail == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        /* we have a host, or more than one */
        cnt += HostHashRowTimeout(hb, hb->tail, ts);
        HRLOCK_UNLOCK(hb);
    }

    return cnt;
}

