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
 *
 * Defrag tracker queue handler functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "defrag-queue.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"

DefragTrackerQueue *DefragTrackerQueueInit (DefragTrackerQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(DefragTrackerQueue));
        DQLOCK_INIT(q);
    }
    return q;
}

DefragTrackerQueue *DefragTrackerQueueNew()
{
    DefragTrackerQueue *q = (DefragTrackerQueue *)SCMalloc(sizeof(DefragTrackerQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in DefragTrackerQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = DefragTrackerQueueInit(q);
    return q;
}

/**
 *  \brief Destroy a tracker queue
 *
 *  \param q the tracker queue to destroy
 */
void DefragTrackerQueueDestroy (DefragTrackerQueue *q)
{
    DQLOCK_DESTROY(q);
}

/**
 *  \brief add a tracker to a queue
 *
 *  \param q queue
 *  \param dt tracker
 */
void DefragTrackerEnqueue (DefragTrackerQueue *q, DefragTracker *dt)
{
#ifdef DEBUG
    BUG_ON(q == NULL || dt == NULL);
#endif

    DQLOCK_LOCK(q);

    /* more trackers in queue */
    if (q->top != NULL) {
        dt->lnext = q->top;
        q->top->lprev = dt;
        q->top = dt;
    /* only tracker */
    } else {
        q->top = dt;
        q->bot = dt;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    DQLOCK_UNLOCK(q);
}

/**
 *  \brief remove a tracker from the queue
 *
 *  \param q queue
 *
 *  \retval dt tracker or NULL if empty list.
 */
DefragTracker *DefragTrackerDequeue (DefragTrackerQueue *q)
{
    DQLOCK_LOCK(q);

    DefragTracker *dt = q->bot;
    if (dt == NULL) {
        DQLOCK_UNLOCK(q);
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->lprev != NULL) {
        q->bot = q->bot->lprev;
        q->bot->lnext = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;

    dt->lnext = NULL;
    dt->lprev = NULL;

    DQLOCK_UNLOCK(q);
    return dt;
}

uint32_t DefragTrackerQueueLen(DefragTrackerQueue *q)
{
    uint32_t len;
    DQLOCK_LOCK(q);
    len = q->len;
    DQLOCK_UNLOCK(q);
    return len;
}

