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
#include "defrag-stack.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"

DefragTrackerStack *DefragTrackerStackInit(DefragTrackerStack *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(DefragTrackerStack));
        DQLOCK_INIT(q);
    }
    return q;
}

/**
 *  \brief Destroy a tracker queue
 *
 *  \param q the tracker queue to destroy
 */
void DefragTrackerStackDestroy(DefragTrackerStack *q)
{
    DQLOCK_DESTROY(q);
}

/**
 *  \brief add a tracker to a queue
 *
 *  \param q queue
 *  \param dt tracker
 */
void DefragTrackerEnqueue(DefragTrackerStack *q, DefragTracker *dt)
{
#ifdef DEBUG
    BUG_ON(q == NULL || dt == NULL);
#endif

    DQLOCK_LOCK(q);
    dt->lnext = q->s;
    q->s = dt;
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
DefragTracker *DefragTrackerDequeue(DefragTrackerStack *q)
{
    DQLOCK_LOCK(q);

    DefragTracker *dt = q->s;
    if (dt == NULL) {
        DQLOCK_UNLOCK(q);
        return NULL;
    }
    q->s = dt->lnext;
    dt->lnext = NULL;

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;
    DQLOCK_UNLOCK(q);
    return dt;
}

/**
 *  \brief return stack size
 */
uint32_t DefragTrackerStackSize(DefragTrackerStack *q)
{
    uint32_t len;
    DQLOCK_LOCK(q);
    len = q->len;
    DQLOCK_UNLOCK(q);
    return len;
}
