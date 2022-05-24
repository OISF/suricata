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
 * Host queue handler functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "host-queue.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"

HostQueue *HostQueueInit (HostQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(HostQueue));
        HQLOCK_INIT(q);
    }
    return q;
}

HostQueue *HostQueueNew()
{
    HostQueue *q = (HostQueue *)SCMalloc(sizeof(HostQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in HostQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = HostQueueInit(q);
    return q;
}

/**
 *  \brief Destroy a host queue
 *
 *  \param q the host queue to destroy
 */
void HostQueueDestroy (HostQueue *q)
{
    HQLOCK_DESTROY(q);
}

/**
 *  \brief add a host to a queue
 *
 *  \param q queue
 *  \param h host
 */
void HostEnqueue (HostQueue *q, Host *h)
{
#ifdef DEBUG
    BUG_ON(q == NULL || h == NULL);
#endif

    HQLOCK_LOCK(q);

    /* more hosts in queue */
    if (q->top != NULL) {
        h->lnext = q->top;
        q->top->lprev = h;
        q->top = h;
    /* only host */
    } else {
        q->top = h;
        q->bot = h;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    HQLOCK_UNLOCK(q);
}

/**
 *  \brief remove a host from the queue
 *
 *  \param q queue
 *
 *  \retval h host or NULL if empty list.
 */
Host *HostDequeue (HostQueue *q)
{
    HQLOCK_LOCK(q);

    Host *h = q->bot;
    if (h == NULL) {
        HQLOCK_UNLOCK(q);
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

    h->lnext = NULL;
    h->lprev = NULL;

    HQLOCK_UNLOCK(q);
    return h;
}

uint32_t HostQueueLen(HostQueue *q)
{
    uint32_t len;
    HQLOCK_LOCK(q);
    len = q->len;
    HQLOCK_UNLOCK(q);
    return len;
}

