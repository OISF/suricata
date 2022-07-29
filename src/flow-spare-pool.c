/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Flow queue handler functions
 */

#include "suricata-common.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-spare-pool.h"
#include "util-validate.h"

typedef struct FlowSparePool {
    FlowQueuePrivate queue;
    struct FlowSparePool *next;
} FlowSparePool;

static uint32_t flow_spare_pool_flow_cnt = 0;
static uint32_t flow_spare_pool_block_size = 100;
static FlowSparePool *flow_spare_pool = NULL;
static SCMutex flow_spare_pool_m = SCMUTEX_INITIALIZER;

uint32_t FlowSpareGetPoolSize(void)
{
    uint32_t size;
    SCMutexLock(&flow_spare_pool_m);
    size = flow_spare_pool_flow_cnt;
    SCMutexUnlock(&flow_spare_pool_m);
    return size;
}

static FlowSparePool *FlowSpareGetPool(void)
{
    FlowSparePool *p = SCCalloc(1, sizeof(*p));
    if (p == NULL)
        return NULL;
    return p;
}

static bool FlowSparePoolUpdateBlock(FlowSparePool *p)
{
    DEBUG_VALIDATE_BUG_ON(p == NULL);

    for (uint32_t i = p->queue.len; i < flow_spare_pool_block_size; i++)
    {
        Flow *f = FlowAlloc();
        if (f == NULL)
            return false;
        FlowQueuePrivateAppendFlow(&p->queue, f);
    }
    return true;
}

#ifdef FSP_VALIDATE
static void Validate(FlowSparePool *top, const uint32_t target)
{
    if (top == NULL) {
        assert(target == 0);
        return;
    }

    assert(top->queue.len >= 1);
    //if (top->next != NULL)
    //    assert(top->next->queue.len == flow_spare_pool_block_size);

    uint32_t cnt = 0;
    for (FlowSparePool *p = top; p != NULL; p = p->next)
    {
        assert(p->queue.len);
        cnt += p->queue.len;
    }
    assert(cnt == target);
}
#endif

void FlowSparePoolReturnFlow(Flow *f)
{
    SCMutexLock(&flow_spare_pool_m);
    if (flow_spare_pool == NULL) {
        flow_spare_pool = FlowSpareGetPool();
    }
    DEBUG_VALIDATE_BUG_ON(flow_spare_pool == NULL);

    /* if the top is full, get a new block */
    if (flow_spare_pool->queue.len >= flow_spare_pool_block_size) {
        FlowSparePool *p = FlowSpareGetPool();
        DEBUG_VALIDATE_BUG_ON(p == NULL);
        p->next = flow_spare_pool;
        flow_spare_pool = p;
    }
    /* add to the (possibly new) top */
    FlowQueuePrivateAppendFlow(&flow_spare_pool->queue, f);
    flow_spare_pool_flow_cnt++;

    SCMutexUnlock(&flow_spare_pool_m);
}

void FlowSparePoolReturnFlows(FlowQueuePrivate *fqp)
{

}

FlowQueuePrivate FlowSpareGetFromPool(void)
{
    SCMutexLock(&flow_spare_pool_m);
    if (flow_spare_pool == NULL || flow_spare_pool_flow_cnt == 0) {
        SCMutexUnlock(&flow_spare_pool_m);
        FlowQueuePrivate empty = { NULL, NULL, 0 };
        return empty;
    }

    /* top if full or its the only block we have */
    if (flow_spare_pool->queue.len >= flow_spare_pool_block_size || flow_spare_pool->next == NULL) {
        FlowSparePool *p = flow_spare_pool;
        flow_spare_pool = p->next;
        DEBUG_VALIDATE_BUG_ON(flow_spare_pool_flow_cnt < p->queue.len);
        flow_spare_pool_flow_cnt -= p->queue.len;
#ifdef FSP_VALIDATE
        Validate(flow_spare_pool, flow_spare_pool_flow_cnt);
#endif
        SCMutexUnlock(&flow_spare_pool_m);

        FlowQueuePrivate ret = p->queue;
        SCFree(p);
        return ret;
    /* next should always be full if it exists */
    } else if (flow_spare_pool->next != NULL) {
        FlowSparePool *p = flow_spare_pool->next;
        flow_spare_pool->next = p->next;
        DEBUG_VALIDATE_BUG_ON(flow_spare_pool_flow_cnt < p->queue.len);
        flow_spare_pool_flow_cnt -= p->queue.len;
#ifdef FSP_VALIDATE
        Validate(flow_spare_pool, flow_spare_pool_flow_cnt);
#endif
        SCMutexUnlock(&flow_spare_pool_m);

        FlowQueuePrivate ret = p->queue;
        SCFree(p);
        return ret;
    }

    SCMutexUnlock(&flow_spare_pool_m);
    FlowQueuePrivate empty = { NULL, NULL, 0 };
    return empty;
}

void FlowSparePoolUpdate(uint32_t size)
{
    const int64_t todo = (int64_t)flow_config.prealloc - (int64_t)size;
    if (todo < 0) {
        uint32_t to_remove = (uint32_t)(todo * -1) / 10;
        while (to_remove) {
            if (to_remove < flow_spare_pool_block_size)
                return;

            FlowSparePool *p = NULL;
            SCMutexLock(&flow_spare_pool_m);
            p = flow_spare_pool;
            if (p != NULL) {
                flow_spare_pool = p->next;
                flow_spare_pool_flow_cnt -= p->queue.len;
                to_remove -= p->queue.len;
            }
            SCMutexUnlock(&flow_spare_pool_m);

            if (p != NULL) {
                Flow *f;
                while ((f = FlowQueuePrivateGetFromTop(&p->queue))) {
                    FlowFree(f);
                }
                SCFree(p);
            }
        }
    } else if (todo > 0) {
        FlowSparePool *head = NULL, *tail = NULL;

        uint32_t blocks = ((uint32_t)todo / flow_spare_pool_block_size) + 1;

        uint32_t flow_cnt = 0;
        for (uint32_t cnt = 0; cnt < blocks; cnt++) {
            FlowSparePool *p = FlowSpareGetPool();
            if (p == NULL) {
                break;
            }
            const bool ok = FlowSparePoolUpdateBlock(p);
            if (p->queue.len == 0) {
                SCFree(p);
                break;
            }
            flow_cnt += p->queue.len;

            /* prepend to list */
            p->next = head;
            head = p;
            if (tail == NULL)
                tail = p;
            if (!ok)
                break;
        }
        if (head) {
            SCMutexLock(&flow_spare_pool_m);
            if (flow_spare_pool == NULL) {
                flow_spare_pool = head;
            } else if (tail != NULL) {
                /* since these are 'full' buckets we don't put them
                 * at the top but right after as the top is likely not
                 * full. */
                tail->next = flow_spare_pool->next;
                flow_spare_pool->next = head;
            }

            flow_spare_pool_flow_cnt += flow_cnt;
#ifdef FSP_VALIDATE
            Validate(flow_spare_pool, flow_spare_pool_flow_cnt);
#endif
            SCMutexUnlock(&flow_spare_pool_m);
        }
    }
}

void FlowSparePoolInit(void)
{
    SCMutexLock(&flow_spare_pool_m);
    for (uint32_t cnt = 0; cnt < flow_config.prealloc; ) {
        FlowSparePool *p = FlowSpareGetPool();
        if (p == NULL) {
            FatalError(SC_ERR_FLOW_INIT, "failed to initialize flow pool");
        }
        FlowSparePoolUpdateBlock(p);
        cnt += p->queue.len;

        /* prepend to list */
        p->next = flow_spare_pool;
        flow_spare_pool = p;
        flow_spare_pool_flow_cnt = cnt;
    }
    SCMutexUnlock(&flow_spare_pool_m);
}

void FlowSparePoolDestroy(void)
{
    SCMutexLock(&flow_spare_pool_m);
    for (FlowSparePool *p = flow_spare_pool; p != NULL; ) {
        uint32_t cnt = 0;
        Flow *f;
        while ((f = FlowQueuePrivateGetFromTop(&p->queue))) {
            FlowFree(f);
            cnt++;
        }
        flow_spare_pool_flow_cnt -= cnt;
        FlowSparePool *next = p->next;
        SCFree(p);
        p = next;
    }
    flow_spare_pool = NULL;
    SCMutexUnlock(&flow_spare_pool_m);
}
