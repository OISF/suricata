/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "suricata.h"
#include "stream-tcp-private.h"
#include "stream-tcp-cache.h"
#include "util-debug.h"

typedef struct TcpPoolCache {
    bool cache_enabled; /**< cache should only be enabled for worker threads */
    TcpSegment *segs_cache[64];
    uint32_t segs_cache_idx;
    uint32_t segs_returns_idx;
    TcpSegment *segs_returns[64];

    TcpSession *ssns_cache[64];
    uint32_t ssns_cache_idx;
    uint32_t ssns_returns_idx;
    TcpSession *ssns_returns[64];
} TcpPoolCache;

static thread_local TcpPoolCache tcp_pool_cache;
extern PoolThread *ssn_pool;
extern PoolThread *segment_thread_pool;

/** \brief enable segment cache. Should only be done for worker threads */
void StreamTcpThreadCacheEnable(void)
{
    tcp_pool_cache.cache_enabled = true;
}

void StreamTcpThreadCacheReturnSegment(TcpSegment *seg)
{
    SCEnter();
#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        PoolThreadReturn(segment_thread_pool, seg);
        SCReturn;
    }
#endif

    /* cache can have segs from any pool id */
    if (tcp_pool_cache.cache_enabled && tcp_pool_cache.segs_cache_idx < 64) {
        tcp_pool_cache.segs_cache[tcp_pool_cache.segs_cache_idx++] = seg;
    } else {
        /* segs_returns should only have a single pool id. If ours is different,
         * flush it. */
        bool flush = false;
        if (tcp_pool_cache.segs_returns_idx &&
                tcp_pool_cache.segs_returns[0]->pool_id != seg->pool_id) {
            flush = true;
        }
        if (tcp_pool_cache.segs_returns_idx == 64) {
            flush = true;
        }

        if (flush) {
            PoolThreadId pool_id = tcp_pool_cache.segs_returns[0]->pool_id;
            PoolThreadLock(segment_thread_pool, pool_id);
            for (uint32_t i = 0; i < tcp_pool_cache.segs_returns_idx; i++) {
                TcpSegment *ret_seg = tcp_pool_cache.segs_returns[i];
                PoolThreadReturnRaw(segment_thread_pool, pool_id, ret_seg);
            }
            PoolThreadUnlock(segment_thread_pool, pool_id);
            tcp_pool_cache.segs_returns_idx = 0;
        }

        tcp_pool_cache.segs_returns[tcp_pool_cache.segs_returns_idx++] = seg;
    }
}

void StreamTcpThreadCacheReturnSession(TcpSession *ssn)
{
    SCEnter();
#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        PoolThreadReturn(ssn_pool, ssn);
        SCReturn;
    }
#endif

    /* cache can have ssns from any pool id */
    if (tcp_pool_cache.cache_enabled && tcp_pool_cache.ssns_cache_idx < 64) {
        tcp_pool_cache.ssns_cache[tcp_pool_cache.ssns_cache_idx++] = ssn;
    } else {
        /* ssns_returns should only have a single pool id. If ours is different,
         * flush it. */
        bool flush = false;
        if (tcp_pool_cache.ssns_returns_idx &&
                tcp_pool_cache.ssns_returns[0]->pool_id != ssn->pool_id) {
            flush = true;
        }
        if (tcp_pool_cache.ssns_returns_idx == 64) {
            flush = true;
        }

        if (flush) {
            PoolThreadId pool_id = tcp_pool_cache.ssns_returns[0]->pool_id;
            PoolThreadLock(ssn_pool, pool_id);
            for (uint32_t i = 0; i < tcp_pool_cache.ssns_returns_idx; i++) {
                TcpSession *ret_ssn = tcp_pool_cache.ssns_returns[i];
                PoolThreadReturnRaw(ssn_pool, pool_id, ret_ssn);
            }
            PoolThreadUnlock(ssn_pool, pool_id);
            tcp_pool_cache.ssns_returns_idx = 0;
        }

        tcp_pool_cache.ssns_returns[tcp_pool_cache.ssns_returns_idx++] = ssn;
    }
    SCReturn;
}

void StreamTcpThreadCacheCleanup(void)
{
    SCEnter();

    /* segments */
    SCLogDebug("tcp_pool_cache.segs_cache_idx %u", tcp_pool_cache.segs_cache_idx);
    for (uint32_t i = 0; i < tcp_pool_cache.segs_cache_idx; i++) {
        PoolThreadReturn(segment_thread_pool, tcp_pool_cache.segs_cache[i]);
    }
    tcp_pool_cache.segs_cache_idx = 0;

    SCLogDebug("tcp_pool_cache.segs_returns_idx %u", tcp_pool_cache.segs_returns_idx);
    if (tcp_pool_cache.segs_returns_idx) {
        PoolThreadId pool_id = tcp_pool_cache.segs_returns[0]->pool_id;
        PoolThreadLock(segment_thread_pool, pool_id);
        for (uint32_t i = 0; i < tcp_pool_cache.segs_returns_idx; i++) {
            TcpSegment *ret_seg = tcp_pool_cache.segs_returns[i];
            PoolThreadReturnRaw(segment_thread_pool, pool_id, ret_seg);
        }
        PoolThreadUnlock(segment_thread_pool, pool_id);
        tcp_pool_cache.segs_returns_idx = 0;
    }

    /* sessions */
    SCLogDebug("tcp_pool_cache.ssns_cache_idx %u", tcp_pool_cache.ssns_cache_idx);
    for (uint32_t i = 0; i < tcp_pool_cache.ssns_cache_idx; i++) {
        PoolThreadReturn(segment_thread_pool, tcp_pool_cache.ssns_cache[i]);
    }
    tcp_pool_cache.ssns_cache_idx = 0;

    SCLogDebug("tcp_pool_cache.ssns_returns_idx %u", tcp_pool_cache.ssns_returns_idx);
    if (tcp_pool_cache.ssns_returns_idx) {
        PoolThreadId pool_id = tcp_pool_cache.ssns_returns[0]->pool_id;
        PoolThreadLock(segment_thread_pool, pool_id);
        for (uint32_t i = 0; i < tcp_pool_cache.ssns_returns_idx; i++) {
            TcpSession *ret_ssn = tcp_pool_cache.ssns_returns[i];
            PoolThreadReturnRaw(segment_thread_pool, pool_id, ret_ssn);
        }
        PoolThreadUnlock(segment_thread_pool, pool_id);
        tcp_pool_cache.ssns_returns_idx = 0;
    }

    SCReturn;
}

TcpSegment *StreamTcpThreadCacheGetSegment(void)
{
    if (tcp_pool_cache.segs_cache_idx) {
        TcpSegment *seg = tcp_pool_cache.segs_cache[tcp_pool_cache.segs_cache_idx - 1];
        tcp_pool_cache.segs_cache_idx--;
        memset(&seg->sbseg, 0, sizeof(seg->sbseg));
        return seg;
    }
    return NULL;
}

TcpSession *StreamTcpThreadCacheGetSession(void)
{
    if (tcp_pool_cache.ssns_cache_idx) {
        TcpSession *ssn = tcp_pool_cache.ssns_cache[tcp_pool_cache.ssns_cache_idx - 1];
        tcp_pool_cache.ssns_cache_idx--;
        return ssn;
    }
    return NULL;
}
