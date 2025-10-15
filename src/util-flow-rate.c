/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 *
 */

#include "suricata-common.h"
#include "flow-storage.h"
#include "flow-util.h"
#include "flow-private.h"
#include "util-storage.h"
#include "conf.h"
#include "util-misc.h"
#include "util-byte.h"
#include "util-flow-rate.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

FlowStorageId g_flowrate_storage_id = { .id = -1 };

FlowRateConfig flow_rate_config;

static void FlowRateStoreFree(void *ptr)
{
    FlowRateStore *frs = (FlowRateStore *)ptr;
    size_t total_free = 0;
    if (frs == NULL)
        return;

    for (int i = 0; i < 2; i++) {
        if (frs->dir[i].buf != NULL) {
            SCFree(frs->dir[i].buf);
            total_free += (frs->dir[i].size * sizeof(uint64_t));
        }
    }

    SCFree(frs);
    total_free += sizeof(*frs);
    (void)SC_ATOMIC_SUB(flow_memuse, total_free);
}

void FlowRateRegisterFlowStorage(void)
{
    SCConfNode *root = SCConfGetNode("flow");
    if (root == NULL)
        return;

    bool track_flow = false;
    track_flow = SCConfNodeLookupChild(root, "rate-tracking") != NULL ? true : false;
    if (!track_flow)
        return;

    SCConfNode *node = SCConfGetNode("flow.rate-tracking");
    const char *val = SCConfNodeLookupChildValue(node, "bytes");
    if (val == NULL) {
        FatalError("No value for flow tracking bytes");
    }
    uint64_t bytes = 0;
    if (ParseSizeStringU64(val, &bytes) < 0) {
        FatalError("Invalid value for flow tracking bytes");
    }
    flow_rate_config.bytes = bytes;

    val = SCConfNodeLookupChildValue(node, "interval");
    if (val == NULL) {
        FatalError("No value for flow tracking interval");
    }
    SCTime_t interval = SCTIME_INITIALIZER;
    uint16_t secs = 0;
    if ((StringParseUint16(&secs, 10, 0, val) < 0) || (secs == 0)) {
        FatalError("Invalid value for flow tracking interval");
    }
    flow_rate_config.interval = SCTIME_ADD_SECS(interval, secs);

    g_flowrate_storage_id =
            FlowStorageRegister("flowrate", sizeof(void *), NULL, FlowRateStoreFree);
}

bool FlowRateStorageEnabled(void)
{
    return (g_flowrate_storage_id.id != -1);
}

FlowRateStore *FlowRateStoreInit(void)
{
    FlowRateStore *frs = NULL;
    size_t total_memuse = 0;
    size_t expected_memuse = (2 * flow_rate_config.interval.secs * sizeof(uint64_t)) + sizeof(*frs);

    if (!FLOW_CHECK_MEMCAP(expected_memuse)) {
        return NULL;
    }
    frs = SCCalloc(1, sizeof(*frs));
    if (unlikely(frs == NULL)) {
        return NULL;
    }

    total_memuse += sizeof(*frs);
    for (int i = 0; i < 2; i++) {
        frs->dir[i].size = (uint16_t)flow_rate_config.interval.secs;
        frs->dir[i].buf = SCCalloc(frs->dir[i].size, sizeof(uint64_t));
        if (unlikely(frs->dir[i].buf == NULL)) {
            FlowRateStoreFree(frs);
            return NULL;
        }
        frs->dir[i].start_ts = SCTIME_INITIALIZER;
        frs->dir[i].last_ts = SCTIME_INITIALIZER;
        total_memuse += (frs->dir[i].size * sizeof(uint64_t));
    }
    DEBUG_VALIDATE_BUG_ON(total_memuse != expected_memuse);
    (void)SC_ATOMIC_ADD(flow_memuse, total_memuse);

    return frs;
}

FlowStorageId FlowRateGetStorageID(void)
{
    return g_flowrate_storage_id;
}

static inline void FlowRateClearSumInRange(
        FlowRateStore *frs, uint16_t start, uint16_t end, int direction)
{
    for (uint16_t i = start; i <= end; i++) {
        uint64_t byte_count_at_i = frs->dir[direction].buf[i];
        frs->dir[direction].buf[i] = 0;
        DEBUG_VALIDATE_BUG_ON(frs->dir[direction].sum < byte_count_at_i);
        frs->dir[direction].sum -= byte_count_at_i;
    }
}

static inline void FlowRateStoreUpdateCurrentRing(
        FlowRateStore *frs, SCTime_t p_ts, uint32_t pkt_len, uint16_t idx, int direction)
{
    if (idx > frs->dir[direction].last_idx + 1) {
        /* Index is not the same as last or the next so, the ring must be flushed for the items
         * in between and sum updated */
        FlowRateClearSumInRange(frs, frs->dir[direction].last_idx + 1, idx, direction);
        frs->dir[direction].buf[idx] += pkt_len;
        /* Update the total sum */
        frs->dir[direction].sum += pkt_len;
    } else if (idx == frs->dir[direction].last_idx) {
        /* Index matches the last updated index in the ring buffer */
        /* Add to the existing open time interval */
        frs->dir[direction].buf[idx] += pkt_len;
        /* Update the total sum */
        frs->dir[direction].sum += pkt_len;
    } else {
        /* Index is revisited after a full round of the buffer */
        uint64_t prev_byte_count = frs->dir[direction].buf[idx];
        /* Overwrite the buffer */
        frs->dir[direction].buf[idx] = pkt_len;
        DEBUG_VALIDATE_BUG_ON(frs->dir[direction].sum < prev_byte_count);
        /* Sum should get rid of previous count on the same index */
        frs->dir[direction].sum += pkt_len - prev_byte_count;
        if (idx != frs->dir[direction].last_idx + 1) {
            /* Revisited index but not the next to last, so, reset start_ts */
            frs->dir[direction].start_ts = p_ts;
        }
    }
    frs->dir[direction].last_idx = idx;
}

static inline void FlowRateStoreFlushRing(
        FlowRateStore *frs, SCTime_t p_ts, uint32_t pkt_len, int direction)
{
    memset(frs->dir[direction].buf, 0, frs->dir[direction].size);
    frs->dir[direction].last_idx = 0;
    frs->dir[direction].start_ts = p_ts;
    frs->dir[direction].buf[0] = pkt_len;
    /* Overwrite the sum calculated so far */
    frs->dir[direction].sum = pkt_len;
}

void FlowRateStoreUpdate(FlowRateStore *frs, SCTime_t p_ts, uint32_t pkt_len, int direction)
{
    if (frs->dir[direction].last_ts.secs == 0) {
        /* Should only happen when the ring is first used */
        DEBUG_VALIDATE_BUG_ON(frs->dir[direction].sum > 0);
        /* Initialize last_ts and start_ts with the first packet's timestamp */
        frs->dir[direction].last_ts = p_ts;
        frs->dir[direction].start_ts = p_ts;
    }

    SCTime_t start_ts = frs->dir[direction].start_ts;
    uint16_t idx = (p_ts.secs - start_ts.secs) % frs->dir[direction].size;
    /* Update start_ts in case of initiating the revisit of buffer */
    if ((frs->dir[direction].last_idx == frs->dir[direction].size - 1) &&
            (frs->dir[direction].last_idx != idx)) {
        start_ts = p_ts;
        if (idx != 0) {
            /* Update the sum */
            FlowRateClearSumInRange(frs, 0, idx, direction);
            /* Consider current packet a new start of the ring */
            idx = 0;
        }
    }
    /* If the packet has come in the last open interval of time */
    if (p_ts.secs - start_ts.secs < frs->dir[direction].size) {
        FlowRateStoreUpdateCurrentRing(frs, p_ts, pkt_len, idx, direction);
    } else {
        /* Packet arrived after one or more rounds of the entire buffer */
        /* Flush the entire buffer */
        FlowRateStoreFlushRing(frs, p_ts, pkt_len, direction);
    }
    /* In any case, update the last seen timestamp */
    frs->dir[direction].last_ts = p_ts;
}

bool FlowRateIsExceeding(FlowRateStore *frs, int direction)
{
    if (frs->dir[direction].sum >= flow_rate_config.bytes) {
        return true;
    }
    return false;
}

#ifdef UNITTESTS

/* Test to check update of the same buffer item */
static int FlowRateTest01(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 100;
    flow_rate_config.interval = (SCTime_t){ .secs = 10, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 10);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 92);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 139);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check update of all buffer items */
static int FlowRateTest02(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 44);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[2] != 47);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->dir[0].sum != 185);
    FAIL_IF(frs->dir[0].last_ts.secs != p4->ts.secs);
    FAIL_IF(frs->dir[0].buf[3] != 46);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check update of wrapping around ring buffer */
static int FlowRateTest03(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 44);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[2] != 47);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->dir[0].sum != 185);
    FAIL_IF(frs->dir[0].last_ts.secs != p4->ts.secs);
    FAIL_IF(frs->dir[0].buf[3] != 46);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p5 = UTHBuildPacket((uint8_t *)"nmn", 3, IPPROTO_TCP);
    p5->ts.secs = p1->ts.secs + 4;
    FlowRateStoreUpdate(frs, p5->ts, GET_PKT_LEN(p5), TOSERVER);
    /* Total length of packet is 43 */
    FAIL_IF(frs->dir[0].sum != 180);
    FAIL_IF(frs->dir[0].last_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);

    Packet *p6 = UTHBuildPacket((uint8_t *)"meerkat", 7, IPPROTO_TCP);
    p6->ts.secs = p1->ts.secs + 5;
    FlowRateStoreUpdate(frs, p6->ts, GET_PKT_LEN(p6), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 183);
    FAIL_IF(frs->dir[0].last_ts.secs != p6->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 47);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    UTHFreePacket(p5);
    UTHFreePacket(p6);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check update of buffer if new pkt comes out of the window */
static int FlowRateTest04(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 60;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 44);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 44);
    FAIL_IF(frs->dir[0].start_ts.secs != p2->ts.secs);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check update of wrapping around ring buffer when the packet
 * out of the window but also does not fall on the first index of the ring */
static int FlowRateTest05(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 44);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[2] != 47);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->dir[0].sum != 185);
    FAIL_IF(frs->dir[0].last_ts.secs != p4->ts.secs);
    FAIL_IF(frs->dir[0].buf[3] != 46);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p5 = UTHBuildPacket((uint8_t *)"nmn", 3, IPPROTO_TCP);
    p5->ts.secs = p1->ts.secs + 6;
    FlowRateStoreUpdate(frs, p5->ts, GET_PKT_LEN(p5), TOSERVER);
    /* Total length of packet is 43 */
    FAIL_IF(frs->dir[0].sum != 89);
    FAIL_IF(frs->dir[0].last_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    UTHFreePacket(p5);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check sum when packet is within the window but is coming after a gap */
static int FlowRateTest06(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 44);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[2] != 47);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->dir[0].sum != 185);
    FAIL_IF(frs->dir[0].last_ts.secs != p4->ts.secs);
    FAIL_IF(frs->dir[0].buf[3] != 46);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p5 = UTHBuildPacket((uint8_t *)"nmn", 3, IPPROTO_TCP);
    p5->ts.secs = p1->ts.secs + 4;
    FlowRateStoreUpdate(frs, p5->ts, GET_PKT_LEN(p5), TOSERVER);
    /* Total length of packet is 43 */
    FAIL_IF(frs->dir[0].sum != 180);
    FAIL_IF(frs->dir[0].last_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);

    Packet *p6 = UTHBuildPacket((uint8_t *)"suricata", 8, IPPROTO_TCP);
    p6->ts.secs = p1->ts.secs + 7;
    FlowRateStoreUpdate(frs, p6->ts, GET_PKT_LEN(p6), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 91);
    FAIL_IF(frs->dir[0].last_ts.secs != p6->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);
    FAIL_IF(frs->dir[0].buf[1] != 0);
    FAIL_IF(frs->dir[0].buf[2] != 0);
    FAIL_IF(frs->dir[0].buf[3] != 48);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    UTHFreePacket(p5);
    UTHFreePacket(p6);
    FlowRateStoreFree(frs);
    PASS;
}

/* Test to check sum when two packets are back to back within the window but are coming after a gap
 */
static int FlowRateTest07(void)
{
    SC_ATOMIC_SET(flow_config.memcap, 10000);
    flow_rate_config.bytes = 200;
    flow_rate_config.interval = (SCTime_t){ .secs = 4, .usecs = 0 };
    FlowRateStore *frs = FlowRateStoreInit();
    FAIL_IF_NULL(frs);
    for (int i = 0; i < 2; i++) {
        FAIL_IF(frs->dir[i].size != 4);
        FAIL_IF(frs->dir[i].sum != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 48);
    FAIL_IF(frs->dir[0].last_ts.secs != p1->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 48);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->dir[0].sum != 92);
    FAIL_IF(frs->dir[0].last_ts.secs != p2->ts.secs);
    FAIL_IF(frs->dir[0].buf[1] != 44);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->dir[0].sum != 139);
    FAIL_IF(frs->dir[0].last_ts.secs != p3->ts.secs);
    FAIL_IF(frs->dir[0].buf[2] != 47);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->dir[0].sum != 185);
    FAIL_IF(frs->dir[0].last_ts.secs != p4->ts.secs);
    FAIL_IF(frs->dir[0].buf[3] != 46);
    FAIL_IF(frs->dir[0].start_ts.secs != p1->ts.secs);

    Packet *p5 = UTHBuildPacket((uint8_t *)"nmn", 3, IPPROTO_TCP);
    p5->ts.secs = p1->ts.secs + 5;
    FlowRateStoreUpdate(frs, p5->ts, GET_PKT_LEN(p5), TOSERVER);
    /* Total length of packet is 43 */
    FAIL_IF(frs->dir[0].sum != 136);
    FAIL_IF(frs->dir[0].last_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);

    Packet *p6 = UTHBuildPacket((uint8_t *)"suricata", 8, IPPROTO_TCP);
    p6->ts.secs = p1->ts.secs + 8;
    FlowRateStoreUpdate(frs, p6->ts, GET_PKT_LEN(p6), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->dir[0].sum != 91);
    FAIL_IF(frs->dir[0].last_ts.secs != p6->ts.secs);
    FAIL_IF(frs->dir[0].start_ts.secs != p5->ts.secs);
    FAIL_IF(frs->dir[0].buf[0] != 43);
    FAIL_IF(frs->dir[0].buf[1] != 0);
    FAIL_IF(frs->dir[0].buf[2] != 0);
    FAIL_IF(frs->dir[0].buf[3] != 48);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);
    UTHFreePacket(p4);
    UTHFreePacket(p5);
    UTHFreePacket(p6);
    FlowRateStoreFree(frs);
    PASS;
}

void FlowRateRegisterTests(void)
{
    UtRegisterTest("FlowRateTest01", FlowRateTest01);
    UtRegisterTest("FlowRateTest02", FlowRateTest02);
    UtRegisterTest("FlowRateTest03", FlowRateTest03);
    UtRegisterTest("FlowRateTest04", FlowRateTest04);
    UtRegisterTest("FlowRateTest05", FlowRateTest05);
    UtRegisterTest("FlowRateTest06", FlowRateTest06);
    UtRegisterTest("FlowRateTest07", FlowRateTest07);
}
#endif
