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

static void FlowRateStoreFree(FlowRateStore *frs)
{
    size_t total_free = 0;
    if (frs == NULL)
        return;

    for (int i = 0; i < 2; i++) {
        if (frs->buf[i] != NULL) {
            SCFree(frs->buf[i]);
            total_free += (frs->size * sizeof(uint64_t));
        }
    }

    SCFree(frs);
    total_free += sizeof(*frs);
    (void)SC_ATOMIC_SUB(flow_memuse, total_free);
}

void FlowRateRegisterFlowStorage(void)
{
    ConfNode *root = ConfGetNode("flow");
    ConfNode *node = NULL;
    bool track_flow = false;

    if (root != NULL) {
        track_flow = ConfNodeLookupChildValue(root, "tracking") ? true : false;
        if (!track_flow) {
            return;
        }

        node = ConfGetNode("flow.tracking");
        const char *val = ConfNodeLookupChildValue(node, "bytes");
        if (val == NULL) {
            FatalError("No value for flow tracking bytes");
        }
        uint64_t bytes = 0;
        if (ParseSizeStringU64(val, &bytes) < 0) {
            FatalError("Invalid value for flow tracking bytes");
        }
        flow_rate_config.bytes = bytes;

        val = ConfNodeLookupChildValue(node, "interval");
        if (val == NULL) {
            FatalError("No value for flow tracking interval");
        }
        SCTime_t interval = SCTIME_INITIALIZER;
        uint16_t secs = 0;
        if (StringParseUint16(&secs, 10, 0, val) < 0) {
            FatalError("Invalid value for flow tracking interval");
        }
        flow_rate_config.interval = SCTIME_ADD_SECS(interval, secs);

        g_flowrate_storage_id = FlowStorageRegister(
                "flowrate", sizeof(void *), NULL, (void (*)(void *))FlowRateStoreFree);
    }
}

bool FlowRateStorageEnabled(void)
{
    return (g_flowrate_storage_id.id != -1);
}

FlowRateStore *FlowRateStoreInit(void)
{
    FlowRateStore *frs = NULL;
    size_t total_memuse = 0;

    if (!FLOW_CHECK_MEMCAP(sizeof(*frs))) {
        return NULL;
    }
    frs = SCCalloc(1, sizeof(*frs));
    if (unlikely(frs == NULL)) {
        SCLogError("Unable to allocate FlowRateStore memory");
        return NULL;
    }

    total_memuse += sizeof(*frs);
    for (int i = 0; i < 2; i++) {
        frs->size = flow_rate_config.interval.secs;
        frs->buf[i] = SCCalloc(frs->size, sizeof(uint64_t));
        frs->sum[i] = 0;
        frs->last_idx[i] = 0;
        frs->start_ts[i] = SCTIME_INITIALIZER;
        frs->last_ts[i] = SCTIME_INITIALIZER;
        total_memuse += (frs->size * sizeof(uint64_t));
    }
    (void)SC_ATOMIC_ADD(flow_memuse, total_memuse);

    return frs;
}

FlowStorageId FlowRateGetStorageID(void)
{
    return g_flowrate_storage_id;
}

void FlowRateStoreUpdate(FlowRateStore *frs, SCTime_t p_ts, uint32_t pkt_len, int dir)
{
    SCTime_t start_ts = frs->start_ts[dir].secs > 0 ? frs->start_ts[dir] : p_ts;
    if (frs->last_ts[dir].secs == 0) {
        frs->last_ts[dir] = p_ts;
        frs->start_ts[dir] = p_ts;
    }

    /* If the packet has come in the last open interval of time */
    if (p_ts.secs - frs->last_ts[dir].secs < frs->size) {
        SCLogDebug("REGULAR");
        uint16_t idx = (p_ts.secs - start_ts.secs) % frs->size;
        /* Index matches the last updated index in the ring buffer */
        /* or is another next index in the buffer */
        if ((idx == frs->last_idx[dir]) || ((idx > frs->last_idx[dir]) && idx < frs->size)) {
            /* Add to the existing open time interval */
            frs->buf[dir][idx % frs->size] += pkt_len;
            /* Update the total sum */
            frs->sum[dir] += pkt_len;
            SCLogDebug("sum for dir %d: %" PRIu64, dir, frs->sum[dir]);
        } else {
            SCLogDebug("REVISIT");
            /* Index is revisited after a full round of the buffer */
            uint64_t prev_byte_count = frs->buf[dir][idx];
            /* Overwrite the buffer */
            frs->buf[dir][idx] = pkt_len;
            DEBUG_VALIDATE_BUG_ON(frs->buf[dir][idx] < prev_byte_count);
            /* Sum should get rid of previous count on the same index */
            frs->sum[dir] += frs->buf[dir][idx] - prev_byte_count;
            frs->start_ts[dir] = p_ts;
            SCLogDebug("sum for dir %d: %" PRIu64, dir, frs->sum[dir]);
        }
        frs->last_idx[dir] = idx;
    } else {
        SCLogDebug("GAP");
        /* Packet arrived after one or more rounds of the entire buffer */
        /* Flush the entire buffer */
        memset(frs->buf[dir], 0, frs->size);
        frs->last_idx[dir] = 0;
        frs->start_ts[dir] = p_ts;
        frs->buf[dir][0] = pkt_len;
        /* Overwrite the sum calculated so far */
        frs->sum[dir] = pkt_len;
    }
    /* In any case, update the last seen timestamp */
    frs->last_ts[dir] = p_ts;
}

bool IsFlowRateExceeding(FlowRateStore *frs, int dir)
{
    if (frs->sum[dir] >= flow_rate_config.bytes) {
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
        FAIL_IF(frs->size != 10);
        FAIL_IF(frs->sum[i] != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->sum[0] != 48);
    FAIL_IF(frs->last_ts[0].secs != p1->ts.secs);
    FAIL_IF(frs->buf[0][0] != 48);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->sum[0] != 92);
    FAIL_IF(frs->last_ts[0].secs != p2->ts.secs);
    FAIL_IF(frs->buf[0][0] != 92);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->sum[0] != 139);
    FAIL_IF(frs->last_ts[0].secs != p3->ts.secs);
    FAIL_IF(frs->buf[0][0] != 139);

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
        FAIL_IF(frs->size != 4);
        FAIL_IF(frs->sum[i] != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->sum[0] != 48);
    FAIL_IF(frs->last_ts[0].secs != p1->ts.secs);
    FAIL_IF(frs->buf[0][0] != 48);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->sum[0] != 92);
    FAIL_IF(frs->last_ts[0].secs != p2->ts.secs);
    FAIL_IF(frs->buf[0][1] != 44);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->sum[0] != 139);
    FAIL_IF(frs->last_ts[0].secs != p3->ts.secs);
    FAIL_IF(frs->buf[0][2] != 47);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->sum[0] != 185);
    FAIL_IF(frs->last_ts[0].secs != p4->ts.secs);
    FAIL_IF(frs->buf[0][3] != 46);

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
        FAIL_IF(frs->size != 4);
        FAIL_IF(frs->sum[i] != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->sum[0] != 48);
    FAIL_IF(frs->last_ts[0].secs != p1->ts.secs);
    FAIL_IF(frs->buf[0][0] != 48);
    FAIL_IF(frs->start_ts[0].secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 1;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->sum[0] != 92);
    FAIL_IF(frs->last_ts[0].secs != p2->ts.secs);
    FAIL_IF(frs->buf[0][1] != 44);
    FAIL_IF(frs->start_ts[0].secs != p1->ts.secs);

    Packet *p3 = UTHBuildPacket((uint8_t *)"ABababa", 7, IPPROTO_TCP);
    p3->ts.secs = p1->ts.secs + 2;
    FlowRateStoreUpdate(frs, p3->ts, GET_PKT_LEN(p3), TOSERVER);
    /* Total length of packet is 47 */
    FAIL_IF(frs->sum[0] != 139);
    FAIL_IF(frs->last_ts[0].secs != p3->ts.secs);
    FAIL_IF(frs->buf[0][2] != 47);
    FAIL_IF(frs->start_ts[0].secs != p1->ts.secs);

    Packet *p4 = UTHBuildPacket((uint8_t *)"yoohoo", 6, IPPROTO_TCP);
    p4->ts.secs = p1->ts.secs + 3;
    FlowRateStoreUpdate(frs, p4->ts, GET_PKT_LEN(p4), TOSERVER);
    /* Total length of packet is 46 */
    FAIL_IF(frs->sum[0] != 185);
    FAIL_IF(frs->last_ts[0].secs != p4->ts.secs);
    FAIL_IF(frs->buf[0][3] != 46);
    FAIL_IF(frs->start_ts[0].secs != p1->ts.secs);

    Packet *p5 = UTHBuildPacket((uint8_t *)"nmn", 3, IPPROTO_TCP);
    p5->ts.secs = p1->ts.secs + 4;
    FlowRateStoreUpdate(frs, p5->ts, GET_PKT_LEN(p5), TOSERVER);
    /* Total length of packet is 43 */
    FAIL_IF(frs->sum[0] != 180);
    FAIL_IF(frs->last_ts[0].secs != p5->ts.secs);
    FAIL_IF(frs->start_ts[0].secs != p5->ts.secs);
    FAIL_IF(frs->buf[0][0] != 43);

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
        FAIL_IF(frs->size != 4);
        FAIL_IF(frs->sum[i] != 0);
    }
    Packet *p1 = UTHBuildPacket((uint8_t *)"blahblah", 8, IPPROTO_TCP);
    FlowRateStoreUpdate(frs, p1->ts, GET_PKT_LEN(p1), TOSERVER);
    /* Total length of packet is 48 */
    FAIL_IF(frs->sum[0] != 48);
    FAIL_IF(frs->last_ts[0].secs != p1->ts.secs);
    FAIL_IF(frs->buf[0][0] != 48);
    FAIL_IF(frs->start_ts[0].secs != p1->ts.secs);

    Packet *p2 = UTHBuildPacket((uint8_t *)"DATA", 4, IPPROTO_TCP);
    p2->ts.secs = p1->ts.secs + 60;
    FlowRateStoreUpdate(frs, p2->ts, GET_PKT_LEN(p2), TOSERVER);
    /* Total length of packet is 44 */
    FAIL_IF(frs->sum[0] != 44);
    FAIL_IF(frs->last_ts[0].secs != p2->ts.secs);
    FAIL_IF(frs->buf[0][0] != 44);
    FAIL_IF(frs->start_ts[0].secs != p2->ts.secs);

    FlowRateStoreFree(frs);
    PASS;
}

void FlowRateRegisterTests(void)
{
    UtRegisterTest("FlowRateTest01", FlowRateTest01);
    UtRegisterTest("FlowRateTest02", FlowRateTest02);
    UtRegisterTest("FlowRateTest03", FlowRateTest03);
    UtRegisterTest("FlowRateTest04", FlowRateTest04);
}
#endif
