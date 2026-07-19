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
 *  \defgroup dpdk DPDK rte_flow rules util functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow rules util functions
 *
 */

#include "decode.h"
#include "flow-bypass.h"
#include "flow-hash.h"
#include "flow-storage.h"
#include "flow-callbacks.h"
#include "runmode-dpdk.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rte-flow.h"
#include "util-device-private.h"
#include "flow-private.h"
#include "flow.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "suricata.h"

#ifdef HAVE_DPDK

#define COUNT_ACTION_ID 1

#define RTE_BYPASS_RING_NAME                       "rte_bypass_ring"
#define RTE_BYPASS_MEMPOOL_NAME                    "rte_bypass_mempool"
#define RTE_BYPASS_INFO_MEMPOOL_NAME               "rte_bypass_info_mempool"
#define RTE_BYPASS_RING_SIZE_DEFAULT               16384
#define RTE_BYPASS_RING_DEQUEUE_BURST_SIZE_DEFAULT 16383

static int RteFlowBypassGetBypassInfoMPSize(const char *, uint32_t *);
int RteFlowBypassLoadConf(const char *, uint32_t *, uint32_t *, uint32_t *);
static int RteFlowBypassGetNodeInt(SCConfNode *, uint32_t *, const char *, uint32_t);
static int RteFlowBypassRuleCreate(
        RteFlowBypassData *, struct rte_flow_item *, int, struct rte_flow **);
static void RteFlowHandleEmergency(ThreadVars *, Flow *, void *);
static void RteFlowBiRuleDestroy(uint16_t, struct rte_flow *, struct rte_flow *);
static int RteFlowUpdateStats(FlowBypassInfo *, LiveDevice *, struct rte_flow *, struct rte_flow *);
static int RteFlowSetFlowBypassInfo(Flow *, struct rte_flow *, struct rte_flow *, int);
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *);

typedef struct RteFlowHandlerToFlow_ {
    struct rte_flow *src_handler;
    struct rte_flow *dst_handler;
    uint16_t livedev_id;
} RteFlowHandlerToFlow;

/**
 * \brief Create a jump rule in the rte_flow default group to the group for bypass rules.
 *  In some NICs, the default group has less capacity and higher rule insertion latency.
 *
 * \param port_id port id of the device to create the rule on
 * \return int 0 on success, negative value on error
 */
int RteFlowCreateJumpRule(uint16_t port_id)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = RTE_DEFAULT_GROUP;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_action_jump jump = {
        .group = RTE_JUMP_GROUP,
    };

    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[0].conf = &jump;

    struct rte_flow *flow_handler = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow_handler == NULL) {
        FatalError("Error when creating rte_flow jump rule: %s", flow_error.message);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief Decide what is the maximal capacity of dynamic bypass rte_flow rules the device can
 * handle.
 *
 * \param driver_name name of the driver
 * \return uint32_t count of rte_flow bypass rules the device can utilize
 */
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *driver_name)
{
    uint32_t retval = 0;
    if (strcmp(driver_name, "mlx5_pci") == 0)
        retval = MLX5_RTE_FLOW_RULES_CAPACITY;
    return retval;
}

/**
 * \brief Retrieve dpdk.capture-bypass and set it to all interfaces.
 *
 * Get dpdk.capture-bypass flag for enabling rte_flow bypass.
 * Set this global flag to each interface.
 * Default setting is disabled.
 *
 * \param iconf configuration of the interface
 * \return 1 if key found, 0 if not
 */
int ConfigSetCaptureBypass(DPDKIfaceConfig *iconf)
{
    SCEnter();
    int entry_bool = 0;
    int retval = SCConfGetBool("dpdk.capture-bypass", &entry_bool);
    if (retval != 1) {
        iconf->capture_bypass_enabled = false;
    } else {
        iconf->capture_bypass_enabled = entry_bool;
        retval = entry_bool;
    }
    SCReturnInt(retval);
}

/**
 * \brief Get bypass-info mempool size from suricata.yaml.
 *
 * \param driver_name name of the driver
 * \param[out] bypass_info_mp_size size of the mempool from config or maximum capacity of rte_flow
 * rules the device can handle.
 * \return 0 on success, negative value on error
 */
static int RteFlowBypassGetBypassInfoMPSize(const char *driver_name, uint32_t *bypass_info_mp_size)
{
    SCEnter();
    SCConfNode *dpdk_root = SCConfGetNode("dpdk");

    uint32_t capa = DeviceDecideRteFlowRulesCapacity(driver_name);
    if (capa < 2) {
        SCLogWarning("rte_flow capture bypass is not supported for driver %s", driver_name);
        SCReturnInt(-1);
    }
    /* We want to have a mempool of size (2^n)-1. Half the capacity of the card is enough, each
     * mempool object holds info about 2 rules */
    uint32_t max_sz = capa / 2 - 1;
    uint32_t sz = 0;

    const char *entry_str = NULL;
    int ret = SCConfGetChildValue(dpdk_root, "bypass-info-mp-size", &entry_str);
    /* Set to maximum if value is "auto" or missing */
    if (ret != 1 || strcmp(entry_str, "auto") == 0) {
        sz = max_sz;
    } else {
        if (StringParseUint32(&sz, 10, 0, entry_str) < 0) {
            SCLogError("bypass-info-mp-size contains non-numerical characters - \"%s\"", entry_str);
            SCReturnInt(-EINVAL);
        }
    }

    if (sz > max_sz) {
        SCLogConfig("bypass-info-mp-size too big (%d), setting it to driver (%s) maximum: %d", sz,
                driver_name, max_sz);
        sz = max_sz;
    } else {
        SCLogConfig("bypass-info-mp-size set to %d", sz);
    }
    *bypass_info_mp_size = sz;
    SCReturnInt(0);
}

static int RteFlowBypassGetNodeInt(
        SCConfNode *root_node, uint32_t *cfg_ret, const char *cfg_str, uint32_t def)
{
    SCEnter();
    uint32_t cfg_curr = 0;
    const char *entry_str = NULL;
    int ret = SCConfGetChildValue(root_node, cfg_str, &entry_str);
    /* Set to default if value is "auto" or missing */
    if (ret != 1 || strcmp(entry_str, "auto") == 0) {
        cfg_curr = def;
    } else {
        if (StringParseUint32(&cfg_curr, 10, 0, entry_str) < 0) {
            SCLogError("configuration for %s is not set to auto and contains non-numerical "
                       "characters - \"%s\"",
                    cfg_str, entry_str);
            SCReturnInt(-EINVAL);
        }
    }
    if (cfg_curr <= 0) {
        SCLogError(
                "configuration for %s is set to %d, but must be greater than 0", cfg_str, cfg_curr);
        SCReturnInt(-EINVAL);
    }
    SCLogConfig("%s set to %d", cfg_str, cfg_curr);
    *cfg_ret = cfg_curr;
    SCReturnInt(0);
}

int RteFlowBypassLoadConf(const char *driver_name, uint32_t *bypass_ring_size,
        uint32_t *bypass_ring_dequeue_burst_size, uint32_t *bypass_info_mempool_size)
{
    SCConfNode *dpdk_root = SCConfGetNode("dpdk");
    int retval = 0;
    retval += RteFlowBypassGetNodeInt(
            dpdk_root, bypass_ring_size, "bypass-ring-size", RTE_BYPASS_RING_SIZE_DEFAULT);
    retval += RteFlowBypassGetNodeInt(dpdk_root, bypass_ring_dequeue_burst_size,
            "bypass-ring-dequeue-burst-size", RTE_BYPASS_RING_DEQUEUE_BURST_SIZE_DEFAULT);
    retval += RteFlowBypassGetBypassInfoMPSize(driver_name, bypass_info_mempool_size);
    SCReturnInt(retval);
}
/**
 * \brief Enable and register functions for BypassManager,
 *        initialize rte_ring data structure and store in global
 *        variable
 *
 * \param iconf configuration of the interface
 * \param driver_name name of the driver
 * \return int 0 on success, negative value on error
 */
int RteBypassInit(DPDKIfaceConfig *iconf, const char *driver_name)
{
    SCEnter();
    static RteFlowBypassData *rte_flow_bypass_data = NULL;
    char *port_name = iconf->iface;
    LiveDevice *livedev = LiveGetDevice(port_name);
    LiveDevUseBypass(livedev);
    int retval = 0;

    /* We do not init the bypass data if the variable is already set */
    if (rte_flow_bypass_data != NULL) {
        iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;
        SCReturnInt(retval);
    }

    RunModeEnablesBypassManager();
    rte_flow_bypass_data = SCCalloc(1, sizeof(RteFlowBypassData));
    if (rte_flow_bypass_data == NULL) {
        SCLogError("%s: Memory allocation for RteFlowBypassData failed", port_name);
        SCReturnInt(-ENOMEM);
    }

    uint32_t bypass_info_mp_size, bypass_ring_size;
    retval = RteFlowBypassLoadConf(driver_name, &bypass_ring_size,
            &rte_flow_bypass_data->rte_ring_dequeue_burst_size, &bypass_info_mp_size);
    if (retval < 0) {
        goto cleanup;
    }

    struct rte_ring *bypass_ring =
            rte_ring_create(RTE_BYPASS_RING_NAME, bypass_ring_size, rte_socket_id(), RING_F_SC_DEQ);
    if (bypass_ring == NULL) {
        SCLogError("%s: rte_ring_create failed with (ring: %s): %s", port_name,
                RTE_BYPASS_RING_NAME, rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_ring = bypass_ring;

    uint32_t bypass_mp_size = (bypass_ring_size * 2) - 1;
    struct rte_mempool *bypass_mp = rte_mempool_create(RTE_BYPASS_MEMPOOL_NAME, bypass_mp_size,
            sizeof(FlowKey), MempoolCacheSizeCalculate(bypass_mp_size), 0, NULL, NULL, NULL, NULL,
            rte_socket_id(), 0);
    if (bypass_mp == NULL) {
        SCLogError("%s: rte_mempool_create failed (mempool: %s): %s", port_name,
                RTE_BYPASS_MEMPOOL_NAME, rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_mp = bypass_mp;

    struct rte_mempool *bypass_info_mp =
            rte_mempool_create(RTE_BYPASS_INFO_MEMPOOL_NAME, bypass_info_mp_size,
                    sizeof(RteFlowHandlerToFlow), MempoolCacheSizeCalculate(bypass_info_mp_size), 0,
                    NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (bypass_info_mp == NULL) {
        SCLogError("%s: rte_mempool_create failed (mempool: %s): %s", port_name,
                RTE_BYPASS_INFO_MEMPOOL_NAME, rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_info_mp = bypass_info_mp;

    BypassedFlowManagerRegisterCheckFunc(RteFlowBypassRuleLoad, NULL, (void *)rte_flow_bypass_data);

    rte_flow_bypass_data->rte_bypass_rule_capacity = DeviceDecideRteFlowRulesCapacity(driver_name);

    /* Destroys rte_flow rules of bypassed flows evicted during emergency mode */
    SCFlowRegisterFinishCallback(RteFlowHandleEmergency, NULL);

    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_active);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_created);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_enqueue_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_enqueue_error_ring_full);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_dequeue_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_max);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_occupancy);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_ops);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flow_lookup_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_key_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_info_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_query_error);

    iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;

    SCReturnInt(retval);

cleanup:
    SCFree(rte_flow_bypass_data);
    SCReturnInt(retval);
}

/**
 * \brief Decides whether the rte_flow rule is active and collects statistics for the flow.
 *        If the rule is not active, it should be removed from the table.
 *
 * \param fc FlowBypassInfo of the flow to check
 * \param livedev LiveDevice the flow belongs to
 * \param src_rule_handler rte_flow rule handler for specific flow in one direction
 * \param dst_rule_handler rte_flow rule handler for specific flow in other direction
 * \param flow flow to be possibly removed from the table
 * \return int 1 if the rte_flow rule is active, 0 if it should be removed
 */
static int RteFlowUpdateStats(FlowBypassInfo *fc, LiveDevice *livedev,
        struct rte_flow *src_rule_handler, struct rte_flow *dst_rule_handler)
{
    SCEnter();
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    uint32_t counter_id = COUNT_ACTION_ID;
    uint64_t src_packets = 0, src_bytes = 0, dst_packets = 0, dst_bytes = 0;

    query_count.reset = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    uint16_t port_id = livedev->dpdk_vars->port_id;
    int retval = rte_flow_query(
            port_id, src_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_query_error, 1);
    } else {
        src_packets = query_count.hits;
        src_bytes = query_count.bytes;
    }

    memset(&query_count, 0, sizeof(struct rte_flow_query_count));
    query_count.reset = 1;
    retval = rte_flow_query(
            port_id, dst_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_query_error, 1);
    } else {
        dst_packets = query_count.hits;
        dst_bytes = query_count.bytes;
    }

    /* Proceed only if there are new filtered packets in the flow */
    if (src_packets || dst_packets) {
        fc->tosrcpktcnt += src_packets;
        fc->tosrcbytecnt += src_bytes;
        fc->todstpktcnt += dst_packets;
        fc->todstbytecnt += dst_bytes;
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 * \brief Create rte_flow drop rule for dynamic bypass
 *
 * \param items array of pattern items
 * \param port_id identifier of a port
 * \param flow_handler rte_flow rule handler
 * \return int 0 on success, negative value on error
 */
static int RteFlowBypassRuleCreate(RteFlowBypassData *rte_flow_bypass_data,
        struct rte_flow_item *items, int port_id, struct rte_flow **flow_handler)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = RTE_JUMP_GROUP;

    uint32_t counter_id = COUNT_ACTION_ID;

    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    int retval = rte_flow_validate(port_id, &attr, items, action, &flow_error);
    if (retval != 0) {
        goto rule_failed;
    }

    *flow_handler = rte_flow_create(port_id, &attr, items, action, &flow_error);
    if (*flow_handler == NULL) {
        retval = -1;
        goto rule_failed;
    }
    SCReturnInt(retval);

rule_failed:
    SCLogError("rte_flow dynamic bypass: create rte_flow rule error %s errmsg: %s",
            rte_strerror(-retval), flow_error.message);
    SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
    SCReturnInt(retval);
}

static void RteFlowHandleEmergency(ThreadVars *tv, Flow *f, void *data)
{
    if (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED &&
            (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY) == 0) {
        return;
    }
    FlowBypassInfo *fc = SCFlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc == NULL)
        return;
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;
    if (flow_handler_info == NULL)
        return;
    if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
        LiveDevice *livedev = LiveDeviceGetById(f->livedev_id);
        RteFlowBiRuleDestroy(livedev->dpdk_vars->port_id, flow_handler_info->src_handler,
                flow_handler_info->dst_handler);
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        SC_ATOMIC_SUB(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 2);
    }
}

/**
 * \brief Destroy rte_flow rules for both directions of a flow
 *
 * \param port_id identifier of a port
 * \param src_handler handler of rte_flow rule
 * \param dst_handler handler of rte_flow rule
 */
static void RteFlowBiRuleDestroy(
        uint16_t port_id, struct rte_flow *src_handler, struct rte_flow *dst_handler)
{
    int retval = 0;
    struct rte_flow_error flow_error = { 0 };
    if (src_handler != NULL) {
        retval = rte_flow_destroy(port_id, src_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }

    if (dst_handler != NULL) {
        retval = rte_flow_destroy(port_id, dst_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }
}

/**
 * \brief Poll flow data from rte_flow_ring structure and create rte_flow bypass rule to bypass flow
 *        from both directions
 *
 * \param th_v thread vars
 * \param bypassstats bypass stats
 * \param curtime time
 * \param data table of flows and rte_flow rule handlers
 * \return int number of successfully created rte_flow rules
 */
int RteFlowBypassRuleLoad(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    SCEnter();
    RteFlowBypassData *rte_flow_bypass_data = (RteFlowBypassData *)data;
    struct rte_ring *bypass_ring = rte_flow_bypass_data->bypass_ring;
    struct rte_mempool *bypass_mp = rte_flow_bypass_data->bypass_mp;
    struct rte_flow_item items[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    uint16_t L2_INDEX = 0, L3_INDEX = 1, L4_INDEX = 2, END_INDEX = 3;
    uint16_t ring_dequeue_num = rte_flow_bypass_data->rte_ring_dequeue_burst_size;
    uint32_t success_count = 0;
    FlowKey *ring_data[ring_dequeue_num];

    memset(ring_data, 0, sizeof(ring_data));
    /* Initialize the reusable part of rte_flow rules */
    items[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    items[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    /* Bypass ring statistics, avg occupancy is calculated in DumpCounters().
       We exclude cycles where the ring is empty from the average*/
    unsigned int bypass_ring_curr = rte_ring_count(bypass_ring);
    if (bypass_ring_curr > SC_ATOMIC_GET(rte_flow_bypass_data->rte_bypass_ring_max))
        SC_ATOMIC_SET(rte_flow_bypass_data->rte_bypass_ring_max, bypass_ring_curr);
    SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_ring_occupancy, bypass_ring_curr);
    if (bypass_ring_curr > 0)
        SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_ring_ops, 1);

    uint32_t to_bypass_packets =
            rte_ring_dequeue_burst(bypass_ring, (void **)ring_data, ring_dequeue_num, NULL);
    /* rte_ring_dequeue_burst() returns the number of dequeued objects (>= 0);
     * it does not return a negative error code, so there is no dequeue error
     * to count. The success counter tracks every successfully dequeued
     * flow key. */
    SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_ring_dequeue_success, to_bypass_packets);
    for (uint32_t i = 0; i < to_bypass_packets; i++) {
        if (unlikely(suricata_ctl_flags != 0)) {
            /* Empty mempool of remaining unutilized entries */
            for (uint32_t j = i; j < to_bypass_packets; j++) {
                rte_mempool_put(bypass_mp, ring_data[j]);
            }
            SCReturnInt(success_count);
        }
        struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
        struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
        struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
        struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
        void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;

        FlowKey *flow_key = ring_data[i];
        uint16_t port_id = LiveDeviceGetById(flow_key->livedev_id)->dpdk_vars->port_id;
        uint32_t flow_hash = FlowKeyGetHash(flow_key);
        Flow *flow = FlowGetExistingFlowFromHash(flow_key, flow_hash);
        rte_mempool_put(bypass_mp, flow_key);

        /* If the flow has already ended (lookup failed) or the NIC's rte_flow
         * rule capacity is exhausted, we cannot install bypass rules. */
        if (flow == NULL || SC_ATOMIC_GET(rte_flow_bypass_data->rte_bypass_rules_active) + 2 >=
                                    rte_flow_bypass_data->rte_bypass_rule_capacity) {
            if (flow == NULL) {
                /* Flow expired before we could create its bypass rule */
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flow_lookup_error, 1);
            } else {
                /* NIC rule capacity exhausted, fall back to local bypass */
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_error, 1);
                FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
                FLOWLOCK_UNLOCK(flow);
            }
            continue;
        }

        /* Create rte_flow rule for original direction */
        if (FLOW_IS_IPV4(flow)) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule");
            ipv4_spec.hdr.src_addr = flow->src.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow->dst.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr.a, flow->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr.a, flow->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr, flow->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow->sp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow->dp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow->sp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow->dp);
            udp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &udp_spec;
            l4_mask = &udp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
        }

        items[L3_INDEX].spec = ip_spec;
        items[L3_INDEX].mask = ip_mask;
        items[L4_INDEX].spec = l4_spec;
        items[L4_INDEX].mask = l4_mask;

        struct rte_flow *src_rule_handler = NULL;
        int retval =
                RteFlowBypassRuleCreate(rte_flow_bypass_data, items, port_id, &src_rule_handler);

        /* Create rte_flow rule for the opposite direction */
        if (FLOW_IS_IPV4(flow)) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule in other direction");
            ipv4_spec.hdr.src_addr = flow->dst.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow->src.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
            memcpy(ipv6_spec.hdr.src_addr.a, flow->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr.a, flow->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
            memcpy(ipv6_spec.hdr.src_addr, flow->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow->dp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow->sp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow->dp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow->sp);
            udp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &udp_spec;
            l4_mask = &udp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
        }

        items[L3_INDEX].spec = ip_spec;
        items[L3_INDEX].mask = ip_mask;
        items[L4_INDEX].spec = l4_spec;
        items[L4_INDEX].mask = l4_mask;

        struct rte_flow *dst_rule_handler = NULL;
        retval += RteFlowBypassRuleCreate(rte_flow_bypass_data, items, port_id, &dst_rule_handler);

        /* If either rule creation failed, destroy both rules (the one that may
         * have succeeded and the one that failed) and fall back to local
         * bypass for this flow. */
        if (retval != 0) {
            RteFlowBiRuleDestroy(port_id, src_rule_handler, dst_rule_handler);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_error, 1);
            FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
            FLOWLOCK_UNLOCK(flow);
            continue;
        }

        int inet_family = FLOW_IS_IPV4(flow) ? AF_INET : AF_INET6;

        retval = RteFlowSetFlowBypassInfo(flow, src_rule_handler, dst_rule_handler, inet_family);
        if (retval == 0) {
            success_count++;
            /* 2 rte_flow rules (src + dst) installed for this flow */
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_active, 2);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_created, 2);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_success, 1);
        } else {
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_error, 1);
        }
        FLOWLOCK_UNLOCK(flow);
    }
    SCReturnInt(success_count);
}

bool RteBypassUpdate(Flow *flow, void *data, time_t tsec)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info == NULL) {
        /* Data already freed */
        return false;
    }
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    if (fc == NULL) {
        /* Data already freed */
        return false;
    }
    if (flow_handler_info->src_handler == NULL || flow_handler_info->dst_handler == NULL) {
        /* Rules already deleted */
        return false;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    bool activity = RteFlowUpdateStats(
            fc, livedev, flow_handler_info->src_handler, flow_handler_info->dst_handler);

    if (activity)
        flow->lastts = SCTIME_FROM_SECS(tsec);

    /* At shutdown, we only get the counters. We delete the rules with rte_flow_flush later */
    if (unlikely(suricata_ctl_flags != 0)) {
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        SC_ATOMIC_SUB(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 2);
        return activity;
    }

    if (!activity) {
        if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
            RteFlowBiRuleDestroy(livedev->dpdk_vars->port_id, flow_handler_info->src_handler,
                    flow_handler_info->dst_handler);
            flow_handler_info->src_handler = NULL;
            flow_handler_info->dst_handler = NULL;
            SC_ATOMIC_SUB(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 2);
        }
    }
    SCReturnBool(activity);
}

void RteBypassFree(void *data)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info == NULL) {
        return;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow_handler_info->livedev_id);
    if (livedev && livedev->dpdk_vars && livedev->dpdk_vars->rte_flow_bypass_data) {
        rte_mempool_put(
                livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp, flow_handler_info);
    }
}

static int RteFlowSetFlowBypassInfo(
        Flow *flow, struct rte_flow *src_handler, struct rte_flow *dst_handler, int family)
{
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    if (fc) {
        if (fc->bypass_data != NULL) {
            SCReturnInt(0);
        }
        RteFlowHandlerToFlow *flow_handler_info;
        if (rte_mempool_get(livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp,
                    (void **)&flow_handler_info) < 0) {
            SC_ATOMIC_ADD(
                    livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_mempool_info_get_error, 1);
            /* Mempool capacity has been reached, switch to local bypass */
            goto bypass_fail;
        }
        flow_handler_info->src_handler = src_handler;
        flow_handler_info->dst_handler = dst_handler;
        flow_handler_info->livedev_id = livedev->id;
        fc->bypass_data = flow_handler_info;
        fc->BypassUpdate = RteBypassUpdate;
        fc->BypassFree = RteBypassFree;
        LiveDevAddBypassStats(livedev, 1, family);
        LiveDevAddBypassSuccess(livedev, 1, family);
        SCReturnInt(0);
    }

bypass_fail:;
    RteFlowBiRuleDestroy(livedev->dpdk_vars->port_id, src_handler, dst_handler);
    LiveDevAddBypassFail(livedev, 1, family);
    FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
    SCReturnInt(-ENOMEM);
}

int RteFlowBypassCallback(Packet *p)
{
    if (p == NULL || p->flow == NULL) {
        SCReturnInt(0);
    }

    /* Only bypass TCP and UDP */
    if (!(PacketIsTCP(p) || PacketIsUDP(p))) {
        SCReturnInt(0);
    }

    FlowKey *flow_key = NULL;
    LiveDevice *livedev = LiveDeviceGetById(p->livedev_id);
    RteFlowBypassData *rte_flow_bypass_data = livedev->dpdk_vars->rte_flow_bypass_data;

    /* The tested rte_flow rule capacity of the device has been exhausted, new rules will be added
     * after bypassed flows time out and the existing rules are deleted */
    if (SC_ATOMIC_GET(rte_flow_bypass_data->rte_bypass_rules_active) + 2 >=
            rte_flow_bypass_data->rte_bypass_rule_capacity) {
        SCReturnInt(0);
    }

    if (rte_mempool_get(rte_flow_bypass_data->bypass_mp, (void **)&flow_key) < 0) {
        SCLogError("Memory allocation for rte_flow bypass data failed");
        SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_mempool_key_get_error, 1);
        SCReturnInt(0);
    }
    memset(flow_key, 0, sizeof(FlowKey));
    if (PacketIsIPv4(p)) {
        flow_key->src.family = AF_INET;
        flow_key->src.address.address_un_data32[0] = (GET_IPV4_SRC_ADDR_U32(p));
        flow_key->dst.family = AF_INET;
        flow_key->dst.address.address_un_data32[0] = (GET_IPV4_DST_ADDR_U32(p));
    } else if (PacketIsIPv6(p)) {
        flow_key->src.family = AF_INET6;
        memcpy(flow_key->src.address.address_un_data8, GET_IPV6_SRC_ADDR(p), 16 * sizeof(uint8_t));
        flow_key->dst.family = AF_INET6;
        memcpy(flow_key->dst.address.address_un_data8, GET_IPV6_DST_ADDR(p), 16 * sizeof(uint8_t));
    }
    if (p->proto == IPPROTO_TCP) {
        flow_key->proto = IPPROTO_TCP;
    } else {
        flow_key->proto = IPPROTO_UDP;
    }
    flow_key->sp = p->sp;
    flow_key->dp = p->dp;
    flow_key->livedev_id = p->livedev_id;
    flow_key->vlan_id[0] = p->vlan_id[0];
    flow_key->vlan_id[1] = p->vlan_id[1];
    flow_key->vlan_id[2] = p->vlan_id[2];
    flow_key->recursion_level = 0;

    int retval = rte_ring_mp_enqueue(rte_flow_bypass_data->bypass_ring, flow_key);
    /* If ring is full, continue with local bypass. Also, if Suricata shuts down, do not increase
     * counters */
    if (retval < 0) {
        rte_mempool_put(rte_flow_bypass_data->bypass_mp, flow_key);
        SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_ring_enqueue_error_ring_full, 1);
    } else {
        SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_ring_enqueue_success, 1);
    }
    retval = retval == 0 ? 1 : 0;
    SCReturnInt(retval);
}

#endif /* HAVE_DPDK */

/**
 * @}
 */
