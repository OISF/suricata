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
#include "util-conf.h"
#include "util-dpdk.h"
#include "source-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rte-flow.h"
#include "util-device-private.h"
#include "flow-private.h"
#include "flow.h"
#include "runmodes.h"
#include "threads.h"
#include "tm-threads.h"
#include "suricata.h"

#ifdef HAVE_DPDK

#define COUNT_ACTION_ID 1

#define RTE_BYPASS_RING_NAME                       "rte_bypass_ring"
#define RTE_BYPASS_MEMPOOL_NAME                    "rte_bypass_mempool"
#define RTE_BYPASS_INFO_MEMPOOL_NAME               "rte_bypass_info_mempool"
#define RTE_BYPASS_RING_SIZE_DEFAULT               16384
#define RTE_BYPASS_RING_DEQUEUE_BURST_SIZE_DEFAULT 16383

enum { L2_INDEX, VLAN_INDEX, L3_INDEX, L4_INDEX, END_INDEX };

static int RteFlowBypassGetBypassInfoMPSize(uint32_t, uint32_t *);
static int RteFlowBypassLoadConf(uint32_t, uint32_t *, uint32_t *, uint32_t *);
static int RteFlowBypassGetNodeInt(SCConfNode *, uint32_t *, const char *, uint32_t, bool);
static int RteFlowBypassRuleCreate(
        RteFlowNicBudget *, struct rte_flow_item *, int, struct rte_flow **);
static void RteBypassFree(void *data);
static void RteFlowHandleEmergency(ThreadVars *, Flow *, void *);
static void RteFlowBiRuleDestroy(uint16_t, struct rte_flow *, struct rte_flow *);
static int RteFlowUpdateStats(FlowBypassInfo *, LiveDevice *, struct rte_flow *, struct rte_flow *);
static int RteFlowSetFlowBypassInfo(
        Flow *, struct rte_flow *, struct rte_flow *, RteFlowNicBudget *, int);
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *);

typedef struct RteFlowHandlerToFlow_ {
    struct rte_flow *src_handler;
    struct rte_flow *dst_handler;
    RteFlowNicBudget *nic_budget;
    uint16_t livedev_id;
} RteFlowHandlerToFlow;

static RteFlowBypassData *rte_flow_bypass_data = NULL;

/**
 * \brief Register the per-NIC rule budget of a physical NIC, if not present yet.
 *
 * \param bypass_data shared rte_flow bypass data
 * \param resource_id user-configured identity of the physical resource
 * \param driver_name name of the driver (rule capacity)
 * \return RteFlowNicBudget budget of the NIC, NULL on error
 */
static RteFlowNicBudget *RteFlowBypassDataRegisterNic(
        RteFlowBypassData *bypass_data, uint32_t resource_id, const char *driver_name)
{
    if (resource_id == DPDK_RESOURCE_ID_UNSET) {
        return NULL;
    }
    for (uint32_t i = 0; i < bypass_data->nic_cnt; i++) {
        if (bypass_data->nic_budgets[i].resource_id == resource_id) {
            /* Already registered by another interface of this NIC. */
            return &bypass_data->nic_budgets[i];
        }
    }

    if (bypass_data->nic_cnt >= RTE_BYPASS_MAX_NICS) {
        SCLogError(
                "rte_flow bypass: too many distinct physical NICs (max %d)", RTE_BYPASS_MAX_NICS);
        return NULL;
    }

    RteFlowNicBudget *budget = &bypass_data->nic_budgets[bypass_data->nic_cnt];
    budget->resource_id = resource_id;
    budget->rule_capacity = DeviceDecideRteFlowRulesCapacity(driver_name);
    bypass_data->total_rule_capacity += budget->rule_capacity;
    SC_ATOMIC_INIT(budget->rules_active);
    SC_ATOMIC_INIT(budget->rules_created);
    SC_ATOMIC_INIT(budget->rules_error);
    bypass_data->nic_cnt++;

    SCLogConfig("rte_flow bypass: physical NIC %d registered with capacity %d rules", resource_id,
            budget->rule_capacity);
    return budget;
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
 * \brief Set the user-configured identity of the physical NIC to the interface.
 *
 * \param iconf configuration of the interface
 * \param entry_int parsed resource-id value (intmax_t)
 * \return 0 on success, negative value on error
 */
int ConfigSetResourceId(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int < 0 || entry_int > UINT16_MAX) {
        SCLogError("%s: resource-id needs to be between 0 and %d", iconf->iface,
                DPDK_RESOURCE_ID_UNSET - 1);
        SCReturnInt(-EINVAL);
    } else if (entry_int == DPDK_RESOURCE_ID_UNSET && iconf->capture_bypass_enabled) {
        SCLogError("%s: capture-bypass enabled but resource-id not set", iconf->iface);
        SCReturnInt(-EINVAL);
    }
    iconf->resource_id = (uint16_t)entry_int;
    SCLogConfig("%s: resource-id set to %" PRIu16, iconf->iface, iconf->resource_id);
    SCReturnInt(0);
}

/**
 * \brief Get bypass-info mempool size from suricata.yaml.
 *
 * The mempool is shared by all physical NICs, so when not user-configured its
 * size is derived from the summed rte_flow rule capacity of all devices.
 *
 * \param total_capacity summed rte_flow rule capacity of all devices
 * \param[out] bypass_info_mp_size size of the mempool from config or maximum
 * capacity of rte_flow rules all devices can handle.
 * \return 0 on success, negative value on error
 */
static int RteFlowBypassGetBypassInfoMPSize(uint32_t total_capacity, uint32_t *bypass_info_mp_size)
{
    SCEnter();
    SCConfNode *dpdk_root = SCConfGetNode("dpdk");

    /* We want to have a mempool of size (2^n)-1. Half the total capacity is enough, each
     * mempool object holds info about 2 rules */
    uint32_t max_sz = total_capacity / 2 - 1;
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
        SCLogConfig("bypass-info-mp-size too big (%d), setting it to the maximum: %d", sz, max_sz);
        sz = max_sz;
    } else {
        SCLogConfig("bypass-info-mp-size set to %d", sz);
    }
    *bypass_info_mp_size = sz;
    SCReturnInt(0);
}

/**
 * \brief Get an integer value from the dpdk configuration node.
 *
 * \param root_node dpdk configuration node
 * \param[out] cfg_ret parsed configuration value
 * \param cfg_str name of the configuration key
 * \param def default value used when the key is missing or set to "auto"
 * \param is_pow2 whether the value must be a power of 2
 * \return 0 on success, negative value on error
 */
static int RteFlowBypassGetNodeInt(
        SCConfNode *root_node, uint32_t *cfg_ret, const char *cfg_str, uint32_t def, bool is_pow2)
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
            SCLogError("Configuration for %s is not set to auto and contains non-numerical "
                       "characters - \"%s\"",
                    cfg_str, entry_str);
            SCReturnInt(-EINVAL);
        }
    }
    if (cfg_curr <= 0) {
        SCLogError(
                "Configuration for %s is set to %d, but must be greater than 0", cfg_str, cfg_curr);
        SCReturnInt(-EINVAL);
    } else if (is_pow2 && !rte_is_power_of_2(cfg_curr)) {
        SCLogError(
                "Configuration for %s is set to %d, but must be a power of 2", cfg_str, cfg_curr);
        SCReturnInt(-EINVAL);
    }
    *cfg_ret = cfg_curr;
    SCReturnInt(0);
}

/**
 * \brief Load the shared rte_flow bypass tunables from suricata.yaml.
 *
 * \param driver_name name of the driver (for logging)
 * \param total_capacity summed rte_flow rule capacity of all devices
 * \param[out] bypass_ring_size size of the bypass ring
 * \param[out] bypass_ring_dequeue_burst_size burst size of dequeuing flows
 *        from the bypass ring
 * \param[out] bypass_info_mempool_size size of the bypass info mempool
 * \return 0 on success, negative value on error
 */
static int RteFlowBypassLoadConf(uint32_t total_capacity, uint32_t *bypass_ring_size,
        uint32_t *bypass_ring_dequeue_burst_size, uint32_t *bypass_info_mempool_size)
{
    SCConfNode *dpdk_root = SCConfGetNode("dpdk");
    int retval = 0;

    retval = RteFlowBypassGetNodeInt(
            dpdk_root, bypass_ring_size, "bypass-ring-size", RTE_BYPASS_RING_SIZE_DEFAULT, true);
    SCLogConfig("bypass-ring-size set to %d", *bypass_ring_size);
    if (retval != 0) {
        SCReturnInt(retval);
    }
    retval = RteFlowBypassGetNodeInt(dpdk_root, bypass_ring_dequeue_burst_size,
            "bypass-ring-dequeue-burst-size", RTE_BYPASS_RING_DEQUEUE_BURST_SIZE_DEFAULT, false);
    if (*bypass_ring_size < *bypass_ring_dequeue_burst_size) {
        SCLogWarning("Configuration for bypass-ring-dequeue-burst-size (%d) is larger than "
                     "bypass-ring-size (%d), capping to %d",
                *bypass_ring_size, *bypass_ring_dequeue_burst_size, *bypass_ring_size - 1);
        *bypass_ring_dequeue_burst_size = *bypass_ring_size - 1;
    }
    if (retval != 0) {
        SCReturnInt(retval);
    }
    SCLogConfig("bypass-ring-dequeue-burst-size set to %d", *bypass_ring_dequeue_burst_size);

    retval = RteFlowBypassGetBypassInfoMPSize(total_capacity, bypass_info_mempool_size);
    SCReturnInt(retval);
}

/**
 * \brief Register the interface's physical NIC budget into the shared bypass
 *        data. The livedev ID and driver name of the FIRST successfully
 *        registered interface are recorded for RteBypassFinalize(), which is
 *        invoked from DeviceConfigureDynamicBypass() once the last device is
 *        configured.
 *
 * \param iconf configuration of the interface
 * \param driver_name name of the driver
 * \return int 0 on success, negative value on error
 */
int RteBypassRegister(DPDKIfaceConfig *iconf, const char *driver_name)
{
    SCEnter();
    char *port_name = iconf->iface;
    LiveDevice *livedev = LiveGetDevice(port_name);
    if (livedev == NULL) {
        SCReturnInt(-EINVAL);
    }
    LiveDevUseBypass(livedev);

    iconf->dpdk_dev_resources->resource_id = iconf->resource_id;

    /* Perform only at first pass */
    if (rte_flow_bypass_data == NULL) {
        rte_flow_bypass_data = SCCalloc(1, sizeof(RteFlowBypassData));
        if (rte_flow_bypass_data == NULL) {
            SCLogError("%s: Memory allocation for RteFlowBypassData failed", port_name);
            SCReturnInt(-ENOMEM);
        }
        SC_ATOMIC_INIT(rte_flow_bypass_data->ref_cnt);
        rte_flow_bypass_data->counter_update_livedev_id = livedev->id;
    }

    RteFlowNicBudget *nic_budget =
            RteFlowBypassDataRegisterNic(rte_flow_bypass_data, iconf->resource_id, driver_name);
    if (nic_budget == NULL) {
        if (SC_ATOMIC_GET(rte_flow_bypass_data->ref_cnt) == 0 &&
                rte_flow_bypass_data->nic_cnt == 0) {
            SCFree(rte_flow_bypass_data);
            rte_flow_bypass_data = NULL;
        }
        SCReturnInt(-EINVAL);
    }

    iconf->dpdk_dev_resources->nic_budget = nic_budget;
    iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;
    RteBypassIncRef(rte_flow_bypass_data);

    SCReturnInt(0);
}

/**
 * \brief Finalize the shared rte_flow bypass: create the shared ring and
 *        mempools, register the BypassManager callback and the flow finish
 *        callback.
 *
 * \return int 0 on success, negative value on error
 */
int RteBypassFinalize(void)
{
    SCEnter();
    if (rte_flow_bypass_data == NULL) {
        SCReturnInt(0);
    }
    uint32_t bypass_ring_size = 0, bypass_mp_size = 0, bypass_info_mp_size = 0;
    int retval = RteFlowBypassLoadConf(rte_flow_bypass_data->total_rule_capacity, &bypass_ring_size,
            &rte_flow_bypass_data->rte_ring_dequeue_burst_size, &bypass_info_mp_size);
    if (retval < 0) {
        goto cleanup;
    }

    FlowKey **ring_dequeue_buffer =
            SCCalloc(rte_flow_bypass_data->rte_ring_dequeue_burst_size, sizeof(FlowKey *));
    if (ring_dequeue_buffer == NULL) {
        retval = -ENOMEM;
        goto cleanup;
    }
    rte_flow_bypass_data->ring_dequeue_buffer = ring_dequeue_buffer;

    struct rte_ring *bypass_ring =
            rte_ring_create(RTE_BYPASS_RING_NAME, bypass_ring_size, rte_socket_id(), RING_F_SC_DEQ);
    if (bypass_ring == NULL) {
        SCLogError("rte_ring_create failed with (ring: %s): %s", RTE_BYPASS_RING_NAME,
                rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_ring = bypass_ring;

    bypass_mp_size = (bypass_ring_size * 2) - 1;
    struct rte_mempool *bypass_mp = rte_mempool_create(RTE_BYPASS_MEMPOOL_NAME, bypass_mp_size,
            sizeof(FlowKey), MempoolCacheSizeCalculate(bypass_mp_size), 0, NULL, NULL, NULL, NULL,
            rte_socket_id(), 0);
    if (bypass_mp == NULL) {
        SCLogError("rte_mempool_create failed (mempool: %s): %s", RTE_BYPASS_MEMPOOL_NAME,
                rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_mp = bypass_mp;

    struct rte_mempool *bypass_info_mp =
            rte_mempool_create(RTE_BYPASS_INFO_MEMPOOL_NAME, bypass_info_mp_size,
                    sizeof(RteFlowHandlerToFlow), MempoolCacheSizeCalculate(bypass_info_mp_size), 0,
                    NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (bypass_info_mp == NULL) {
        SCLogError("rte_mempool_create failed (mempool: %s): %s", RTE_BYPASS_INFO_MEMPOOL_NAME,
                rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_info_mp = bypass_info_mp;

    RunModeEnablesBypassManager();
    retval = BypassedFlowManagerRegisterCheckFunc(
            RteFlowBypassRuleLoad, NULL, (void *)rte_flow_bypass_data);
    if (retval < 0) {
        SCLogError("Bypass Manager callback failed");
        goto cleanup;
    }
    /* Destroys rte_flow rules of bypassed flows evicted during emergency mode */
    if (!SCFlowRegisterFinishCallback(RteFlowHandleEmergency, NULL)) {
        SCLogError("Flow finish callback registration failed");
        goto cleanup;
    }

    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_query_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_enqueue_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_enqueue_error_ring_full);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_dequeue_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_max);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_occupancy);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_ring_ops);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_lookup_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_key_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_info_get_error);

    SCReturnInt(0);

cleanup:
    int ref_cnt = SC_ATOMIC_GET(rte_flow_bypass_data->ref_cnt);
    while (ref_cnt > 0) {
        RteBypassDecRef(&rte_flow_bypass_data);
        ref_cnt--;
    }
    SCReturnInt(retval);
}

/**
 * \brief Increase the reference count of the shared rte_flow bypass data.
 *
 * \param bypass_data rte_flow bypass data
 */
void RteBypassIncRef(RteFlowBypassData *bypass_data)
{
    if (bypass_data == NULL)
        return;
    SC_ATOMIC_ADD(bypass_data->ref_cnt, 1);
}

/**
 * \brief Decrease the reference count of the shared rte_flow bypass data.
 *        Free resources if the refcount hits 0.
 *
 * \param bypass_data shared rte_flow bypass data
 */
void RteBypassDecRef(RteFlowBypassData **bypass_data_ref)
{
    RteFlowBypassData *bypass_data = *bypass_data_ref;
    if (bypass_data == NULL)
        return;

    if (SC_ATOMIC_SUB(bypass_data->ref_cnt, 1) != 1)
        return;

    if (bypass_data->bypass_mp) {
        rte_mempool_free(bypass_data->bypass_mp);
        bypass_data->bypass_mp = NULL;
    }
    if (bypass_data->bypass_info_mp) {
        rte_mempool_free(bypass_data->bypass_info_mp);
        bypass_data->bypass_info_mp = NULL;
    }
    if (bypass_data->bypass_ring) {
        rte_ring_free(bypass_data->bypass_ring);
        bypass_data->bypass_ring = NULL;
    }
    if (bypass_data->ring_dequeue_buffer) {
        SCFree(bypass_data->ring_dequeue_buffer);
        bypass_data->ring_dequeue_buffer = NULL;
    }
    SCFree(bypass_data);
    *bypass_data_ref = NULL;
}

/**
 * \brief Create a jump rule in the rte_flow default group to the group for bypass rules.
 *  In some NICs, the default group has less capacity and higher rule insertion latency.
 *
 * \param port_id port id of the device to create the rule on
 * \param port_name name of the device's port
 * \return int 0 on success, negative value on error
 */
int RteFlowCreateJumpRule(uint16_t port_id, const char *port_name)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = RTE_GROUP_DEFAULT;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_action_jump jump = {
        .group = RTE_GROUP_JUMP,
    };

    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[0].conf = &jump;

    struct rte_flow *flow_handler = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow_handler == NULL) {
        SCLogWarning(
                "%s: Error when creating rte_flow jump rule: %s", port_name, flow_error.message);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief Decides whether the rte_flow rule is active and collects statistics for the flow.
 *        If the rule is not active, it should be removed from the table.
 *
 * \param fc FlowBypassInfo of the flow to check
 * \param livedev LiveDevice the flow belongs to
 * \param src_rule_handler rte_flow rule handler for specific flow in one direction
 * \param dst_rule_handler rte_flow rule handler for specific flow in other direction
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
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_query_error, 1);
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
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_query_error, 1);
    } else {
        dst_packets = query_count.hits;
        dst_bytes = query_count.bytes;
    }

    /* Proceed only if there are new filtered packets in the flow */
    if (src_packets || dst_packets) {
        fc->tosrcpktcnt += dst_packets;
        fc->tosrcbytecnt += dst_bytes;
        fc->todstpktcnt += src_packets;
        fc->todstbytecnt += src_bytes;
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 * \brief Create rte_flow drop rule for dynamic bypass
 *
 * \param nic_budget rule budget of the NIC the rule is created on
 * \param items array of pattern items
 * \param port_id identifier of a port
 * \param flow_handler rte_flow rule handler
 * \return int 0 on success, negative value on error
 */
static int RteFlowBypassRuleCreate(RteFlowNicBudget *nic_budget, struct rte_flow_item *items,
        int port_id, struct rte_flow **flow_handler)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = RTE_GROUP_JUMP;

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
    SC_ATOMIC_ADD(nic_budget->rules_error, 1);
    SCReturnInt(retval);
}

static void RteFlowHandleEmergency(ThreadVars *tv, Flow *f, void *data)
{
    if (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED ||
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
        if (livedev == NULL || livedev->dpdk_vars == NULL ||
                livedev->dpdk_vars->rte_flow_bypass_data == NULL) {
            /* LiveDevice or bypass data already freed */
            return;
        }
        uint16_t port_id = livedev->dpdk_vars->port_id;
        RteFlowBiRuleDestroy(
                port_id, flow_handler_info->src_handler, flow_handler_info->dst_handler);
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        if (flow_handler_info->nic_budget != NULL)
            SC_ATOMIC_SUB(flow_handler_info->nic_budget->rules_active, 2);
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
 * \param data pointer to RteFlowBypassData structure
 * \return int number of successfully created rte_flow rules
 */
int RteFlowBypassRuleLoad(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    SCEnter();
    RteFlowBypassData *rte_flow_bypass_data = (RteFlowBypassData *)data;
    struct rte_ring *bypass_ring = rte_flow_bypass_data->bypass_ring;
    struct rte_mempool *bypass_mp = rte_flow_bypass_data->bypass_mp;
    struct rte_flow_item items[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    uint32_t ring_dequeue_num = rte_flow_bypass_data->rte_ring_dequeue_burst_size;
    uint32_t success_count = 0;
    FlowKey **ring_data = rte_flow_bypass_data->ring_dequeue_buffer;

    /* Clear the buffer from any leftover data */
    memset(ring_data, 0, rte_flow_bypass_data->rte_ring_dequeue_burst_size * sizeof(FlowKey *));
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
        struct rte_flow_item_vlan vlan_spec = { 0 }, vlan_mask = { 0 };
        struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
        struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
        struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
        struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
        void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;

        FlowKey *flow_key = ring_data[i];
        LiveDevice *livedev = LiveDeviceGetById(flow_key->livedev_id);
        if (livedev == NULL || livedev->dpdk_vars == NULL ||
                livedev->dpdk_vars->nic_budget == NULL) {
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_lookup_error, 1);
            rte_mempool_put(bypass_mp, flow_key);
            continue;
        }
        uint16_t port_id = livedev->dpdk_vars->port_id;
        RteFlowNicBudget *nic_budget = livedev->dpdk_vars->nic_budget;
        uint32_t flow_hash = FlowKeyGetHash(flow_key);
        /* We acquire a LOCKED flow here */
        Flow *flow = FlowGetExistingFlowFromHash(flow_key, flow_hash);
        rte_mempool_put(bypass_mp, flow_key);

        /* If the flow has already ended (lookup failed), the flow's state has changed
           or the NIC's rte_flow rule capacity is exhausted, we cannot install bypass rules. */
        if (flow == NULL || (flow->flow_state != FLOW_STATE_CAPTURE_BYPASSED) ||
                SC_ATOMIC_GET(nic_budget->rules_active) + 2 >= nic_budget->rule_capacity) {
            if (flow == NULL) {
                /* Flow expired before we could create its bypass rule */
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_lookup_error, 1);
            } else if (flow->flow_state != FLOW_STATE_CAPTURE_BYPASSED) {
                /* Flow is no longer in the correct state to create bypass rules */
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_lookup_error, 1);
                FLOWLOCK_UNLOCK(flow);
            } else {
                /* NIC rule capacity exhausted, fall back to local bypass */
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_error, 1);
                FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
                FLOWLOCK_UNLOCK(flow);
            }
            continue;
        }

        /* If the flow is VLAN tagged, insert a VLAN pattern item matching the
         * outermost VLAN ID so the bypass rule only matches tagged traffic of
         * this flow. */
        if (flow->vlan_idx) {
            SCLogDebug("Add a VLAN rte_flow bypass rule (VLAN ID %u)", flow->vlan_id[0]);
            vlan_spec.hdr.vlan_tci = htons(flow->vlan_id[0]);
            vlan_mask.hdr.vlan_tci = htons(0x0FFF);
            items[VLAN_INDEX].type = RTE_FLOW_ITEM_TYPE_VLAN;
            items[VLAN_INDEX].spec = &vlan_spec;
            items[VLAN_INDEX].mask = &vlan_mask;
        } else {
            items[VLAN_INDEX].type = RTE_FLOW_ITEM_TYPE_VOID;
            items[VLAN_INDEX].spec = NULL;
            items[VLAN_INDEX].mask = NULL;
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
        int retval = RteFlowBypassRuleCreate(nic_budget, items, port_id, &src_rule_handler);

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
        retval += RteFlowBypassRuleCreate(nic_budget, items, port_id, &dst_rule_handler);

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

        retval = RteFlowSetFlowBypassInfo(
                flow, src_rule_handler, dst_rule_handler, nic_budget, inet_family);
        if (retval == 0) {
            success_count++;
            /* 2 rte_flow rules (src + dst) installed for this flow */
            SC_ATOMIC_ADD(nic_budget->rules_active, 2);
            SC_ATOMIC_ADD(nic_budget->rules_created, 2);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_success, 1);
        } else {
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flows_bypass_error, 1);
        }
        FLOWLOCK_UNLOCK(flow);
    }
    SCReturnInt(success_count);
}

/**
 * \brief Update statistics of a bypassed flow and destroy its rte_flow rules
 *        when the flow is no longer active.
 *
 * \param flow flow to update
 * \param data RteFlowHandlerToFlow holding the flow's rte_flow rule handlers
 * \param tsec current time in seconds
 * \return bool true if the flow is still active, false if it can be evicted
 */
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
    if (livedev == NULL || livedev->dpdk_vars == NULL ||
            livedev->dpdk_vars->rte_flow_bypass_data == NULL) {
        /* LiveDevice or bypass data already freed */
        return false;
    }
    bool activity = RteFlowUpdateStats(
            fc, livedev, flow_handler_info->src_handler, flow_handler_info->dst_handler);

    if (activity)
        flow->lastts = SCTIME_FROM_SECS(tsec);

    /* At shutdown, we only get the counters. We delete the rules with rte_flow_flush later */
    if (unlikely(suricata_ctl_flags != 0)) {
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        if (flow_handler_info->nic_budget != NULL)
            SC_ATOMIC_SUB(flow_handler_info->nic_budget->rules_active, 2);
        return activity;
    }

    if (!activity) {
        if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
            RteFlowBiRuleDestroy(livedev->dpdk_vars->port_id, flow_handler_info->src_handler,
                    flow_handler_info->dst_handler);
            flow_handler_info->src_handler = NULL;
            flow_handler_info->dst_handler = NULL;
            if (flow_handler_info->nic_budget != NULL)
                SC_ATOMIC_SUB(flow_handler_info->nic_budget->rules_active, 2);
        }
    }
    SCReturnBool(activity);
}

/**
 * \brief Free the memory allocated for the flow bypass data
 *
 * \param data pointer to the flow bypass data
 */
static void RteBypassFree(void *data)
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

/**
 * \brief Store the rte_flow rule handlers of a bypassed flow in its flow
 *        bypass info. On failure, destroy the created rules and fall back to
 *        local bypass.
 *
 * \param flow flow that is being bypassed
 * \param src_handler rte_flow rule handler for the original direction
 * \param dst_handler rte_flow rule handler for the opposite direction
 * \param nic_budget rule budget of the NIC the rules are created on
 * \param family address family of the flow (AF_INET or AF_INET6)
 * \return int 0 on success, negative value on error
 */
static int RteFlowSetFlowBypassInfo(Flow *flow, struct rte_flow *src_handler,
        struct rte_flow *dst_handler, RteFlowNicBudget *nic_budget, int family)
{
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    int retval = 0;
    if (fc) {
        if (fc->bypass_data != NULL) {
            retval = -EEXIST;
            goto bypass_fail;
        }
        RteFlowHandlerToFlow *flow_handler_info;
        if (rte_mempool_get(livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp,
                    (void **)&flow_handler_info) < 0) {
            SC_ATOMIC_ADD(
                    livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_mempool_info_get_error, 1);
            /* Mempool capacity has been reached, switch to local bypass */
            FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
            retval = -ENOMEM;
            goto bypass_fail;
        }
        flow_handler_info->src_handler = src_handler;
        flow_handler_info->dst_handler = dst_handler;
        flow_handler_info->nic_budget = nic_budget;
        flow_handler_info->livedev_id = livedev->id;
        fc->bypass_data = flow_handler_info;
        fc->BypassUpdate = RteBypassUpdate;
        fc->BypassFree = RteBypassFree;
        LiveDevAddBypassStats(livedev, 1, family);
        LiveDevAddBypassSuccess(livedev, 1, family);
        SCReturnInt(retval);
    }

bypass_fail:;
    RteFlowBiRuleDestroy(livedev->dpdk_vars->port_id, src_handler, dst_handler);
    LiveDevAddBypassFail(livedev, 1, family);
    SCReturnInt(retval);
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
    if (livedev == NULL || livedev->dpdk_vars == NULL ||
            livedev->dpdk_vars->rte_flow_bypass_data == NULL) {
        SCReturnInt(0);
    }
    RteFlowBypassData *rte_flow_bypass_data = livedev->dpdk_vars->rte_flow_bypass_data;

    RteFlowNicBudget *nic_budget = livedev->dpdk_vars->nic_budget;
    if (nic_budget == NULL ||
            SC_ATOMIC_GET(nic_budget->rules_active) + 2 >= nic_budget->rule_capacity) {
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
    /* If ring is full, continue with local bypass. */
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
