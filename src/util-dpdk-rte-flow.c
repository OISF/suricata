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
#include "runmode-dpdk.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"
#include "util-device-private.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "suricata.h"

#ifdef HAVE_DPDK
#include <rte_ring.h>

#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

#define INITIAL_RTE_FLOW_RULE_COUNT_CAPACITY 5
#define DATA_BUFFER_SIZE                     1024
#define COUNT_ACTION_ID                      128
#define RTE_BYPASS_RING_NAME                 "rte_bypass_ring"
#define RTE_BYPASS_MEMPOOL_NAME              "rte_bypass_mempool"

static int RteFlowRuleStorageInit(RteFlowRuleStorage *);
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *, const char *);
static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *);
static char *DriverSpecificErrorMessage(const char *, struct rte_flow_item *);
static bool RteFlowRulesContainPatternWildcard(char **, uint32_t);
static bool RteFlowDropFilterInit(uint32_t, char **, struct rte_flow_attr *,
        struct rte_flow_action *, uint32_t *, const char *, const char *);
static int RteFlowBypassRuleCreate(struct rte_flow_item *, int, struct rte_flow **);
static int RteFlowUpdateStats(FlowBypassInfo *, uint16_t, struct rte_flow *, struct rte_flow *);
static int RteFlowSetFlowBypassInfo(Flow *, struct rte_flow *, struct rte_flow *, int);

/**
 * \brief Specify ambiguous error messages as some drivers have specific
 *        behaviour when creating rte_flow rules
 *
 * \param driver_name name of a driver
 * \param items array of pattern items
 */
static char *DriverSpecificErrorMessage(const char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        if (iceDeviceRteFlowPatternError(items) == true) {
            char msg[] = "Driver specific errmsg: ice driver does not support broad patterns";
            char *ret = SCCalloc((strlen(msg) + 1), sizeof(char));
            strlcpy(ret, msg, sizeof(char) * (strlen(msg) + 1));
            return ret;
        }
    }

    return NULL;
}

/**
 * \brief Checks whether at least one pattern contains wildcard matching
 *
 * \param patterns array of loaded rte_flow rule patterns from suricata.yaml
 * \param rule_count number of loaded rte_flow rule patterns
 * \return true pattern contains wildcard matching
 * \return false pattern does not contain wildcard matching
 */
static bool RteFlowRulesContainPatternWildcard(char **patterns, uint32_t rule_count)
{
    for (size_t i = 0; i < rule_count; i++) {
        char *pattern = patterns[i];
        if (strstr(pattern, " mask ") != NULL || (strstr(pattern, " last ") != NULL))
            return true;
    }
    return false;
}

/**
 * \brief Initializes rte_flow rules and decides whether statistics about the rule (count of
 *        filtered packets) can be gathered or not
 *
 * \param rule_count number of rte_flow rules present
 * \param patterns array of patterns for rte_flow rules
 * \param attr out variable for initialized rte_flow attributes
 * \param action out variable for initialized rte_flow action
 * \param counter_id id of a rte_flow counter action
 * \param driver_name name of the driver
 * \param port_name name of the port
 * \return true if statistics about rte_flow rules can be gathered
 * \return false if statistics about rte_flow rules can not be gathered
 */
static bool RteFlowDropFilterInit(uint32_t rule_count, char **patterns, struct rte_flow_attr *attr,
        struct rte_flow_action *action, uint32_t *counter_id, const char *driver_name,
        const char *port_name)
{
    attr->ingress = 1;
    attr->priority = 0;

    /* ICE PMD does not support count action with wildcard pattern (mask and last pattern item
     * types). The count action is omitted when wildcard pattern is detected */
    if (strcmp(driver_name, "net_ice") == 0) {
        if (RteFlowRulesContainPatternWildcard(patterns, rule_count) == true) {
            action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
            action[1].type = RTE_FLOW_ACTION_TYPE_END;
            SCLogWarning(
                    "%s: gathering statistic for the rte_flow rule is disabled because of wildcard "
                    "pattern (ice PMD specific)",
                    port_name);
            return false;
        }
/* ICE PMD has to have attribute group set to 2 on DPDK 23.11 and higher for the count action to
 * work properly */
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)
        attr->group = 2;
#else
        attr->group = 0;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0) */
    }

    if (strcmp(driver_name, "net_ice") == 0 || strcmp(driver_name, "mlx5_pci") == 0) {

        action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
        action[0].conf = counter_id;
        action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[2].type = RTE_FLOW_ACTION_TYPE_END;

        return true;
    }

    action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;
    return false;
}

static int RteFlowRuleStorageInit(RteFlowRuleStorage *rule_storage)
{
    SCEnter();
    rule_storage->rule_cnt = 0;
    rule_storage->rule_size = INITIAL_RTE_FLOW_RULE_COUNT_CAPACITY;
    rule_storage->rules = SCCalloc(rule_storage->rule_size, sizeof(char *));

    if (rule_storage->rules == NULL) {
        SCLogError("Setup memory allocation for rte_flow rule storage failed");
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *rule_storage, const char *rule)
{
    SCEnter();
    rule_storage->rules[rule_storage->rule_cnt] = SCCalloc(strlen(rule) + 1, sizeof(char));
    if (rule_storage->rules[rule_storage->rule_cnt] == NULL) {
        SCLogError("Memory allocation for rte_flow rule string failed");
        RteFlowRuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    strlcpy(rule_storage->rules[rule_storage->rule_cnt], rule, (strlen(rule) + 1) * sizeof(char));
    rule_storage->rule_cnt++;

    if (rule_storage->rule_cnt == rule_storage->rule_size) {
        int retval = RteFlowRuleStorageExtendCapacity(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }
    }
    SCReturnInt(0);
}

static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *rule_storage)
{
    SCEnter();
    char **tmp_rules;

    rule_storage->rule_size = 2 * rule_storage->rule_size;
    tmp_rules = SCRealloc(rule_storage->rules, rule_storage->rule_size * sizeof(char *));

    if (tmp_rules == NULL) {
        SCLogError("Memory reallocation for rte_flow rule storage failed");
        RteFlowRuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    rule_storage->rules = tmp_rules;
    SCReturnInt(0);
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */

/**
 * \brief Deallocation of memory containing user set rte_flow rules
 *
 * \param rule_storage rules loaded from suricata.yaml
 */
void RteFlowRuleStorageFree(RteFlowRuleStorage *rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

    if (rule_storage->rules == NULL) {
        SCReturn;
    }
    for (int i = 0; i < rule_storage->rule_cnt; ++i) {
        SCFree(rule_storage->rules[i]);
    }
    SCFree(rule_storage->rules);
    rule_storage->rules = NULL;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
}

/**
 * \brief Load rte_flow rules patterns from suricata.yaml
 *
 * \param if_root root node in suricata.yaml
 * \param if_default default value
 * \param filter_type type of rte_flow rules to be loaded, only drop_filter is supported
 * \param rule_storage pointer to structure to load rte_flow rules into
 * \return int 0 on success, -1 on error
 */
int ConfigLoadRteFlowRules(
        SCConfNode *if_root, const char *filter_type, RteFlowRuleStorage *rule_storage)
{
    SCEnter();
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCConfNode *node = SCConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("No configuration node found for %s", filter_type);
    } else {
        SCConfNode *rule_node;
        const char *rule;
        int retval = RteFlowRuleStorageInit(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }

        TAILQ_FOREACH (rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {
                SCConfGetChildValue(rule_node, "rule", &rule);
                retval = RteFlowRuleStorageAddRule(rule_storage, rule);
                if (retval != 0) {
                    SCReturnInt(retval);
                }
            } else {
                SCLogError("Found string that is not \"rule\" in dpdk dropfilter section in "
                           "suricata.yaml");
                SCReturnInt(-1);
            }
        }
    }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
    SCReturnInt(0);
}

/**
 * \brief Query the number of packets filtered by rte_flow rules defined by user in suricata.yaml
 *
 * \param rules array of rte_flow rule handlers
 * \param rule_count number of existing rules
 * \param port_id id of a port
 * \param filtered_packets out variable for the number of packets filtered by the rte_flow rules
 * \return int 0 on success, a negative errno value otherwise and rte_errno is set
 */
uint64_t RteFlowFilteredPacketsQuery(struct rte_flow **rules, uint16_t rule_count,
        char *device_name, int port_id, uint64_t *filtered_packets)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    uint32_t counter_id = COUNT_ACTION_ID;
    int retval = 0;

    query_count.reset = 0;
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    for (uint16_t i = 0; i < rule_count; i++) {
        retval +=
                rte_flow_query(port_id, rules[i], &(action[0]), (void *)&query_count, &flow_error);
        if (retval != 0) {
            SCLogError("%s: rte_flow count query error %s errmsg: %s", device_name,
                    rte_strerror(-retval), flow_error.message);
            SCReturnInt(retval);
        };
        *filtered_packets += query_count.hits;
    }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
    SCReturnInt(0);
}

/**
 * \brief Create rte_flow drop rules with patterns stored in rule_storage on a port with id
 *        port_id
 *
 * \param port_name name of a port
 * \param port_id identificator of a port
 * \param rule_storage pointer to structure containing rte_flow rule patterns
 * \param driver_name name of a driver
 * \return int 0 on success, -1 on error
 */
int RteFlowRulesCreate(
        char *port_name, int port_id, RteFlowRuleStorage *rule_storage, const char *driver_name)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCEnter();
    int failed_rule_count = 0;
    uint32_t counter_id = COUNT_ACTION_ID;
    struct rte_flow_error flush_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    bool should_gather_stats = RteFlowDropFilterInit(rule_storage->rule_cnt, rule_storage->rules,
            &attr, action, &counter_id, driver_name, port_name);

    rule_storage->rule_handlers = SCCalloc(rule_storage->rule_size, sizeof(struct rte_flow *));
    if (rule_storage->rule_handlers == NULL) {
        SCLogError("%s: Memory allocation for rte_flow rule string failed", port_name);
        RteFlowRuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    for (int i = 0; i < rule_storage->rule_cnt; i++) {
        struct rte_flow_item *items = { 0 };
        struct rte_flow_error flow_error = { 0 };
        uint8_t items_data_buffer[DATA_BUFFER_SIZE] = { 0 };

        int retval = ParsePattern(
                rule_storage->rules[i], items_data_buffer, sizeof(items_data_buffer), &items);
        if (retval != 0) {
            failed_rule_count++;
            SCLogError("%s: Error when parsing rte_flow rule \"%s\"", port_name,
                    rule_storage->rules[i]);
            continue;
        }

        retval = rte_flow_validate(port_id, &attr, items, action, &flow_error);
        if (retval != 0) {
            failed_rule_count++;
            char *driver_specific_err = DriverSpecificErrorMessage(driver_name, items);
            SCLogError("%s: Error when validating rte_flow rule \"%s\": %s, errmsg: "
                       "%s. %s",
                    port_name, rule_storage->rules[i], rte_strerror(-retval), flow_error.message,
                    driver_specific_err != NULL ? driver_specific_err : "");
            if (driver_specific_err != NULL) {
                SCFree(driver_specific_err);
            }
            continue;
        }

        struct rte_flow *flow_handler = rte_flow_create(port_id, &attr, items, action, &flow_error);
        if (flow_handler == NULL) {
            failed_rule_count++;
            SCLogError("%s: Error when creating rte_flow rule \"%s\": %s", port_name,
                    rule_storage->rules[i], flow_error.message);
            continue;
        }
        rule_storage->rule_handlers[i] = flow_handler;
        SCLogInfo("%s: rte_flow rule \"%s\" created", port_name, rule_storage->rules[i]);
    }

    if (failed_rule_count) {
        SCLogError("%s: Error parsing/creating %i rte_flow rule(s), flushing rules", port_name,
                failed_rule_count);
        int retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s Unable to flush rte_flow rules: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        SCReturnInt(-1);
    }

    if (!should_gather_stats) {
        SCFree(rule_storage->rule_handlers);
        rule_storage->rule_cnt = 0;
    }

#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)*/
    SCReturnInt(0);
}

/**
 * \brief Enable and register functions for BypassManager,
 *        initialize rte_ring data structure and store in global
 *        variable
 *
 * \param port_name name of a port
 * \param port_id identificator of a port
 * \return int 0 on success, negative value on error
 */
int RteBypassInit(DPDKDeviceResources *dpdk_resources, uint32_t bypass_ring_size,
        const char *port_name, int port_id)
{
    SCEnter();
    LiveDevice *livedev = LiveGetDevice(port_name);
    LiveDevUseBypass(livedev);
    RunModeEnablesBypassManager();

    RteFlowBypassData *rte_flow_bypass_data = SCCalloc(1, sizeof(RteFlowBypassData));
    if (rte_flow_bypass_data == NULL) {
        SCLogError("%s: Memory allocation for RteFlowBypassData failed", port_name);
        SCReturnInt(-1);
    }

    struct rte_ring *bypass_ring =
            rte_ring_create(RTE_BYPASS_RING_NAME, bypass_ring_size, rte_socket_id(), RING_F_SC_DEQ);
    if (bypass_ring == NULL) {
        SCLogError("%s: rte_ring_create failed with code %d (ring: %s): %s", port_name, rte_errno,
                RTE_BYPASS_RING_NAME, rte_strerror(rte_errno));
        SCReturnInt(-1);
    }
    rte_flow_bypass_data->bypass_ring = bypass_ring;

    uint32_t mempool_size = (bypass_ring_size * 2) - 1;
    struct rte_mempool *bypass_mp = rte_mempool_create(RTE_BYPASS_MEMPOOL_NAME, mempool_size,
            sizeof(FlowKey), MempoolCacheSizeCalculate(mempool_size), 0, NULL, NULL, NULL, NULL,
            rte_socket_id(), 0);
    if (bypass_mp == NULL) {
        SCLogError("%s: rte_mempool_create failed with code %d (mempool: %s): %s", port_name,
                rte_errno, RTE_BYPASS_MEMPOOL_NAME, rte_strerror(rte_errno));
        SCReturnInt(-1);
    }
    BypassedFlowManagerRegisterCheckFunc(
            RteFlowBypassRuleLoad, RteFlowBypassCheckFlowInit, (void *)rte_flow_bypass_data);

    rte_flow_bypass_data->bypass_mp = bypass_mp;
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_active);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_created);

    dpdk_resources->rte_flow_bypass_data = rte_flow_bypass_data;

    SCReturnInt(0);
}

/**
 * \brief Decides whether the rte_flow rule should be removed from the table
 *
 * \param port_id identificator of a port
 * \param src_rule_handler rte_flow rule handler for specific flow in one direction
 * \param dst_rule_handler rte_flow rule handler for specific flow in other direction
 * \param flow flow to be possibly removed from the table
 * \return int 1 if the rte_flow rule is active, 0 if it should be removed
 */
static int RteFlowUpdateStats(FlowBypassInfo *fc, uint16_t port_id,
        struct rte_flow *src_rule_handler, struct rte_flow *dst_rule_handler)
{
    SCEnter();
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    uint32_t counter_id = COUNT_ACTION_ID;
    int retval = 0;

    query_count.reset = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    retval = rte_flow_query(
            port_id, src_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
    };

    uint32_t src_packets = query_count.hits;
    uint32_t src_bytes = query_count.bytes;

    memset(&query_count, 0, sizeof(struct rte_flow_query_count));
    query_count.reset = 1;
    retval = rte_flow_query(
            port_id, dst_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
    };

    uint32_t dst_packets = query_count.hits;
    uint32_t dst_bytes = query_count.bytes;

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
 * \param port_id identificator of a port
 * \param flow_handler rte_flow rule handler
 * \return int 0 on success, negative value on error
 */
static int RteFlowBypassRuleCreate(
        struct rte_flow_item *items, int port_id, struct rte_flow **flow_handler)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = 0;

    uint32_t counter_id = COUNT_ACTION_ID;

    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    int retval = rte_flow_validate(port_id, &attr, items, action, &flow_error);
    if (retval != 0) {
        SCReturnInt(retval);
    }

    *flow_handler = rte_flow_create(port_id, &attr, items, action, &flow_error);
    if (*flow_handler == NULL) {
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief Placeholder function for BypassManager
 *
 * \param th_v Ignored
 * \param curtime Ignored
 * \param data Ignored
 * \return 0
 */
int RteFlowBypassCheckFlowInit(ThreadVars *th_v, struct timespec *curtime, void *data)
{
    SCReturnInt(0);
}

/**
 * \brief Poll flow data from rte_flow_ring structure and create rte_flow bypass rule to bypass flow
 *        from both directions
 *
 * \param th_v Ignored
 * \param bypassstats Ignored
 * \param curtime Ignored
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
    uint16_t ring_dequeue_num = 20;
    uint32_t success_count = 0;
    FlowKey *ring_data[ring_dequeue_num];

    /* Initialize the reusable part of rte_flow rules */
    items[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    items[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    uint32_t to_bypass_packets =
            rte_ring_dequeue_burst(bypass_ring, (void **)ring_data, ring_dequeue_num, NULL);
    for (uint16_t i = 0; i < to_bypass_packets; i++) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCReturnInt(success_count);
        }
        struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
        struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
        struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
        struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
        void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;

        FlowKey *flow_key = ring_data[i];
        LiveDevice *livedev = LiveGetDeviceByIdx(flow_key->livedev_id);
        uint16_t port_id = livedev->dpdk_vars->port_id;

        /* Create rte_flow rule for original direction */
        if (flow_key->src.family == AF_INET) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule");
            ipv4_spec.hdr.src_addr = flow_key->src.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow_key->dst.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow_key->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow_key->sp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow_key->dp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow_key->sp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow_key->dp);
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
        int retval = RteFlowBypassRuleCreate(items, port_id, &src_rule_handler);

        /* Create rte_flow rule for the opposite direction */
        if (flow_key->src.family == AF_INET) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule in other direction");
            ipv4_spec.hdr.src_addr = flow_key->dst.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow_key->src.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow_key->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow_key->dp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow_key->sp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow_key->dp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow_key->sp);
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
        retval += RteFlowBypassRuleCreate(items, port_id, &dst_rule_handler);

        uint32_t flow_hash = FlowKeyGetHash(flow_key);
        Flow *flow = FlowGetExistingFlowFromHash(flow_key, flow_hash);
        rte_mempool_put(bypass_mp, flow_key);
        /* If error, destroy the rule for flow in original direction and set flow state to local
         * bypass*/
        if (retval != 0 || flow == NULL) {
            struct rte_flow_error flow_error = { 0 };
            if (src_rule_handler != NULL) {
                retval = rte_flow_destroy(port_id, src_rule_handler, &flow_error);
                if (retval != 0) {
                    SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                            rte_strerror(-retval), flow_error.message);
                }
            }
            if (dst_rule_handler != NULL) {
                retval = rte_flow_destroy(port_id, dst_rule_handler, &flow_error);
                if (retval != 0) {
                    SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                            rte_strerror(-retval), flow_error.message);
                }
            }
            if (flow != NULL) {
                FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
                FLOWLOCK_UNLOCK(flow);
            }
            continue;
        }

        int inet_family;
        if (FLOW_IS_IPV4(flow))
            inet_family = AF_INET;
        else
            inet_family = AF_INET6;
        retval = RteFlowSetFlowBypassInfo(flow, src_rule_handler, dst_rule_handler, inet_family);
        if (retval != 0) {
            SC_ATOMIC_ADD(
                    flow->livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 1);
            SC_ATOMIC_ADD(
                    flow->livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_created, 1);
            bypassstats->count++;
            success_count++;
        }
        FLOWLOCK_UNLOCK(flow);
    }
    SCReturnInt(success_count);
}

bool RteBypassUpdate(Flow *flow, void *data, time_t tsec)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info == NULL) {
        SCLogError("rte_flow dynamic bypass: flow_handler_info is NULL");
        return false;
    }
    FlowBypassInfo *fc = FlowGetStorageById(flow, GetFlowBypassInfoID());
    if (fc == NULL) {
        SCLogError("rte_flow dynamic bypass: flow bypass info is NULL");
        return false;
    }
    if (flow_handler_info->src_handler == NULL || flow_handler_info->dst_handler == NULL) {
        return false;
    }
    bool activity = RteFlowUpdateStats(fc, flow->livedev->dpdk_vars->port_id,
            flow_handler_info->src_handler, flow_handler_info->dst_handler);
    if (activity)
        flow->lastts = SCTIME_FROM_SECS(tsec);
    if (!activity || unlikely(suricata_ctl_flags != 0)) {
        if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
            struct rte_flow_error flow_error = { 0 };
            int retval = rte_flow_destroy(flow_handler_info->dpdk_vars->port_id,
                    flow_handler_info->src_handler, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
            }
            flow_handler_info->src_handler = NULL;
            retval = rte_flow_destroy(flow_handler_info->dpdk_vars->port_id,
                    flow_handler_info->dst_handler, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
            }
            flow_handler_info->dst_handler = NULL;
            SC_ATOMIC_SUB(
                    flow_handler_info->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 1);
        }
    }
    SCReturnBool(activity);
}

void RteBypassFree(void *data)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    struct rte_flow_error flow_error = { 0 };
    if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
        FlowBypassInfo *fc = FlowGetStorageById(flow_handler_info->flow, GetFlowBypassInfoID());
        if (fc == NULL) {
            SCLogError("rte_flow dynamic bypass: flow_bypass_info is NULL");
            return;
        }
        RteFlowUpdateStats(fc, flow_handler_info->flow->livedev->dpdk_vars->port_id,
                flow_handler_info->src_handler, flow_handler_info->dst_handler);
        int retval = rte_flow_destroy(
                flow_handler_info->dpdk_vars->port_id, flow_handler_info->src_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
        flow_handler_info->src_handler = NULL;
        retval = rte_flow_destroy(
                flow_handler_info->dpdk_vars->port_id, flow_handler_info->dst_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
        flow_handler_info->dst_handler = NULL;
        SC_ATOMIC_SUB(
                flow_handler_info->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 1);
    }
    if (flow_handler_info != NULL) {
        SCFree(flow_handler_info);
    }
}

static int RteFlowSetFlowBypassInfo(
        Flow *flow, struct rte_flow *src_handler, struct rte_flow *dst_handler, int family)
{
    FlowBypassInfo *fc = FlowGetStorageById(flow, GetFlowBypassInfoID());
    if (fc) {
        if (fc->bypass_data != NULL) {
            SCReturnInt(0);
        }
        RteFlowHandlerToFlow *flow_handler_info = SCCalloc(1, sizeof(RteFlowHandlerToFlow));
        if (flow_handler_info == NULL) {
            goto bypass_fail;
        }
        flow_handler_info->flow = flow;
        flow_handler_info->src_handler = src_handler;
        flow_handler_info->dst_handler = dst_handler;
        flow_handler_info->dpdk_vars = flow->livedev->dpdk_vars;
        fc->bypass_data = flow_handler_info;
        fc->BypassUpdate = RteBypassUpdate;
        fc->BypassFree = RteBypassFree;
        LiveDevAddBypassStats(flow->livedev, 1, family);
        LiveDevAddBypassSuccess(flow->livedev, 1, family);
        SCReturnInt(1);
    }

bypass_fail:;
    struct rte_flow_error flow_error = { 0 };
    int retval = rte_flow_destroy(flow->livedev->dpdk_vars->port_id, src_handler, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
    }

    retval = rte_flow_destroy(flow->livedev->dpdk_vars->port_id, dst_handler, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
    }
    LiveDevAddBypassFail(flow->livedev, 1, family);
    SCReturnInt(0);
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
    RteFlowBypassData *rte_flow_bypass_data = p->livedev->dpdk_vars->rte_flow_bypass_data;
    if (rte_mempool_get(rte_flow_bypass_data->bypass_mp, (void **)&flow_key) < 0) {
        SCLogError("Memory allocation for rte_flow bypass data failed");
        SCReturnInt(0);
    }

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
    flow_key->livedev_id = p->livedev->id;
    flow_key->vlan_id[0] = p->vlan_id[0];
    flow_key->vlan_id[1] = p->vlan_id[1];
    flow_key->vlan_id[2] = p->vlan_id[2];
    flow_key->recursion_level = 0;

    int retval = rte_ring_mp_enqueue(rte_flow_bypass_data->bypass_ring, flow_key);
    /* If ring is full, continue with local bypass */
    if (retval < 0) {
        rte_mempool_put(rte_flow_bypass_data->bypass_mp, flow_key);
        SCReturnInt(0);
    }
    retval = retval == 0 ? 1 : 0;
    SCReturnInt(retval);
}

/**
 * @}
 */

#endif /* HAVE_DPDK */
