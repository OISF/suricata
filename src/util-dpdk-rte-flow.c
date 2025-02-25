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
#include "runmode-dpdk.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"

#ifdef HAVE_DPDK
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

#define INITIAL_RTE_FLOW_RULE_COUNT_CAPACITY 5
#define DATA_BUFFER_SIZE                     1024
#define COUNT_ACTION_ID                      128

static int RteFlowRuleStorageInit(RteFlowRuleStorage *);
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *, const char *);
static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *);
static char *DriverSpecificErrorMessage(const char *, struct rte_flow_item *);
static bool RteFlowRulesContainPatternWildcard(char **, uint32_t);
static bool RteFlowDropFilterInit(uint32_t, char **, struct rte_flow_attr *,
        struct rte_flow_action *, uint32_t *, const char *, const char *);

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
        ConfNode *if_root, const char *filter_type, RteFlowRuleStorage *rule_storage)
{
    SCEnter();
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    ConfNode *node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("No configuration node found for %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rule;
        int retval = RteFlowRuleStorageInit(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }

        TAILQ_FOREACH (rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {
                ConfGetChildValue(rule_node, "rule", &rule);
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

#endif /* HAVE_DPDK */
/**
 * @}
 */
