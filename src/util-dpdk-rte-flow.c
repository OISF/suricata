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

#define DATA_BUFFER_SIZE       1024
#define RULE_STORAGE_INIT_SIZE 8
#define RULE_STORAGE_SIZE_INC  16

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)

static int RteFlowRuleStorageInit(RteFlowRuleStorage *);
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *, const char *);
static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *, int);
static char *DriverSpecificErrorMessage(const char *, struct rte_flow_item *);

/**
 * \brief Specify ambiguous error messages as some drivers have specific
 *        behaviour when creating rte_flow rules.
 *
 * \param driver_name name of a driver
 * \param items array of pattern items
 * \return error message if error present, NULL otherwise
 */
static char *DriverSpecificErrorMessage(const char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        if (iceDeviceRteFlowPatternError(items) == true) {
            char msg[] = "Driver specific errmsg: ice driver does not support broad patterns";
            char *ret = SCCalloc((strlen(msg) + 1), sizeof(msg[0]));
            strlcpy(ret, msg, sizeof(msg[0]) * (strlen(msg) + 1));
            return ret;
        }
    }

    return NULL;
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0) */

static int RteFlowRuleStorageInit(RteFlowRuleStorage *rule_storage)
{
    SCEnter();
    rule_storage->rule_cnt = 0;
    rule_storage->rule_size = RULE_STORAGE_INIT_SIZE;
    rule_storage->rules = SCCalloc(rule_storage->rule_size, sizeof(char *));

    if (rule_storage->rules == NULL) {
        SCLogError("Setup memory allocation for rte_flow rule storage failed");
        SCReturnInt(-ENOMEM);
    }
    SCReturnInt(0);
}

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *rule_storage, const char *rule)
{
    SCEnter();
    if (rule_storage->rule_cnt == rule_storage->rule_size) {
        int retval = RteFlowRuleStorageExtendCapacity(rule_storage, RULE_STORAGE_SIZE_INC);
        if (retval != 0)
            SCReturnInt(retval);
    }

    rule_storage->rules[rule_storage->rule_cnt] = SCCalloc(strlen(rule) + 1, sizeof(rule[0]));
    if (rule_storage->rules[rule_storage->rule_cnt] == NULL) {
        SCLogError("Memory allocation for rte_flow rule string failed");
        SCReturnInt(-ENOMEM);
    }

    strlcpy(rule_storage->rules[rule_storage->rule_cnt], rule,
            (strlen(rule) + 1) * sizeof(rule[0]));
    rule_storage->rule_cnt++;
    SCReturnInt(0);
}

static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *rule_storage, int inc)
{
    SCEnter();
    char **tmp_rules;

    rule_storage->rule_size += inc;
    tmp_rules = SCRealloc(rule_storage->rules, rule_storage->rule_size * sizeof(char *));

    if (tmp_rules == NULL) {
        SCLogError("Memory reallocation for rte_flow rule storage failed");
        SCReturnInt(-ENOMEM);
    }

    rule_storage->rules = tmp_rules;
    SCReturnInt(0);
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0) */

/**
 * \brief Deallocation of memory containing user set rte_flow rules
 *
 * \param rule_storage rules loaded from suricata.yaml
 */
void RteFlowRuleStorageFree(RteFlowRuleStorage *rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)

    if (rule_storage->rules == NULL) {
        SCReturn;
    }
    for (int i = 0; i < rule_storage->rule_cnt; i++) {
        SCFree(rule_storage->rules[i]);
    }
    SCFree(rule_storage->rules);
    rule_storage->rules = NULL;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0) */
}

/**
 * \brief Load rte_flow rules patterns from suricata.yaml
 *
 * \param if_root root node in suricata.yaml
 * \param if_default default value
 * \param drop_filter_str value to look for in suricata.yaml
 * \param rule_storage pointer to structure to load rte_flow rules into
 * \return 0 on success, -1 on error
 */
int ConfigLoadRteFlowRules(
        SCConfNode *if_root, const char *drop_filter_str, RteFlowRuleStorage *rule_storage)
{
    SCEnter();
    SCConfNode *node = SCConfNodeLookupChild(if_root, drop_filter_str);
    if (node == NULL) {
        SCLogInfo("No configuration node found for %s", drop_filter_str);
    } else {
        SCConfNode *rule_node;
        const char *rule = NULL;
        /* Suppress unused variable warning in case of DPDK version < 21.11  */
        (void)rule;
        int retval = RteFlowRuleStorageInit(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }

        TAILQ_FOREACH (rule_node, &node->head, next) {
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
            if (strcmp(rule_node->val, "rule") == 0) {
                SCConfGetChildValue(rule_node, "rule", &rule);
                retval = RteFlowRuleStorageAddRule(rule_storage, rule);
                if (retval != 0) {
                    RteFlowRuleStorageFree(rule_storage);
                    SCReturnInt(retval);
                }
            } else {
                SCLogError("DPDK .%s contains unrecognized key, only \"rule\" is supported",
                        drop_filter_str);
                SCReturnInt(-1);
            }
#else
            if (strcmp(rule_node->val, "rule") == 0) {
                SCLogError("DPDK .%s is supported from DPDK version 21.11 and higher, "
                           "filter not applied",
                        drop_filter_str);
                RteFlowRuleStorageFree(rule_storage);
                SCReturnInt(0);
            }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0) */
        }
    }
    SCReturnInt(0);
}

/**
 * \brief Create rte_flow drop rules with patterns stored in rule_storage on a port with id
 *        port_id
 *
 * \param port_id identificator of a port
 * \param rule_storage pointer to structure containing rte_flow rule patterns
 * \param driver_name name of a driver
 * \return 0 on success, -1 on error
 */
int RteFlowRulesCreate(uint16_t port_id, RteFlowRuleStorage *rule_storage, const char *driver_name)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    SCEnter();
    int failed_rule_count = 0;
    struct rte_flow_error flush_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    const char *port_name = DPDKGetPortNameByPortID(port_id);

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    rule_storage->rule_handlers = SCCalloc(rule_storage->rule_size, sizeof(struct rte_flow *));
    if (rule_storage->rule_handlers == NULL) {
        SCLogError("%s: Memory allocation for rte_flow rule string failed", port_name);
        RteFlowRuleStorageFree(rule_storage);
        SCReturnInt(-ENOMEM);
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
        SCReturnInt(-ENOTSUP);
    }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)*/
    SCReturnInt(0);
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
