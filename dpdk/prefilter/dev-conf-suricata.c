/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>

#include "dev-conf-suricata.h"
#include "dev-conf.h"
#include "logger.h"

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"

struct RingConfigAttributes {
    const char *ring_name_base;
    const char *ring_elems;
};

struct NicConfigAttributes {
    const char *port_pcie1;
    const char *port_pcie2;
    const char *promisc;
    const char *multicast;
    const char *rss;
    const char *checksum_checks_offload;
    const char *mtu;
    const char *mempool_size;
    const char *mempool_cache_size;
    const char *rx_descriptors;
    const char *tx_descriptors;
};

struct MempoolConfigAttributes {
    const char *mp_name_base;
    const char *mp_entries;
    const char *mp_cache_entries;
};

struct BypassMessageAttributes {
    struct RingConfigAttributes task_ring;
    struct RingConfigAttributes results_ring;
    struct MempoolConfigAttributes msgs_mp;
};

struct RingEntryAttributes {
    struct RingConfigAttributes main_ring;
    const char *prefilter_lcores;
    const char *secondary_app_lcores;
    const char *op_mode;
    const char *bypass_table_name;
    const char *bypass_table_entries;
    const char *bypass_mp_name;
    const char *bypass_mp_entries;
    const char *bypass_mp_cache_entries;
    struct NicConfigAttributes nic_config;
    struct BypassMessageAttributes bypass_messages;
};

#define PROMISC_ENABLED       1 << 0
#define MULTICAST_ENABLED     1 << 1
#define RSS_ENABLED           1 << 2
#define CHSUM_OFFLOAD_ENABLED 1 << 3

#define BYPASS_TABLE_PREFIX "bypass-table."
#define NIC_CONFIG_PREFIX   "nic-config."
#define MESSAGES_PREFIX     "messages."
#define TASK_RING_PREFIX    "task-ring."
#define RESULTS_RING_PREFIX "results-ring."
#define MSG_MEMPOOL_PREFIX  "message-mempool."

const struct RingEntryAttributes pf_yaml = {
    .main_ring = {
            .ring_name_base = NULL, // value obtained from the root value
            .ring_elems = "elements"
    },
    .prefilter_lcores = "pf-lcores",
    .secondary_app_lcores = "secondary-app-lcores",
    .op_mode = "op-mode",
    .bypass_table_name = BYPASS_TABLE_PREFIX "base-name",
    .bypass_table_entries = BYPASS_TABLE_PREFIX "entries",
    .bypass_mp_name = BYPASS_TABLE_PREFIX "mempool-name",
    .bypass_mp_entries = BYPASS_TABLE_PREFIX "mempool-entries",
    .bypass_mp_cache_entries = BYPASS_TABLE_PREFIX "mempool-cache-entries",
    .nic_config = {
        .port_pcie1 = NIC_CONFIG_PREFIX "port-pcie1",
        .port_pcie2 = NIC_CONFIG_PREFIX "port-pcie2",
        .promisc = NIC_CONFIG_PREFIX "promisc",
        .multicast = NIC_CONFIG_PREFIX "multicast",
        .rss = NIC_CONFIG_PREFIX "rss",
        .checksum_checks_offload = NIC_CONFIG_PREFIX "checksum-checks-offload",
        .mtu = NIC_CONFIG_PREFIX "mtu",
        .mempool_size = NIC_CONFIG_PREFIX "mempool-size",
        .mempool_cache_size = NIC_CONFIG_PREFIX "mempool-cache-size",
        .rx_descriptors = NIC_CONFIG_PREFIX "rx-descriptors",
        .tx_descriptors = NIC_CONFIG_PREFIX "tx-descriptors",
    },
    .bypass_messages = {
        .task_ring = {
            .ring_name_base = MESSAGES_PREFIX TASK_RING_PREFIX "name",
            .ring_elems = MESSAGES_PREFIX TASK_RING_PREFIX "elements",
        },
        .results_ring = {
            .ring_name_base = MESSAGES_PREFIX RESULTS_RING_PREFIX "name", // loaded from the root
            .ring_elems = MESSAGES_PREFIX RESULTS_RING_PREFIX "elements",
        },
        .msgs_mp = {
            .mp_name_base = MESSAGES_PREFIX MSG_MEMPOOL_PREFIX "name",
            .mp_entries = MESSAGES_PREFIX MSG_MEMPOOL_PREFIX "entries",
            .mp_cache_entries = MESSAGES_PREFIX MSG_MEMPOOL_PREFIX "cache-entries",
        },
    },
};

#define PF_NODE_NAME_MAX 1024

/**
 * \brief Find the configuration node for a specific item.

 * \param node The node to start looking for the item configuration.
 * \param iface The name of the interface to find the config for.
 */
static ConfNode *ConfFindItemConfig(ConfNode *node, const char *itemname, const char *iface)
{
    ConfNode *if_node, *item;
    TAILQ_FOREACH (if_node, &node->head, next) {
        TAILQ_FOREACH (item, &if_node->head, next) {
            if (strcmp(item->name, itemname) == 0 && strcmp(item->val, iface) == 0) {
                return if_node;
            }
        }
    }

    return NULL;
}

static ConfNode *ConfNodeLookupDescendant(const ConfNode *base, const char *name)
{
    ConfNode *node = (ConfNode *)base;
    char node_name[PF_NODE_NAME_MAX];
    char *key;
    char *next;

    if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
        SCLogError(SC_ERR_CONF_NAME_TOO_LONG, "Configuration name too long: %s", name);
        return NULL;
    }

    key = node_name;
    do {
        if ((next = strchr(key, '.')) != NULL)
            *next++ = '\0';
        node = ConfNodeLookupChild(node, key);
        key = next;
    } while (next != NULL && node != NULL);

    return node;
}

static int ConfGetDescendantValue(const ConfNode *base, const char *name, const char **vptr)
{
    ConfNode *node = ConfNodeLookupDescendant(base, name);

    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    } else {
        *vptr = node->val;
        return 1;
    }
}

static int ConfGetDescendantValueInt(const ConfNode *base, const char *name, intmax_t *val)
{
    const char *strval = NULL;
    intmax_t tmpint;
    char *endptr;

    if (ConfGetDescendantValue(base, name, &strval) == 0)
        return 0;
    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "malformed integer value "
                "for %s with base %s: '%s'",
                name, base->name, strval);
        return 0;
    }
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "integer value for %s with "
                " base %s out of range: '%s'",
                name, base->name, strval);
        return 0;
    }

    *val = tmpint;
    return 1;
}

static int ConfGetDescendantValueBool(const ConfNode *base, const char *name, int *val)
{
    const char *strval = NULL;

    *val = 0;
    if (ConfGetDescendantValue(base, name, &strval) == 0)
        return 0;

    *val = ConfValIsTrue(strval);

    return 1;
}

int DevConfSuricataLoadRingEntryConf(ConfNode *rnode, struct ring_list_entry *re, const char *rname)
{
    struct ring_list_entry_suricata *rc = (struct ring_list_entry_suricata *)re->pre_ring_conf;
    const char *entry_str = NULL;
    intmax_t entry_int;
    int retval, entry_bool;
    const char *entry_char;

    re->main_ring.name_base = rname;

    retval = ConfGetChildValueInt(rnode, pf_yaml.main_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.main_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        re->main_ring.elem_cnt = entry_int;
    }

    retval = ConfGetChildValueInt(rnode, pf_yaml.prefilter_lcores, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.prefilter_lcores);
        return -EXIT_FAILURE;
    } else {
        re->pf_cores_cnt = entry_int;
    }

    retval = ConfGetChildValueInt(rnode, pf_yaml.secondary_app_lcores, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.secondary_app_lcores);
        return -EXIT_FAILURE;
    } else {
        re->sec_app_cores_cnt = entry_int;
    }

    retval = ConfGetChildValue(rnode, pf_yaml.op_mode, &entry_char);
    if (retval != 1 || entry_char == NULL) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.op_mode);
        return -EXIT_FAILURE;
    } else {
        if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_PIPELINE) == 0)
            re->opmode = PIPELINE;
        else if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_IDS) == 0)
            re->opmode = IDS;
        else if (strcmp(entry_char, PREFILTER_CONFIG_OPERATION_MODE_IPS) == 0)
            re->opmode = IPS;
        else {
            Log().error(ENOENT, "Unable to read value of %s", pf_yaml.op_mode);
            return -EXIT_FAILURE;
        }
    }

    retval = ConfGetDescendantValue(rnode, pf_yaml.bypass_table_name, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_table_name);
        return -EXIT_FAILURE;
    } else {
        re->bypass_table_base.name = entry_char;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.bypass_table_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_table_entries);
        return -EXIT_FAILURE;
    } else {
        re->bypass_table_base.entries = entry_int;
    }

    retval = ConfGetDescendantValue(rnode, pf_yaml.bypass_mp_name, &entry_char);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_name);
        return -EXIT_FAILURE;
    } else {
        if (entry_char == NULL || entry_char[0] == '\0' || strcmp(entry_char, "none") == 0)
            re->bypass_mempool.name = NULL;
        else
            re->bypass_mempool.name = entry_char;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.bypass_mp_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_entries);
        return -EXIT_FAILURE;
    } else {
        re->bypass_mempool.entries = entry_int;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.bypass_mp_cache_entries, &entry_int);
    if (retval != 1 || entry_int < 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.bypass_mp_cache_entries);
        return -EXIT_FAILURE;
    } else {
        re->bypass_mempool.cache_entries = entry_int;
    }

    retval = ConfGetDescendantValue(rnode, pf_yaml.nic_config.port_pcie1, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.port_pcie1);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.port1_pcie = entry_char;
    }

    retval = ConfGetDescendantValue(rnode, pf_yaml.nic_config.port_pcie2, &entry_char);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.port_pcie2);
        return -EXIT_FAILURE;
    } else {
        if (entry_char == NULL || entry_char[0] == '\0' || strcmp(entry_char, "none") == 0)
            rc->nic_conf.port2_pcie = NULL;
        else
            rc->nic_conf.port2_pcie = entry_char;
    }

    retval = ConfGetDescendantValueBool(rnode, pf_yaml.nic_config.promisc, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.promisc);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= DPDK_PROMISC;
    }

    retval = ConfGetDescendantValueBool(rnode, pf_yaml.nic_config.multicast, &entry_bool);
    if (retval != 1) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.multicast);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= DPDK_MULTICAST;
    }

    retval = ConfGetDescendantValueBool(
            rnode, pf_yaml.nic_config.checksum_checks_offload, &entry_bool);
    if (retval != 1) {
        Log().error(
                ENOENT, "Unable to read value of %s", pf_yaml.nic_config.checksum_checks_offload);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.flags |= DPDK_RX_CHECKSUM_OFFLOAD;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.nic_config.mtu, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mtu);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mtu = entry_int;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.nic_config.mempool_size, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mempool_size);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mempool_size = entry_int;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.nic_config.mempool_cache_size, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.mempool_cache_size);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.mempool_cache_size = entry_int;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.nic_config.rx_descriptors, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.rx_descriptors);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.nb_rx_desc = entry_int;
    }

    retval = ConfGetDescendantValueInt(rnode, pf_yaml.nic_config.tx_descriptors, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s", pf_yaml.nic_config.tx_descriptors);
        return -EXIT_FAILURE;
    } else {
        rc->nic_conf.nb_tx_desc = entry_int;
    }

    retval = ConfGetDescendantValue(
            rnode, pf_yaml.bypass_messages.task_ring.ring_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s",
                pf_yaml.bypass_messages.task_ring.ring_name_base);
        return -EXIT_FAILURE;
    } else {
        re->msgs.task_ring.name_base = entry_char;
    }

    retval = ConfGetDescendantValueInt(
            rnode, pf_yaml.bypass_messages.task_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(
                ENOENT, "Unable to read value of %s", pf_yaml.bypass_messages.task_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        re->msgs.task_ring.elem_cnt = entry_int;
    }

    retval = ConfGetDescendantValue(
            rnode, pf_yaml.bypass_messages.results_ring.ring_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(ENOENT, "Unable to read value of %s",
                pf_yaml.bypass_messages.results_ring.ring_name_base);
        return -EXIT_FAILURE;
    } else {
        re->msgs.result_ring.name_base = entry_char;
    }

    retval = ConfGetDescendantValueInt(
            rnode, pf_yaml.bypass_messages.results_ring.ring_elems, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s",
                pf_yaml.bypass_messages.results_ring.ring_elems);
        return -EXIT_FAILURE;
    } else {
        re->msgs.result_ring.elem_cnt = entry_int;
    }

    retval = ConfGetDescendantValue(
            rnode, pf_yaml.bypass_messages.msgs_mp.mp_name_base, &entry_char);
    if (retval != 1 || entry_char == NULL || entry_char[0] == '\0') {
        Log().error(
                ENOENT, "Unable to read value of %s", pf_yaml.bypass_messages.msgs_mp.mp_name_base);
        return -EXIT_FAILURE;
    } else {
        re->msgs.mempool.name = entry_char;
    }

    retval = ConfGetDescendantValueInt(
            rnode, pf_yaml.bypass_messages.msgs_mp.mp_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(
                ENOENT, "Unable to read value of %s", pf_yaml.bypass_messages.msgs_mp.mp_entries);
        return -EXIT_FAILURE;
    } else {
        re->msgs.mempool.entries = entry_int;
    }

    retval = ConfGetDescendantValueInt(
            rnode, pf_yaml.bypass_messages.msgs_mp.mp_cache_entries, &entry_int);
    if (retval != 1 || entry_int <= 0) {
        Log().error(ENOENT, "Unable to read value of %s",
                pf_yaml.bypass_messages.msgs_mp.mp_cache_entries);
        return -EXIT_FAILURE;
    } else {
        re->msgs.mempool.cache_entries = entry_int;
    }

    return 0;
}

static DPDKIfaceConfig ConfPrefitlerToSuricataAdapter(struct ring_list_entry *re, bool first_port)
{
    struct ring_list_entry_suricata *re_suri = (struct ring_list_entry_suricata *)re->pre_ring_conf;
    DPDKIfaceConfig suri_conf = { 0 };
    if (first_port)
        strlcpy(suri_conf.iface, re_suri->nic_conf.port1_pcie, sizeof(suri_conf.iface));
    else
        strlcpy(suri_conf.iface, re_suri->nic_conf.port2_pcie, sizeof(suri_conf.iface));

    suri_conf.nb_rx_queues = re->pf_cores_cnt;
    suri_conf.nb_tx_queues = re->pf_cores_cnt;
    suri_conf.mtu = re_suri->nic_conf.mtu;
    suri_conf.checksum_mode = CHECKSUM_VALIDATION_ENABLE;
    suri_conf.flags = re_suri->nic_conf.flags;
    suri_conf.nb_rx_desc = re_suri->nic_conf.nb_rx_desc;
    suri_conf.nb_tx_desc = re_suri->nic_conf.nb_tx_desc;
    suri_conf.mempool_size = re_suri->nic_conf.mempool_size;
    suri_conf.mempool_cache_size = re_suri->nic_conf.mempool_cache_size;
    return suri_conf;
}

static void ConfSuricataToPrefitlerAdapter(
        struct ring_list_entry *re, DPDKIfaceConfig *post_suri_conf, bool first_port)
{
    struct ring_list_entry_suricata *re_suri = (struct ring_list_entry_suricata *)re->pre_ring_conf;
    DPDKIfaceConfig suri_conf = { 0 };
    if (first_port)
        re_suri->nic_conf.port1_id = post_suri_conf->port_id;
    else
        re_suri->nic_conf.port2_id = post_suri_conf->port_id;

    re_suri->nic_conf.socket_id = post_suri_conf->port_id;
    re_suri->nic_conf.pkt_mempool = post_suri_conf->pkt_mempool;
}

static int DevConfSuricataConfigureDevices(struct ring_list_entry *rconf)
{
    struct ring_list_entry_suricata *devconf =
            (struct ring_list_entry_suricata *)rconf->pre_ring_conf;
    int retval;
    DPDKIfaceConfig suri_conf;

    suri_conf = ConfPrefitlerToSuricataAdapter(rconf, true);

    retval = DeviceConfigure(&suri_conf);
    if (retval != 0)
        return retval;

    ConfSuricataToPrefitlerAdapter(rconf, &suri_conf, true);

    if (rconf->opmode != IDS) {
        suri_conf = ConfPrefitlerToSuricataAdapter(rconf, false);

        retval = DeviceConfigure(&suri_conf);
        if (retval != 0)
            return retval;

        ConfSuricataToPrefitlerAdapter(rconf, &suri_conf, false);
    }

    return 0;
}

int DevConfSuricataStartRing(void *ring_conf)
{
    int retval;
    struct ring_list_entry *re = (struct ring_list_entry *)ring_conf;
    struct ring_list_entry_suricata *re_suri = (struct ring_list_entry_suricata *)ring_conf;

    retval = rte_eth_dev_start(re_suri->nic_conf.port1_id);
    if (retval < 0) {
        Log().error(EINVAL, "Error (%s) during device startup of %s", rte_strerror(-retval),
                re_suri->nic_conf.port1_pcie);
        return retval;
    }

    struct rte_eth_dev_info dev_info;
    retval = rte_eth_dev_info_get(re_suri->nic_conf.port1_id, &dev_info);
    if (retval != 0) {
        Log().error(EINVAL, "Error (%s) when getting device info of %s", rte_strerror(-retval),
                re_suri->nic_conf.port1_pcie);
        return retval;
    }

    // some PMDs requires additional actions only after the device has started
    DevicePostStartPMDSpecificActions(
            re_suri->nic_conf.port1_id, re->sec_app_cores_cnt, dev_info.driver_name);
}

int DevConfSuricataStopRing(void *ring_conf)
{
    int retval;
    struct ring_list_entry_suricata *rc = (struct ring_list_entry_suricata *)ring_conf;
    struct rte_eth_dev_info dev_info;

    retval = rte_eth_dev_info_get(rc->nic_conf.port1_id, &dev_info);
    if (retval != 0) {
        Log().error(EINVAL, "Error (err=%d) during getting device info (port %s)", retval,
                rc->nic_conf.port1_pcie);
        return retval;
    }

    DevicePreStopPMDSpecificActions(rc->nic_conf.port1_id, dev_info.driver_name);
}

int DevConfSuricataConfigureBy(void *conf)
{
    int retval;
    const char *conf_path = conf;
    char *interfaces_selector = "rings";
    char *itemname = "ring";
    const char *live_dev_c = NULL;
    int ldev;

    SCLogInitLogModule(NULL); // Suricata Conf module uses Suricata Logging module - init required
    /* Initialize the Suricata configuration module. */
    ConfInit();

    retval = ConfYamlLoadFile(conf_path);
    if (retval != 0) {
        Log().error(-retval, "Configuration not good");
        return retval;
    }

    retval = LiveBuildDeviceListCustom(interfaces_selector, itemname);
    if (retval == 0)
        Log().error(ENODEV, "no ring found");

    Log().info("Found %d rings", retval);
    LiveDeviceFinalize();

    RingListInitHead();

    int nlive = LiveGetDeviceCount();
    for (ldev = 0; ldev < nlive; ldev++) {
        live_dev_c = LiveGetDeviceName(ldev);

        ConfNode *rings_node = ConfGetNode("rings");
        ConfNode *ring_node = ConfFindItemConfig(rings_node, itemname, live_dev_c);
        if (ring_node == NULL) {
            Log().notice("Unable to find configuration for %s \"%s\"", itemname, live_dev_c);
        }

        struct ring_list_entry_suricata *rc = rte_calloc(
                "struct ring_list_entry_suricata", 1, sizeof(struct ring_list_entry_suricata), 0);
        if (rc == NULL)
            Log().error(ENOMEM, "Calloc for Suricata configuration structure failed");

        struct ring_list_entry re = {
            .pre_ring_conf = rc,
            .start = DevConfSuricataStartRing,
            .stop = DevConfSuricataStopRing,
        };

        retval = DevConfSuricataLoadRingEntryConf(ring_node, &re, live_dev_c);
        if (retval != 0) {
            return retval;
        }

        retval = DevConfSuricataConfigureDevices(&re);
        if (retval != 0)
            return retval;

        RingListAddConf(&re);
    }
    return 0;
}

void ClosePort(const char *pname, const uint16_t pid)
{
    int ret;
    ret = rte_eth_dev_stop(pid);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE, "Error (%s): unable to stop device %s\n", strerror(-ret), pname);
    }

    rte_eth_dev_close(pid);
}

// TODO: Clean LiveDeviceList - LiveDeviceListClean() can not be used as it does multiple things
void DevConfSuricataDeinit(void)
{
    int ret;
    struct ring_list_entry *re;
    struct ring_list_entry_suricata *sconf;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        sconf = (struct ring_list_entry_suricata *)re->pre_ring_conf;

        ClosePort(sconf->nic_conf.port1_pcie, sconf->nic_conf.port1_id);

        if (re->opmode != IDS) {
            ClosePort(sconf->nic_conf.port2_pcie, sconf->nic_conf.port2_id);
        }
    }

    ConfDeInit();
    SCLogDeInitLogModule();
}

static int DevConfSuricataStartPort(uint16_t pid, const char *pname, uint16_t rings_cnt)
{
    int ret;
    struct rte_eth_dev_info port_info;
    ret = rte_eth_dev_info_get(pid, &port_info);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when getting port info of %s", rte_strerror(-ret), pname);
        return ret;
    }

    ret = rte_eth_dev_start(pid);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when starting port %s", rte_strerror(-ret), pname);
        return ret;
    }

    DevicePostStartPMDSpecificActions(pid, rings_cnt, port_info.driver_name);
    return 0;
}

int DevConfSuricataStartAll(void)
{
    int ret;
    struct ring_list_entry *re;
    struct ring_list_entry_suricata *sconf;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        sconf = (struct ring_list_entry_suricata *)re->pre_ring_conf;
        ret = DevConfSuricataStartPort(
                sconf->nic_conf.port1_id, sconf->nic_conf.port1_pcie, re->pf_cores_cnt);
        if (ret != 0) {
            Log().error(-ret, "Error (%s): unable to start device %s", rte_strerror(-ret),
                    sconf->nic_conf.port1_pcie);
            return ret;
        }

        if (re->opmode != IDS) {
            ret = DevConfSuricataStartPort(
                    sconf->nic_conf.port2_id, sconf->nic_conf.port2_pcie, re->pf_cores_cnt);
            if (ret != 0) {
                Log().error(-ret, "Error (%s): unable to start device %s", rte_strerror(-ret),
                        sconf->nic_conf.port2_pcie);
                return ret;
            }
        }
    }

    return 0;
}

static int DevConfSuricataStopPort(uint16_t pid, const char *pname)
{
    int ret;
    struct rte_eth_dev_info port_info;
    ret = rte_eth_dev_info_get(pid, &port_info);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when getting port info of %s", rte_strerror(-ret), pname);
        return ret;
    }

    DevicePreStopPMDSpecificActions(pid, port_info.driver_name);
    ret = rte_eth_dev_stop(pid);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when stopping port %s", rte_strerror(-ret), pname);
        return ret;
    }
    return 0;
}

int DevConfSuricataStopAll(void)
{
    int ret;
    struct ring_list_entry *re;
    struct ring_list_entry_suricata *sconf;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        sconf = (struct ring_list_entry_suricata *)re->pre_ring_conf;
        ret = DevConfSuricataStopPort(sconf->nic_conf.port1_id, sconf->nic_conf.port1_pcie);
        if (ret != 0) {
            Log().error(-ret, "Error (%s): unable to stop device %s", rte_strerror(-ret),
                    sconf->nic_conf.port1_pcie);
            return ret;
        }

        if (re->opmode != IDS) {
            ret = DevConfSuricataStopPort(sconf->nic_conf.port2_id, sconf->nic_conf.port2_pcie);
            if (ret != 0) {
                Log().error(-ret, "Error (%s): unable to stop device %s", rte_strerror(-ret),
                        sconf->nic_conf.port2_pcie);
                return ret;
            }
        }
    }

    return 0;
}

struct DeviceConfigurer dev_conf_suricata_ops = {
    .StartAll = DevConfSuricataStartAll,
    .StopAll = DevConfSuricataStopAll,
    .ConfigureBy = DevConfSuricataConfigureBy,
    .Deinit = DevConfSuricataDeinit,
};