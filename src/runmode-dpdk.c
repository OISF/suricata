/* Copyright (C) 2021 Open Information Security Foundation
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
 * \ingroup dpdk
 *
 * @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK runmode
 *
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"
#include "util-runmodes.h"
#include "util-byte.h"
#include "util-dpdk.h"

#ifdef HAVE_DPDK

#define ROUNDUP(x, y) ((((x) + ((y)-1)) / (y)) * (y))

#define RSS_HKEY_LEN 40
static uint8_t rss_hkey[] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
    0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
    0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A };

struct Arguments {
    uint16_t capacity;
    char **argv;
    uint16_t argc;
};

static char *AllocArgument(size_t arg_len);
static char *AllocAndSetArgument(const char *arg);
static char *AllocAndSetOption(const char *arg);

static int ArgumentsInit(struct Arguments *args, unsigned capacity);
static void ArgumentsCleanup(struct Arguments *args);
static int ArgumentsAdd(struct Arguments *args, char *value);
static int ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg);
static int InitEal(void);

static ConfNode *ConfSetRootIfaceNode(const char *dpdk_node_name, const char *iface);
static ConfNode *ConfSetDefaultNode(const char *dpdk_node_name);
static int ConfSetRootAndDefaultNodes(
        const char *dpdk_node_name, const char *iface, ConfNode **if_root, ConfNode **if_default);
static int ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues);
static int ConfigSetTxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues);
static int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetTxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetChecksumChecks(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetChecksumOffload(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetCopyIface(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetCopyMode(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetCopyIfaceSettings(DPDKIfaceConfig *iconf, const char *iface, const char *mode);
static void ConfigInit(DPDKIfaceConfig **iconf);
static int ConfigLoad(DPDKIfaceConfig *iconf, const char *iface);
static DPDKIfaceConfig *ConfigParse(const char *iface);
static void DeviceInitPortConf(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf);
static int DeviceConfigureQueues(DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        const struct rte_eth_conf *port_conf);
static int DeviceValidateOutIfaceConfig(DPDKIfaceConfig *iconf);
static int DeviceConfigureIPS(DPDKIfaceConfig *iconf);
static int DeviceConfigure(DPDKIfaceConfig *iconf);
static void *ParseDpdkConfigAndConfigureDevice(const char *iface);
static void DPDKDerefConfig(void *conf);

DPDKIfaceConfigAttributes dpdk_yaml = {
    .threads = "threads",
    .promisc = "promisc",
    .multicast = "multicast",
    .checksum_checks = "checksum-checks",
    .checksum_checks_offload = "checksum-checks-offload",
    .mtu = "mtu",
    .mempool_size = "mempool-size",
    .mempool_cache_size = "mempool-cache-size",
    .rx_descriptors = "rx-descriptors",
    .tx_descriptors = "tx-descriptors",
    .copy_mode = "copy-mode",
    .copy_iface = "copy-iface",
};

char *AllocArgument(size_t arg_len)
{
    char *ptr;

    arg_len += 1; // null character
    ptr = (char *)SCCalloc(arg_len, sizeof(char));
    if (ptr == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Could not allocate memory for an argument");
        errno = ENOMEM;
        SCReturnPtr(NULL, "char *");
    }

    SCReturnPtr(ptr, "char *");
}

/**
 * Allocates space for length of the given string and then copies contents
 * @param arg String to set to the newly allocated space
 * @return memory address if no error otherwise NULL (with errno set)
 */
char *AllocAndSetArgument(const char *arg)
{
    if (arg == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "Passed argument is NULL in DPDK config initialization");
        errno = EINVAL;
        SCReturnPtr(NULL, "char *");
    }

    char *ptr;
    size_t arg_len = strlen(arg);

    ptr = AllocArgument(arg_len);
    if (ptr == NULL)
        SCReturnPtr(NULL, "char *");

    strlcpy(ptr, arg, arg_len + 1);
    SCReturnPtr(ptr, "char *");
}

char *AllocAndSetOption(const char *arg)
{
    if (arg == NULL) {
        errno = EINVAL;
        SCReturnPtr(NULL, "char *");
    }

    char *ptr = NULL;
    size_t arg_len = strlen(arg);
    uint8_t is_long_arg = arg_len > 1;
    const char *dash_prefix = is_long_arg ? "--" : "-";
    size_t full_len = arg_len + strlen(dash_prefix);

    ptr = AllocArgument(full_len);
    if (ptr == NULL)
        SCReturnPtr(NULL, "char *");

    strlcpy(ptr, dash_prefix, strlen(dash_prefix) + 1);
    strlcat(ptr, arg, full_len + 1);
    SCReturnPtr(ptr, "char *");
}

int ArgumentsInit(struct Arguments *args, unsigned capacity)
{
    args->argv = SCCalloc(capacity, sizeof(args->argv));
    if (args->argv == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Could not allocate memory for Arguments structure");
        SCReturnInt(-ENOMEM);
    }

    args->capacity = capacity;
    args->argc = 0;
    SCReturnInt(0);
}

void ArgumentsCleanup(struct Arguments *args)
{
    for (int i = 0; i < args->argc; i++) {
        if (args->argv[i] != NULL) {
            SCFree(args->argv[i]);
            args->argv[i] = NULL;
        }
    }

    SCFree(args->argv);
    args->argv = NULL;
    args->argc = 0;
    args->capacity = 0;
}

int ArgumentsAdd(struct Arguments *args, char *value)
{
    if (args->argc + 1 > args->capacity) {
        SCLogError(SC_ERR_DPDK_EAL_INIT, "No capacity for more arguments");
        SCReturnInt(-ENOBUFS);
    }

    args->argv[args->argc++] = value;
    SCReturnInt(0);
}

int ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg)
{
    int retval;
    char *option;
    char *argument;

    option = AllocAndSetOption(opt);
    if (option == NULL)
        SCReturnInt(-errno);

    retval = ArgumentsAdd(args, option);
    if (retval < 0) {
        SCFree(option);
        SCReturnInt(retval);
    }

    // Empty argument could mean option only (e.g. --no-huge)
    if (arg == NULL || arg[0] == '\0')
        SCReturnInt(0);

    argument = AllocAndSetArgument(arg);
    if (argument == NULL) {
        SCReturnInt(-errno);
    }
    ArgumentsAdd(args, argument);
    SCReturnInt(0);
}

int InitEal()
{
    int retval;
    ConfNode *param;
    const ConfNode *ealParams = ConfGetNode("dpdk.eal-params");
    struct Arguments args;
    char **eal_argv;

    if (ealParams == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "DPDK EAL parameters not found in the config");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    retval = ArgumentsInit(&args, EAL_ARGS);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ArgumentsAdd(&args, AllocAndSetArgument("suricata"));
    if (retval < 0) {
        SCReturnInt(retval);
    }

    TAILQ_FOREACH (param, &ealParams->head, next) {
        retval = ArgumentsAddOptionAndArgument(&args, param->name, param->val);
        if (retval < 0) {
            ArgumentsCleanup(&args);
            return retval;
        }
    }

    // creating a shallow copy for cleanup because rte_eal_init changes array contents
    eal_argv = SCMalloc(args.argc * sizeof(args.argv));
    if (eal_argv == NULL) {
        SCLogError(
                SC_ERR_MEM_ALLOC, "Could not allocate memory for the array of DPDK EAL arguments");
        errno = ENOMEM;
        ArgumentsCleanup(&args);
        SCReturnInt(-errno);
    }
    memcpy(eal_argv, args.argv, args.argc * sizeof(*args.argv));

    rte_log_set_global_level(RTE_LOG_WARNING);
    retval = rte_eal_init(args.argc, eal_argv);

    ArgumentsCleanup(&args);
    SCFree(eal_argv);

    if (retval < 0) { // retval binded to the result of rte_eal_init
        SCLogError(SC_ERR_DPDK_EAL_INIT, "DPDK EAL initialization error");
        return retval;
    }

    return 0;
}

void DPDKDerefConfig(void *conf)
{
    DPDKIfaceConfig *iconf = (DPDKIfaceConfig *)conf;

    if (SC_ATOMIC_SUB(iconf->ref, 1) == 1) {
        if (iconf->pkt_mempool_array != NULL) {
            for (uint16_t queue_id = 0; queue_id < iconf->nb_rx_queues; queue_id++) {
                if (iconf->pkt_mempool_array[queue_id] != NULL) {
                    rte_mempool_free(iconf->pkt_mempool_array[queue_id]);
                }
            }
            SCFree(iconf->pkt_mempool_array);
        }

        SCFree(iconf);
    }
}

void ConfigInit(DPDKIfaceConfig **iconf)
{
    DPDKIfaceConfig *ptr = NULL;
    ptr = SCCalloc(1, sizeof(DPDKIfaceConfig));
    if (ptr == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "Could not allocate memory for DPDKIfaceConfig");
        SCReturn;
    }

    ptr->pkt_mempool_array = NULL;
    ptr->out_port_id = -1; // make sure no port is set
    SC_ATOMIC_INIT(ptr->ref);
    (void)SC_ATOMIC_ADD(ptr->ref, 1);
    ptr->DerefFunc = DPDKDerefConfig;
    ptr->flags = 0;

    *iconf = ptr;
}

ConfNode *ConfSetRootIfaceNode(const char *dpdk_node_name, const char *iface)
{
    ConfNode *if_root;
    ConfNode *dpdk_node;
    /* Find initial node */
    dpdk_node = ConfGetNode(dpdk_node_name);
    if (dpdk_node == NULL) {
        SCLogWarning(SC_WARN_DPDK_CONF, "unable to find %s config", dpdk_node_name);
    }

    if_root = ConfFindDeviceConfig(dpdk_node, iface);
    if (if_root == NULL) {
        SCLogWarning(SC_WARN_DPDK_CONF, "unable to find interface %s in DPDK config", iface);
    }

    return if_root;
}

ConfNode *ConfSetDefaultNode(const char *dpdk_node_name)
{
    ConfNode *if_default;
    ConfNode *dpdk_node;
    /* Find initial node */
    dpdk_node = ConfGetNode(dpdk_node_name);
    if (dpdk_node == NULL) {
        SCLogWarning(SC_WARN_DPDK_CONF, "unable to find %s config", dpdk_node_name);
    }

    if_default = ConfFindDeviceConfig(dpdk_node, "default");
    if (if_default == NULL) {
        SCLogWarning(SC_WARN_DPDK_CONF, "unable to find default interface in DPDK config");
    }

    return if_default;
}

int ConfSetRootAndDefaultNodes(
        const char *dpdk_node_name, const char *iface, ConfNode **if_root, ConfNode **if_default)
{
    *if_root = ConfSetRootIfaceNode(dpdk_node_name, iface);
    *if_default = ConfSetDefaultNode(dpdk_node_name);

    if (*if_root == NULL && *if_default == NULL) {
        SCLogError(SC_ERR_DPDK_CONF,
                "unable to find DPDK config for "
                "interface \"%s\" or \"default\", using default values",
                iface);
        SCReturnInt(-ENODEV);
    }

    /* If there is no setting for current interface use default one as main iface */
    if (*if_root == NULL) {
        *if_root = *if_default;
        *if_default = NULL;
    }

    SCReturnInt(0);
}

int ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0') {
        SCLogError(SC_ERR_INVALID_VALUE, "Passed value is NULL");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->port_id);
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Name of the interface (%s) not valid", entry_str);
        errno = -retval;
        SCReturnInt(retval);
    }

    strlcpy(iconf->iface, entry_str, sizeof(iconf->iface));
    SCReturnInt(0);
}

int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str)
{
    const char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("single", active_runmode)) {
        iconf->threads = 1;
        SCReturnInt(0);
    }

    if (entry_str == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Passed value is NULL");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    if (strcmp(entry_str, "auto") == 0) {
        iconf->threads = (int)rte_lcore_count() - 1;
        SCReturnInt(0);
    }

    if (StringParseInt32(&iconf->threads, 10, 0, entry_str) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Value %s can not be parsed to int", entry_str);
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    if (iconf->threads < 1 || iconf->threads > ((int)rte_lcore_count() - 1)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid number of threads");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    SCReturnInt(0);
}

int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues)
{
    iconf->nb_rx_queues = nb_queues;
    if (iconf->nb_rx_queues < 1) {
        SCLogError(SC_ERR_INVALID_VALUE, "Number of rx queues must be positive");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    SCReturnInt(0);
}

int ConfigSetTxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues)
{
    iconf->nb_tx_queues = nb_queues;
    if (iconf->nb_tx_queues < 1) {
        SCLogError(SC_ERR_INVALID_VALUE, "Number of tx queues must be positive");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    SCReturnInt(0);
}

int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    if (entry_int <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid memory pool size");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    iconf->mempool_size = entry_int;
    SCReturnInt(0);
}

int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    if (entry_int <= 0 || entry_int > RTE_MEMPOOL_CACHE_MAX_SIZE) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Invalid memory pool cache size"
                "(max %" PRIu32,
                RTE_MEMPOOL_CACHE_MAX_SIZE);
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    iconf->mempool_cache_size = entry_int;
    SCReturnInt(0);
}

int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    if (entry_int <= 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Number of RX descriptors must be a positive number");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    iconf->nb_rx_desc = entry_int;
    SCReturnInt(0);
}

int ConfigSetTxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    if (entry_int <= 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Number of TX descriptors must be a positive number");
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    iconf->nb_rx_desc = entry_int;
    SCReturnInt(0);
}

int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    if (entry_int < RTE_ETHER_MIN_MTU || entry_int > RTE_ETHER_MAX_JUMBO_FRAME_LEN) {
        SCLogError(SC_ERR_DPDK_CONF, "Size of MTU must be between %" PRIu32 " and %" PRIu32,
                RTE_ETHER_MIN_MTU, RTE_ETHER_MAX_JUMBO_FRAME_LEN);
        errno = ERANGE;
        SCReturnInt(-errno);
    }

    iconf->mtu = entry_int;
    SCReturnInt(0);
}

int ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool)
{
    if (entry_bool)
        iconf->flags |= DPDK_PROMISC;

    SCReturnInt(0);
}

int ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool)
{
    if (entry_bool)
        iconf->flags |= DPDK_MULTICAST; // enable

    SCReturnInt(0);
}

int ConfigSetChecksumChecks(DPDKIfaceConfig *iconf, int entry_bool)
{
    if (entry_bool)
        iconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;

    SCReturnInt(0);
}

int ConfigSetChecksumOffload(DPDKIfaceConfig *iconf, int entry_bool)
{
    if (entry_bool)
        iconf->flags |= DPDK_RX_CHECKSUM_OFFLOAD;

    SCReturnInt(0);
}

int ConfigSetCopyIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "none") == 0) {
        iconf->out_iface = NULL;
        SCReturnInt(0);
    }

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->out_port_id);
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Name of the copy interface (%s) not valid", entry_str);
        errno = -retval;
        SCReturnInt(retval);
    }

    iconf->out_iface = entry_str;
    SCReturnInt(0);
}

int ConfigSetCopyMode(DPDKIfaceConfig *iconf, const char *entry_str)
{
    if (entry_str == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Passed value is NULL");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    if (strcmp(entry_str, "none") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_NONE;
    } else if (strcmp(entry_str, "tap") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_TAP;
    } else if (strcmp(entry_str, "ips") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_IPS;
    } else {
        SCLogError(SC_ERR_INVALID_VALUE, "Copy mode not valid (none|tap|ips)");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    SCReturnInt(0);
}

int ConfigSetCopyIfaceSettings(DPDKIfaceConfig *iconf, const char *iface, const char *mode)
{
    int retval;

    retval = ConfigSetCopyIface(iconf, iface);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfigSetCopyMode(iconf, mode);
    if (retval < 0)
        SCReturnInt(retval);

    if (iconf->copy_mode == DPDK_COPY_MODE_NONE) {
        if (iconf->out_iface != NULL) {
            SCFree((void *)iconf->out_iface);
            iconf->out_iface = NULL;
        }

        SCReturnInt(0);
    }

    if (iconf->out_iface == NULL || strlen(iconf->out_iface) <= 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Copy mode enabled but interface not set");
        errno = EINVAL;
        SCReturnInt(-errno);
    }

    if (iconf->copy_mode == DPDK_COPY_MODE_IPS)
        SCLogInfo("DPDK IPS mode activated between %s and %s", iconf->iface, iconf->out_iface);
    else if (iconf->copy_mode == DPDK_COPY_MODE_TAP)
        SCLogInfo("DPDK IPS mode activated between %s and %s", iconf->iface, iconf->out_iface);

    SCReturnInt(0);
}

int ConfigLoad(DPDKIfaceConfig *iconf, const char *iface)
{
    int retval;
    ConfNode *if_root;
    ConfNode *if_default;
    const char *entry_str = NULL;
    intmax_t entry_int = 0;
    int entry_bool = 0;
    const char *copy_iface_str = NULL;
    const char *copy_mode_str = NULL;

    ConfigSetIface(iconf, iface);

    retval = ConfSetRootAndDefaultNodes("dpdk.interfaces", iconf->iface, &if_root, &if_default);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.threads, &entry_str) != 1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.threads);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetThreads(iconf, entry_str);
    if (retval < 0) {
        return retval;
    }

    // currently only mapping "1 thread = 1 RX (and 1 TX queue in IPS mode)" is supported
    retval = ConfigSetRxQueues(iconf, (uint16_t)iconf->threads);
    if (retval < 0) {
        return retval;
    }

    // currently only mapping "1 thread = 1 RX (and 1 TX queue in IPS mode)" is supported
    retval = ConfigSetTxQueues(iconf, (uint16_t)iconf->threads);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueIntWithDefault(if_root, if_default, dpdk_yaml.mempool_size, &entry_int) !=
            1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.mempool_size);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetMempoolSize(iconf, entry_int);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueIntWithDefault(
                if_root, if_default, dpdk_yaml.mempool_cache_size, &entry_int) != 1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing",
                dpdk_yaml.mempool_cache_size);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetMempoolCacheSize(iconf, entry_int);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueIntWithDefault(
                if_root, if_default, dpdk_yaml.rx_descriptors, &entry_int) != 1) {
        SCLogError(
                SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.rx_descriptors);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetRxDescriptors(iconf, entry_int);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueIntWithDefault(
                if_root, if_default, dpdk_yaml.tx_descriptors, &entry_int) != 1) {
        SCLogError(
                SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.tx_descriptors);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetTxDescriptors(iconf, entry_int);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueIntWithDefault(if_root, if_default, dpdk_yaml.mtu, &entry_int) != 1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.mtu);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetMtu(iconf, entry_int);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, dpdk_yaml.promisc, &entry_bool) !=
            1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.promisc);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetPromiscuousMode(iconf, entry_bool);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, dpdk_yaml.multicast, &entry_bool) !=
            1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.multicast);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetMulticast(iconf, entry_bool);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueBoolWithDefault(
                if_root, if_default, dpdk_yaml.checksum_checks, &entry_bool) != 1) {
        SCLogError(
                SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.checksum_checks);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetChecksumChecks(iconf, entry_bool);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueBoolWithDefault(
                if_root, if_default, dpdk_yaml.checksum_checks_offload, &entry_bool) != 1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing",
                dpdk_yaml.checksum_checks_offload);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetChecksumOffload(iconf, entry_bool);
    if (retval < 0) {
        return retval;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.copy_mode, &copy_mode_str) !=
            1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.copy_mode);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    if (ConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.copy_iface, &copy_iface_str) !=
            1) {
        SCLogError(SC_ERR_DPDK_CONF, "Value of \"%s\" invalid or missing", dpdk_yaml.copy_iface);
        errno = EINVAL;
        SCReturnInt(-errno);
    }
    retval = ConfigSetCopyIfaceSettings(iconf, copy_iface_str, copy_mode_str);
    if (retval < 0) {
        return retval;
    }

    if (iconf->copy_mode == DPDK_COPY_MODE_NONE) {
        SCLogInfo("IDS mode enabled, disabling TX settings");
        iconf->nb_tx_queues = 0;
        iconf->nb_tx_desc = 0;
    }

    SCReturnInt(0);
}
DPDKIfaceConfig *ConfigParse(const char *iface)
{
    int retval;
    DPDKIfaceConfig *iconf = NULL;
    if (iface == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "Provided iface is NULL");
        SCReturnPtr(NULL, "void *");
    }

    ConfigInit(&iconf);
    if (iconf == NULL) {
        SCReturnPtr(NULL, "void *");
    }
    retval = ConfigLoad(iconf, iface);
    if (retval < 0) {
        iconf->DerefFunc(iconf);
        SCReturnPtr(NULL, "void *");
    }

    return iconf;
}

void DeviceInitPortConf(const DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        struct rte_eth_conf *port_conf)
{
    *port_conf = (struct rte_eth_conf){
            .rxmode = {
                    .mq_mode = ETH_MQ_RX_NONE,
                    .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
                    .offloads = 0, // turn every offload off to prevent any packet modification
            },
            .txmode = {
                    .mq_mode = ETH_MQ_TX_NONE,
                    .offloads = 0,
            },
    };

    // configure RX offloads
    if (dev_info->rx_offload_capa & DEV_RX_OFFLOAD_RSS_HASH) {
        if (iconf->nb_rx_queues > 1) {
            SCLogConfig("RSS enabled on %s for %d queues", iconf->iface, iconf->nb_rx_queues);
            port_conf->rx_adv_conf.rss_conf.rss_key = rss_hkey;
            port_conf->rx_adv_conf.rss_conf.rss_key_len = RSS_HKEY_LEN;
            port_conf->rx_adv_conf.rss_conf.rss_hf = ETH_RSS_TCP | ETH_RSS_UDP;
            port_conf->rxmode.mq_mode = ETH_MQ_RX_RSS;
        } else {
            SCLogConfig("RSS not enabled on %s", iconf->iface);
            port_conf->rx_adv_conf.rss_conf.rss_key = NULL;
            port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
        }
    } else {
        SCLogConfig("RSS not supported on %s", iconf->iface);
    }

    if (iconf->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        SCLogConfig("Checksum validation disabled on %s", iconf->iface);
    } else if (dev_info->rx_offload_capa & DEV_RX_OFFLOAD_CHECKSUM) {
        if (iconf->checksum_mode == CHECKSUM_VALIDATION_ENABLE &&
                iconf->flags & DPDK_RX_CHECKSUM_OFFLOAD) {
            SCLogConfig("IP, TCP and UDP checksum validation enabled and offloaded "
                        "on %s",
                    iconf->iface);
            port_conf->rxmode.offloads |= DEV_RX_OFFLOAD_CHECKSUM;
        } else if (iconf->checksum_mode == CHECKSUM_VALIDATION_ENABLE &&
                   !(iconf->flags & DPDK_RX_CHECKSUM_OFFLOAD)) {
            SCLogConfig("Suricata checksum validation enabled "
                        "but not offloaded on %s",
                    iconf->iface);
        }
    }

    if (dev_info->tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf->txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }
}

int DeviceConfigureQueues(DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        const struct rte_eth_conf *port_conf)
{
    int retval;
    uint16_t mtu_size;
    uint16_t mbuf_size;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;

    iconf->pkt_mempool_array = SCCalloc(iconf->nb_rx_queues, sizeof(struct rte_mempool *));
    if (unlikely(iconf->pkt_mempool_array == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Could not allocate memory for packet mempool pointers");
        SCReturnInt(-ENOMEM);
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_rx_queues; queue_id++) {
        char mempool_name[64];
        snprintf(mempool_name, 64, "pktmbuf_pool_p%d_q%d", iconf->port_id, queue_id);
        // +4 for VLAN header
        mtu_size = iconf->mtu + RTE_ETHER_CRC_LEN + RTE_ETHER_HDR_LEN + 4;
        mbuf_size = ROUNDUP(mtu_size, 1024) + RTE_PKTMBUF_HEADROOM;
        SCLogInfo("Creating a packet mbuf pool %s of size %d, cache size %d, mbuf size %d",
                mempool_name, iconf->mempool_size, iconf->mempool_cache_size, mbuf_size);
        iconf->pkt_mempool_array[queue_id] =
                rte_pktmbuf_pool_create(mempool_name, iconf->mempool_size,
                        iconf->mempool_cache_size, 0, mbuf_size, (int)iconf->socket_id);
        if (iconf->pkt_mempool_array[queue_id] == NULL) {
            retval = -rte_errno;
            SCLogError(SC_ERR_DPDK_INIT,
                    "Error (err=%d) during rte_pktmbuf_pool_create (mempool: %s) - %s", rte_errno,
                    mempool_name, rte_strerror(rte_errno));
            SCReturnInt(retval);
        }

        rxq_conf = dev_info->default_rxconf;
        rxq_conf.offloads = port_conf->rxmode.offloads;
        rxq_conf.rx_thresh.hthresh = 0;
        rxq_conf.rx_thresh.pthresh = 0;
        rxq_conf.rx_thresh.wthresh = 0;
        rxq_conf.rx_free_thresh = 0;
        rxq_conf.rx_drop_en = 0;
        SCLogInfo(
                "Creating Q %d of P %d using desc RX: %d TX: %d RX htresh: %d RX pthresh %d wtresh "
                "%d free_tresh %d drop_en %d Offloads %lu",
                queue_id, iconf->port_id, iconf->nb_rx_desc, iconf->nb_tx_desc,
                rxq_conf.rx_thresh.hthresh, rxq_conf.rx_thresh.pthresh, rxq_conf.rx_thresh.wthresh,
                rxq_conf.rx_free_thresh, rxq_conf.rx_drop_en, rxq_conf.offloads);

        retval = rte_eth_rx_queue_setup(iconf->port_id, queue_id, iconf->nb_rx_desc,
                iconf->socket_id, &rxq_conf, iconf->pkt_mempool_array[queue_id]);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT,
                    "Error (err=%d) during initialization of device queue %u of port %u", retval,
                    queue_id, iconf->port_id);
            SCReturnInt(retval);
        }
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_tx_queues; queue_id++) {
        txq_conf = dev_info->default_txconf;
        txq_conf.offloads = port_conf->txmode.offloads;
        SCLogInfo("Creating TX queue %d on port %d", queue_id, iconf->port_id);
        retval = rte_eth_tx_queue_setup(
                iconf->port_id, queue_id, iconf->nb_tx_desc, iconf->socket_id, &txq_conf);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT,
                    "Error (err=%d) during initialization of device queue %u of port %u", retval,
                    queue_id, iconf->port_id);
            SCReturnInt(retval);
        }
    }

    SCReturnInt(0);
}

int DeviceValidateOutIfaceConfig(DPDKIfaceConfig *iconf)
{
    int retval;
    DPDKIfaceConfig *out_iconf = NULL;
    ConfigInit(&out_iconf);
    if (out_iconf == NULL) {
        SCReturnInt(-EXIT_FAILURE);
    }

    retval = ConfigLoad(out_iconf, iconf->out_iface);
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Fail to load config of interface %s", iconf->out_iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EXIT_FAILURE);
    }

    if (iconf->nb_rx_queues != out_iconf->nb_tx_queues) {
        SCLogError(SC_ERR_DPDK_CONF,
                "Interface %s has configured %d RX queues but copy interface %s has %d TX queues"
                " - number of queues must be equal",
                iconf->iface, iconf->nb_rx_queues, out_iconf->iface, out_iconf->nb_tx_queues);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EXIT_FAILURE);
    } else if (iconf->mtu != out_iconf->mtu) {
        SCLogError(SC_ERR_DPDK_CONF,
                "Interface %s has configured MTU of %dB but copy interface %s has MTU set to %dB"
                " - MTU must be equal",
                iconf->iface, iconf->mtu, out_iconf->iface, out_iconf->mtu);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EXIT_FAILURE);
    } else if (iconf->copy_mode != out_iconf->copy_mode) {
        SCLogError(SC_ERR_DPDK_CONF, "Copy modes of interfaces %s and %s are not equal",
                iconf->iface, out_iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EXIT_FAILURE);
    } else if (strcmp(iconf->iface, out_iconf->out_iface) != 0) {
        // check if the other iface has the current iface set as a copy iface
        SCLogError(SC_ERR_DPDK_CONF, "Copy interface of %s is not set to %s", out_iconf->iface,
                iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EXIT_FAILURE);
    }

    out_iconf->DerefFunc(out_iconf);
    SCReturnInt(EXIT_SUCCESS);
}

int DeviceConfigureIPS(DPDKIfaceConfig *iconf)
{
    int retval;

    if (iconf->out_iface != NULL) {
        retval = rte_eth_dev_get_port_by_name(iconf->out_iface, &iconf->out_port_id);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during obtaining port id of %s", retval,
                    iconf->out_iface);
            SCReturnInt(retval);
        }

        if (rte_eth_dev_socket_id(iconf->port_id) != rte_eth_dev_socket_id(iconf->out_port_id)) {
            SCLogWarning(SC_WARN_DPDK_CONF, "%s and %s are not on the same NUMA node", iconf->iface,
                    iconf->out_iface);
        }

        retval = DeviceValidateOutIfaceConfig(iconf);
        if (retval != 0) {
            // Error will be written out by the validation function
            SCReturnInt(retval);
        }
    }
    SCReturnInt(0);
}

int DeviceConfigure(DPDKIfaceConfig *iconf)
{
    // configure device
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;

    retval = rte_eth_dev_get_port_by_name(iconf->iface, &(iconf->port_id));
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when getting port id of %s Is device enabled?",
                retval, iconf->iface);
        SCReturnInt(retval);
    }

    if (!rte_eth_dev_is_valid_port(iconf->port_id)) {
        SCLogError(SC_ERR_DPDK_INIT, "Specified port %d is invalid", iconf->port_id);
        SCReturnInt(retval);
    }

    retval = rte_eth_dev_socket_id(iconf->port_id);
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) invalid socket id (port %u)", retval,
                iconf->port_id);
        SCReturnInt(retval);
    } else {
        iconf->socket_id = retval;
    }

    retval = rte_eth_dev_info_get(iconf->port_id, &dev_info);
    if (retval != 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during getting device info (port %" PRIu16 ")",
                retval, iconf->port_id);
        SCReturnInt(retval);
    }

    if (iconf->nb_rx_queues > dev_info.max_rx_queues) {
        errno = ERANGE;
        SCLogError(SC_ERR_DPDK_INIT,
                "Number of configured RX queues of port %" PRIu16
                " is higher than maximum allowed (%" PRIu16 ")",
                iconf->port_id, dev_info.max_rx_queues);
        SCReturnInt(-errno);
    }

    if (iconf->nb_tx_queues > dev_info.max_tx_queues) {
        errno = ERANGE;
        SCLogError(SC_ERR_DPDK_INIT,
                "Number of configured TX queues of port %" PRIu16
                " is higher than maximum allowed (%" PRIu16 ")",
                iconf->port_id, dev_info.max_tx_queues);
        SCReturnInt(-errno);
    }

    if (iconf->mtu > dev_info.max_mtu || iconf->mtu < dev_info.min_mtu) {
        errno = ERANGE;
        SCLogError(SC_ERR_DPDK_INIT,
                "Loaded MTU of port %" PRIu16 " is out of bounds. "
                "Min MTU: %" PRIu16 " Max MTU: %" PRIu16,
                iconf->port_id, dev_info.min_mtu, dev_info.max_mtu);
        SCReturnInt(-errno);
    }

    DeviceInitPortConf(iconf, &dev_info, &port_conf);
    if (port_conf.rxmode.offloads & DEV_RX_OFFLOAD_CHECKSUM) {
        // Suricata does not need recalc checksums now
        iconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
    }

    retval = rte_eth_dev_configure(
            iconf->port_id, iconf->nb_rx_queues, iconf->nb_tx_queues, &port_conf);
    if (retval != 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during configuring the device (port %u)",
                retval, iconf->port_id);
        SCReturnInt(retval);
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(
            iconf->port_id, &iconf->nb_rx_desc, &iconf->nb_tx_desc);
    if (retval != 0) {
        SCLogError(SC_ERR_DPDK_INIT,
                "Error (err=%d) during adjustment of device queues descriptors (port %u)", retval,
                iconf->port_id);
        SCReturnInt(retval);
    }

    retval = iconf->flags & DPDK_MULTICAST ? rte_eth_allmulticast_enable(iconf->port_id)
                                           : rte_eth_allmulticast_disable(iconf->port_id);
    if (retval == -ENOTSUP) {
        retval = rte_eth_allmulticast_get(iconf->port_id);
        // when multicast is enabled but set to disable or vice versa
        if ((retval == 1 && !(iconf->flags & DPDK_MULTICAST)) ||
                (retval == 0 && (iconf->flags & DPDK_MULTICAST))) {
            SCLogError(SC_ERR_DPDK_CONF,
                    "Allmulticast setting of port (%" PRIu16
                    ") can not be configured. Set it to %s",
                    iconf->port_id, retval == 1 ? "true" : "false");
        } else if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) Unable to get multicast mode on port %u",
                    retval, iconf->port_id);
            SCReturnInt(retval);
        }

        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) Unable to get multicast mode on port %u",
                    retval, iconf->port_id);
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when en/disabling multicast on port %u",
                retval, iconf->port_id);
        SCReturnInt(retval);
    }

    retval = iconf->flags & DPDK_PROMISC ? rte_eth_promiscuous_enable(iconf->port_id)
                                         : rte_eth_promiscuous_disable(iconf->port_id);
    if (retval == -ENOTSUP) {
        retval = rte_eth_promiscuous_get(iconf->port_id);
        if ((retval == 1 && !(iconf->flags & DPDK_PROMISC)) ||
                (retval == 0 && (iconf->flags & DPDK_PROMISC))) {
            SCLogError(SC_ERR_DPDK_CONF,
                    "Promiscuous setting of port (%" PRIu16 ") can not be configured. Set it to %s",
                    iconf->port_id, retval == 1 ? "true" : "false");
        } else if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) Unable to get promiscuous mode on port %u",
                    retval, iconf->port_id);
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when enabling promiscuous mode on port %u",
                retval, iconf->port_id);
        iconf->DerefFunc(iconf);
        SCReturnInt(TM_ECODE_FAILED);
    }

    // set maximum transmission unit
    SCLogConfig("Setting MTU of %s to %dB", iconf->iface, iconf->mtu);
    retval = rte_eth_dev_set_mtu(iconf->port_id, iconf->mtu);
    if (retval == -ENOTSUP) {
        SCLogWarning(SC_WARN_DPDK_CONF,
                "Changing MTU on port %u is not supported, ignoring the setting...",
                iconf->port_id);
        // if it is not possible to set the MTU, retrieve it
        retval = rte_eth_dev_get_mtu(iconf->port_id, &iconf->mtu);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) Unable to retrieve MTU from port %u",
                    retval, iconf->port_id);
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when setting MTU to %u on port %u", retval,
                iconf->mtu, iconf->port_id);
        SCReturnInt(retval);
    }

    retval = DeviceConfigureQueues(iconf, &dev_info, &port_conf);
    if (retval < 0) {
        SCReturnInt(retval);
    }

    retval = DeviceConfigureIPS(iconf);
    if (retval < 0) {
        SCReturnInt(retval);
    }

    SCReturnInt(0);
}
void *ParseDpdkConfigAndConfigureDevice(const char *iface)
{
    DPDKIfaceConfig *iconf = ConfigParse(iface);
    if (iconf == NULL) {
        FatalError(SC_ERR_DPDK_CONF, "DPDK configuration could not be parsed");
    }

    if (DeviceConfigure(iconf) != 0) {
        iconf->DerefFunc(iconf);
        FatalError(SC_ERR_DPDK_CONF, "Device %s fails to configure", iface);
    }

    SC_ATOMIC_RESET(iconf->ref);
    (void)SC_ATOMIC_ADD(iconf->ref, iconf->threads);
    // This counter is increased by worker threads that individually pick queue IDs.
    SC_ATOMIC_RESET(iconf->queue_id);
    return iconf;
}

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * After configuration is loaded, DPDK also configures the device according to the settings.
 *
 * \return a DPDKIfaceConfig corresponding to the interface name
 */

static int DPDKConfigGetThreadsCount(void *conf)
{
    if (conf == NULL)
        FatalError(SC_ERR_DPDK_CONF, "Configuration file is NULL");

    DPDKIfaceConfig *dpdk_conf = (DPDKIfaceConfig *)conf;
    return dpdk_conf->threads;
}

#endif

const char *RunModeDpdkGetDefaultMode(void)
{
    return "workers";
}

void RunModeDpdkRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "workers",
            "Workers DPDK mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsDpdkWorkers);
}

/**
 * \brief Workers version of the AF_PACKET processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsDpdkWorkers(void)
{
    SCEnter();
#ifdef HAVE_DPDK
    int ret;

    RunModeInitialize();
    TimeModeSetLive();

    ret = InitEal();
    if (ret < 0)
        FatalError(SC_ERR_DPDK_EAL_INIT, "Error (%" PRIu32 ") Failed to initialize DPDK EAL", ret);

    ret = RunModeSetLiveCaptureWorkers(ParseDpdkConfigAndConfigureDevice, DPDKConfigGetThreadsCount,
            "ReceiveDPDK", "DecodeDPDK", thread_name_workers, NULL);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsDpdkWorkers initialised");

#endif /* HAVE_DPDK */
    SCReturnInt(0);
}

/**
 * @}
 */
