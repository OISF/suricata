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
#include "util-cpu.h"
#include "util-dpdk.h"
#include "util-dpdk-i40e.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-ixgbe.h"
#include "util-time.h"

#ifdef HAVE_DPDK

#define RSS_HKEY_LEN 40
// General purpose RSS key for symmetric bidirectional flow distribution
uint8_t rss_hkey[] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
    0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
    0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A };

// Calculates the closest multiple of y from x
#define ROUNDUP(x, y) ((((x) + ((y)-1)) / (y)) * (y))

/* Maximum DPDK EAL parameters count. */
#define EAL_ARGS 48

struct Arguments {
    uint16_t capacity;
    char **argv;
    uint16_t argc;
};

static char *AllocArgument(size_t arg_len);
static char *AllocAndSetArgument(const char *arg);
static char *AllocAndSetOption(const char *arg);

static void ArgumentsInit(struct Arguments *args, unsigned capacity);
static void ArgumentsCleanup(struct Arguments *args);
static void ArgumentsAdd(struct Arguments *args, char *value);
static void ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg);
static void InitEal(void);

static void ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues);
static int ConfigSetTxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues);
static int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetTxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int);
static int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int);
static bool ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool);
static bool ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool);
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

#define DPDK_CONFIG_DEFAULT_THREADS                     "auto"
#define DPDK_CONFIG_DEFAULT_MEMPOOL_SIZE                65535
#define DPDK_CONFIG_DEFAULT_MEMPOOL_CACHE_SIZE          "auto"
#define DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS              1024
#define DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS              1024
#define DPDK_CONFIG_DEFAULT_MTU                         1500
#define DPDK_CONFIG_DEFAULT_PROMISCUOUS_MODE            1
#define DPDK_CONFIG_DEFAULT_MULTICAST_MODE              1
#define DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION         1
#define DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION_OFFLOAD 1
#define DPDK_CONFIG_DEFAULT_COPY_MODE                   "none"
#define DPDK_CONFIG_DEFAULT_COPY_INTERFACE              "none"

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

static int GreatestDivisorUpTo(uint32_t num, uint32_t max_num)
{
    for (int i = max_num; i >= 2; i--) {
        if (num % i == 0) {
            return i;
        }
    }
    return 1;
}

static char *AllocArgument(size_t arg_len)
{
    SCEnter();
    char *ptr;

    arg_len += 1; // null character
    ptr = (char *)SCCalloc(arg_len, sizeof(char));
    if (ptr == NULL)
        FatalError(SC_ERR_MEM_ALLOC, "Could not allocate memory for an argument");

    SCReturnPtr(ptr, "char *");
}

/**
 * Allocates space for length of the given string and then copies contents
 * @param arg String to set to the newly allocated space
 * @return memory address if no error otherwise NULL (with errno set)
 */
static char *AllocAndSetArgument(const char *arg)
{
    SCEnter();
    if (arg == NULL)
        FatalError(SC_ERR_DPDK_CONF, "Passed argument is NULL in DPDK config initialization");

    char *ptr;
    size_t arg_len = strlen(arg);

    ptr = AllocArgument(arg_len);
    strlcpy(ptr, arg, arg_len + 1);
    SCReturnPtr(ptr, "char *");
}

static char *AllocAndSetOption(const char *arg)
{
    SCEnter();
    if (arg == NULL)
        FatalError(SC_ERR_DPDK_CONF, "Passed option is NULL in DPDK config initialization");

    char *ptr = NULL;
    size_t arg_len = strlen(arg);
    uint8_t is_long_arg = arg_len > 1;
    const char *dash_prefix = is_long_arg ? "--" : "-";
    size_t full_len = arg_len + strlen(dash_prefix);

    ptr = AllocArgument(full_len);
    strlcpy(ptr, dash_prefix, strlen(dash_prefix) + 1);
    strlcat(ptr, arg, full_len + 1);
    SCReturnPtr(ptr, "char *");
}

static void ArgumentsInit(struct Arguments *args, unsigned capacity)
{
    SCEnter();
    args->argv = SCCalloc(capacity, sizeof(args->argv));
    if (args->argv == NULL)
        FatalError(SC_ERR_MEM_ALLOC, "Could not allocate memory for Arguments structure");

    args->capacity = capacity;
    args->argc = 0;
    SCReturn;
}

static void ArgumentsCleanup(struct Arguments *args)
{
    SCEnter();
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

static void ArgumentsAdd(struct Arguments *args, char *value)
{
    SCEnter();
    if (args->argc + 1 > args->capacity)
        FatalError(SC_ERR_DPDK_EAL_INIT, "No capacity for more arguments (Max: %" PRIu32 ")",
                EAL_ARGS);

    args->argv[args->argc++] = value;
    SCReturn;
}

static void ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg)
{
    SCEnter();
    char *option;
    char *argument;

    option = AllocAndSetOption(opt);
    ArgumentsAdd(args, option);

    // Empty argument could mean option only (e.g. --no-huge)
    if (arg == NULL || arg[0] == '\0')
        SCReturn;

    argument = AllocAndSetArgument(arg);
    ArgumentsAdd(args, argument);
    SCReturn;
}

static void InitEal()
{
    SCEnter();
    int retval;
    ConfNode *param;
    const ConfNode *eal_params = ConfGetNode("dpdk.eal-params");
    struct Arguments args;
    char **eal_argv;

    if (eal_params == NULL) {
        FatalError(SC_ERR_DPDK_CONF, "DPDK EAL parameters not found in the config");
    }

    ArgumentsInit(&args, EAL_ARGS);
    ArgumentsAdd(&args, AllocAndSetArgument("suricata"));

    TAILQ_FOREACH (param, &eal_params->head, next) {
        ArgumentsAddOptionAndArgument(&args, param->name, param->val);
    }

    // creating a shallow copy for cleanup because rte_eal_init changes array contents
    eal_argv = SCMalloc(args.argc * sizeof(args.argv));
    if (eal_argv == NULL) {
        FatalError(
                SC_ERR_MEM_ALLOC, "Failed to allocate memory for the array of DPDK EAL arguments");
    }
    memcpy(eal_argv, args.argv, args.argc * sizeof(*args.argv));

    rte_log_set_global_level(RTE_LOG_WARNING);
    retval = rte_eal_init(args.argc, eal_argv);

    ArgumentsCleanup(&args);
    SCFree(eal_argv);

    if (retval < 0) { // retval binded to the result of rte_eal_init
        FatalError(
                SC_ERR_DPDK_EAL_INIT, "DPDK EAL initialization error: %s", rte_strerror(-retval));
    }
}

static void DPDKDerefConfig(void *conf)
{
    SCEnter();
    DPDKIfaceConfig *iconf = (DPDKIfaceConfig *)conf;

    if (SC_ATOMIC_SUB(iconf->ref, 1) == 1) {
        if (iconf->pkt_mempool != NULL) {
            rte_mempool_free(iconf->pkt_mempool);
        }

        SCFree(iconf);
    }
    SCReturn;
}

static void ConfigInit(DPDKIfaceConfig **iconf)
{
    SCEnter();
    DPDKIfaceConfig *ptr = NULL;
    ptr = SCCalloc(1, sizeof(DPDKIfaceConfig));
    if (ptr == NULL)
        FatalError(SC_ERR_DPDK_CONF, "Could not allocate memory for DPDKIfaceConfig");

    ptr->pkt_mempool = NULL;
    ptr->out_port_id = -1; // make sure no port is set
    SC_ATOMIC_INIT(ptr->ref);
    (void)SC_ATOMIC_ADD(ptr->ref, 1);
    ptr->DerefFunc = DPDKDerefConfig;
    ptr->flags = 0;

    *iconf = ptr;
    SCReturn;
}

static void ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0')
        FatalError(SC_ERR_INVALID_VALUE, "Interface name in DPDK config is NULL or empty");

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->port_id);
    if (retval < 0)
        FatalError(SC_ERR_DPDK_CONF, "Interface \"%s\": %s", entry_str, rte_strerror(-retval));

    strlcpy(iconf->iface, entry_str, sizeof(iconf->iface));
    SCReturn;
}

static int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    const char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("single", active_runmode)) {
        iconf->threads = 1;
        SCReturnInt(0);
    }

    if (entry_str == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Number of threads for interface \"%s\" not specified",
                iconf->iface);
        SCReturnInt(-EINVAL);
    }

    if (strcmp(entry_str, "auto") == 0) {
        iconf->threads = (int)UtilCpuGetNumProcessorsOnline();
        SCLogPerf("%u cores, so using %u threads", iconf->threads, iconf->threads);
        SCReturnInt(0);
    }

    if (StringParseInt32(&iconf->threads, 10, 0, entry_str) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Threads entry for interface %s contain non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->threads < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Interface %s has a negative number of threads",
                iconf->iface);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues)
{
    SCEnter();
    iconf->nb_rx_queues = nb_queues;
    if (iconf->nb_rx_queues < 1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have positive number of RX queues", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetTxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues)
{
    SCEnter();
    iconf->nb_tx_queues = nb_queues;
    if (iconf->nb_tx_queues < 1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have positive number of TX queues", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Interface %s requires to have positive memory pool size",
                iconf->iface);
        SCReturnInt(-ERANGE);
    }

    iconf->mempool_size = entry_int;
    SCReturnInt(0);
}

static int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "auto") == 0) {
        // calculate the mempool size based on the mempool size (it needs to be already filled in)
        // It is advised to have mempool cache size lower or equal to:
        //   RTE_MEMPOOL_CACHE_MAX_SIZE (by default 512) and "mempool-size / 1.5"
        // and at the same time "mempool-size modulo cache_size == 0".
        if (iconf->mempool_size == 0) {
            SCLogError(SC_ERR_INVALID_VALUE,
                    "Cannot calculate mempool cache size of a mempool with size %d",
                    iconf->mempool_size);
            SCReturnInt(-EINVAL);
        }

        uint32_t max_cache_size = MAX(RTE_MEMPOOL_CACHE_MAX_SIZE, iconf->mempool_size / 1.5);
        iconf->mempool_cache_size = GreatestDivisorUpTo(iconf->mempool_size, max_cache_size);
        SCReturnInt(0);
    }

    if (StringParseUint32(&iconf->mempool_cache_size, 10, 0, entry_str) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Mempool cache size entry for interface %s contain non-numerical "
                "characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->mempool_cache_size <= 0 || iconf->mempool_cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have positive memory pool size and be less than %" PRIu32,
                iconf->iface, RTE_MEMPOOL_CACHE_MAX_SIZE);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have positive number of RX descriptors", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    iconf->nb_rx_desc = entry_int;
    SCReturnInt(0);
}

static int ConfigSetTxDescriptors(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have positive number of TX descriptors", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    iconf->nb_tx_desc = entry_int;
    SCReturnInt(0);
}

static int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int < RTE_ETHER_MIN_MTU || entry_int > RTE_ETHER_MAX_JUMBO_FRAME_LEN) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Interface %s requires to have size of MTU between %" PRIu32 " and %" PRIu32,
                iconf->iface, RTE_ETHER_MIN_MTU, RTE_ETHER_MAX_JUMBO_FRAME_LEN);
        SCReturnInt(-ERANGE);
    }

    iconf->mtu = entry_int;
    SCReturnInt(0);
}

static bool ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_PROMISC;

    SCReturnBool(true);
}

static bool ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_MULTICAST; // enable

    SCReturnBool(true);
}

static int ConfigSetChecksumChecks(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;

    SCReturnInt(0);
}

static int ConfigSetChecksumOffload(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_RX_CHECKSUM_OFFLOAD;

    SCReturnInt(0);
}

static int ConfigSetCopyIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "none") == 0) {
        iconf->out_iface = NULL;
        SCReturnInt(0);
    }

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->out_port_id);
    if (retval < 0) {
        SCLogWarning(SC_ERR_DPDK_CONF,
                "Name of the copy interface (%s) for the interface %s is not valid, changing to %s",
                entry_str, iconf->iface, DPDK_CONFIG_DEFAULT_COPY_INTERFACE);
        iconf->out_iface = DPDK_CONFIG_DEFAULT_COPY_INTERFACE;
    }

    iconf->out_iface = entry_str;
    SCReturnInt(0);
}

static int ConfigSetCopyMode(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE,
                "Interface %s has no copy mode specified, changing to %s ", iconf->iface,
                DPDK_CONFIG_DEFAULT_COPY_MODE);
        entry_str = DPDK_CONFIG_DEFAULT_COPY_MODE;
    }

    if (strcmp(entry_str, "none") != 0 && strcmp(entry_str, "tap") != 0 &&
            strcmp(entry_str, "ips") != 0) {
        SCLogWarning(SC_ERR_INVALID_VALUE,
                "Copy mode \"%s\" is not one of the possible values (none|tap|ips) for interface "
                "%s. Changing to %s",
                entry_str, iconf->iface, DPDK_CONFIG_DEFAULT_COPY_MODE);
        entry_str = DPDK_CONFIG_DEFAULT_COPY_MODE;
    }

    if (strcmp(entry_str, "none") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_NONE;
    } else if (strcmp(entry_str, "tap") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_TAP;
    } else if (strcmp(entry_str, "ips") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_IPS;
    }

    SCReturnInt(0);
}

static int ConfigSetCopyIfaceSettings(DPDKIfaceConfig *iconf, const char *iface, const char *mode)
{
    SCEnter();
    int retval;

    retval = ConfigSetCopyIface(iconf, iface);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfigSetCopyMode(iconf, mode);
    if (retval < 0)
        SCReturnInt(retval);

    if (iconf->copy_mode == DPDK_COPY_MODE_NONE) {
        if (iconf->out_iface != NULL)
            iconf->out_iface = NULL;
        SCReturnInt(0);
    }

    if (iconf->out_iface == NULL || strlen(iconf->out_iface) <= 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Copy mode enabled but interface not set");
        SCReturnInt(-EINVAL);
    }

    if (iconf->copy_mode == DPDK_COPY_MODE_IPS)
        SCLogInfo("DPDK IPS mode activated between %s and %s", iconf->iface, iconf->out_iface);
    else if (iconf->copy_mode == DPDK_COPY_MODE_TAP)
        SCLogInfo("DPDK IPS mode activated between %s and %s", iconf->iface, iconf->out_iface);

    SCReturnInt(0);
}

static int ConfigLoad(DPDKIfaceConfig *iconf, const char *iface)
{
    SCEnter();
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
        FatalError(SC_ERR_DPDK_CONF, "failed to find DPDK configuration for the interface %s",
                iconf->iface);
    }

    retval = ConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.threads, &entry_str) != 1
                     ? ConfigSetThreads(iconf, DPDK_CONFIG_DEFAULT_THREADS)
                     : ConfigSetThreads(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    // currently only mapping "1 thread == 1 RX (and 1 TX queue in IPS mode)" is supported
    retval = ConfigSetRxQueues(iconf, (uint16_t)iconf->threads);
    if (retval < 0)
        SCReturnInt(retval);

    // currently only mapping "1 thread == 1 RX (and 1 TX queue in IPS mode)" is supported
    retval = ConfigSetTxQueues(iconf, (uint16_t)iconf->threads);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueIntWithDefault(
                     if_root, if_default, dpdk_yaml.mempool_size, &entry_int) != 1
                     ? ConfigSetMempoolSize(iconf, DPDK_CONFIG_DEFAULT_MEMPOOL_SIZE)
                     : ConfigSetMempoolSize(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueWithDefault(
                     if_root, if_default, dpdk_yaml.mempool_cache_size, &entry_str) != 1
                     ? ConfigSetMempoolCacheSize(iconf, DPDK_CONFIG_DEFAULT_MEMPOOL_CACHE_SIZE)
                     : ConfigSetMempoolCacheSize(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueIntWithDefault(
                     if_root, if_default, dpdk_yaml.rx_descriptors, &entry_int) != 1
                     ? ConfigSetRxDescriptors(iconf, DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS)
                     : ConfigSetRxDescriptors(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueIntWithDefault(
                     if_root, if_default, dpdk_yaml.tx_descriptors, &entry_int) != 1
                     ? ConfigSetTxDescriptors(iconf, DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS)
                     : ConfigSetTxDescriptors(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueIntWithDefault(if_root, if_default, dpdk_yaml.mtu, &entry_int) != 1
                     ? ConfigSetMtu(iconf, DPDK_CONFIG_DEFAULT_MTU)
                     : ConfigSetMtu(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.promisc, &entry_bool) != 1
                     ? ConfigSetPromiscuousMode(iconf, DPDK_CONFIG_DEFAULT_PROMISCUOUS_MODE)
                     : ConfigSetPromiscuousMode(iconf, entry_bool);
    if (retval != true)
        SCReturnInt(-EINVAL);

    retval = ConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.multicast, &entry_bool) != 1
                     ? ConfigSetMulticast(iconf, DPDK_CONFIG_DEFAULT_MULTICAST_MODE)
                     : ConfigSetMulticast(iconf, entry_bool);
    if (retval != true)
        SCReturnInt(-EINVAL);

    retval = ConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.checksum_checks, &entry_bool) != 1
                     ? ConfigSetChecksumChecks(iconf, DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION)
                     : ConfigSetChecksumChecks(iconf, entry_bool);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.checksum_checks_offload, &entry_bool) != 1
                     ? ConfigSetChecksumOffload(
                               iconf, DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION_OFFLOAD)
                     : ConfigSetChecksumOffload(iconf, entry_bool);
    if (retval < 0)
        SCReturnInt(retval);

    retval =
            ConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.copy_mode, &copy_mode_str) |
            ConfGetChildValueWithDefault(
                    if_root, if_default, dpdk_yaml.copy_iface, &copy_iface_str);
    // if one of copy interface settings fail to load then the default values are set
    retval = retval != 1 ? ConfigSetCopyIfaceSettings(iconf, DPDK_CONFIG_DEFAULT_COPY_INTERFACE,
                                   DPDK_CONFIG_DEFAULT_COPY_MODE)
                         : ConfigSetCopyIfaceSettings(iconf, copy_iface_str, copy_mode_str);
    if (retval < 0)
        SCReturnInt(retval);

    SCReturnInt(0);
}

static DPDKIfaceConfig *ConfigParse(const char *iface)
{
    SCEnter();
    int retval;
    DPDKIfaceConfig *iconf = NULL;
    if (iface == NULL)
        FatalError(SC_ERR_DPDK_CONF, "DPDK interface is NULL");

    ConfigInit(&iconf);
    retval = ConfigLoad(iconf, iface);
    if (retval < 0) {
        iconf->DerefFunc(iconf);
        SCReturnPtr(NULL, "void *");
    }

    SCReturnPtr(iconf, "DPDKIfaceConfig *");
}

static void DeviceSetPMDSpecificRSS(struct rte_eth_rss_conf *rss_conf, const char *driver_name)
{
    // RSS is configured in a specific way for a driver i40e and DPDK version <= 19.xx
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSSHashFunction(&rss_conf->rss_hf);
    if (strcmp(driver_name, "net_ice") == 0)
        iceDeviceSetRSSHashFunction(&rss_conf->rss_hf);
    if (strcmp(driver_name, "net_ixgbe") == 0)
        ixgbeDeviceSetRSSHashFunction(&rss_conf->rss_hf);
}

static void DumpRSSFlags(const uint64_t requested, const uint64_t actual)
{
    SCLogConfig("REQUESTED (groups):");

    SCLogConfig("ETH_RSS_IP %sset", ((requested & ETH_RSS_IP) == ETH_RSS_IP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_TCP %sset", ((requested & ETH_RSS_TCP) == ETH_RSS_TCP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_UDP %sset", ((requested & ETH_RSS_UDP) == ETH_RSS_UDP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_SCTP %sset", ((requested & ETH_RSS_SCTP) == ETH_RSS_SCTP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_TUNNEL %sset", ((requested & ETH_RSS_TUNNEL) == ETH_RSS_TUNNEL) ? "" : "NOT ");

    SCLogConfig("REQUESTED (individual):");
    SCLogConfig("ETH_RSS_IPV4 %sset", (requested & ETH_RSS_IPV4) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_FRAG_IPV4 %sset", (requested & ETH_RSS_FRAG_IPV4) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV4_TCP %sset", (requested & ETH_RSS_NONFRAG_IPV4_TCP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV4_UDP %sset", (requested & ETH_RSS_NONFRAG_IPV4_UDP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV4_SCTP %sset",
            (requested & ETH_RSS_NONFRAG_IPV4_SCTP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV4_OTHER %sset",
            (requested & ETH_RSS_NONFRAG_IPV4_OTHER) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6 %sset", (requested & ETH_RSS_IPV6) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_FRAG_IPV6 %sset", (requested & ETH_RSS_FRAG_IPV6) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV6_TCP %sset", (requested & ETH_RSS_NONFRAG_IPV6_TCP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV6_UDP %sset", (requested & ETH_RSS_NONFRAG_IPV6_UDP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV6_SCTP %sset",
            (requested & ETH_RSS_NONFRAG_IPV6_SCTP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV6_OTHER %sset",
            (requested & ETH_RSS_NONFRAG_IPV6_OTHER) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_L2_PAYLOAD %sset", (requested & ETH_RSS_L2_PAYLOAD) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_EX %sset", (requested & ETH_RSS_IPV6_EX) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_TCP_EX %sset", (requested & ETH_RSS_IPV6_TCP_EX) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_UDP_EX %sset", (requested & ETH_RSS_IPV6_UDP_EX) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_PORT %sset", (requested & ETH_RSS_PORT) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_VXLAN %sset", (requested & ETH_RSS_VXLAN) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NVGRE %sset", (requested & ETH_RSS_NVGRE) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_GTPU %sset", (requested & ETH_RSS_GTPU) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_L3_SRC_ONLY %sset", (requested & ETH_RSS_L3_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L3_DST_ONLY %sset", (requested & ETH_RSS_L3_DST_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L4_SRC_ONLY %sset", (requested & ETH_RSS_L4_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L4_DST_ONLY %sset", (requested & ETH_RSS_L4_DST_ONLY) ? "" : "NOT ");

    SCLogConfig("ACTUAL (group):");
    SCLogConfig("ETH_RSS_IP %sset", ((actual & ETH_RSS_IP) == ETH_RSS_IP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_TCP %sset", ((actual & ETH_RSS_TCP) == ETH_RSS_TCP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_UDP %sset", ((actual & ETH_RSS_UDP) == ETH_RSS_UDP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_SCTP %sset", ((actual & ETH_RSS_SCTP) == ETH_RSS_SCTP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_TUNNEL %sset", ((actual & ETH_RSS_TUNNEL) == ETH_RSS_TUNNEL) ? "" : "NOT ");

    SCLogConfig("ACTUAL (individual flags):");
    SCLogConfig("ETH_RSS_IPV4 %sset", (actual & ETH_RSS_IPV4) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_FRAG_IPV4 %sset", (actual & ETH_RSS_FRAG_IPV4) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV4_TCP %sset", (actual & ETH_RSS_NONFRAG_IPV4_TCP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV4_UDP %sset", (actual & ETH_RSS_NONFRAG_IPV4_UDP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV4_SCTP %sset", (actual & ETH_RSS_NONFRAG_IPV4_SCTP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV4_OTHER %sset",
            (actual & ETH_RSS_NONFRAG_IPV4_OTHER) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6 %sset", (actual & ETH_RSS_IPV6) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_FRAG_IPV6 %sset", (actual & ETH_RSS_FRAG_IPV6) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV6_TCP %sset", (actual & ETH_RSS_NONFRAG_IPV6_TCP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV6_UDP %sset", (actual & ETH_RSS_NONFRAG_IPV6_UDP) ? "" : "NOT ");
    SCLogConfig(
            "ETH_RSS_NONFRAG_IPV6_SCTP %sset", (actual & ETH_RSS_NONFRAG_IPV6_SCTP) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NONFRAG_IPV6_OTHER %sset",
            (actual & ETH_RSS_NONFRAG_IPV6_OTHER) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_L2_PAYLOAD %sset", (actual & ETH_RSS_L2_PAYLOAD) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_EX %sset", (actual & ETH_RSS_IPV6_EX) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_TCP_EX %sset", (actual & ETH_RSS_IPV6_TCP_EX) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_IPV6_UDP_EX %sset", (actual & ETH_RSS_IPV6_UDP_EX) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_PORT %sset", (actual & ETH_RSS_PORT) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_VXLAN %sset", (actual & ETH_RSS_VXLAN) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_NVGRE %sset", (actual & ETH_RSS_NVGRE) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_GTPU %sset", (actual & ETH_RSS_GTPU) ? "" : "NOT ");

    SCLogConfig("ETH_RSS_L3_SRC_ONLY %sset", (actual & ETH_RSS_L3_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L3_DST_ONLY %sset", (actual & ETH_RSS_L3_DST_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L4_SRC_ONLY %sset", (actual & ETH_RSS_L4_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("ETH_RSS_L4_DST_ONLY %sset", (actual & ETH_RSS_L4_DST_ONLY) ? "" : "NOT ");
}

static int DeviceValidateMTU(const DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info)
{
    if (iconf->mtu > dev_info->max_mtu || iconf->mtu < dev_info->min_mtu) {
        SCLogError(SC_ERR_DPDK_INIT,
                "Loaded MTU of \"%s\" is out of bounds. "
                "Min MTU: %" PRIu16 " Max MTU: %" PRIu16,
                iconf->iface, dev_info->min_mtu, dev_info->max_mtu);
        SCReturnInt(-ERANGE);
    }

#if RTE_VER_YEAR < 21 || RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11
    // check if jumbo frames are set and are available
    if (iconf->mtu > RTE_ETHER_MAX_LEN &&
            !(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME)) {
        SCLogError(SC_ERR_DPDK_CONF, "Jumbo frames not supported, set MTU of \"%s\" to 1500B",
                iconf->iface);
        SCReturnInt(-EINVAL);
    }
#endif

    SCReturnInt(0);
}

static void DeviceSetMTU(struct rte_eth_conf *port_conf, uint16_t mtu)
{
#if RTE_VER_YEAR > 21 || RTE_VER_YEAR == 21 && RTE_VER_MONTH == 11
    port_conf->rxmode.mtu = mtu;
#else
    port_conf->rxmode.max_rx_pkt_len = mtu;
    if (mtu > RTE_ETHER_MAX_LEN) {
        port_conf->rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
    }
#endif
}

static void DeviceInitPortConf(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
    *port_conf = (struct rte_eth_conf){
            .rxmode = {
                    .mq_mode = ETH_MQ_RX_NONE,
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
            port_conf->rx_adv_conf.rss_conf = (struct rte_eth_rss_conf){
                .rss_key = rss_hkey,
                .rss_key_len = RSS_HKEY_LEN,
                .rss_hf = ETH_RSS_IP,
            };

            DeviceSetPMDSpecificRSS(&port_conf->rx_adv_conf.rss_conf, dev_info->driver_name);

            uint64_t rss_hf_tmp =
                    port_conf->rx_adv_conf.rss_conf.rss_hf & dev_info->flow_type_rss_offloads;
            if (port_conf->rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp) {
                DumpRSSFlags(port_conf->rx_adv_conf.rss_conf.rss_hf, rss_hf_tmp);

                SCLogWarning(SC_WARN_DPDK_CONF,
                        "Interface %s modified RSS hash function based on hardware support, "
                        "requested:%#" PRIx64 " configured:%#" PRIx64,
                        iconf->iface, port_conf->rx_adv_conf.rss_conf.rss_hf, rss_hf_tmp);
                port_conf->rx_adv_conf.rss_conf.rss_hf = rss_hf_tmp;
            }
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
            SCLogConfig("Suricata checksum validation enabled (but can be offloaded on %s)",
                    iconf->iface);
        }
    }

    DeviceSetMTU(port_conf, iconf->mtu);

    if (dev_info->tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf->txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }
}

static int DeviceConfigureQueues(DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        const struct rte_eth_conf *port_conf)
{
    SCEnter();
    int retval;
    uint16_t mtu_size;
    uint16_t mbuf_size;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;

    char mempool_name[64];
    snprintf(mempool_name, 64, "mempool_%.20s", iconf->iface);
    // +4 for VLAN header
    mtu_size = iconf->mtu + RTE_ETHER_CRC_LEN + RTE_ETHER_HDR_LEN + 4;
    mbuf_size = ROUNDUP(mtu_size, 1024) + RTE_PKTMBUF_HEADROOM;
    SCLogInfo("Creating a packet mbuf pool %s of size %d, cache size %d, mbuf size %d",
            mempool_name, iconf->mempool_size, iconf->mempool_cache_size, mbuf_size);

    iconf->pkt_mempool = rte_pktmbuf_pool_create(mempool_name, iconf->mempool_size,
            iconf->mempool_cache_size, 0, mbuf_size, (int)iconf->socket_id);
    if (iconf->pkt_mempool == NULL) {
        retval = -rte_errno;
        SCLogError(SC_ERR_DPDK_INIT,
                "Error (err=%d) during rte_pktmbuf_pool_create (mempool: %s) - %s", rte_errno,
                mempool_name, rte_strerror(rte_errno));
        SCReturnInt(retval);
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_rx_queues; queue_id++) {
        rxq_conf = dev_info->default_rxconf;
        rxq_conf.offloads = port_conf->rxmode.offloads;
        rxq_conf.rx_thresh.hthresh = 0;
        rxq_conf.rx_thresh.pthresh = 0;
        rxq_conf.rx_thresh.wthresh = 0;
        rxq_conf.rx_free_thresh = 0;
        rxq_conf.rx_drop_en = 0;
        SCLogPerf(
                "Creating Q %d of P %d using desc RX: %d TX: %d RX htresh: %d RX pthresh %d wtresh "
                "%d free_tresh %d drop_en %d Offloads %lu",
                queue_id, iconf->port_id, iconf->nb_rx_desc, iconf->nb_tx_desc,
                rxq_conf.rx_thresh.hthresh, rxq_conf.rx_thresh.pthresh, rxq_conf.rx_thresh.wthresh,
                rxq_conf.rx_free_thresh, rxq_conf.rx_drop_en, rxq_conf.offloads);

        retval = rte_eth_rx_queue_setup(iconf->port_id, queue_id, iconf->nb_rx_desc,
                iconf->socket_id, &rxq_conf, iconf->pkt_mempool);
        if (retval < 0) {
            rte_mempool_free(iconf->pkt_mempool);
            SCLogError(SC_ERR_DPDK_INIT,
                    "Error (err=%d) during initialization of device queue %u of port %u", retval,
                    queue_id, iconf->port_id);
            SCReturnInt(retval);
        }
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_tx_queues; queue_id++) {
        txq_conf = dev_info->default_txconf;
        txq_conf.offloads = port_conf->txmode.offloads;
        SCLogPerf("Creating TX queue %d on port %d", queue_id, iconf->port_id);
        retval = rte_eth_tx_queue_setup(
                iconf->port_id, queue_id, iconf->nb_tx_desc, iconf->socket_id, &txq_conf);
        if (retval < 0) {
            rte_mempool_free(iconf->pkt_mempool);
            SCLogError(SC_ERR_DPDK_INIT,
                    "Error (err=%d) during initialization of device queue %u of port %u", retval,
                    queue_id, iconf->port_id);
            SCReturnInt(retval);
        }
    }

    SCReturnInt(0);
}

static int DeviceValidateOutIfaceConfig(DPDKIfaceConfig *iconf)
{
    SCEnter();
    int retval;
    DPDKIfaceConfig *out_iconf = NULL;
    ConfigInit(&out_iconf);
    if (out_iconf == NULL) {
        FatalError(
                SC_ERR_DPDK_CONF, "Copy interface of the interface \"%s\" is NULL", iconf->iface);
    }

    retval = ConfigLoad(out_iconf, iconf->out_iface);
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Fail to load config of interface %s", iconf->out_iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    }

    if (iconf->nb_rx_queues != out_iconf->nb_tx_queues) {
        // the other direction is validated when the copy interface is configured
        SCLogError(SC_ERR_DPDK_CONF,
                "Interface %s has configured %d RX queues but copy interface %s has %d TX queues"
                " - number of queues must be equal",
                iconf->iface, iconf->nb_rx_queues, out_iconf->iface, out_iconf->nb_tx_queues);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (iconf->mtu != out_iconf->mtu) {
        SCLogError(SC_ERR_DPDK_CONF,
                "Interface %s has configured MTU of %dB but copy interface %s has MTU set to %dB"
                " - MTU must be equal",
                iconf->iface, iconf->mtu, out_iconf->iface, out_iconf->mtu);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (iconf->copy_mode != out_iconf->copy_mode) {
        SCLogError(SC_ERR_DPDK_CONF, "Copy modes of interfaces %s and %s are not equal",
                iconf->iface, out_iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (strcmp(iconf->iface, out_iconf->out_iface) != 0) {
        // check if the other iface has the current iface set as a copy iface
        SCLogError(SC_ERR_DPDK_CONF, "Copy interface of %s is not set to %s", out_iconf->iface,
                iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    }

    out_iconf->DerefFunc(out_iconf);
    SCReturnInt(0);
}

static int DeviceConfigureIPS(DPDKIfaceConfig *iconf)
{
    SCEnter();
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

static int DeviceConfigure(DPDKIfaceConfig *iconf)
{
    SCEnter();
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
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) invalid socket id (port %s)", retval,
                iconf->iface);
        SCReturnInt(retval);
    } else {
        iconf->socket_id = retval;
    }

    retval = rte_eth_dev_info_get(iconf->port_id, &dev_info);
    if (retval != 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during getting device info (port %s)", retval,
                iconf->iface);
        SCReturnInt(retval);
    }

    if (iconf->nb_rx_queues > dev_info.max_rx_queues) {
        SCLogError(SC_ERR_DPDK_INIT,
                "Number of configured RX queues of %s is higher than maximum allowed (%" PRIu16 ")",
                iconf->iface, dev_info.max_rx_queues);
        SCReturnInt(-ERANGE);
    }

    if (iconf->nb_tx_queues > dev_info.max_tx_queues) {
        SCLogError(SC_ERR_DPDK_INIT,
                "Number of configured TX queues of %s is higher than maximum allowed (%" PRIu16 ")",
                iconf->iface, dev_info.max_tx_queues);
        SCReturnInt(-ERANGE);
    }

    retval = DeviceValidateMTU(iconf, &dev_info);
    if (retval != 0)
        return retval;

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
            SCReturnInt(TM_ECODE_FAILED);
        } else if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) Unable to get promiscuous mode on port %u",
                    retval, iconf->port_id);
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when enabling promiscuous mode on port %u",
                retval, iconf->port_id);
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

static void *ParseDpdkConfigAndConfigureDevice(const char *iface)
{
    int retval;
    DPDKIfaceConfig *iconf = ConfigParse(iface);
    if (iconf == NULL) {
        FatalError(SC_ERR_DPDK_CONF, "DPDK configuration could not be parsed");
    }

    if (DeviceConfigure(iconf) != 0) {
        iconf->DerefFunc(iconf);
        retval = rte_eal_cleanup();
        if (retval != 0)
            FatalError(SC_ERR_DPDK_EAL_INIT, "EAL cleanup failed: %s", strerror(-retval));

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

#endif /* HAVE_DPDK */

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
 * \brief Workers version of the DPDK processing.
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

    InitEal();
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
