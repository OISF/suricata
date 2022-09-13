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
 * \ingroup afxdppacket
 *
 * @{
 */

/**
 * \file
 *
 * \author Richard McConnell <richard_mcconnell@rapid7.com>
 *
 * AF_XDP socket runmode
 *
 */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H  1
#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-af-xdp.h"
#include "output.h"
#include "log-httplog.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-debuglog.h"

#include "flow-bypass.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"
#include "util-ebpf.h"
#include "util-byte.h"

#include "source-af-xdp.h"

#ifdef HAVE_AF_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#endif

const char *RunModeAFXDPGetDefaultMode(void)
{
    return "workers";
}

void RunModeIdsAFXDPRegister(void)
{
    RunModeRegisterNewRunMode(
            RUNMODE_AFXDP_DEV, "single", "Single threaded af-xdp mode", RunModeIdsAFXDPSingle);
    RunModeRegisterNewRunMode(RUNMODE_AFXDP_DEV, "workers",
            "Workers af-xdp mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsAFXDPWorkers);
    RunModeRegisterNewRunMode(RUNMODE_AFXDP_DEV, "autofp",
            "Multi socket AF_XDP mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread.",
            RunModeIdsAFXDPAutoFp);
    return;
}

#ifdef HAVE_AF_XDP

#define DEFAULT_BUSY_POLL_TIME    20
#define DEFAULT_BUSY_POLL_BUDGET  64
#define DEFAULT_GRO_FLUSH_TIMEOUT 2000000
#define DEFAULT_NAPI_HARD_IRQS    2

static void AFXDPDerefConfig(void *conf)
{
    AFXDPIfaceConfig *pfp = (AFXDPIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) <= 1) {
        SCFree(pfp);
    }
}

static int ConfigSetThreads(AFXDPIfaceConfig *aconf, const char *entry_str)
{
    SCEnter();
    const char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("single", active_runmode)) {
        aconf->threads = 1;
        SCReturnInt(0);
    }

    if (entry_str == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Number of threads for interface \"%s\" not specified",
                aconf->iface);
        SCReturnInt(-EINVAL);
    }

    const int nr_queues = GetIfaceRSSQueuesNum(aconf->iface);

    if (strcmp(entry_str, "auto") == 0) {

        const int nr_cores = (int)UtilCpuGetNumProcessorsOnline();

        /* Threads limited to MIN(cores vs queues) */
        aconf->threads = (nr_cores <= nr_queues) ? nr_cores : nr_queues;
        const char *sys_type = nr_cores <= nr_queues ? "cores" : "queues";

        SCLogPerf("%u %s, so using %u threads", aconf->threads, sys_type, aconf->threads);
        SCReturnInt(0);
    }

    if (StringParseInt32(&aconf->threads, 10, 0, entry_str) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Threads entry for interface %s contain non-numerical characters - \"%s\"",
                aconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (aconf->threads < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Interface %s has a negative number of threads",
                aconf->iface);
        SCReturnInt(-ERANGE);
    }

    if (aconf->threads > nr_queues) {
        SCLogWarning(SC_WARN_AFXDP_CONF,
                "Selected threads greater than configured queues, using: %d thread(s)", nr_queues);
        aconf->threads = nr_queues;
    }

    SCReturnInt(0);
}

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * \return a AFXDPIfaceConfig corresponding to the interface name
 */
static void *ParseAFXDPConfig(const char *iface)
{
    const char *confstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_xdp_node = NULL;
    int conf_val = 0;
    intmax_t conf_val_int = 0;
    bool boolval = false;

    if (iface == NULL) {
        return NULL;
    }

    AFXDPIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    memset(aconf, 0, sizeof(*aconf));

    /* default/basic config setup */
    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->DerefFunc = AFXDPDerefConfig;
    aconf->threads = 1;
    aconf->promisc = 1;
    aconf->busy_poll_time = DEFAULT_BUSY_POLL_TIME;
    aconf->busy_poll_budget = DEFAULT_BUSY_POLL_BUDGET;
    aconf->mode = XDP_FLAGS_UPDATE_IF_NOEXIST;
    aconf->gro_flush_timeout = DEFAULT_GRO_FLUSH_TIMEOUT;
    aconf->napi_defer_hard_irqs = DEFAULT_NAPI_HARD_IRQS;
    aconf->mem_alignment = XSK_UMEM__DEFAULT_FLAGS;

    /* Find initial node */
    af_xdp_node = ConfGetNode("af-xdp");
    if (af_xdp_node == NULL) {
        SCLogInfo("unable to find af-xdp config using default values");
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(af_xdp_node, iface);
    if_default = ConfFindDeviceConfig(af_xdp_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("unable to find af-xdp config for "
                  "interface \"%s\" or \"default\", using default values",
                iface);
        goto finalize;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    /* Threading */
    int ret = ConfGetChildValueWithDefault(if_root, if_default, "threads", &confstr) != 1
                      ? ConfigSetThreads(aconf, "auto")
                      : ConfigSetThreads(aconf, confstr);

    if (ret < 0) {
        aconf->DerefFunc(aconf);
        return NULL;
    }
    SC_ATOMIC_RESET(aconf->ref);
    (void)SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    /* Promisc Mode */
    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Disabling promiscuous mode on iface %s", aconf->iface);
        aconf->promisc = 0;
    }

#ifdef HAVE_AF_XDP
    /* AF_XDP socket mode options */
    if (ConfGetChildValueWithDefault(if_root, if_default, "force-xdp-mode", &confstr) == 1) {
        if (strncasecmp(confstr, "drv", 3) == 0) {
            aconf->mode |= XDP_FLAGS_DRV_MODE;
        } else if (strncasecmp(confstr, "skb", 3) == 0) {
            aconf->mode |= XDP_FLAGS_SKB_MODE;
        } else if (strncasecmp(confstr, "none", 4) == 0) {
        } else {
            SCLogWarning(SC_WARN_AFXDP_CONF,
                    "Incorrect af-xdp xdp-mode setting, default (none) shall be applied");
        }
    }

    /* copy and zerocopy binding options */
    if (ConfGetChildValueWithDefault(if_root, if_default, "force-copy-mode", &confstr) == 1) {
        if (strncasecmp(confstr, "zero", 4) == 0) {
            aconf->bind_flags |= XDP_ZEROCOPY;
        } else if (strncasecmp(confstr, "copy", 4) == 0) {
            aconf->bind_flags |= XDP_COPY;
        } else if (strncasecmp(confstr, "none", 4) == 0) {
        } else {
            SCLogWarning(SC_WARN_AFXDP_CONF,
                    "Incorrect af-xdp copy-mode setting, default (none) shall be applied");
        }
    }

    /* memory alignment mode selection */
    if (ConfGetChildValueWithDefault(if_root, if_default, "mem-unaligned", &confstr) == 1) {
        if (strncasecmp(confstr, "yes", 3) == 0) {
            aconf->mem_alignment = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
        }
    }

    /* Busy polling options */
    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "enable-busy-poll", &conf_val) == 1) {
        if (conf_val) {
            aconf->enable_busy_poll = true;

            if (ConfGetChildValueIntWithDefault(
                        if_root, if_default, "busy-poll-time", &conf_val_int) == 1) {
                if (conf_val_int) {
                    aconf->busy_poll_time = conf_val_int;
                }
            }

            if (ConfGetChildValueIntWithDefault(
                        if_root, if_default, "busy-poll-budget", &conf_val_int) == 1) {
                if (conf_val_int) {
                    aconf->busy_poll_budget = conf_val_int;
                }
            }

            /* 0 value is valid for these Linux tunable's */
            if (ConfGetChildValueIntWithDefault(
                        if_root, if_default, "gro-flush-timeout", &conf_val_int) == 1) {
                aconf->gro_flush_timeout = conf_val_int;
            }

            if (ConfGetChildValueIntWithDefault(
                        if_root, if_default, "napi-defer-hard-irq", &conf_val_int) == 1) {
                aconf->napi_defer_hard_irqs = conf_val_int;
            }
        }
    }
#endif

finalize:
    return aconf;
}

static int AFXDPConfigGetThreadsCount(void *conf)
{
    if (conf == NULL)
        FatalError(SC_ERR_AFXDP_CONF, "Configuration file is NULL");

    AFXDPIfaceConfig *afxdp_conf = (AFXDPIfaceConfig *)conf;
    return afxdp_conf->threads;
}

int AFXDPRunModeIsIPS()
{
    return 0;
}

#endif /* HAVE_AF_XDP */

/**
 * \brief Single thread version of the AF_XDP processing.
 */
int RunModeIdsAFXDPSingle(void)
{
    SCEnter();

#ifdef HAVE_AF_XDP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-xdp.live-interface", &live_dev);

    if (AFXDPQueueProtectionInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init AF_XDP queue protection.");
    }

    ret = RunModeSetLiveCaptureSingle(ParseAFXDPConfig, AFXDPConfigGetThreadsCount, "ReceiveAFXDP",
            "DecodeAFXDP", thread_name_single, live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsAFXDPSingle initialised");

#endif /* HAVE_AF_XDP */
    SCReturnInt(0);
}

/**
 * \brief Workers version of the AF_XDP processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsAFXDPWorkers(void)
{
    SCEnter();

#ifdef HAVE_AF_XDP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-xdp.live-interface", &live_dev);

    if (AFXDPQueueProtectionInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init AF_XDP queue protection.");
    }

    ret = RunModeSetLiveCaptureWorkers(ParseAFXDPConfig, AFXDPConfigGetThreadsCount, "ReceiveAFXDP",
            "DecodeAFXDP", thread_name_workers, live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsAFXDPWorkers initialised");

#endif /* HAVE_AF_XDP */
    SCReturnInt(0);
}

int RunModeIdsAFXDPAutoFp(void)
{
    SCEnter();

#ifdef HAVE_AF_XDP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-xdp.live-interface", &live_dev);

    if (AFXDPQueueProtectionInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init AF_XDP queue protection.");
    }

    ret = RunModeSetLiveCaptureAutoFp(ParseAFXDPConfig, AFXDPConfigGetThreadsCount, "ReceiveAFXDP",
            "DecodeAFXDP", thread_name_autofp, live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsAFXDPAutoFp initialised");
#endif /* HAVE_AF_XDP */

    SCReturnInt(0);
}
/**
 * @}
 */
