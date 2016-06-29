/* Copyright (C) 2014-2018 Open Information Security Foundation
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
* \ingroup netmap
*
* @{
*/

/**
* \file
*
* \author Aleksey Katargin <gureedo@gmail.com>
*
* Netmap runmode
*
*/

#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-netmap.h"
#include "output.h"
#include "log-httplog.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"

#include "source-netmap.h"

extern int max_pending_packets;

const char *RunModeNetmapGetDefaultMode(void)
{
    return "workers";
}

void RunModeIdsNetmapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "single",
            "Single threaded netmap mode",
            RunModeIdsNetmapSingle);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "workers",
            "Workers netmap mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsNetmapWorkers);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "autofp",
            "Multi threaded netmap mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread.",
            RunModeIdsNetmapAutoFp);
    return;
}

#ifdef HAVE_NETMAP

static void NetmapDerefConfig(void *conf)
{
    NetmapIfaceConfig *pfp = (NetmapIfaceConfig *)conf;
    /* config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        SCFree(pfp);
    }
}

static int ParseNetmapSettings(NetmapIfaceSettings *ns, const char *iface,
        ConfNode *if_root, ConfNode *if_default)
{
    ns->threads = 0;
    ns->promisc = true;
    ns->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    ns->copy_mode = NETMAP_COPY_MODE_NONE;
    strlcpy(ns->iface, iface, sizeof(ns->iface));

    if (ns->iface[0]) {
        size_t len = strlen(ns->iface);
        if (ns->iface[len-1] == '+') {
            SCLogWarning(SC_WARN_OPTION_OBSOLETE,
                    "netmap interface %s uses obsolete '+' notation. "
                    "Using '^' instead.", ns->iface);
            ns->iface[len-1] = '^';
            ns->sw_ring = true;
        } else if (ns->iface[len-1] == '^') {
            ns->sw_ring = true;
        }
    }

    /* prefixed with netmap or vale means it's not a real interface
     * and we don't check offloading. */
    if (strncmp(ns->iface, "netmap:", 7) != 0 &&
            strncmp(ns->iface, "vale", 4) != 0) {
        ns->real = true;
    }

    const char *bpf_filter = NULL;
    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            ns->bpf_filter = bpf_filter;
            SCLogInfo("Going to use command-line provided bpf filter '%s'",
                    ns->bpf_filter);
        }
    }

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find netmap config for "
                "interface \"%s\" or \"default\", using default values",
                iface);
        goto finalize;

    /* If there is no setting for current interface use default one as main iface */
    } else if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    const char *threadsstr = NULL;
    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        ns->threads = 0;
        ns->threads_auto = true;
    } else {
        if (strcmp(threadsstr, "auto") == 0) {
            ns->threads = 0;
            ns->threads_auto = true;
        } else {
            ns->threads = atoi(threadsstr);
        }
    }

    /* load netmap bpf filter */
    /* command line value has precedence */
    if (ns->bpf_filter == NULL) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                ns->bpf_filter = bpf_filter;
                SCLogInfo("Going to use bpf filter %s", ns->bpf_filter);
            }
        }
    }

    int boolval = 0;
    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogInfo("Disabling promiscuous mode on iface %s", ns->iface);
        ns->promisc = false;
    }

    const char *tmpctype;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "checksum-checks", &tmpctype) == 1)
    {
        if (strcmp(tmpctype, "auto") == 0) {
            ns->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            ns->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            ns->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid value for "
                    "checksum-checks for %s", iface);
        }
    }

    const char *copymodestr;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "copy-mode", &copymodestr) == 1)
    {
        if (strcmp(copymodestr, "ips") == 0) {
            ns->copy_mode = NETMAP_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            ns->copy_mode = NETMAP_COPY_MODE_TAP;
        } else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid copy-mode "
                    "(valid are tap, ips)");
        }
    }

finalize:

    ns->ips = (ns->copy_mode != NETMAP_COPY_MODE_NONE);

    if (ns->sw_ring) {
        /* just one thread per interface supported */
        ns->threads = 1;
    } else if (ns->threads_auto) {
        /* As NetmapGetRSSCount used to be broken on Linux,
         * fall back to GetIfaceRSSQueuesNum if needed. */
        ns->threads = NetmapGetRSSCount(ns->iface);
        if (ns->threads == 0) {
            ns->threads = GetIfaceRSSQueuesNum(ns->iface);
        }
    }
    if (ns->threads <= 0) {
        ns->threads = 1;
    }

    return 0;
}

/**
* \brief extract information from config file
*
* The returned structure will be freed by the thread init function.
* This is thus necessary to or copy the structure before giving it
* to thread or to reparse the file for each thread (and thus have
* new structure.
*
* \return a NetmapIfaceConfig corresponding to the interface name
*/
static void *ParseNetmapConfig(const char *iface_name)
{
    ConfNode *if_root = NULL;
    ConfNode *if_default = NULL;
    const char *out_iface = NULL;

    if (iface_name == NULL) {
        return NULL;
    }

    NetmapIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }
    memset(aconf, 0, sizeof(*aconf));

    aconf->DerefFunc = NetmapDerefConfig;
    strlcpy(aconf->iface_name, iface_name, sizeof(aconf->iface_name));
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);

    /* Find initial node */
    ConfNode *netmap_node = ConfGetNode("netmap");
    if (netmap_node == NULL) {
        SCLogInfo("Unable to find netmap config using default value");
    } else {
        if_root = ConfFindDeviceConfig(netmap_node, aconf->iface_name);
        if_default = ConfFindDeviceConfig(netmap_node, "default");
    }

    /* parse settings for capture iface */
    ParseNetmapSettings(&aconf->in, aconf->iface_name, if_root, if_default);

    /* if we have a copy iface, parse that as well */
    if (netmap_node != NULL &&
            ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1)
    {
        if (strlen(out_iface) > 0) {
            if_root = ConfFindDeviceConfig(netmap_node, out_iface);
            ParseNetmapSettings(&aconf->out, out_iface, if_root, if_default);

            /* if one side of the IPS peering uses a sw_ring, we will default
             * to using a single ring/thread on the other side as well. Only
             * if thread variable is set to 'auto'. So the user can override
             * this. */
            if (aconf->out.sw_ring && aconf->in.threads_auto) {
                aconf->out.threads = aconf->in.threads = 1;
            } else if (aconf->in.sw_ring && aconf->out.threads_auto) {
                aconf->out.threads = aconf->in.threads = 1;
            }
        }
    }

    /* netmap needs all offloading to be disabled */
    if (aconf->in.real) {
        char base_name[sizeof(aconf->in.iface)];
        strlcpy(base_name, aconf->in.iface, sizeof(base_name));
        /* for a sw_ring enabled device name, strip the trailing char */
        if (aconf->in.sw_ring) {
            base_name[strlen(base_name) - 1] = '\0';
        }

        if (LiveGetOffload() == 0) {
            (void)GetIfaceOffloading(base_name, 1, 1);
        } else {
            DisableIfaceOffloading(LiveGetDevice(base_name), 1, 1);
        }
    }

    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->in.threads);
    SCLogPerf("Using %d threads for interface %s", aconf->in.threads,
            aconf->iface_name);

    return aconf;
}

static int NetmapConfigGeThreadsCount(void *conf)
{
    NetmapIfaceConfig *aconf = (NetmapIfaceConfig *)conf;
    return aconf->in.threads;
}

int NetmapRunModeIsIPS()
{
    int nlive = LiveGetDeviceCount();
    int ldev;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *netmap_node;
    int has_ips = 0;
    int has_ids = 0;

    /* Find initial node */
    netmap_node = ConfGetNode("netmap");
    if (netmap_node == NULL) {
        return 0;
    }

    if_default = ConfNodeLookupKeyValue(netmap_node, "interface", "default");

    for (ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
            return 0;
        }
        const char *copymodestr = NULL;
        if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = if_default;
        }

        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
            if (strcmp(copymodestr, "ips") == 0) {
                has_ips = 1;
            } else {
                has_ids = 1;
            }
        } else {
            has_ids = 1;
        }
    }

    if (has_ids && has_ips) {
        SCLogInfo("Netmap mode using IPS and IDS mode");
        for (ldev = 0; ldev < nlive; ldev++) {
            const char *live_dev = LiveGetDeviceName(ldev);
            if (live_dev == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);
            const char *copymodestr = NULL;

            if (if_root == NULL) {
                if (if_default == NULL) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                    return 0;
                }
                if_root = if_default;
            }

            if (! ((ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) &&
                    (strcmp(copymodestr, "ips") == 0))) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "Netmap IPS mode used and interface '%s' is in IDS or TAP mode. "
                                "Sniffing '%s' but expect bad result as stream-inline is activated.",
                        live_dev, live_dev);
            }
        }
    }

    return has_ips;
}

#endif // #ifdef HAVE_NETMAP

int RunModeIdsNetmapAutoFp(void)
{
    SCEnter();

#ifdef HAVE_NETMAP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    ret = RunModeSetLiveCaptureAutoFp(
                              ParseNetmapConfig,
                              NetmapConfigGeThreadsCount,
                              "ReceiveNetmap",
                              "DecodeNetmap", thread_name_autofp,
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsNetmapAutoFp initialised");
#endif /* HAVE_NETMAP */

    SCReturnInt(0);
}

/**
* \brief Single thread version of the netmap processing.
*/
int RunModeIdsNetmapSingle(void)
{
    SCEnter();

#ifdef HAVE_NETMAP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureSingle(
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsNetmapSingle initialised");

#endif /* HAVE_NETMAP */
    SCReturnInt(0);
}

/**
* \brief Workers version of the netmap processing.
*
* Start N threads with each thread doing all the work.
*
*/
int RunModeIdsNetmapWorkers(void)
{
    SCEnter();

#ifdef HAVE_NETMAP
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureWorkers(
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", thread_name_workers,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsNetmapWorkers initialised");

#endif /* HAVE_NETMAP */
    SCReturnInt(0);
}

/**
* @}
*/
