/* Copyright (C) 2014 Open Information Security Foundation
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
#include "log-httplog.h"
#include "output.h"
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

static const char *default_mode_workers = NULL;

const char *RunModeNetmapGetDefaultMode(void)
{
    return default_mode_workers;
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
    default_mode_workers = "workers";
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
    char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *netmap_node;
    NetmapIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *tmpctype;
    char *copymodestr;
    int boolval;
    char *bpf_filter = NULL;
    char *out_iface = NULL;

    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    if (iface_name == NULL) {
        SCFree(aconf);
        return NULL;
    }

    memset(aconf, 0, sizeof(*aconf));
    aconf->DerefFunc = NetmapDerefConfig;
    aconf->threads = 1;
    aconf->promisc = 1;
    aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    aconf->copy_mode = NETMAP_COPY_MODE_NONE;
    strlcpy(aconf->iface_name, iface_name, sizeof(aconf->iface_name));
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);

    strlcpy(aconf->iface, aconf->iface_name, sizeof(aconf->iface));
    if (aconf->iface[0]) {
        size_t len = strlen(aconf->iface);
        if (aconf->iface[len-1] == '+') {
            aconf->iface[len-1] = '\0';
            aconf->iface_sw = 1;
        }
    }

    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            aconf->bpf_filter = bpf_filter;
            SCLogInfo("Going to use command-line provided bpf filter '%s'",
                    aconf->bpf_filter);
        }
    }

    /* Find initial node */
    netmap_node = ConfGetNode("netmap");
    if (netmap_node == NULL) {
        SCLogInfo("Unable to find netmap config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(netmap_node, "interface", aconf->iface_name);

    if_default = ConfNodeLookupKeyValue(netmap_node, "interface", "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find netmap config for "
                "interface \"%s\" or \"default\", using default value",
                aconf->iface_name);
        return aconf;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        aconf->threads = 1;
    } else {
        if (strcmp(threadsstr, "auto") == 0) {
            aconf->threads = GetIfaceRSSQueuesNum(aconf->iface);
        } else {
            aconf->threads = (uint8_t)atoi(threadsstr);
        }
    }

    if (aconf->threads <= 0) {
        aconf->threads = 1;
    }
    if (aconf->threads) {
        SCLogInfo("Using %d threads for interface %s", aconf->threads,
                  aconf->iface_name);
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface_name = out_iface;
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface_name == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                    " iface. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface_name = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("Netmap IPS mode activated %s->%s",
                    aconf->iface_name,
                    aconf->out_iface_name);
            aconf->copy_mode = NETMAP_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("Netmap TAP mode activated %s->%s",
                    aconf->iface_name,
                    aconf->out_iface_name);
            aconf->copy_mode = NETMAP_COPY_MODE_TAP;
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    if (aconf->out_iface_name && aconf->out_iface_name[0]) {
        strlcpy(aconf->out_iface, aconf->out_iface_name,
                sizeof(aconf->out_iface));
        size_t len = strlen(aconf->out_iface);
        if (aconf->out_iface[len-1] == '+') {
            aconf->out_iface[len-1] = '\0';
            aconf->out_iface_sw = 1;
        }
    }

    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    /* load netmap bpf filter */
    /* command line value has precedence */
    if (ConfGet("bpf-filter", &bpf_filter) != 1) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                aconf->bpf_filter = bpf_filter;
                SCLogInfo("Going to use bpf filter %s", aconf->bpf_filter);
            }
        }
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogInfo("Disabling promiscuous mode on iface %s", aconf->iface);
        aconf->promisc = 0;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (strcmp(tmpctype, "yes") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(tmpctype, "no") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface_name);
        }
    }

    return aconf;
}

static int NetmapConfigGeThreadsCount(void *conf)
{
    NetmapIfaceConfig *aconf = (NetmapIfaceConfig *)conf;
    return aconf->threads;
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
        char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
            return 0;
        }
        char *copymodestr = NULL;
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
            char *live_dev = LiveGetDeviceName(ldev);
            if (live_dev == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);
            char *copymodestr = NULL;

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
    char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    ret = RunModeSetLiveCaptureAutoFp(
                              ParseNetmapConfig,
                              NetmapConfigGeThreadsCount,
                              "ReceiveNetmap",
                              "DecodeNetmap", "RxNetmap",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapAutoFp initialised");
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
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureSingle(
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", "NetmapPkt",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapSingle initialised");

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
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureWorkers(
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", "NetmapPkt",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapWorkers initialised");

#endif /* HAVE_NETMAP */
    SCReturnInt(0);
}

/**
* @}
*/
