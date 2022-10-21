/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * \author Bill Meeks <billmeeks8@gmail.com>
 *
 * Netmap runmode
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "runmodes.h"
#include "runmode-netmap.h"
#include "util-runmodes.h"
#include "util-ioctl.h"
#include "util-byte.h"

#ifdef HAVE_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include "util-time.h"
#endif /* HAVE_NETMAP */

#include "source-netmap.h"
#include "util-conf.h"

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
            "Multi-threaded netmap mode.  Packets from "
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
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
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

    /* we will need the base interface name for later */
    char base_name[IFNAMSIZ];
    strlcpy(base_name, ns->iface, sizeof(base_name));
    if (strlen(base_name) > 0 &&
            (base_name[strlen(base_name) - 1] == '^' || base_name[strlen(base_name) - 1] == '*')) {
        base_name[strlen(base_name) - 1] = '\0';
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
            if (StringParseUint16(&ns->threads, 10, 0, threadsstr) < 0) {
                SCLogWarning(SC_EINVAL,
                        "Invalid config value for "
                        "threads: %s, resetting to 0",
                        threadsstr);
                ns->threads = 0;
            }
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

    if (ns->threads_auto) {
        /* As NetmapGetRSSCount used to be broken on Linux,
         * fall back to GetIfaceRSSQueuesNum if needed. */
        ns->threads = NetmapGetRSSCount(ns->iface);
        if (ns->threads == 0) {
            /* need to use base_name of interface here */
            ns->threads = GetIfaceRSSQueuesNum(base_name);
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
 * This is thus necessary to copy the structure before giving it
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

    NetmapIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

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
        }
    }

    int ring_count = NetmapGetRSSCount(aconf->iface_name);
    if (strlen(aconf->iface_name) > 0 &&
            (aconf->iface_name[strlen(aconf->iface_name) - 1] == '^' ||
                    aconf->iface_name[strlen(aconf->iface_name) - 1] == '*')) {
        SCLogDebug("%s -- using %d netmap host ring pair%s", aconf->iface_name, ring_count,
                ring_count == 1 ? "" : "s");
    } else {
        SCLogDebug("%s -- using %d netmap ring pair%s", aconf->iface_name, ring_count,
                ring_count == 1 ? "" : "s");
    }

    for (int i = 0; i < ring_count; i++) {
        char live_buf[32] = { 0 };
        snprintf(live_buf, sizeof(live_buf), "netmap%d", i);
        LiveRegisterDevice(live_buf);
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

    LiveDeviceHasNoStats();
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
            SCLogError(SC_EINVAL, "Problem with config file");
            return 0;
        }
        const char *copymodestr = NULL;
        if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError(SC_EINVAL, "Problem with config file");
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
                SCLogError(SC_EINVAL, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);
            const char *copymodestr = NULL;

            if (if_root == NULL) {
                if (if_default == NULL) {
                    SCLogError(SC_EINVAL, "Problem with config file");
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

typedef enum { NETMAP_AUTOFP, NETMAP_WORKERS, NETMAP_SINGLE } NetmapRunMode_t;

static int NetmapRunModeInit(NetmapRunMode_t runmode)
{
    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    const char *live_dev = NULL;
    (void)ConfGet("netmap.live-interface", &live_dev);

    int ret;
    switch (runmode) {
        case NETMAP_AUTOFP:
            ret = RunModeSetLiveCaptureAutoFp(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_autofp, live_dev);
            break;
        case NETMAP_WORKERS:
            ret = RunModeSetLiveCaptureWorkers(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_workers, live_dev);
            break;
        case NETMAP_SINGLE:
            ret = RunModeSetLiveCaptureSingle(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_single, live_dev);
            break;
    }
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode %s",
                runmode == NETMAP_AUTOFP ? "autofp"
                                         : runmode == NETMAP_WORKERS ? "workers" : "single");
    }

    SCLogDebug("%s initialized",
            runmode == NETMAP_AUTOFP ? "autofp" : runmode == NETMAP_WORKERS ? "workers" : "single");

    SCReturnInt(0);
}

int RunModeIdsNetmapAutoFp(void)
{
    return NetmapRunModeInit(NETMAP_AUTOFP);
}

/**
* \brief Single thread version of the netmap processing.
*/
int RunModeIdsNetmapSingle(void)
{
    return NetmapRunModeInit(NETMAP_SINGLE);
}

/**
 * \brief Workers version of the netmap processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsNetmapWorkers(void)
{
    return NetmapRunModeInit(NETMAP_WORKERS);
}
#else
int RunModeIdsNetmapAutoFp(void)
{
    SCEnter();
    FatalError(SC_ERR_FATAL, "Netmap not configured");
    SCReturnInt(0);
}

/**
 * \brief Single thread version of the netmap processing.
 */
int RunModeIdsNetmapSingle(void)
{
    SCEnter();
    FatalError(SC_ERR_FATAL, "Netmap not configured");
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
    FatalError(SC_ERR_FATAL, "Netmap not configured");
    SCReturnInt(0);
}
#endif // #ifdef HAVE_NETMAP

/**
* @}
*/
