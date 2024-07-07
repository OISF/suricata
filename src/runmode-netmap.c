/* Copyright (C) 2014-2022 Open Information Security Foundation
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
#include "util-time.h"

#ifdef HAVE_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif /* HAVE_NETMAP */

#include "source-netmap.h"
#include "util-conf.h"
#include "suricata.h"
#include "util-bpf.h"

extern uint32_t max_pending_packets;

const char *RunModeNetmapGetDefaultMode(void)
{
    return "workers";
}

static int NetmapRunModeIsIPS(void)
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
            SCLogError("Problem with config file");
            return -1;
        }
        if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError("Problem with config file");
                return -1;
            }
            if_root = if_default;
        }

        const char *copymodestr = NULL;
        const char *copyifacestr = NULL;
        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1 &&
                ConfGetChildValue(if_root, "copy-iface", &copyifacestr) == 1) {
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
        SCLogError("using both IPS and TAP/IDS mode is not allowed due to undefined behavior. See "
                   "ticket #5588.");
        return -1;
    }

    return has_ips;
}

static int NetmapRunModeEnableIPS(void)
{
    int r = NetmapRunModeIsIPS();
    if (r == 1) {
        SCLogInfo("Netmap: Setting IPS mode");
        EngineModeSetIPS();
    }
    return r;
}

void RunModeIdsNetmapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "single", "Single threaded netmap mode",
            RunModeIdsNetmapSingle, NetmapRunModeEnableIPS);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "workers",
            "Workers netmap mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsNetmapWorkers, NetmapRunModeEnableIPS);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "autofp",
            "Multi-threaded netmap mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread.",
            RunModeIdsNetmapAutoFp, NetmapRunModeEnableIPS);
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
            SCLogWarning("%s: interface uses obsolete '+' notation. Using '^' instead", ns->iface);
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

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("%s: unable to find netmap config for interface \"%s\" or \"default\", using "
                  "default values",
                iface, iface);
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
                SCLogWarning("%s: invalid config value for threads: %s, resetting to 0", iface,
                        threadsstr);
                ns->threads = 0;
            }
        }
    }

    ConfSetBPFFilter(if_root, if_default, iface, &ns->bpf_filter);

    int boolval = 0;
    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogInfo("%s: disabling promiscuous mode", ns->iface);
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
            SCLogWarning("%s: invalid value for checksum-checks '%s'", iface, tmpctype);
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
            SCLogWarning("%s: invalid copy-mode %s (valid are tap, ips)", iface, copymodestr);
        }
    }

finalize:

    ns->ips = (ns->copy_mode != NETMAP_COPY_MODE_NONE);

    if (ns->threads_auto) {
        /* As NetmapGetRSSCount used to be broken on Linux,
         * fall back to GetIfaceRSSQueuesNum if needed. */
        ns->threads = NetmapGetRSSCount(base_name);
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
        SCLogInfo("%s: unable to find netmap config using default value", iface_name);
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

    int ring_count = 0;
    if (aconf->in.real)
        ring_count = NetmapGetRSSCount(aconf->iface_name);
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

    /* we need the base interface name with any trailing software
     * ring marker stripped for HW offloading checks */
    char base_name[sizeof(aconf->in.iface)];
    strlcpy(base_name, aconf->in.iface, sizeof(base_name));
    /* for a sw_ring enabled device name, strip the trailing char */
    if (aconf->in.sw_ring) {
        base_name[strlen(base_name) - 1] = '\0';
    }

    /* netmap needs all offloading to be disabled */
    if (aconf->in.real) {
        if (LiveGetOffload() == 0) {
            (void)GetIfaceOffloading(base_name, 1, 1);
        } else {
            DisableIfaceOffloading(LiveGetDevice(base_name), 1, 1);
        }
    }

    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->in.threads);
    SCLogPerf("%s: using %d threads", aconf->iface_name, aconf->in.threads);

    LiveDeviceHasNoStats();
    return aconf;
}

static int NetmapConfigGeThreadsCount(void *conf)
{
    NetmapIfaceConfig *aconf = (NetmapIfaceConfig *)conf;
    return aconf->in.threads;
}

typedef enum { NETMAP_AUTOFP, NETMAP_WORKERS, NETMAP_SINGLE } NetmapRunMode_t;

static int NetmapRunModeInit(NetmapRunMode_t runmode)
{
    SCEnter();

    TimeModeSetLive();

    const char *live_dev = NULL;
    (void)ConfGet("netmap.live-interface", &live_dev);

    const char *runmode_str = "unknown";
    int ret;
    switch (runmode) {
        case NETMAP_AUTOFP:
            runmode_str = "autofp";
            ret = RunModeSetLiveCaptureAutoFp(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_autofp, live_dev);
            break;
        case NETMAP_WORKERS:
            runmode_str = "workers";
            ret = RunModeSetLiveCaptureWorkers(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_workers, live_dev);
            break;
        case NETMAP_SINGLE:
            runmode_str = "single";
            ret = RunModeSetLiveCaptureSingle(ParseNetmapConfig, NetmapConfigGeThreadsCount,
                    "ReceiveNetmap", "DecodeNetmap", thread_name_single, live_dev);
            break;
    }
    if (ret != 0) {
        FatalError("Unable to start runmode %s", runmode_str);
    }

    SCLogDebug("%s initialized", runmode_str);

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
    FatalError("Netmap not configured");
    SCReturnInt(0);
}

/**
 * \brief Single thread version of the netmap processing.
 */
int RunModeIdsNetmapSingle(void)
{
    SCEnter();
    FatalError("Netmap not configured");
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
    FatalError("Netmap not configured");
    SCReturnInt(0);
}
#endif // #ifdef HAVE_NETMAP

/**
* @}
*/
