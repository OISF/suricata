/* Copyright (C) 2011,2012 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
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

#include "source-netmap.h"

extern int max_pending_packets;

static const char *default_mode_auto = NULL;
static const char *default_mode_autofp = NULL;

const char *RunModeNetmapGetDefaultMode(void)
{
    return default_mode_autofp;
}

void RunModeIdsNetmapRegister(void)
{
    default_mode_auto = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "auto",
                              "Multi threaded Netmap mode",
                              RunModeIdsNetmapAuto);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "single",
                              "Single threaded Netmap mode",
                              RunModeIdsNetmapSingle);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "workers",
                              "Workers Netmap mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsNetmapWorkers);
    default_mode_autofp = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "autofp",
                              "Multi socket Netmap mode.  Packets from "
                              "each flow are assigned to a single detect "
                              "thread.",
                              RunModeIdsNetmapAutoFp);
    return;
}

void NetmapDerefConfig(void *conf)
{
    NetmapIfaceConfig *pfp = (NetmapIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
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
void *ParseNetmapConfig(const char *iface)
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

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->threads = 1;
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);
    aconf->promisc = 1;
    aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
    aconf->DerefFunc = NetmapDerefConfig;
    aconf->flags = 0;
    aconf->bpf_filter = NULL;
    aconf->out_iface = NULL;

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

    if_root = ConfNodeLookupKeyValue(netmap_node, "interface", iface);

    if_default = ConfNodeLookupKeyValue(netmap_node, "interface", "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find netmap config for "
                  "interface \"%s\" or \"default\", using default value",
                  iface);
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
        if (threadsstr != NULL) {
            aconf->threads = (uint8_t)atoi(threadsstr);
        }
    }
    if (aconf->threads == 0) {
        aconf->threads = 1;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }

    aconf->copy_mode = NETMAP_COPY_MODE_NONE;
    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("Netmap IPS mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = NETMAP_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("AF_PACKET TAP mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = NETMAP_COPY_MODE_TAP;
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    /*load af_packet bpf filter*/
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
        SCLogInfo("Disabling promiscuous mode on iface %s",
                aconf->iface);
        aconf->promisc = 0;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (strcmp(tmpctype, "yes") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(tmpctype, "no") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "kernel") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

    return aconf;
}

int NetmapConfigGeThreadsCount(void *conf)
{
    NetmapIfaceConfig *afp = (NetmapIfaceConfig *)conf;
    return afp->threads;
}

/**
 * \brief RunModeIdsNetmapAuto set up the following thread packet handlers:
 *        - Receive thread (from live iface)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu.
 *
 * \param de_ctx Pointer to the Detection Engine.
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeIdsNetmapAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();

#ifdef HAVE_NETMAP
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    if (NetmapPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureAuto(de_ctx,
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", "RecvNetmap",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (NetmapPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapAuto initialised");
#endif
    SCReturnInt(0);
}

int RunModeIdsNetmapAutoFp(DetectEngineCtx *de_ctx)
{
    SCEnter();

/* We include only if Netmap is enabled */
#ifdef HAVE_NETMAP
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    if (NetmapPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureAutoFp(de_ctx,
                              ParseNetmapConfig,
                              NetmapConfigGeThreadsCount,
                              "ReceiveNetmap",
                              "DecodeNetmap", "RxNetmap",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (NetmapPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapAutoFp initialised");
#endif /* HAVE_NETMAP */

    SCReturnInt(0);
}

/**
 * \brief Single thread version of the Netmap processing.
 */
int RunModeIdsNetmapSingle(DetectEngineCtx *de_ctx)
{
#ifdef HAVE_NETMAP
    int ret;
    char *live_dev = NULL;
#endif
    SCEnter();
#ifdef HAVE_NETMAP

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    if (NetmapPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureSingle(de_ctx,
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", "Netmap",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (NetmapPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapSingle initialised");

#endif /* HAVE_NETMAP */
    SCReturnInt(0);
}

/**
 * \brief Workers version of the Netmap processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsNetmapWorkers(DetectEngineCtx *de_ctx)
{
#ifdef HAVE_NETMAP
    int ret;
    char *live_dev = NULL;
#endif
    SCEnter();
#ifdef HAVE_NETMAP

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    if (NetmapPeersListInit() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Unable to init peers list.");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureWorkers(de_ctx,
                                    ParseNetmapConfig,
                                    NetmapConfigGeThreadsCount,
                                    "ReceiveNetmap",
                                    "DecodeNetmap", "Netmap",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    /* In IPS mode each threads must have a peer */
    if (NetmapPeersListCheck() != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "Some IPS capture threads did not peer.");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsNetmapWorkers initialised");

#endif /* HAVE_NETMAP */
    SCReturnInt(0);
}

/**
 * @}
 */
