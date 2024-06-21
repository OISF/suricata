/* Copyright (C) 2007-2018 Open Information Security Foundation
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

#include "suricata-common.h"
#include "runmode-pfring.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "source-pfring.h"
#include "suricata.h"
#include "util-bpf.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-runmodes.h"
#include "util-device.h"
#include "util-ioctl.h"
#include "util-byte.h"
#include "util-conf.h"

#ifdef HAVE_PFRING
#include <pfring.h>
#endif

#define PFRING_CONF_V1 1
#define PFRING_CONF_V2 2

const char *RunModeIdsPfringGetDefaultMode(void)
{
#ifdef HAVE_PFRING
    return "workers";
#else
    return NULL;
#endif
}

void RunModeIdsPfringRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PFRING, "autofp",
            "Multi threaded pfring mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread, unlike \"pfring_auto\" where packets "
            "from the same flow can be processed by any "
            "detect thread",
            "default mode",
            "autofp,single,workers",
            RunModeIdsPfringAutoFp, NULL);
    /*RunModeRegisterNewRunMode(
            RUNMODE_PFRING, "single", "Single threaded pfring mode","default mode", RunModeIdsPfringSingle, NULL);
    RunModeRegisterNewRunMode(RUNMODE_PFRING, "workers",
            "Workers pfring mode, each thread does all"
            " tasks from acquisition to logging",
            "default mode",
            RunModeIdsPfringWorkers, NULL);*/
    return;
}

#ifdef HAVE_PFRING
static void PfringDerefConfig(void *conf)
{
    PfringIfaceConfig *pfp = (PfringIfaceConfig *)conf;
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
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
 * If old config system is used, then return the same parameters
 * value for each interface.
 *
 * \return a PfringIfaceConfig corresponding to the interface name
 */
static void *OldParsePfringConfig(const char *iface)
{
    const char *threadsstr = NULL;
    PfringIfaceConfig *pfconf = SCMalloc(sizeof(*pfconf));
    const char *tmpclusterid;
    const char *tmpctype = NULL;
    cluster_type default_ctype = CLUSTER_FLOW;

    if (unlikely(pfconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(pfconf);
        return NULL;
    }

    strlcpy(pfconf->iface, iface, sizeof(pfconf->iface));
    pfconf->flags = 0;
    pfconf->threads = 1;
    pfconf->cluster_id = 1;
    pfconf->ctype = default_ctype;
    pfconf->DerefFunc = PfringDerefConfig;
    pfconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    SC_ATOMIC_INIT(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, 1);

    /* Find initial node */
    if (ConfGet("pfring.threads", &threadsstr) != 1) {
        pfconf->threads = 1;
    } else {
        if (threadsstr != NULL) {
            if (StringParseInt32(&pfconf->threads, 10, 0, threadsstr) < 0) {
                SCLogWarning("Invalid value for "
                             "pfring.threads: '%s'. Resetting to 1.",
                        threadsstr);
                pfconf->threads = 1;
            }
        }
    }
    if (pfconf->threads == 0) {
        pfconf->threads = 1;
    }

    SC_ATOMIC_RESET(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, pfconf->threads);

    if (strncmp(pfconf->iface, "zc", 2) == 0) {
        SCLogInfo("%s: ZC interface detected, not setting cluster-id", pfconf->iface);
    }
    else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
        SCLogInfo("DNA interface detected, not setting cluster-id");
    } else if (ConfGet("pfring.cluster-id", &tmpclusterid) != 1) {
        SCLogError("Could not get cluster-id from config");
    } else {
        if (StringParseInt32(&pfconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
            SCLogWarning("Invalid value for "
                         "pfring.cluster_id: '%s'. Resetting to 1.",
                    tmpclusterid);
            pfconf->cluster_id = 1;
        }
        pfconf->flags |= PFRING_CONF_FLAGS_CLUSTER;
        SCLogDebug("Going to use cluster-id %" PRId32, pfconf->cluster_id);
    }

    if (strncmp(pfconf->iface, "zc", 2) == 0) {
        SCLogInfo("%s: ZC interface detected, not setting cluster type for PF_RING", pfconf->iface);
    } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
        SCLogInfo(
                "%s: DNA interface detected, not setting cluster type for PF_RING", pfconf->iface);
    } else if (ConfGet("pfring.cluster-type", &tmpctype) != 1) {
        SCLogError("Could not get cluster-type from config");
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogInfo("%s: Using round-robin cluster mode for PF_RING", pfconf->iface);
        pfconf->ctype = (cluster_type)tmpctype;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        SCLogInfo("%s: Using flow cluster mode for PF_RING", pfconf->iface);
        pfconf->ctype = (cluster_type)tmpctype;
    } else {
        SCLogError("invalid cluster-type %s", tmpctype);
        SCFree(pfconf);
        return NULL;
    }

    return pfconf;
}

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * If old config system is used, then return the same parameters
 * value for each interface.
 *
 * \return a PfringIfaceConfig corresponding to the interface name
 */
static void *ParsePfringConfig(const char *iface)
{
    const char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *pf_ring_node;
    PfringIfaceConfig *pfconf = SCMalloc(sizeof(*pfconf));
    const char *tmpclusterid;
    const char *tmpctype = NULL;
    cluster_type default_ctype = CLUSTER_FLOW;
    int getctype = 0;
    int bool_val;
    const char *active_runmode = RunmodeGetActive();

    if (unlikely(pfconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(pfconf);
        return NULL;
    }

    memset(pfconf, 0, sizeof(PfringIfaceConfig));
    strlcpy(pfconf->iface, iface, sizeof(pfconf->iface));
    pfconf->threads = 1;
    pfconf->cluster_id = 1;
    pfconf->ctype = (cluster_type)default_ctype;
    pfconf->DerefFunc = PfringDerefConfig;
    SC_ATOMIC_INIT(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, 1);

    /* Find initial node */
    pf_ring_node = ConfGetNode("pfring");
    if (pf_ring_node == NULL) {
        SCLogInfo("Unable to find pfring config using default value");
        return pfconf;
    }

    if_root = ConfFindDeviceConfig(pf_ring_node, iface);

    if_default = ConfFindDeviceConfig(pf_ring_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find pfring config for "
                  "interface %s, using default value or 1.0 "
                  "configuration system. ",
                  iface);
        return pfconf;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    if (active_runmode && !strcmp("single", active_runmode)) {
        pfconf->threads = 1;
    } else if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        pfconf->threads = 1;
    } else if (threadsstr != NULL) {
        if (strcmp(threadsstr, "auto") == 0) {
            pfconf->threads = (int)UtilCpuGetNumProcessorsOnline();
            if (pfconf->threads > 0) {
                SCLogPerf("%u cores, so using %u threads", pfconf->threads, pfconf->threads);
            } else {
                pfconf->threads = GetIfaceRSSQueuesNum(iface);
                if (pfconf->threads > 0) {
                    SCLogPerf("%d RSS queues, so using %u threads", pfconf->threads, pfconf->threads);
                }
            }
        } else {
            uint16_t threads = 0;
            if (StringParseUint16(&threads, 10, 0, (const char *)threadsstr) < 0) {
                SCLogWarning("Invalid value for "
                             "pfring.threads: '%s'. Resetting to 1.",
                        threadsstr);
                pfconf->threads = 1;
            } else {
                pfconf->threads = threads;
            }
        }
    }
    if (pfconf->threads <= 0) {
        pfconf->threads = 1;
    }

    SC_ATOMIC_RESET(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, pfconf->threads);

    /* command line value has precedence */
    if (ConfGet("pfring.cluster-id", &tmpclusterid) == 1) {
        if (StringParseInt32(&pfconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
            SCLogWarning("Invalid value for "
                         "pfring.cluster-id: '%s'. Resetting to 1.",
                    tmpclusterid);
            pfconf->cluster_id = 1;
        }
        pfconf->flags |= PFRING_CONF_FLAGS_CLUSTER;
        SCLogDebug("Going to use command-line provided cluster-id %" PRId32,
                   pfconf->cluster_id);
    } else {

        if (strncmp(pfconf->iface, "zc", 2) == 0) {
            SCLogInfo(
                    "%s: ZC interface detected, not setting cluster-id for PF_RING", pfconf->iface);
        } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
            SCLogInfo("%s: DNA interface detected, not setting cluster-id for PF_RING",
                    pfconf->iface);
        } else if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
            SCLogError("Could not get cluster-id from config");
        } else {
            if (StringParseInt32(&pfconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
                SCLogWarning("Invalid value for "
                             "pfring.cluster-id: '%s'. Resetting to 1.",
                        tmpclusterid);
                pfconf->cluster_id = 1;
            }
            pfconf->flags |= PFRING_CONF_FLAGS_CLUSTER;
            SCLogDebug("Going to use cluster-id %" PRId32, pfconf->cluster_id);
        }
    }

    ConfSetBPFFilter(if_root, if_default, pfconf->iface, &pfconf->bpf_filter);

    if (EngineModeIsIPS()) {
        FatalError("IPS mode not supported in PF_RING.");
    }

    if (ConfGet("pfring.cluster-type", &tmpctype) == 1) {
        SCLogDebug("Going to use command-line provided cluster-type");
        getctype = 1;
    } else {
        if (strncmp(pfconf->iface, "zc", 2) == 0) {
            SCLogInfo("%s: ZC interface detected, not setting cluster type for PF_RING",
                    pfconf->iface);
        } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
            SCLogInfo("%s: DNA interface detected, not setting cluster type for PF_RING",
                    pfconf->iface);
        } else if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
            SCLogError("Could not get cluster-type from config");
        } else {
            getctype = 1;
        }
    }

    if (getctype) {
        if (strcmp(tmpctype, "cluster_round_robin") == 0) {
            SCLogInfo("%s: Using round-robin cluster mode for PF_RING."
                      " This mode is not recommended.",
                    pfconf->iface);
            pfconf->ctype = CLUSTER_ROUND_ROBIN;
        } else if (strcmp(tmpctype, "cluster_flow") == 0) {
            SCLogInfo("%s: Using flow cluster mode for PF_RING", pfconf->iface);
            pfconf->ctype = CLUSTER_FLOW;
        } else if (strcmp(tmpctype, "cluster_inner_flow") == 0) {
            SCLogInfo("%s: Using flow cluster mode inner mode for PF_RING", pfconf->iface);
            pfconf->ctype = CLUSTER_INNER_FLOW;
        } else if (strcmp(tmpctype, "cluster_inner_flow_2_tuple") == 0) {
            SCLogInfo("%s: Using flow cluster inner 2 tuple mode for PF_RING", pfconf->iface);
            pfconf->ctype = CLUSTER_INNER_FLOW_2_TUPLE;
        } else if (strcmp(tmpctype, "cluster_inner_flow_4_tuple") == 0) {
            SCLogInfo("%s: Using flow cluster inner 4 tuple mode for PF_RING", pfconf->iface);
            pfconf->ctype = CLUSTER_INNER_FLOW_4_TUPLE;
        } else if (strcmp(tmpctype, "cluster_inner_flow_5_tuple") == 0) {
            SCLogInfo("%s: Using flow cluster inner 5 tuple mode for PF_RING", pfconf->iface);
            pfconf->ctype = CLUSTER_INNER_FLOW_5_TUPLE;
        } else {
            SCLogError("invalid cluster-type %s", tmpctype);
            SCFree(pfconf);
            return NULL;
        }
    }
    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "rx-only") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_RXONLY;
        } else {
            SCLogError("%s: Invalid value for checksum-checks", pfconf->iface);
        }
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "bypass", &bool_val) == 1) {
        if (bool_val) {
#ifdef HAVE_PF_RING_FLOW_OFFLOAD
            SCLogConfig("%s: Enabling bypass support in PF_RING (if supported by underlying hw)",
                    pfconf->iface);
            pfconf->flags |= PFRING_CONF_FLAGS_BYPASS;
#else
            SCLogError("Bypass is not supported by this Pfring version, please upgrade");
            SCFree(pfconf);
            return NULL;
#endif
        }
    }

    if (LiveGetOffload() == 0) {
        if (GetIfaceOffloading(iface, 0, 1) == 1) {
            SCLogWarning("Using PF_RING with offloading activated leads to capture problems");
        }
    } else {
        DisableIfaceOffloading(LiveGetDevice(iface), 0, 1);
    }
    return pfconf;
}

static int PfringConfigGetThreadsCount(void *conf)
{
    PfringIfaceConfig *pfp = (PfringIfaceConfig *)conf;
    return pfp->threads;
}

static int PfringConfLevel(void)
{
    const char *def_dev = NULL;
    /* 1.0 config should return a string */
    if (ConfGet("pfring.interface", &def_dev) != 1) {
        return PFRING_CONF_V2;
    } else {
        return PFRING_CONF_V1;
    }
}

static int GetDevAndParser(const char **live_dev, ConfigIfaceParserFunc *parser)
{
     ConfGet("pfring.live-interface", live_dev);

    /* determine which config type we have */
    if (PfringConfLevel() > PFRING_CONF_V1) {
        *parser = ParsePfringConfig;
    } else {
        SCLogInfo("Using 1.0 style configuration for pfring");
        *parser = OldParsePfringConfig;
        /* In v1: try to get interface name from config */
        if (*live_dev == NULL) {
            if (ConfGet("pfring.interface", live_dev) == 1) {
                SCLogInfo("Using interface %s", *live_dev);
                LiveRegisterDevice(*live_dev);
            } else {
                SCLogInfo("No interface found, problem incoming");
                *live_dev = NULL;
            }
        }
    }

    return 0;
}
#endif

int RunModeIdsPfringAutoFp(void)
{
    SCEnter();

/* We include only if pfring is enabled */
#ifdef HAVE_PFRING
    int ret;
    const char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        FatalError("Unable to get parser and interface params");
    }

    ret = RunModeSetLiveCaptureAutoFp(tparser, PfringConfigGetThreadsCount, "ReceivePfring",
            "DecodePfring", thread_name_autofp, live_dev);
    if (ret != 0) {
        FatalError("Runmode start failed");
    }

    SCLogInfo("RunModeIdsPfringAutoFp initialised");
#endif /* HAVE_PFRING */

    return 0;
}

int RunModeIdsPfringSingle(void)
{
    SCEnter();

/* We include only if pfring is enabled */
#ifdef HAVE_PFRING
    int ret;
    const char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        FatalError("Unable to get parser and interface params");
    }

    ret = RunModeSetLiveCaptureSingle(tparser,
                              PfringConfigGetThreadsCount,
                              "ReceivePfring",
                              "DecodePfring", thread_name_single,
                              live_dev);
    if (ret != 0) {
        FatalError("Runmode start failed");
    }

    SCLogInfo("RunModeIdsPfringSingle initialised");
#endif /* HAVE_PFRING */

    return 0;
}

int RunModeIdsPfringWorkers(void)
{
    SCEnter();

/* We include only if pfring is enabled */
#ifdef HAVE_PFRING
    int ret;
    const char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        FatalError("Unable to get parser and interface params");
    }

    ret = RunModeSetLiveCaptureWorkers(tparser, PfringConfigGetThreadsCount, "ReceivePfring",
            "DecodePfring", thread_name_workers, live_dev);
    if (ret != 0) {
        FatalError("Runmode start failed");
    }

    SCLogInfo("RunModeIdsPfringWorkers initialised");
#endif /* HAVE_PFRING */

    return 0;
}
