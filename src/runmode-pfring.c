/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-pfring.h"
#include "source-pfring.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"

static const char *default_mode_autofp = NULL;


#define PFRING_CONF_V1 1
#define PFRING_CONF_V2 2

const char *RunModeIdsPfringGetDefaultMode(void)
{
#ifdef HAVE_PFRING
    return default_mode_autofp;
#else
    return NULL;
#endif
}

void RunModeIdsPfringRegister(void)
{
    default_mode_autofp = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_PFRING, "autofp",
                              "Multi threaded pfring mode.  Packets from "
                              "each flow are assigned to a single detect "
                              "thread, unlike \"pfring_auto\" where packets "
                              "from the same flow can be processed by any "
                              "detect thread",
                              RunModeIdsPfringAutoFp);
    RunModeRegisterNewRunMode(RUNMODE_PFRING, "single",
                              "Single threaded pfring mode",
                              RunModeIdsPfringSingle);
    RunModeRegisterNewRunMode(RUNMODE_PFRING, "workers",
                              "Workers pfring mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsPfringWorkers);
    return;
}

void PfringDerefConfig(void *conf)
{
    PfringIfaceConfig *pfp = (PfringIfaceConfig *)conf;
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        if (pfp->bpf_filter) {
            SCFree(pfp->bpf_filter);
        }
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
 * If old config system is used, then return the smae parameters
 * value for each interface.
 *
 * \return a PfringIfaceConfig corresponding to the interface name
 */
void *OldParsePfringConfig(const char *iface)
{
    char *threadsstr = NULL;
    PfringIfaceConfig *pfconf = SCMalloc(sizeof(*pfconf));
    char *tmpclusterid;
#ifdef HAVE_PFRING
    char *tmpctype = NULL;
    cluster_type default_ctype = CLUSTER_ROUND_ROBIN;
#endif

    if (unlikely(pfconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(pfconf);
        return NULL;
    }

    strlcpy(pfconf->iface, iface, sizeof(pfconf->iface));
    pfconf->threads = 1;
    pfconf->cluster_id = 1;
#ifdef HAVE_PFRING
    pfconf->ctype = default_ctype;
#endif
    pfconf->DerefFunc = PfringDerefConfig;
    pfconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    SC_ATOMIC_INIT(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, 1);

    /* Find initial node */
    if (ConfGet("pfring.threads", &threadsstr) != 1) {
        pfconf->threads = 1;
    } else {
        if (threadsstr != NULL) {
            pfconf->threads = (uint8_t)atoi(threadsstr);
        }
    }
    if (pfconf->threads == 0) {
        pfconf->threads = 1;
    }

    SC_ATOMIC_RESET(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, pfconf->threads);

    if (strncmp(pfconf->iface, "zc", 2) == 0) {
        SCLogInfo("ZC interface detected, not setting cluster-id");
    }
    else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
        SCLogInfo("DNA interface detected, not setting cluster-id");
    } else if (ConfGet("pfring.cluster-id", &tmpclusterid) != 1) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Could not get cluster-id from config");
    } else {
        pfconf->cluster_id = (uint16_t)atoi(tmpclusterid);
        SCLogDebug("Going to use cluster-id %" PRId32, pfconf->cluster_id);
    }

#ifdef HAVE_PFRING
    if (strncmp(pfconf->iface, "zc", 2) == 0) {
        SCLogInfo("ZC interface detected, not setting cluster type for PF_RING (iface %s)",
                pfconf->iface);
    } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
        SCLogInfo("DNA interface detected, not setting cluster type for PF_RING (iface %s)",
                pfconf->iface);
    } else if (ConfGet("pfring.cluster-type", &tmpctype) != 1) {
        SCLogError(SC_ERR_GET_CLUSTER_TYPE_FAILED,"Could not get cluster-type from config");
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogInfo("Using round-robin cluster mode for PF_RING (iface %s)",
                pfconf->iface);
        pfconf->ctype = (cluster_type)tmpctype;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        SCLogInfo("Using flow cluster mode for PF_RING (iface %s)",
                pfconf->iface);
        pfconf->ctype = (cluster_type)tmpctype;
    } else {
        SCLogError(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
        SCFree(pfconf);
        return NULL;
    }
#endif /* HAVE_PFRING */

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
 * If old config system is used, then return the smae parameters
 * value for each interface.
 *
 * \return a PfringIfaceConfig corresponding to the interface name
 */
void *ParsePfringConfig(const char *iface)
{
    char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *pf_ring_node;
    PfringIfaceConfig *pfconf = SCMalloc(sizeof(*pfconf));
    char *tmpclusterid;
    char *tmpctype = NULL;
#ifdef HAVE_PFRING
    cluster_type default_ctype = CLUSTER_ROUND_ROBIN;
    int getctype = 0;
#endif
    char *bpf_filter = NULL;

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
#ifdef HAVE_PFRING
    pfconf->ctype = (cluster_type)default_ctype;
#endif
    pfconf->DerefFunc = PfringDerefConfig;
    SC_ATOMIC_INIT(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, 1);

    /* Find initial node */
    pf_ring_node = ConfGetNode("pfring");
    if (pf_ring_node == NULL) {
        SCLogInfo("Unable to find pfring config using default value");
        return pfconf;
    }

    if_root = ConfNodeLookupKeyValue(pf_ring_node, "interface", iface);

    if_default = ConfNodeLookupKeyValue(pf_ring_node, "interface", "default");

    if (if_root == NULL && if_default == NULL) {
        /* Switch to old mode */
        if_root = pf_ring_node;
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

    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        pfconf->threads = 1;
    } else {
        if (threadsstr != NULL) {
            pfconf->threads = (uint8_t)atoi(threadsstr);
        }
    }
    if (pfconf->threads == 0) {
        pfconf->threads = 1;
    }

    SC_ATOMIC_RESET(pfconf->ref);
    (void) SC_ATOMIC_ADD(pfconf->ref, pfconf->threads);

    /* command line value has precedence */
    if (ConfGet("pfring.cluster-id", &tmpclusterid) == 1) {
        pfconf->cluster_id = (uint16_t)atoi(tmpclusterid);
        SCLogDebug("Going to use command-line provided cluster-id %" PRId32,
                   pfconf->cluster_id);
    } else {

        if (strncmp(pfconf->iface, "zc", 2) == 0) {
            SCLogInfo("ZC interface detected, not setting cluster-id for PF_RING (iface %s)",
                    pfconf->iface);
        } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
            SCLogInfo("DNA interface detected, not setting cluster-id for PF_RING (iface %s)",
                    pfconf->iface);
        } else if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                       "Could not get cluster-id from config");
        } else {
            pfconf->cluster_id = (uint16_t)atoi(tmpclusterid);
            SCLogDebug("Going to use cluster-id %" PRId32, pfconf->cluster_id);
        }
    }

    /*load pfring bpf filter*/
    /* command line value has precedence */
    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            pfconf->bpf_filter = SCStrdup(bpf_filter);
            if (unlikely(pfconf->bpf_filter == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC,
                           "Can't allocate BPF filter string");
            } else {
                SCLogDebug("Going to use command-line provided bpf filter %s",
                           pfconf->bpf_filter);
            }
        }
    } else {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                pfconf->bpf_filter = SCStrdup(bpf_filter);
                if (unlikely(pfconf->bpf_filter == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC,
                               "Can't allocate BPF filter string");
                } else {
                    SCLogDebug("Going to use bpf filter %s",
                               pfconf->bpf_filter);
                }
            }
        }
    }

#ifdef HAVE_PFRING
    if (ConfGet("pfring.cluster-type", &tmpctype) == 1) {
        SCLogDebug("Going to use command-line provided cluster-type");
        getctype = 1;
    } else {
        if (strncmp(pfconf->iface, "zc", 2) == 0) {
            SCLogInfo("ZC interface detected, not setting cluster type for PF_RING (iface %s)",
                    pfconf->iface);
        } else if ((pfconf->threads == 1) && (strncmp(pfconf->iface, "dna", 3) == 0)) {
            SCLogInfo("DNA interface detected, not setting cluster type for PF_RING (iface %s)",
                    pfconf->iface);
        } else if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
            SCLogError(SC_ERR_GET_CLUSTER_TYPE_FAILED,
                       "Could not get cluster-type from config");
        } else {
            getctype = 1;
        }
    }

    if (getctype) {
        if (strcmp(tmpctype, "cluster_round_robin") == 0) {
            SCLogInfo("Using round-robin cluster mode for PF_RING (iface %s)",
                    pfconf->iface);
            pfconf->ctype = CLUSTER_ROUND_ROBIN;
        } else if (strcmp(tmpctype, "cluster_flow") == 0) {
            SCLogInfo("Using flow cluster mode for PF_RING (iface %s)",
                    pfconf->iface);
            pfconf->ctype = CLUSTER_FLOW;
        } else {
            SCLogError(SC_ERR_INVALID_CLUSTER_TYPE,
                       "invalid cluster-type %s",
                       tmpctype);
            SCFree(pfconf);
            return NULL;
        }
    }
#endif /* HAVE_PFRING */
    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (strcmp(tmpctype, "yes") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(tmpctype, "no") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "rx-only") == 0) {
            pfconf->checksum_mode = CHECKSUM_VALIDATION_RXONLY;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", pfconf->iface);
        }
    }

    return pfconf;
}

int PfringConfigGeThreadsCount(void *conf)
{
    PfringIfaceConfig *pfp = (PfringIfaceConfig *)conf;
    return pfp->threads;
}

int PfringConfLevel()
{
    char *def_dev;
    /* 1.0 config should return a string */
    if (ConfGet("pfring.interface", &def_dev) != 1) {
        return PFRING_CONF_V2;
    } else {
        return PFRING_CONF_V1;
    }
    return PFRING_CONF_V2;
}

#ifdef HAVE_PFRING
static int GetDevAndParser(char **live_dev, ConfigIfaceParserFunc *parser)
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
    char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    RunModeInitialize();

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                "Unable to get parser and interface params");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureAutoFp(tparser,
                              PfringConfigGeThreadsCount,
                              "ReceivePfring",
                              "DecodePfring", "C-",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
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
    char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    RunModeInitialize();

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                "Unable to get parser and interface params");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureSingle(tparser,
                              PfringConfigGeThreadsCount,
                              "ReceivePfring",
                              "DecodePfring", "W-",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
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
    char *live_dev = NULL;
    ConfigIfaceParserFunc tparser;

    RunModeInitialize();

    TimeModeSetLive();

    ret = GetDevAndParser(&live_dev, &tparser);
    if (ret != 0) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                "Unable to get parser and interface params");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureWorkers(tparser,
                              PfringConfigGeThreadsCount,
                              "ReceivePfring",
                              "DecodePfring", "W-",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsPfringWorkers initialised");
#endif /* HAVE_PFRING */

    return 0;
}
