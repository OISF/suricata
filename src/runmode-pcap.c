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
#include "runmode-pcap.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "source-pfring.h"
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
#include "util-atomic.h"

static const char *default_mode = NULL;

const char *RunModeIdsGetDefaultMode(void)
{
    return default_mode;
}

void RunModeIdsPcapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "single",
                              "Single threaded pcap live mode",
                              RunModeIdsPcapSingle);
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "auto",
                              "Multi threaded pcap live mode",
                              RunModeIdsPcapAuto);
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "autofp",
                              "Multi threaded pcap live mode.  Packets from "
                              "each flow are assigned to a single detect thread, "
                              "unlike \"pcap_live_auto\" where packets from "
                              "the same flow can be processed by any detect "
                              "thread",
                              RunModeIdsPcapAutoFp);

    return;
}

void PcapDerefConfig(void *conf)
{
    PcapIfaceConfig *pfp = (PcapIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        SCFree(pfp);
    }
}


void *ParsePcapConfig(const char *iface)
{
    ConfNode *if_root;
    ConfNode *pcap_node;
    PcapIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *tmpbpf;
    char *tmpctype;
    intmax_t value;

    if (aconf == NULL) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));

    aconf->buffer_size = 0;
    /* If set command line option has precedence over config */
    if ((ConfGetInt("pcap.buffer-size", &value)) == 1) {
        SCLogInfo("Pcap will use %d buffer size", (int)value);
        aconf->buffer_size = value;
    }

    aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    aconf->bpf_filter = NULL;
    if ((ConfGet("bpf-filter", &tmpbpf)) == 1) {
        aconf->bpf_filter = tmpbpf;
    }

    SC_ATOMIC_INIT(aconf->ref);
    SC_ATOMIC_ADD(aconf->ref, 1);
    aconf->DerefFunc = PcapDerefConfig;

    /* Find initial node */
    pcap_node = ConfGetNode("pcap");
    if (pcap_node == NULL) {
        SCLogInfo("Unable to find pcap config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(pcap_node, "interface", iface);
    if (if_root == NULL) {
        SCLogInfo("Unable to find pcap config for "
                  "interface %s, using default value",
                  iface);
        return aconf;
    }

    if (aconf->buffer_size == 0) {
        if ((ConfGetChildValueInt(if_root, "buffer-size", &value)) == 1) {
            aconf->buffer_size = value;
            SCLogInfo("Pcap will use %d buffer size (config file provided "
                    "value)", (int)value);
        }
    }

    if (aconf->bpf_filter == NULL) {
        /* set bpf filter if we have one */
        if (ConfGetChildValue(if_root, "bpf-filter", &tmpbpf) != 1) {
            SCLogDebug("could not get bpf or none specified");
        } else {
            aconf->bpf_filter = tmpbpf;
        }
    } else {
        SCLogInfo("BPF filter set from command line or via old 'bpf-filter' option.");
    }

    if (ConfGetChildValue(if_root, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (strcmp(tmpctype, "yes") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(tmpctype, "no") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

    return aconf;
}

int PcapConfigGeThreadsCount(void *conf)
{
    return 1;
}

/**
 * \brief Single thread version of the Pcap live processing.
 */
int RunModeIdsPcapSingle(DetectEngineCtx *de_ctx)
{
    int ret;
    char *live_dev = NULL;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureSingle(de_ctx,
                                    ParsePcapConfig,
                                    PcapConfigGeThreadsCount,
                                    "ReceivePcap",
                                    "DecodePcap", "PcapLive",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsPcapSingle initialised");

    SCReturnInt(0);
}


/**
 * \brief RunModeIdsPcapAuto set up the following thread packet handlers:
 *        - Receive thread (from iface pcap)
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
int RunModeIdsPcapAuto(DetectEngineCtx *de_ctx)
{
    /* tname = Detect + cpuid, this is 11bytes length as max */
    char *live_dev = NULL;
    int ret;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureAuto(de_ctx,
                                    ParsePcapConfig,
                                    PcapConfigGeThreadsCount,
                                    "ReceivePcap",
                                    "DecodePcap", "RecvPcap",
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsPcapAuto initialised");

    SCReturnInt(0);
}

/**
 * \brief RunModIdsPcapAutoFp set up the following thread packet handlers:
 *        - Receive thread (from pcap device)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu.
 *
 * \param de_ctx Pointer to the Detection Engine
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeIdsPcapAutoFp(DetectEngineCtx *de_ctx)
{
    int ret;
    char *live_dev = NULL;

    SCEnter();
    RunModeInitialize();
    TimeModeSetLive();

    ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureAutoFp(de_ctx,
                              ParsePcapConfig,
                              PcapConfigGeThreadsCount,
                              "ReceivePcap",
                              "DecodePcap", "RxPcap",
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsPcapAutoFp initialised");

    SCReturnInt(0);
}
