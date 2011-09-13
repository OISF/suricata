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
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"

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
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "autofp",
                              "Multi threaded pcap live mode.  Packets from "
                              "each flow are assigned to a single detect thread, "
                              "unlike \"pcap_live_auto\" where packets from "
                              "the same flow can be processed by any detect "
                              "thread",
                              RunModeIdsPcapAutoFp);

    return;
}


void *ParsePcapConfig(const char *iface)
{
    ConfNode *if_root;
    ConfNode *pcap_node;
    PcapIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *tmpbpf;
    intmax_t value;

    if (iface == NULL) {
        return NULL;
    }

    if (aconf == NULL) {
        return NULL;
    }
    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->buffer_size = 0;

    /* Find initial node */
    pcap_node = ConfGetNode("pcap");
    if (pcap_node == NULL) {
        SCLogInfo("Unable to find af-packet config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(pcap_node, "interface", iface);
    if (if_root == NULL) {
        SCLogInfo("Unable to find pcap config for "
                  "interface %s, using default value",
                  iface);
        return aconf;
    }

    if ((ConfGetChildValueInt(if_root, "buffer-size", &value)) == 1) {
        aconf->buffer_size = value;
    } else {
        aconf->buffer_size = 0;
    }

    /* set bpf filter if we have one */
    if (ConfGetChildValue(if_root, "bpf-filter", &tmpbpf) != 1) {
        SCLogDebug("could not get bpf or none specified");
    } else {
        /* TODO free this */
        aconf->bpf_filter = strdup(tmpbpf);
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
    int npcap = LiveGetDeviceCount();
    char *pcap_dev = NULL;
    char *pcap_devc = NULL;

    if (npcap > 1) {
        SCLogError(SC_ERR_RUNMODE,
                   "Can't use single runmode with multiple device");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();
    TimeModeSetLive();

    if (ConfGet("pcap.single_pcap_dev", &pcap_dev) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                "pcap.single_pcap_dev from Conf");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("pcap_dev %s", pcap_dev);
    pcap_devc = SCStrdup(pcap_dev);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler("PcapLive",
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, pcap_devc);

    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, (void *)de_ctx);

    SetupOutputs(tv);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
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
    char *live_dev;
    int ret;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    /* TODO handle compat with pcap.single_pcap_dev */
    ConfGet("pcap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureAuto(de_ctx,
                                    ParsePcapConfig, "ReceivePcap",
                                    "DecodePcap", "RecvPcap",
                                    live_dev);
    if (ret != 0) {
        printf("ERROR: Unable to start runmode\n");
        if (live_dev)
            SCFree(live_dev);
        exit(EXIT_FAILURE);
    }

    if (live_dev)
        SCFree(live_dev);

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

    /* TODO handle compat with pcap.single_pcap_dev */
    ConfGet("pcap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureAutoFp(de_ctx,
                              ParsePcapConfig,
                              PcapConfigGeThreadsCount,
                              "ReceivePcap",
                              "DecodePcap", "RxPcap",
                              live_dev);
    if (ret != 0) {
        printf("ERROR: Unable to start runmode\n");
        if (live_dev)
            SCFree(live_dev);
        exit(EXIT_FAILURE);
    }

    if (live_dev)
        SCFree(live_dev);

    SCLogInfo("RunModeIdsPcapAutoFp initialised");

    SCReturnInt(0);
}
