/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "output.h"
#include "log-httplog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-atomic.h"
#include "util-misc.h"
#include "util-byte.h"

const char *RunModeIdsGetDefaultMode(void)
{
    return "autofp";
}

int RunModeIdsPcapWorkers(void);

void RunModeIdsPcapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "single",
                              "Single threaded pcap live mode",
                              RunModeIdsPcapSingle);
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "autofp",
                              "Multi threaded pcap live mode.  Packets from "
                              "each flow are assigned to a single detect thread, "
                              "unlike \"pcap_live_auto\" where packets from "
                              "the same flow can be processed by any detect "
                              "thread",
                              RunModeIdsPcapAutoFp);
    RunModeRegisterNewRunMode(RUNMODE_PCAP_DEV, "workers",
                              "Workers pcap live mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsPcapWorkers);

    return;
}

static void PcapDerefConfig(void *conf)
{
    PcapIfaceConfig *pfp = (PcapIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
        SCFree(pfp);
    }
}

static void *ParsePcapConfig(const char *iface)
{
    const char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *pcap_node;
    PcapIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    const char *tmpbpf;
    const char *tmpctype;
    intmax_t value;
    int promisc = 0;
    intmax_t snaplen = 0;

    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }

    memset(aconf, 0x00, sizeof(*aconf));
    strlcpy(aconf->iface, iface, sizeof(aconf->iface));

    aconf->buffer_size = 0;
    /* If set command line option has precedence over config */
    if ((ConfGetInt("pcap.buffer-size", &value)) == 1) {
        if (value >= 0 && value <= INT_MAX) {
            SCLogInfo("Pcap will use %d buffer size", (int)value);
            aconf->buffer_size = value;
        } else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "pcap.buffer-size "
                    "value of %"PRIiMAX" is invalid. Valid range is "
                    "0-2147483647", value);
        }
    }

    aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    aconf->bpf_filter = NULL;
    if ((ConfGet("bpf-filter", &tmpbpf)) == 1) {
        aconf->bpf_filter = tmpbpf;
    }

    SC_ATOMIC_INIT(aconf->ref);
    aconf->DerefFunc = PcapDerefConfig;
    aconf->threads = 1;

    /* Find initial node */
    pcap_node = ConfGetNode("pcap");
    if (pcap_node == NULL) {
        SCLogInfo("Unable to find pcap config using default value");
        return aconf;
    }

    if_root = ConfFindDeviceConfig(pcap_node, iface);

    if_default = ConfFindDeviceConfig(pcap_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find pcap config for "
                  "interface %s, using default value",
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
            if (StringParseInt32(&aconf->threads, 10, 0, (const char *)threadsstr) < 0) {
                SCLogWarning(SC_ERR_INVALID_VALUE, "Invalid value for "
                             "pcap.threads: %s, resetting to 1", threadsstr);
                aconf->threads = 1;
            }
        }
    }
    if (aconf->threads == 0) {
        aconf->threads = 1;
    }
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    if (aconf->buffer_size == 0) {
        const char *s_limit = NULL;
        int ret;
        ret = ConfGetChildValueWithDefault(if_root, if_default, "buffer-size", &s_limit);
        if (ret == 1 && s_limit) {
            uint64_t bsize = 0;

            if (ParseSizeStringU64(s_limit, &bsize) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to parse pcap buffer size: %s",
                    s_limit);
            } else {
                /* the string 2gb returns 2147483648 which is 1 to high
                 * for a int. */
                if (bsize == (uint64_t)((uint64_t)INT_MAX + (uint64_t)1))
                    bsize = (uint64_t)INT_MAX;

                if (bsize > INT_MAX) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                            "Failed to set pcap buffer size: 2gb max. %"PRIu64" > %d", bsize, INT_MAX);
                } else {
                    aconf->buffer_size = (int)bsize;
                }
            }
        }
    }

    if (aconf->bpf_filter == NULL) {
        /* set bpf filter if we have one */
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &tmpbpf) != 1) {
            SCLogDebug("could not get bpf or none specified");
        } else {
            aconf->bpf_filter = tmpbpf;
        }
    } else {
        SCLogInfo("BPF filter set from command line or via old 'bpf-filter' option.");
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

    aconf->promisc = LIBPCAP_PROMISC;
    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "promisc", &promisc) != 1) {
        SCLogDebug("could not get promisc or none specified");
    } else {
        aconf->promisc = promisc;
    }

    aconf->snaplen = 0;
    if (ConfGetChildValueIntWithDefault(if_root, if_default, "snaplen", &snaplen) != 1) {
        SCLogDebug("could not get snaplen or none specified");
    } else {
        aconf->snaplen = snaplen;
    }

    return aconf;
}

static int PcapConfigGeThreadsCount(void *conf)
{
    PcapIfaceConfig *pfp = (PcapIfaceConfig *)conf;
    return pfp->threads;
}

/**
 * \brief Single thread version of the Pcap live processing.
 */
int RunModeIdsPcapSingle(void)
{
    int ret;
    const char *live_dev = NULL;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureSingle(ParsePcapConfig,
                                    PcapConfigGeThreadsCount,
                                    "ReceivePcap",
                                    "DecodePcap", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Runmode start failed");
    }

    SCLogInfo("RunModeIdsPcapSingle initialised");

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
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeIdsPcapAutoFp(void)
{
    int ret;
    const char *live_dev = NULL;

    SCEnter();
    RunModeInitialize();
    TimeModeSetLive();

    (void) ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureAutoFp(ParsePcapConfig,
                              PcapConfigGeThreadsCount,
                              "ReceivePcap",
                              "DecodePcap", thread_name_autofp,
                              live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Runmode start failed");
    }

    SCLogInfo("RunModeIdsPcapAutoFp initialised");

    SCReturnInt(0);
}

/**
 * \brief Workers version of the PCAP LIVE processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsPcapWorkers(void)
{
    int ret;
    const char *live_dev = NULL;
    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    (void) ConfGet("pcap.single-pcap-dev", &live_dev);

    ret = RunModeSetLiveCaptureWorkers(ParsePcapConfig,
                                    PcapConfigGeThreadsCount,
                                    "ReceivePcap",
                                    "DecodePcap", thread_name_workers,
                                    live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogInfo("RunModeIdsPcapWorkers initialised");

    SCReturnInt(0);
}
