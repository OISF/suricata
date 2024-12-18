/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \file
 *
 * \author Mahmoud Maatuq <mahmoudmatook.mm@gmail.com>
 *
 * Pcap over ip packet runmode.
 */
#include "suricata-common.h"
#include "runmode-pcap-over-ip.h"
#include "runmodes.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-runmodes.h"

#include "source-pcap-over-ip.h"

#define PCAP_OVER_IP_BUFFER_SIZE_DEFAULT 131072U // 128 KiB
#define PCAP_OVER_IP_BUFFER_SIZE_MIN     4096U   // 4 KiB
#define PCAP_OVER_IP_BUFFER_SIZE_MAX                                                               \
    67108864U // 64 MiB
              //
/**
 * \brief Return default mode for pcap-over-ip
 */
const char *RunModePcapOverIPGetDefaultMode(void)
{
    return "autofp";
}

/**
 * \brief Register runmodes for pcap-over-ip
 */
void RunModePcapOverIPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PCAP_OVER_IP, "single", "Single threaded pcap-over-ip mode",
            RunModePcapOverIPSingle, NULL);

    RunModeRegisterNewRunMode(RUNMODE_PCAP_OVER_IP, "autofp",
            "Multi-threaded pcap-over-ip mode. Packets from each flow are "
            "assigned to a consistent detection thread",
            RunModePcapOverIPAutoFp, NULL);
}

static void PcapOverIPDerefConfig(void *conf)
{
    PcapOverIPIfaceConfig *pfp = (PcapOverIPIfaceConfig *)conf;
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
        SCFree(pfp);
    }
}

static void *ParsePcapOverIPConfig(const char *socket_addr)
{
    intmax_t value;

    PcapOverIPIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (aconf == NULL) {
        return NULL;
    }

    if (socket_addr == NULL) {
        SCFree(aconf);
        return NULL;
    }

    strlcpy(aconf->socket_addr, socket_addr, sizeof(aconf->socket_addr));

    const char *tmpbpf = NULL;
    if ((ConfGet("bpf-filter", &tmpbpf)) == 1) {
        aconf->bpf_filter = tmpbpf;
    }

    aconf->buffer_size = 0;

    if (ConfGetInt("pcap-over-ip.buffer-size", &value) == 1) {
        if (value < (intmax_t)PCAP_OVER_IP_BUFFER_SIZE_MIN ||
                value > (intmax_t)PCAP_OVER_IP_BUFFER_SIZE_MAX) {
            SCLogWarning("pcap-over-ip.buffer-size value of %" PRIiMAX
                         " is invalid. Valid range is "
                         "%" PRIu32 "-%" PRIu32 ". Using default of %" PRIu32 ".",
                    value, PCAP_OVER_IP_BUFFER_SIZE_MIN, PCAP_OVER_IP_BUFFER_SIZE_MAX,
                    PCAP_OVER_IP_BUFFER_SIZE_DEFAULT);
            aconf->buffer_size = (int)PCAP_OVER_IP_BUFFER_SIZE_DEFAULT;
        } else {
            SCLogInfo("pcap-over-ip.buffer-size set to %" PRIiMAX, value);
            aconf->buffer_size = (int)value;
        }
    } else {
        aconf->buffer_size = (int)PCAP_OVER_IP_BUFFER_SIZE_DEFAULT;
        SCLogInfo("pcap-over-ip.buffer-size not set; using default of %d", aconf->buffer_size);
    }

    const char *tmpctype = NULL;
    if (ConfGet("pcap-over-ip.checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        }
    } else {
        aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    }

    aconf->threads = 1;
    intmax_t threads = 0;
    if (ConfGetInt("pcap-over-ip.threads", &threads) == 1 && threads > 0 && threads < INT_MAX) {
        aconf->threads = (int)threads;
    }

    SC_ATOMIC_INIT(aconf->ref);
    aconf->DerefFunc = PcapOverIPDerefConfig;

    return aconf;
}

static int PcapOverIPConfigGetThreadsCount(void *conf)
{
    PcapOverIPIfaceConfig *pfp = (PcapOverIPIfaceConfig *)conf;
    return pfp->threads;
}

/**
 * \brief Single thread version of pcap-over-ip processing.
 */
int RunModePcapOverIPSingle(void)
{
    SCEnter();

    TimeModeSetLive();

    const char *endpoint = NULL;
    if (ConfGet("pcap-over-ip.endpoint", &endpoint) == 0 || endpoint == NULL) {
        FatalError("Failed retrieving pcap-over-ip.endpoint from configuration.");
    }

    int ret = RunModeSetLiveCaptureSingle(ParsePcapOverIPConfig, PcapOverIPConfigGetThreadsCount,
            "ReceivePcapOverIP", "DecodePcapOverIP", thread_name_single, endpoint);
    if (ret != 0) {
        FatalError("Runmode start failed (pcap-over-ip single)");
    }

    SCLogDebug("RunModePcapOverIPSingle initialised");

    SCReturnInt(0);
}

/**
 * \brief AutoFP multi-threaded version of pcap-over-ip.
 */
int RunModePcapOverIPAutoFp(void)
{
    SCEnter();
    TimeModeSetLive();

    const char *socket_addr = NULL;
    if (ConfGet("pcap-over-ip.socket_addr", &socket_addr) == 0 || socket_addr == NULL) {
        FatalError("Failed retrieving pcap-over-ip.endpoint from configuration.");
    }

    int ret = RunModeSetLiveCaptureAutoFp(ParsePcapOverIPConfig, PcapOverIPConfigGetThreadsCount,
            "ReceivePcapOverIP", "DecodePcapOverIP", thread_name_autofp, socket_addr);
    if (ret != 0) {
        FatalError("Runmode start failed (pcap-over-ip autofp)");
    }

    SCLogDebug("RunModePcapOverIPAutoFp initialised");

    SCReturnInt(0);
}
