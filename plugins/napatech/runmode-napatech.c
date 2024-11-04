/* Copyright (C) 2012-2017 Open Information Security Foundation
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
 *  \author nPulse Technologies, LLC.
 *  \author Matt Keeler <mk@npulsetech.com>
 */

#include "suricata-common.h"
#include "suricata-plugin.h"

#include "tm-threads.h"

#include "runmode-napatech.h"
#include "source-napatech.h" // need NapatechStreamDevConf structure
#include "util-napatech.h"

#include "conf.h"
#include "runmodes.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"

static const char *default_mode = "workers";

#define NT_RUNMODE_WORKERS 1

#define MAX_STREAMS 256
static uint16_t num_configured_streams = 0;
static uint16_t first_stream = 0xffff;
static uint16_t last_stream = 0xffff;
static int auto_config = 0;
static int use_hw_bypass = 0;

uint16_t NapatechGetNumConfiguredStreams(void)
{
    return num_configured_streams;
}

uint16_t NapatechGetNumFirstStream(void)
{
    return first_stream;
}

uint16_t NapatechGetNumLastStream(void)
{
    return last_stream;
}

bool NapatechIsAutoConfigEnabled(void)
{
    return (auto_config != 0);
}

bool NapatechUseHWBypass(void)
{
    return (use_hw_bypass != 0);
}

const char *RunModeNapatechGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatechRegister(int slot)
{
    RunModeRegisterNewRunMode(slot, "workers",
            "Workers Napatech mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeNapatechWorkers, NULL);
    return;
}

static int NapatechRegisterDeviceStreams(void)
{
    /* Display the configuration mode */
    int use_all_streams;

    if (ConfGetBool("napatech.use-all-streams", &use_all_streams) == 0) {
        SCLogInfo("Could not find napatech.use-all-streams in config file.  Defaulting to \"no\".");
        use_all_streams = 0;
    }

    if (ConfGetBool("napatech.auto-config", &auto_config) == 0) {
        SCLogInfo("napatech.auto-config not found in config file.  Defaulting to disabled.");
    }

    if (ConfGetBool("napatech.hardware-bypass", &use_hw_bypass) == 0) {
        SCLogInfo("napatech.hardware-bypass not found in config file.  Defaulting to disabled.");
    }

    /* use_all_streams uses existing streams created prior to starting Suricata.  auto_config
     * automatically creates streams.  Therefore, these two options are mutually exclusive.
     */
    if (use_all_streams && auto_config) {
        FatalError("napatech.auto-config cannot be used in configuration file at the same time as "
                   "napatech.use-all-streams.");
    }

    /* to use hardware_bypass we need to configure the streams to be consistent.
     * with the rest of the configuration.  Therefore auto_config is not a valid
     * option.
     */
    if (use_hw_bypass && auto_config == 0) {
        FatalError("napatech auto-config must be enabled when using napatech.use_hw_bypass.");
    }

    /* Get the stream ID's either from the conf or by querying Napatech */
    NapatechStreamConfig stream_config[MAX_STREAMS];

    uint16_t stream_cnt = NapatechGetStreamConfig(stream_config);
    num_configured_streams = stream_cnt;
    SCLogDebug("Configuring %d Napatech Streams...", stream_cnt);

    for (uint16_t inst = 0; inst < stream_cnt; ++inst) {
        char *plive_dev_buf = SCCalloc(1, 9);
        if (unlikely(plive_dev_buf == NULL)) {
            FatalError("Failed to allocate memory for NAPATECH stream counter.");
        }
        snprintf(plive_dev_buf, 9, "nt%d", stream_config[inst].stream_id);

        if (auto_config) {
            if (stream_config[inst].is_active) {
                SCLogError("Registering Napatech device: %s - active stream found.", plive_dev_buf);
                SCLogError(
                        "run /opt/napatech3/bin/ntpl -e \"delete=all\" to delete existing stream");
                FatalError("or disable auto-config in the conf file before running.");
            }
        } else {
            SCLogInfo("Registering Napatech device: %s - active stream%sfound.", plive_dev_buf,
                    stream_config[inst].is_active ? " " : " NOT ");
        }
        LiveRegisterDevice(plive_dev_buf);

        if (first_stream == 0xffff) {
            first_stream = stream_config[inst].stream_id;
        }
        last_stream = stream_config[inst].stream_id;
    }

    /* Napatech stats come from a separate thread.  This will suppress
     * the counters when suricata exits.
     */
    LiveDeviceHasNoStats();
    return 0;
}

static void *NapatechConfigParser(const char *device)
{
    /* Expect device to be of the form nt%d where %d is the stream id to use */
    int dev_len = strlen(device);
    if (dev_len < 3 || dev_len > 5) {
        SCLogError("Could not parse config for device: %s - invalid length", device);
        return NULL;
    }

    struct NapatechStreamDevConf *conf = SCCalloc(1, sizeof(struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        SCLogError("Failed to allocate memory for NAPATECH device name.");
        return NULL;
    }

    /* device+2 is a pointer to the beginning of the stream id after the constant nt portion */
    if (StringParseUint16(&conf->stream_id, 10, 0, device + 2) < 0) {
        SCLogError("Invalid value for stream_id: %s", device + 2);
        SCFree(conf);
        return NULL;
    }

    return (void *)conf;
}

static int NapatechGetThreadsCount(void *conf __attribute__((unused)))
{
    /* No matter which live device it is there is no reason to ever use more than 1 thread
       2 or more thread would cause packet duplication */
    return 1;
}

static int NapatechInit(int runmode)
{
    int status;

    TimeModeSetLive();

    /* Initialize the API and check version compatibility */
    if ((status = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NAPATECH_ERROR(status);
        exit(EXIT_FAILURE);
    }

    status = NapatechRegisterDeviceStreams();
    if (status < 0 || num_configured_streams <= 0) {
        FatalError("Unable to find existing Napatech Streams");
    }

    struct NapatechStreamDevConf *conf = SCCalloc(1, sizeof(struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        FatalError("Failed to allocate memory for NAPATECH device.");
    }

    if (use_hw_bypass) {
#ifdef NAPATECH_ENABLE_BYPASS
        if (NapatechVerifyBypassSupport()) {
            SCLogInfo("Napatech Hardware Bypass is supported and enabled.");
        } else {
            FatalError("Napatech Hardware Bypass requested in conf but is not supported by the "
                       "hardware.");
        }
#else
        FatalError(
                "Napatech Hardware Bypass requested in conf but is not enabled by the software.");
#endif
    } else {
        SCLogInfo("Hardware Bypass is disabled in the conf file.");
    }

    /* Start a thread to process the statistics */
    NapatechStartStats();

    switch (runmode) {
        case NT_RUNMODE_WORKERS:
            status = RunModeSetLiveCaptureWorkers(NapatechConfigParser, NapatechGetThreadsCount,
                    "NapatechStream", "NapatechDecode", thread_name_workers, NULL);
            break;
        default:
            status = -1;
    }

    if (status != 0) {
        FatalError("Runmode start failed");
    }
    return 0;
}

int RunModeNapatechWorkers(void)
{
    return NapatechInit(NT_RUNMODE_WORKERS);
}
