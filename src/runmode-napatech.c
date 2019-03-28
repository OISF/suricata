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
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "output.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"
#include "util-napatech.h"
#include "runmode-napatech.h"
#include "source-napatech.h" // need NapatechStreamDevConf structure

#define NT_RUNMODE_AUTOFP  1
#define NT_RUNMODE_WORKERS 2

static const char *default_mode = "workers";

#ifdef HAVE_NAPATECH

#define MAX_STREAMS 256
static uint16_t num_configured_streams = 0;
static uint16_t first_stream = 0xffff;
static uint16_t last_stream = 0xffff;
static int auto_config = 0;

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

#endif

const char *RunModeNapatechGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatechRegister(void)
{
#ifdef HAVE_NAPATECH
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH, "workers",
            "Workers Napatech mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeNapatechWorkers);
    return;
#endif
}


#ifdef HAVE_NAPATECH

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

    if (use_all_streams && auto_config) {
        SCLogError(SC_ERR_RUNMODE, "auto-config cannot be used with use-all-streams.");
    }

    /* Get the stream ID's either from the conf or by querying Napatech */
    NapatechStreamConfig stream_config[MAX_STREAMS];

    uint16_t stream_cnt = NapatechGetStreamConfig(stream_config);
    num_configured_streams = stream_cnt;
    SCLogDebug("Configuring %d Napatech Streams...", stream_cnt);

    for (uint16_t inst = 0; inst < stream_cnt; ++inst) {
        char *plive_dev_buf = SCCalloc(1, 9);
        if (unlikely(plive_dev_buf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }
        snprintf(plive_dev_buf, 9, "nt%d", stream_config[inst].stream_id);

        if (auto_config) {
            if (stream_config[inst].is_active) {
                SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                        "Registering Napatech device: %s - active stream found.",
                        plive_dev_buf);
                SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                        "Delete the stream or disable auto-config before running.");
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Registering Napatech device: %s - active stream%sfound.",
                    plive_dev_buf, stream_config[inst].is_active ? " " : " NOT ");
        }
        LiveRegisterDevice(plive_dev_buf);

        if (first_stream == 0xffff) {
            first_stream = stream_config[inst].stream_id;
        }
        last_stream = stream_config[inst].stream_id;
    }

    /* Napatech stats come from a separate thread.  This will surpress
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
        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                "Could not parse config for device: %s - invalid length", device);
        return NULL;
    }

    struct NapatechStreamDevConf *conf = SCCalloc(1, sizeof (struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Failed to allocate memory for NAPATECH device name.");
        return NULL;
    }

    /* device+5 is a pointer to the beginning of the stream id after the constant nt portion */
    conf->stream_id = atoi(device + 2);

    /* Set the host buffer allowance for this stream
     * Right now we just look at the global default - there is no per-stream hba configuration
     */
    if (ConfGetInt("napatech.hba", &conf->hba) == 0) {
        conf->hba = -1;
    }
    return (void *) conf;
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

    RunModeInitialize();
    TimeModeSetLive();

    /* Initialize the API and check version compatibility */
    if ((status = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    status = NapatechRegisterDeviceStreams();
    if (status < 0 || num_configured_streams <= 0) {
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                    "Unable to find existing Napatech Streams");
        exit(EXIT_FAILURE);
    }

    struct NapatechStreamDevConf *conf =
                            SCCalloc(1, sizeof (struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH device.");
        exit(EXIT_FAILURE);
    }

    if ((ConfGetInt("napatech.hba", &conf->hba) != 0) && (conf->hba > 0)) {
        SCLogInfo("Host Buffer Allowance: %d", (int) conf->hba);
    }

    /* Start a thread to process the statistics */
    NapatechStartStats();

    switch (runmode) {
        case NT_RUNMODE_WORKERS:
            status = RunModeSetLiveCaptureWorkers(NapatechConfigParser,
                    NapatechGetThreadsCount,
                    "NapatechStream", "NapatechDecode",
                    thread_name_workers, NULL);
            break;
        default:
            status = -1;
    }

    if (status != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int RunModeNapatechAutoFp(void)
{
    return NapatechInit(NT_RUNMODE_AUTOFP);
}

int RunModeNapatechWorkers(void)
{
    return NapatechInit(NT_RUNMODE_WORKERS);
}

#endif
