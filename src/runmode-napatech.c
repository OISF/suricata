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

static const char *default_mode = NULL;
#ifdef HAVE_NAPATECH

#define MAX_STREAMS 256
static uint16_t num_configured_streams = 0;

uint16_t GetNumConfiguredStreams(void) {
    return num_configured_streams;
}

#endif

const char *RunModeNapatechGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatechRegister(void)
{
#ifdef HAVE_NAPATECH
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH, "autofp",
            "Multi threaded Napatech mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread instead of any detect thread",
            RunModeNapatechAutoFp);
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
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.use-all-streams from Conf");
        exit(EXIT_FAILURE);
    }

    if (use_all_streams) {
        SCLogInfo("Using All Napatech Streams");
    } else {
        SCLogInfo("Using Selected Napatech Streams");
    }

    /* Get the stream ID's either from the conf or by querying Napatech */
    NapatechStreamConfig stream_config[MAX_STREAMS];
    uint16_t stream_cnt = NapatechGetStreamConfig(stream_config);
    num_configured_streams = stream_cnt;
    SCLogDebug("Configuring %d Napatech Streams...", stream_cnt);

    for (uint16_t inst = 0; inst < stream_cnt; ++inst) {
        char *plive_dev_buf = SCCalloc(1, 9);
        if (unlikely(plive_dev_buf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }
        snprintf(plive_dev_buf, 9, "nt%d", stream_config[inst].stream_id);
        SCLogInfo("registering Napatech device: %s - active stream%sfound.",
                        plive_dev_buf, stream_config[inst].is_active ? " " : " NOT ");
        LiveRegisterDevice(plive_dev_buf);
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
    struct NapatechStreamDevConf *conf = SCCalloc(1, sizeof (struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH device name.");
        return NULL;
    }
    if (dev_len < 3 || dev_len > 5) {
        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG, "Could not parse config for device: %s - invalid length", device);
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
    int ret;
    char error_buf[100];

    RunModeInitialize();
    TimeModeSetLive();

    /* Initialize the API and check version compatibility */
    if ((ret = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NT_ExplainError(ret, error_buf, sizeof (error_buf));
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED, "NT_Init failed. Code 0x%X = %s", ret, error_buf);
        exit(EXIT_FAILURE);
    }

    ret = NapatechRegisterDeviceStreams();
    if (ret < 0 || num_configured_streams <= 0) {
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "Unable to setup up Napatech Streams");
        exit(EXIT_FAILURE);
    }

    struct NapatechStreamDevConf *conf = SCCalloc(1, sizeof (struct NapatechStreamDevConf));
    if (unlikely(conf == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH device.");
        exit(EXIT_FAILURE);
    }

    if ( (ConfGetInt("napatech.hba", &conf->hba) != 0) && (conf->hba > 0)){
        SCLogInfo("Host Buffer Allowance: %d", (int)conf->hba);
    }

    /* Start a thread to process the statistics */
    NapatechStartStats();

    switch (runmode) {
        case NT_RUNMODE_AUTOFP:
            ret = RunModeSetLiveCaptureAutoFp(NapatechConfigParser, NapatechGetThreadsCount,
                    "NapatechStream", "NapatechDecode",
                    thread_name_autofp, NULL);
            break;
        case NT_RUNMODE_WORKERS:
            ret = RunModeSetLiveCaptureWorkers(NapatechConfigParser, NapatechGetThreadsCount,
                    "NapatechStream", "NapatechDecode",
                    thread_name_workers, NULL);
            break;
        default:
            ret = -1;
    }

    if (ret != 0) {
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
