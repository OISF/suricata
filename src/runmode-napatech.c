/* Copyright (C) 2012 Open Information Security Foundation
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

#include "runmode-napatech.h"

// need NapatechStreamDevConf structure
#include "source-napatech.h"

#define NT_RUNMODE_AUTOFP  1
#define NT_RUNMODE_WORKERS 2

static const char *default_mode = NULL;
#ifdef HAVE_NAPATECH
static int num_configured_streams = 0;
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
int NapatechRegisterDeviceStreams()
{
    NtInfoStream_t info_stream;
    NtInfo_t info;
    char error_buf[100];
    int status;
    int i;
    char live_dev_buf[9];
    int use_all_streams;
    ConfNode *ntstreams;
    ConfNode *stream_id;

    if (ConfGetBool("napatech.use-all-streams", &use_all_streams) == 0)
    {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.use-all-streams from Conf");
        exit(EXIT_FAILURE);
    }

    if (use_all_streams)
    {
        SCLogInfo("Using All Napatech Streams");
        // When using the default streams we need to query the service for a list of all configured
        if ((status = NT_InfoOpen(&info_stream, "SuricataStreamInfo")) != NT_SUCCESS)
        {
            NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
            SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "NT_InfoOpen failed: %s", error_buf);
            return -1;
        }

        info.cmd = NT_INFO_CMD_READ_STREAM;
        if ((status = NT_InfoRead(info_stream, &info)) != NT_SUCCESS)
        {
            NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
            SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "NT_InfoRead failed: %s", error_buf);
            return -1;
        }

        num_configured_streams = info.u.stream.data.count;
        for (i = 0; i < num_configured_streams; i++)
        {
            // The Stream IDs do not have to be sequential
            snprintf(live_dev_buf, sizeof(live_dev_buf), "nt%d", info.u.stream.data.streamIDList[i]);
            LiveRegisterDevice(live_dev_buf);
        }

        if ((status = NT_InfoClose(info_stream)) != NT_SUCCESS)
        {
            NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
            SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "NT_InfoClose failed: %s", error_buf);
            return -1;
        }
    }
    else
    {
        SCLogInfo("Using Selected Napatech Streams");
        // When not using the default streams we need to parse the array of streams from the conf
        if ((ntstreams = ConfGetNode("napatech.streams")) == NULL)
        {
            SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.streams from Conf");
            exit(EXIT_FAILURE);
        }

        // Loop through all stream numbers in the array and register the devices
        TAILQ_FOREACH(stream_id, &ntstreams->head, next)
        {
            if (stream_id == NULL)
            {
                SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "Couldn't Parse Stream Configuration");
                exit(EXIT_FAILURE);
            }
            num_configured_streams++;

            snprintf(live_dev_buf, sizeof(live_dev_buf), "nt%d", atoi(stream_id->val));
            LiveRegisterDevice(live_dev_buf);
        }
    }
    return 0;
}

void *NapatechConfigParser(const char *device)
{
    // Expect device to be of the form nt%d where %d is the stream id to use
    int dev_len = strlen(device);
    struct NapatechStreamDevConf *conf = SCMalloc(sizeof(struct NapatechStreamDevConf));
    if (unlikely(conf == NULL))
        return NULL;
    if (dev_len < 3 || dev_len > 5)
    {
        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG, "Could not parse config for device: %s - invalid length", device);
        return NULL;
    }

    // device+5 is a pointer to the beginning of the stream id after the constant nt portion
    conf->stream_id = atoi(device+2);

    // Set the host buffer allowance for this stream
    // Right now we just look at the global default - there is no per-stream hba configuration
    if (ConfGetInt("napatech.hba", &conf->hba) == 0)
        conf->hba = -1;

    return (void *) conf;
}

int NapatechGetThreadsCount(void *conf __attribute__((unused))) {
    // No matter which live device it is there is no reason to ever use more than 1 thread
    //   2 or more thread would cause packet duplication
    return 1;
}

static int NapatechInit(int runmode)
{
    int ret;
    char errbuf[100];

    RunModeInitialize();
    TimeModeSetLive();

    /* Initialize the API and check version compatibility */
    if ((ret = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NT_ExplainError(ret, errbuf, sizeof(errbuf));
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED ,"NT_Init failed. Code 0x%X = %s", ret, errbuf);
        exit(EXIT_FAILURE);
    }

    ret = NapatechRegisterDeviceStreams();
    if (ret < 0 || num_configured_streams <= 0) {
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, "Unable to setup up Napatech Streams");
        exit(EXIT_FAILURE);
    }

    switch(runmode) {
        case NT_RUNMODE_AUTOFP:
            ret = RunModeSetLiveCaptureAutoFp(NapatechConfigParser, NapatechGetThreadsCount,
                                              "NapatechStream", "NapatechDecode",
                                              "RxNT", NULL);
            break;
        case NT_RUNMODE_WORKERS:
            ret = RunModeSetLiveCaptureWorkers(NapatechConfigParser, NapatechGetThreadsCount,
                                               "NapatechStream", "NapatechDecode",
                                               "RxNT", NULL);
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
