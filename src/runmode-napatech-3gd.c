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
#include "log-httplog.h"
#include "output.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"

#include "runmode-napatech-3gd.h"

// need Napatech3GDStreamDevConf structure
#include "source-napatech-3gd.h"

#define NT3GD_RUNMODE_AUTO    1
#define NT3GD_RUNMODE_AUTOFP  2
#define NT3GD_RUNMODE_WORKERS 4

static const char *default_mode = NULL;
#ifdef HAVE_NAPATECH_3GD
static int num_configured_streams = 0;
#endif

const char *RunModeNapatech3GDGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatech3GDRegister(void)
{
#ifdef HAVE_NAPATECH_3GD
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH_3GD, "auto",
            "Multi threaded Napatech 3GD mode",
            RunModeNapatech3GDAuto);
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH_3GD, "autofp",
            "Multi threaded Napatech 3GD mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread instead of any detect thread",
            RunModeNapatech3GDAutoFp);
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH_3GD, "workers",
            "Workers Napatech 3GD mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeNapatech3GDWorkers);
    return;
#endif
}

#ifdef HAVE_NAPATECH_3GD
int Napatech3GDRegisterDeviceStreams()
{
    NtInfoStream_t info_stream;
    NtInfo_t info;
    char error_buf[100];
    int status;
    int i;
    char live_dev_buf[9];

    if ((status = NT_InfoOpen(&info_stream, "Test")) != NT_SUCCESS)
    {
        NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
        SCLogError(SC_ERR_NAPATECH_3GD_STREAMS_REGISTER_FAILED, "NT_InfoOpen failed: %s", error_buf);
        return -1;
    }


    info.cmd = NT_INFO_CMD_READ_STREAM;
    if ((status = NT_InfoRead(info_stream, &info)) != NT_SUCCESS)
    {
        NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
        SCLogError(SC_ERR_NAPATECH_3GD_STREAMS_REGISTER_FAILED, "NT_InfoRead failed: %s", error_buf);
        return -1;
    }

    num_configured_streams = info.u.stream.data.count;
    for (i = 0; i < num_configured_streams; i++)
    {
        // The Stream IDs do not have to be sequential
        snprintf(live_dev_buf, sizeof(live_dev_buf), "nt3gd%d", info.u.stream.data.streamIDList[i]);
        LiveRegisterDevice(live_dev_buf);
    }

    if ((status = NT_InfoClose(info_stream)) != NT_SUCCESS)
    {
        NT_ExplainError(status, error_buf, sizeof(error_buf) -1);
        SCLogError(SC_ERR_NAPATECH_3GD_STREAMS_REGISTER_FAILED, "NT_InfoClose failed: %s", error_buf);
        return -1;
    }
    return 0;
}

void *Napatech3GDConfigParser(const char *device) {
    // Expect device to be of the form nt3gd%d where %d is the stream id to use
    int dev_len = strlen(device);
    struct Napatech3GDStreamDevConf *conf = SCMalloc(sizeof(struct Napatech3GDStreamDevConf));
    if (dev_len < 6 || dev_len > 8)
    {
        SCLogError(SC_ERR_NAPATECH_3GD_PARSE_CONFIG, "Could not parse config for device: %s - invalid length", device);
        return NULL;
    }

    // device+5 is a pointer to the beginning of the stream id after the constant nt3gd portion
    conf->stream_id = atoi(device+5);
    return (void *) conf;
}

int Napatech3GDGetThreadsCount(void *conf __attribute__((unused))) {
    // No matter which live device it is there is no reason to ever use more than 1 thread
    //   2 or more thread would cause packet duplication
    return 1;
}

int Napatech3GDInit(DetectEngineCtx *de_ctx, int runmode) {
    int ret;
    char errbuf[100];

    RunModeInitialize();
    TimeModeSetLive();

    /* Initialize the 3GD API and check version compatibility */
    if ((ret = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NT_ExplainError(ret, errbuf, sizeof(errbuf));
        SCLogError(SC_ERR_NAPATECH_3GD_INIT_FAILED ,"NT_Init failed. Code 0x%X = %s", ret, errbuf);
        exit(EXIT_FAILURE);
    }

    ret = Napatech3GDRegisterDeviceStreams();
    if (ret < 0 || num_configured_streams <= 0) {
        SCLogError(SC_ERR_NAPATECH_3GD_STREAMS_REGISTER_FAILED, "Unable to setup up Napatech 3GD Streams");
        exit(EXIT_FAILURE);
    }

    switch(runmode) {
        case NT3GD_RUNMODE_AUTO:
            ret = RunModeSetLiveCaptureAuto(de_ctx, Napatech3GDConfigParser, Napatech3GDGetThreadsCount,
                                            "Napatech3GDStream", "Napatech3GDDecode",
                                            "RxNT3GD", NULL);
            break;
        case NT3GD_RUNMODE_AUTOFP:
            ret = RunModeSetLiveCaptureAutoFp(de_ctx, Napatech3GDConfigParser, Napatech3GDGetThreadsCount,
                                              "Napatech3GDStream", "Napatech3GDDecode",
                                              "RxNT3GD", NULL);
            break;
        case NT3GD_RUNMODE_WORKERS:
            ret = RunModeSetLiveCaptureWorkers(de_ctx, Napatech3GDConfigParser, Napatech3GDGetThreadsCount,
                                               "Napatech3GDStream", "Napatech3GDDecode",
                                               "RxNT3GD", NULL);
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

int RunModeNapatech3GDAuto(DetectEngineCtx *de_ctx) {
    return Napatech3GDInit(de_ctx, NT3GD_RUNMODE_AUTO);
}

int RunModeNapatech3GDAutoFp(DetectEngineCtx *de_ctx) {
    return Napatech3GDInit(de_ctx, NT3GD_RUNMODE_AUTOFP);
}

int RunModeNapatech3GDWorkers(DetectEngineCtx *de_ctx) {
    return Napatech3GDInit(de_ctx, NT3GD_RUNMODE_WORKERS);
}

#endif

