/* Copyright (C) 2024 Open Information Security Foundation
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
#include "runmodes.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"

#include "runmode.h"

static int ThreadCountAutoFp(void *config)
{
    return 1;
}

static int ThreadCountWorkers(void *config)
{
    return 3;
}

const char *DefaultRunMode(void)
{
    return "workers";
}

static int RunModeSingle(void)
{
    SCEnter();
    TimeModeSetLive();
    int ret = RunModeSetLiveCaptureSingle(
            NULL, NULL, "ReceiveCiCapture", "DecodeCiCapture", thread_name_single, "fake0");
    if (ret != 0) {
        FatalError("RunModeSingle failed");
    }
    SCReturnInt(0);
}

static int RunModeWorkers(void)
{
    SCEnter();
    TimeModeSetLive();
    int ret = RunModeSetLiveCaptureWorkers(NULL, ThreadCountWorkers, "ReceiveCiCapture",
            "DecodeCiCapture", thread_name_workers, "fake0");
    if (ret != 0) {
        FatalError("RunModeWorkers failed");
    }
    SCReturnInt(0);
}

static int RunModeAutoFp(void)
{
    SCEnter();
    TimeModeSetLive();
    int ret = RunModeSetLiveCaptureAutoFp(NULL, ThreadCountAutoFp, "ReceiveCiCapture",
            "DecodeCiCapture", thread_name_workers, "fake0");
    if (ret != 0) {
        FatalError("RunModeAutoFp failed");
    }
    SCReturnInt(0);
}

void RegisterCaptureModes(int slot)
{
    LiveRegisterDevice("fake0");
    RunModeRegisterNewRunMode(slot, "single", "Single threaded", RunModeSingle, NULL);
    RunModeRegisterNewRunMode(slot, "workers", "Multi threaded", RunModeWorkers, NULL);
    RunModeRegisterNewRunMode(slot, "autofp", "AutoFP", RunModeAutoFp, NULL);
}
