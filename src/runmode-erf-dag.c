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
#include "runmode-erf-dag.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"

static int DagConfigGetThreadCount(void *conf)
{
    return 1;
}

static void *ParseDagConfig(const char *iface)
{
    return (void *)iface;
}

const char *RunModeErfDagGetDefaultMode(void)
{
    return "autofp";
}

void RunModeErfDagRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_DAG, "autofp",
        "Multi threaded DAG mode.  Packets from "
        "each flow are assigned to a single detect "
        "thread, unlike \"dag_auto\" where packets "
        "from the same flow can be processed by any "
        "detect thread",
        RunModeIdsErfDagAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_DAG, "single",
        "Singled threaded DAG mode",
        RunModeIdsErfDagSingle);

    RunModeRegisterNewRunMode(RUNMODE_DAG, "workers",
        "Workers DAG mode, each thread does all "
        " tasks from acquisition to logging",
        RunModeIdsErfDagWorkers);

    return;
}

int RunModeIdsErfDagSingle(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureSingle(ParseDagConfig,
        DagConfigGetThreadCount,
        "ReceiveErfDag",
        "DecodeErfDag",
        thread_name_single,
        NULL);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "DAG single runmode failed to start");
    }

    SCLogInfo("RunModeIdsDagSingle initialised");

    SCReturnInt(0);
}

int RunModeIdsErfDagAutoFp(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureAutoFp(ParseDagConfig, NULL, DagConfigGetThreadCount,
            "ReceiveErfDag", "DecodeErfDag", thread_name_autofp, NULL);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "DAG autofp runmode failed to start");
    }

    SCLogInfo("RunModeIdsDagAutoFp initialised");

    SCReturnInt(0);
}

int RunModeIdsErfDagWorkers(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureWorkers(ParseDagConfig, NULL, DagConfigGetThreadCount,
            "ReceiveErfDag", "DecodeErfDag", thread_name_workers, NULL);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "DAG workers runmode failed to start");
    }

    SCLogInfo("RunModeIdsErfDagWorkers initialised");

    SCReturnInt(0);
}
