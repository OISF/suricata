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

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * Handling of ipfw runmodes.
 */



#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-ipfw.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "source-ipfw.h"
#include "util-device.h"

const char *RunModeIpsIPFWGetDefaultMode(void)
{
    return "autofp";
}

void RunModeIpsIPFWRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_IPFW, "autofp",
                              "Multi threaded IPFW IPS mode with respect to flow",
                              RunModeIpsIPFWAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_IPFW, "workers",
                              "Multi queue IPFW IPS mode with one thread per queue",
                              RunModeIpsIPFWWorker);

    return;
}

int RunModeIpsIPFWAutoFp(void)
{
    SCEnter();
    int ret = 0;
#ifdef IPFW

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSAutoFp(IPFWGetThread,
            "ReceiveIPFW",
            "VerdictIPFW",
            "DecodeIPFW");
#endif /* IPFW */
    return ret;
}

int RunModeIpsIPFWWorker(void)
{
    SCEnter();
    int ret = 0;
#ifdef IPFW

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSWorker(IPFWGetThread,
            "ReceiveIPFW",
            "VerdictIPFW",
            "DecodeIPFW");
#endif /* IPFW */
    return ret;
}
