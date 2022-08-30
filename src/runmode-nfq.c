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
 * Handling of NFQ runmodes.
 */


#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-nfq.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"

const char *RunModeIpsNFQGetDefaultMode(void)
{
    return "autofp";
}

void RunModeIpsNFQRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_NFQ, "autofp",
                              "Multi threaded NFQ IPS mode with respect to flow",
                              RunModeIpsNFQAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_NFQ, "workers",
                              "Multi queue NFQ IPS mode with one thread per queue",
                              RunModeIpsNFQWorker);
    return;
}

int RunModeIpsNFQAutoFp(void)
{
    SCEnter();
    int ret = 0;
#ifdef NFQ

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSAutoFp(NFQGetThread,
            "ReceiveNFQ",
            "VerdictNFQ",
            "DecodeNFQ");
#endif /* NFQ */
    return ret;
}

int RunModeIpsNFQWorker(void)
{
    SCEnter();
    int ret = 0;
#ifdef NFQ

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSWorker(NFQGetThread,
            "ReceiveNFQ",
            "VerdictNFQ",
            "DecodeNFQ");
#endif /* NFQ */
    return ret;
}
