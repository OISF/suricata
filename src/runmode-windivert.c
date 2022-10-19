/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 * Handling of WinDivert runmodes.
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-windivert.h"
#include "output.h"

#include "util-affinity.h"
#include "util-cpu.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-time.h"

const char *RunModeIpsWinDivertGetDefaultMode(void)
{
    return "autofp";
}

void RunModeIpsWinDivertRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_WINDIVERT, "autofp",
            "Multi-threaded WinDivert IPS mode load-balanced by flow", RunModeIpsWinDivertAutoFp,
            NULL);
}

int RunModeIpsWinDivertAutoFp(void)
{
    SCEnter();
    int ret = 0;
#ifdef WINDIVERT
    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSAutoFp(WinDivertGetThread, "ReceiveWinDivert",
                              "VerdictWinDivert", "DecodeWinDivert");
#endif /* WINDIVERT */
    return ret;
}
