/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 */
#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "source-nfq.h"
#include "runmodes.h"
#include "runmode-netfilter.h"
#include "runmode-nflog.h"
#include "runmode-nfq.h"

#include "util-debug.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-misc.h"

static const char *default_mode = NULL;

const char *RunModeNetfilterGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNetfilterRegister(void)
{
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NETFILTER, "autofp",
                              "Multi threaded netfilter mode",
                              RunModeNetfilterAutoFp);
    /* NFQ doesn't support single runmode */
    /*
    RunModeRegisterNewRunMode(RUNMODE_NETFILTER, "single",
                              "Single threaded netfilter mode",
                              RunModeNetfilterSingle);
    */
    RunModeRegisterNewRunMode(RUNMODE_NETFILTER, "workers",
                              "Workers netfilter mode",
                              RunModeNetfilterWorkers);
    return;
}

int RunModeNetfilterAutoFp(void)
{
    SCEnter();

#if defined(HAVE_NFLOG) || defined(NFQ)
    int ret = 0;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();
#endif
#ifdef HAVE_NFLOG
    ret = RunModeSetLiveCaptureAutoFp(ParseNflogConfig,
                                      NflogConfigGeThreadsCount,
                                      "ReceiveNFLOG",
                                      "DecodeNFLOG",
                                      "RecvNFLOG",
                                      live_dev, "nflog");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start nflog runmode");
        exit(EXIT_FAILURE);
    }
#endif /* HAVE_NFLOG */
#ifdef NFQ
    ret = RunModeSetIPSAutoFp(NFQGetThread,
                              "ReceiveNFQ",
                              "VerdictNFQ",
                              "DecodeNFQ",
                              "nfq");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start nfq runmode");
        exit(EXIT_FAILURE);
    }
#endif /* NFQ */
    SCLogInfo("RunModeNetfilterAutoFp initialised");

    SCReturnInt(0);
}

int RunModeNetfilterWorkers(void)
{
    SCEnter();

#if defined(HAVE_NFLOG) || defined(NFQ)
    int ret = 0;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();
#endif
#ifdef HAVE_NFLOG
    ret = RunModeSetLiveCaptureWorkers(ParseNflogConfig,
                                       NflogConfigGeThreadsCount,
                                       "ReceiveNFLOG",
                                       "DecodeNFLOG",
                                       "RecvNFLOG",
                                       live_dev, "nflog");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start nflog runmode");
        exit(EXIT_FAILURE);
    }
#endif /* HAVE_NFLOG */
#ifdef NFQ
    ret = RunModeSetIPSWorker(NFQGetThread,
                              "ReceiveNFQ",
                              "VerdictNFQ",
                              "DecodeNFQ",
                              "nfq");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start nfq runmode");
        exit(EXIT_FAILURE);
    }
#endif /* NFQ */
    SCLogInfo("RunModeNetfilterWorkers initialised");

    SCReturnInt(0);
}
