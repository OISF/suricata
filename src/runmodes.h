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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __RUNMODES_H__
#define __RUNMODES_H__

/* Run mode */
enum {
    RUNMODE_UNKNOWN = 0,
    RUNMODE_PCAP_DEV,
    RUNMODE_PCAP_FILE,
    RUNMODE_PFRING,
    RUNMODE_NFQ,
    RUNMODE_IPFW,
    RUNMODE_ERF_FILE,
    RUNMODE_DAG,
    RUNMODE_AFP_DEV,
    RUNMODE_UNITTEST,
    RUNMODE_MAX,
};

char *RunmodeGetActive(void);

void RunModeListRunmodes(void);
void RunModeDispatch(int, const char *, DetectEngineCtx *);
void RunModeRegisterRunModes(void);
void RunModeRegisterNewRunMode(int, const char *, const char *,
                               int (*RunModeFunc)(DetectEngineCtx *));
void RunModeInitialize(void);
void RunModeInitializeOutputs(void);
void SetupOutputs(ThreadVars *);
void RunModeShutDown(void);

#include "runmode-pcap.h"
#include "runmode-pcap-file.h"
#include "runmode-pfring.h"
#include "runmode-nfq.h"
#include "runmode-ipfw.h"
#include "runmode-erf-file.h"
#include "runmode-erf-dag.h"
#include "runmode-af-packet.h"

int threading_set_cpu_affinity;
extern float threading_detect_ratio;

#endif /* __RUNMODES_H__ */
