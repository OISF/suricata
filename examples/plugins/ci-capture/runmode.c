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

#include "runmode.h"

const char *CiCaptureIdsGetDefaultRunMode(void)
{
    return "autofp";
}

static int RunModeSingle(void)
{
    SCLogNotice("...");

    char thread_name[TM_THREAD_NAME_MAX];
    snprintf(thread_name, sizeof(thread_name), "%s#01", thread_name_single);
    ThreadVars *tv = TmThreadCreatePacketHandler(
            thread_name, "packetpool", "packetpool", "packetpool", "packetpool", "pktacqloop");
    if (tv == NULL) {
        SCLogError("TmThreadCreatePacketHandler failed");
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveCiCapture");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceiveCiCapture");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("DecodeCiCapture");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName DecodeCiCapture failed");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName for FlowWorker failed");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        FatalError("TmThreadSpawn failed");
    }

    return 0;
}

void CiCaptureIdsRegister(int slot)
{
    RunModeRegisterNewRunMode(slot, "single", "Single threaded", RunModeSingle, NULL);
}
