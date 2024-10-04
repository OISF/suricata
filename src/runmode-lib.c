/* Copyright (C) 2023-2024 Open Information Security Foundation
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
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  Library runmode.
 */
#include "suricata-common.h"
#include "runmode-lib.h"
#include "runmodes.h"
#include "tm-threads.h"

/** \brief register runmodes for suricata as a library */
void SCRunModeLibIdsRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_LIB, "offline", "Library offline mode (pcap replaying)",
            SCRunModeLibIdsOffline, NULL);
    RunModeRegisterNewRunMode(RUNMODE_LIB, "live", "Library live mode", SCRunModeLibIdsLive, NULL);
    return;
}

/** \brief runmode for offline packet processing (pcap files) */
int SCRunModeLibIdsOffline(void)
{
    TimeModeSetOffline();

    return 0;
}

/** \brief runmode for live packet processing */
int SCRunModeLibIdsLive(void)
{
    TimeModeSetLive();

    return 0;
}

const char *SCRunModeLibGetDefaultMode(void)
{
    return "live";
}

ThreadVars *SCRunModeLibCreateThreadVars(int worker_id)
{
    char tname[TM_THREAD_NAME_MAX];
    TmModule *tm_module = NULL;
    snprintf(tname, sizeof(tname), "%s#%02d", thread_name_workers, worker_id);

    ThreadVars *tv = TmThreadCreatePacketHandler(
            tname, "packetpool", "packetpool", "packetpool", "packetpool", "lib");
    if (tv == NULL) {
        SCLogError("TmThreadsCreate failed");
        return NULL;
    }

    tm_module = TmModuleGetByName("DecodeLib");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName DecodeLib failed");
        return NULL;
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName for FlowWorker failed");
        return NULL;
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadAppend(tv, tv->type);

    return tv;
}

/** \brief start the "fake" worker.
 *
 *  This method performs all the initialization tasks.
 */
int SCRunModeLibSpawnWorker(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;

    if (TmThreadLibSpawn(tv) != TM_ECODE_OK) {
        SCLogError("TmThreadLibSpawn failed");
        return -1;
    }

    TmThreadsSetFlag(tv, THV_RUNNING);
    return 0;
}
