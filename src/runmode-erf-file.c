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
#include "runmode-erf-file.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "util-runmodes.h"

const char *RunModeErfFileGetDefaultMode(void)
{
    return "autofp";
}

void RunModeErfFileRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_ERF_FILE, "single", "Single threaded ERF file mode",
            RunModeErfFileSingle, NULL);

    RunModeRegisterNewRunMode(RUNMODE_ERF_FILE, "autofp",
            "Multi threaded ERF file mode.  Packets from "
            "each flow are assigned to a single detect thread",
            RunModeErfFileAutoFp, NULL);
}

int RunModeErfFileSingle(void)
{
    const char *file;

    SCEnter();

    if (SCConfGet("erf-file.file", &file) == 0) {
        FatalError("Failed to get erf-file.file from config.");
    }

    TimeModeSetOffline();

    /* Basically the same setup as PCAP files. */

    ThreadVars *tv = TmThreadCreatePacketHandler(thread_name_single,
        "packetpool", "packetpool",
        "packetpool", "packetpool",
        "pktacqloop");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveErfFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveErfFile\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

    tm_module = TmModuleGetByName("DecodeErfFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeErfFile failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName for FlowWorker failed");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeErfFileSingle initialised");

    SCReturnInt(0);
}

int RunModeErfFileAutoFp(void)
{
    SCEnter();
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    uint16_t cpu = 0;
    char *queues = NULL;
    uint16_t thread;

    const char *file = NULL;
    if (SCConfGet("erf-file.file", &file) == 0) {
        FatalError("Failed retrieving erf-file.file from config");
    }

    TimeModeSetOffline();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;

    /* always create at least one thread */
    int thread_max = TmThreadGetNbThreads(WORKER_CPU_SET);
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;
    if (thread_max > 1024)
        thread_max = 1024;

    queues = RunmodeAutoFpCreatePickupQueuesString(thread_max);
    if (queues == NULL) {
        FatalError("RunmodeAutoFpCreatePickupQueuesString failed");
    }

    /* create the threads */
    ThreadVars *tv =
        TmThreadCreatePacketHandler(thread_name_autofp,
                                    "packetpool", "packetpool",
                                    queues, "flow",
                                    "pktacqloop");
    SCFree(queues);

    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveErfFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveErfFile\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

    tm_module = TmModuleGetByName("DecodeErfFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeErfFile failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    for (thread = 0; thread < (uint16_t)thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02d", thread_name_workers, thread + 1);
        snprintf(qname, sizeof(qname), "pickup%d", thread + 1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        SCLogDebug("Assigning %s affinity to cpu %u", tname, cpu);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError("TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_detect_ncpu, cpu);
            /* If we have more than one core/cpu, the first Detect thread
             * (at cpu 0) will have less priority (higher 'nice' value)
             * In this case we will set the thread priority to +10 (default is 0)
             */
            if (cpu == 0 && ncpus > 1) {
                TmThreadSetThreadPriority(tv_detect_ncpu, PRIO_LOW);
            } else if (ncpus > 1) {
                TmThreadSetThreadPriority(tv_detect_ncpu, PRIO_MEDIUM);
            }
        }

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    SCLogInfo("RunModeErfFileAutoFp initialised");

    SCReturnInt(0);
}
