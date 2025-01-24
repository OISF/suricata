/* Copyright (C) 2007-2023 Open Information Security Foundation
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
#include "runmode-pcap-file.h"
#include "output.h"

#include "detect-engine.h"
#include "source-pcap-file.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "util-runmodes.h"

const char *RunModeFilePcapGetDefaultMode(void)
{
    return "autofp";
}

void RunModeFilePcapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "single", "Single threaded pcap file mode",
            RunModeFilePcapSingle, NULL);
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "autofp",
            "Multi-threaded pcap file mode. Packets from each flow are assigned to a consistent "
            "detection thread",
            RunModeFilePcapAutoFp, NULL);
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcapSingle(void)
{
    const char *file = NULL;
    char tname[TM_THREAD_NAME_MAX];

    if (ConfGet("pcap-file.file", &file) == 0) {
        FatalError("Failed retrieving pcap-file from Conf");
    }

    TimeModeSetOffline();

    PcapFileGlobalInit();

    snprintf(tname, sizeof(tname), "%s#01", thread_name_single);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        FatalError("threading setup failed");
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceivePcap");
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

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

/**
 * \brief RunModeFilePcapAutoFp set up the following thread packet handlers:
 *        - Receive thread (from pcap file)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu.
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeFilePcapAutoFp(void)
{
    SCEnter();
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    uint16_t cpu = 0;
    char *queues = NULL;
    uint16_t thread;

    const char *file = NULL;
    if (ConfGet("pcap-file.file", &file) == 0) {
        FatalError("Failed retrieving pcap-file from Conf");
    }
    SCLogDebug("file %s", file);

    TimeModeSetOffline();

    PcapFileGlobalInit();

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

    snprintf(tname, sizeof(tname), "%s#01", thread_name_autofp);

    /* create the threads */
    ThreadVars *tv_receivepcap =
        TmThreadCreatePacketHandler(tname,
                                    "packetpool", "packetpool",
                                    queues, "flow",
                                    "pktacqloop");
    SCFree(queues);

    if (tv_receivepcap == NULL) {
        FatalError("threading setup failed");
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceivePcap");
    }
    TmSlotSetFuncAppend(tv_receivepcap, tm_module, file);

    TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        FatalError("TmThreadSpawn failed");
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
            FatalError("TmThreadsCreate failed");
        }

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError("TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            FatalError("TmThreadSpawn failed");
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    return 0;
}
