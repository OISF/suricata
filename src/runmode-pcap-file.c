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
#include "runmode-pcap-file.h"
#include "output.h"

#include "detect-engine.h"
#include "source-pcap-file.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "util-runmodes.h"

static const char *default_mode = NULL;

const char *RunModeFilePcapGetDefaultMode(void)
{
    return default_mode;
}

void RunModeFilePcapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "single",
                              "Single threaded pcap file mode",
                              RunModeFilePcapSingle);
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "autofp",
                              "Multi threaded pcap file mode.  Packets from "
                              "each flow are assigned to a single detect thread, "
                              "unlike \"pcap-file-auto\" where packets from "
                              "the same flow can be processed by any detect "
                              "thread",
                              RunModeFilePcapAutoFp);

    return;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcapSingle(void)
{
    const char *file = NULL;
    char tname[TM_THREAD_NAME_MAX];

    if (ConfGet("pcap-file.file", &file) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving pcap-file from Conf");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();
    TimeModeSetOffline();

    PcapFileGlobalInit();

    snprintf(tname, sizeof(tname), "%s#01", thread_name_single);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        SCLogError(SC_ERR_RUNMODE, "threading setup failed");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName failed for ReceivePcap");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName DecodePcap failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

#ifndef AFLFUZZ_PCAP_RUNMODE
    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }
#else
    /* in afl mode we don't spawn a new thread, but run the pipeline
     * in the main thread */
    tv->tm_func(tv);
    int afl_runmode_exit_immediately = 0;
    (void)ConfGetBool("afl.exit_after_pcap", &afl_runmode_exit_immediately);
    if (afl_runmode_exit_immediately) {
        SCLogNotice("exit because of afl-runmode-exit-after-pcap commandline option");
        exit(EXIT_SUCCESS);
    }
#endif

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

    RunModeInitialize();

    const char *file = NULL;
    if (ConfGet("pcap-file.file", &file) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving pcap-file from Conf");
        exit(EXIT_FAILURE);
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
        SCLogError(SC_ERR_RUNMODE, "RunmodeAutoFpCreatePickupQueuesString failed");
        exit(EXIT_FAILURE);
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
        SCLogError(SC_ERR_FATAL, "threading setup failed");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName failed for ReceivePcap");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receivepcap, tm_module, file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName DecodePcap failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receivepcap, tm_module, NULL);

    TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    for (thread = 0; thread < (uint16_t)thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02u", thread_name_workers, thread+1);
        snprintf(qname, sizeof(qname), "pickup%u", thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);
        SCLogDebug("Assigning %s affinity to cpu %u", tname, cpu);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    return 0;
}
