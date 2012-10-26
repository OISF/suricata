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
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "source-pfring.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

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
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "auto",
                              "Multi threaded pcap file mode",
                              RunModeFilePcapAuto);
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
int RunModeFilePcapSingle(DetectEngineCtx *de_ctx)
{
    char *file = NULL;
    if (ConfGet("pcap-file.file", &file) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving pcap-file from Conf");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();
    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler("PcapFile",
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, (void *)de_ctx);

    SetupOutputs(tv);

    TmThreadSetCPU(tv, DETECT_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/*
 * \brief RunModeFilePcapAuto set up the following thread packet handlers:
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
 * \param de_ctx Pointer to the Detection Engine.
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeFilePcapAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();
    char tname[16];
    uint16_t cpu = 0;
    TmModule *tm_module;
    int cuda = 0;
    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    char *file = NULL;
    if (ConfGet("pcap-file.file", &file) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving pcap-file from Conf");
        exit(EXIT_FAILURE);
    }
    SCLogDebug("file %s", file);

    TimeModeSetOffline();

#if defined(__SC_CUDA_SUPPORT__)
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        cuda = 1;
    }
#endif

    if (cuda == 0) {
        /* create the threads */
        ThreadVars *tv_receivepcap =
            TmThreadCreatePacketHandler("ReceivePcapFile",
                    "packetpool", "packetpool",
                    "detect-queue1", "simple",
                    "pktacqloop");
        if (tv_receivepcap == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceivePcapFile");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivepcap, tm_module, file);

        tm_module = TmModuleGetByName("DecodePcapFile");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodePcap failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivepcap, tm_module, NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivepcap, tm_module, (void *)de_ctx);

        TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
#if defined(__SC_CUDA_SUPPORT__)
    } else {
        /* create the threads */
        ThreadVars *tv_receivepcap =
            TmThreadCreatePacketHandler("ReceivePcapFile",
                                        "packetpool", "packetpool",
                                        "cuda-pb", "simple",
                                        "pktacqloop");
        if (tv_receivepcap == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceivePcapFile");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivepcap, tm_module, file);

        TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

        tm_module = TmModuleGetByName("DecodePcapFile");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodePcap failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivepcap, tm_module, NULL);

        TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_cuda_PB =
            TmThreadCreate("CUDA_PB",
                           "cuda-pb", "simple",
                           "detect-queue1", "simple",
                           "custom", SCCudaPBTmThreadsSlot1, 0);
        if (tv_cuda_PB == NULL) {
            printf("ERROR: TmThreadsCreate failed for CUDA_PB\n");
            exit(EXIT_FAILURE);
        }
        tv_cuda_PB->type = TVT_PPT;

        tm_module = TmModuleGetByName("CudaPacketBatcher");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName CudaPacketBatcher failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_cuda_PB, tm_module, de_ctx);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_cuda_PB, tm_module, NULL);

        if (TmThreadSpawn(tv_cuda_PB) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

#endif
    }

    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;

    /* always create at least one thread */
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    int thread;
    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "Detect%"PRIu16, thread+1);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: Can not strdup thread name\n");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        "detect-queue1", "simple",
                                        "alert-queue1", "simple",
                                        "1slot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, (void *)de_ctx);

        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    ThreadVars *tv_outputs =
        TmThreadCreatePacketHandler("Outputs",
                                    "alert-queue1", "simple",
                                    "packetpool", "packetpool",
                                    "varslot");
    if (tv_outputs == NULL) {
        printf("ERROR: TmThreadCreatePacketHandler for Outputs failed\n");
        exit(EXIT_FAILURE);
    }

    SetupOutputs(tv_outputs);

    TmThreadSetCPU(tv_outputs, OUTPUT_CPU_SET);

    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
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
 * \param de_ctx Pointer to the Detection Engine
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeFilePcapAutoFp(DetectEngineCtx *de_ctx)
{
    SCEnter();
    char tname[12];
    char qname[12];
    uint16_t cpu = 0;
    char queues[2048] = "";

    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;

    /* always create at least one thread */
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    int thread;
    for (thread = 0; thread < thread_max; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", sizeof(queues));

        snprintf(qname, sizeof(qname), "pickup%"PRIu16, thread+1);
        strlcat(queues, qname, sizeof(queues));
    }
    SCLogDebug("queues %s", queues);

    char *file = NULL;
    if (ConfGet("pcap-file.file", &file) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving pcap-file from Conf");
        exit(EXIT_FAILURE);
    }
    SCLogDebug("file %s", file);

    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv_receivepcap =
        TmThreadCreatePacketHandler("ReceivePcapFile",
                                    "packetpool", "packetpool",
                                    queues, "flow",
                                    "pktacqloop");
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receivepcap, tm_module, file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receivepcap, tm_module, NULL);

    TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "Detect%"PRIu16, thread+1);
        snprintf(qname, sizeof(qname), "pickup%"PRIu16, thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: Can not strdup thread name\n");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, (void *)de_ctx);


        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        /* add outputs as well */
        SetupOutputs(tv_detect_ncpu);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    return 0;
}
