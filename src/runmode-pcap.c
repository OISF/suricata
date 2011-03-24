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
#include "runmode-pcap.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "source-pfring.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"


/**
 * \brief RunModeIdsPcapAuto set up the following thread packet handlers:
 *        - Receive thread (from iface pcap)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu
 *
 * \param de_ctx pointer to the Detection Engine
 * \param iface pointer to the name of the interface from which we will
 *              fetch the packets
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
int RunModeIdsPcapAuto(DetectEngineCtx *de_ctx, char *iface) {
    SCEnter();
    /* tname = Detect + cpuid, this is 11bytes length as max */
    char tname[16];
    uint16_t cpu = 0;
    TmModule *tm_module;
    uint16_t thread;

    RunModeInitialize();
    TimeModeSetLive();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int npcap = PcapLiveGetDeviceCount();

    if (npcap == 1) {
        /* create the threads */
        ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler("ReceivePcap","packetpool","packetpool","pickup-queue","simple","1slot");
        if (tv_receivepcap == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceivePcap");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)iface);

        TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Using %d pcap device(s).", npcap);

        for (thread = 0; thread < npcap; thread++) {
            char *pcap_dev = PcapLiveGetDevice(thread);
            if (pcap_dev == NULL) {
                printf("Failed to lookup pcap dev %d\n", thread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("pcap_dev %s", pcap_dev);

            snprintf(tname, sizeof(tname),"RecvPcap-%s", pcap_dev);
            char *tnamec = SCStrdup(tname);
            char *pcap_devc = SCStrdup(pcap_dev);

            /* create the threads */
            ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler(tnamec,"packetpool","packetpool","pickup-queue","simple","1slot");
            if (tv_receivepcap == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("ReceivePcap");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
                exit(EXIT_FAILURE);
            }
            Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)pcap_devc);

            TmThreadSetCPU(tv_receivepcap, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }
    }

#if defined(__SC_CUDA_SUPPORT__)
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode",
                                                             "pickup-queue", "simple",
                                                             "decode-queue1", "simple",
                                                             "1slot");
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadsCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodePcap");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodePcap failed\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_decode1, tm_module, NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_cuda_PB = TmThreadCreate("CUDA_PB",
                                                "decode-queue1", "simple",
                                                "cuda-pb-queue1", "simple",
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
        Tm1SlotSetFunc(tv_cuda_PB, tm_module, (void *)de_ctx);


        TmThreadSetCPU(tv_cuda_PB, DETECT_CPU_SET);

        if (TmThreadSpawn(tv_cuda_PB) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1",
                                                             "cuda-pb-queue1", "simple",
                                                             "stream-queue1", "simple",
                                                             "1slot");
        if (tv_stream1 == NULL) {
            printf("ERROR: TmThreadsCreate failed for Stream1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

        TmThreadSetCPU(tv_stream1, STREAM_CPU_SET);

        if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode & Stream",
                                                             "pickup-queue", "simple",
                                                             "stream-queue1", "simple",
                                                             "varslot");
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadsCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodePcap");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodePcap failed\n");
            exit(EXIT_FAILURE);
        }
        TmVarSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmVarSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }
#else
//#if 0
    //ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode & Stream","pickup-queue","simple","packetpool","packetpool","varslot");
    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode & Stream","pickup-queue","simple","stream-queue1","simple","varslot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_decode1,tm_module,NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_decode1,tm_module,NULL);

    TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
#endif
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

    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname),"Detect%"PRIu16, thread+1);
        if (tname == NULL)
            break;

        char *thread_name = SCStrdup(tname);
        SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

        ThreadVars *tv_detect_ncpu = TmThreadCreatePacketHandler(thread_name,"stream-queue1","simple","verdict-queue","simple","1slot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_detect_ncpu,tm_module,(void *)de_ctx);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        char *thread_group_name = SCStrdup("Detect");
        if (thread_group_name == NULL) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    TmThreadSetCPU(tv_rreject, REJECT_CPU_SET);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);

    TmThreadSetCPU(tv_outputs, OUTPUT_CPU_SET);

    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
