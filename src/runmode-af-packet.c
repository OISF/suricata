/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * AF_PACKET socket runmode
 *
 */


#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-af-packet.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "detect-engine-mpm.h"

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
#include "util-device.h"

#include "source-af-packet.h"

static const char *default_mode_auto = NULL;
static const char *default_mode_autofp = NULL;

const char *RunModeAFPGetDefaultMode(void)
{
    return default_mode_autofp;
}

void RunModeIdsAFPRegister(void)
{
    default_mode_auto = "auto";
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "auto",
                              "Multi threaded af-packet mode",
                              RunModeIdsAFPAuto);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
                              "Single threaded af-packet mode",
                              RunModeIdsAFPSingle);
    default_mode_autofp = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "autofp",
                              "Multi socket AF_PACKET mode.  Packets from "
                              "each flow are assigned to a single detect "
                              "thread.",
                              RunModeIdsAFPAutoFp);
    return;
}

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * \return a AFPIfaceConfig corresponding to the interface name
 */
AFPIfaceConfig *ParseAFPConfig(char *iface)
{
    char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *af_packet_node;
    AFPIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *tmpclusterid;
    char *tmpctype;
    intmax_t value;
    int dispromisc;

    if (aconf == NULL) {
        return NULL;
    }
    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->threads = 1;
    aconf->buffer_size = 0;
    aconf->cluster_id = 1;
    aconf->cluster_type = PACKET_FANOUT_HASH;
    aconf->promisc = 1;

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        SCLogInfo("Unable to find af-packet config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(af_packet_node, "interface", iface);
    if (if_root == NULL) {
        SCLogInfo("Unable to find af-packet config for "
                  "interface %s, using default value",
                  iface);
        return aconf;
    }

    if (ConfGetChildValue(if_root, "threads", &threadsstr) != 1) {
        aconf->threads = 1;
    } else {
        if (threadsstr != NULL) {
            aconf->threads = (uint8_t)atoi(threadsstr);
        }
    }
    if (aconf->threads == 0) {
        aconf->threads = 1;
    }
    if (ConfGetChildValue(if_root, "cluster-id", &tmpclusterid) != 1) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Could not get cluster-id from config");
    } else {
        aconf->cluster_id = (uint16_t)atoi(tmpclusterid);
        SCLogDebug("Going to use cluster-id %" PRId32, aconf->cluster_id);
    }

    if (ConfGetChildValue(if_root, "cluster-type", &tmpctype) != 1) {
        SCLogError(SC_ERR_GET_CLUSTER_TYPE_FAILED,"Could not get cluster-type fron config");
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogInfo("Using round-robin cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_LB;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        /* In hash mode, we also ask for defragmentation needed to
         * compute the hash */
        uint16_t defrag = 0;
        SCLogInfo("Using flow cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        ConfGetChildValueBool(if_root, "defrag", (int *)&defrag);
        if (defrag) {
            SCLogInfo("Using defrag kernel functionnality for AF_PACKET (iface %s)",
                    aconf->iface);
            defrag = PACKET_FANOUT_FLAG_DEFRAG;
        }
        aconf->cluster_type = PACKET_FANOUT_HASH | defrag;
    } else if (strcmp(tmpctype, "cluster_cpu") == 0) {
        SCLogInfo("Using cpu cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_CPU;
    } else {
        SCLogError(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
        return NULL;
    }

    if ((ConfGetChildValueInt(if_root, "buffer-size", &value)) == 1) {
        aconf->buffer_size = value;
    } else {
        aconf->buffer_size = 0;
    }

    ConfGetChildValueBool(if_root, "disable-promisc", (int *)&dispromisc);
    if (dispromisc) {
        SCLogInfo("Disabling promiscuous mode on iface %s",
                aconf->iface);
        aconf->promisc = 0;
    }

    return aconf;
}


/**
 * \brief RunModeIdsAFPAuto set up the following thread packet handlers:
 *        - Receive thread (from live iface)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu.
 *
 * \param de_ctx Pointer to the Detection Engine.
 *
 * \retval 0 If all goes well. (If any problem is detected the engine will
 *           exit()).
 */
int RunModeIdsAFPAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();

#ifdef HAVE_AF_PACKET
    /* tname = Detect + cpuid, this is 11bytes length as max */
    char tname[16];
    uint16_t cpu = 0;
    TmModule *tm_module;
    uint16_t thread;

    RunModeInitialize();
    TimeModeSetLive();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();

    if (nlive == 1) {
        char *live_dev = NULL;
        AFPIfaceConfig *aconf;
        /* TODO be clever than that */
        if (ConfGet("af-packet.live-interface", &live_dev) == 0) {
            SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                       "interface from command line");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("live_dev %s", live_dev);

        if (live_dev == NULL) {
            printf("Failed to lookup live dev\n");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("live_dev %s", live_dev);

        aconf = ParseAFPConfig(live_dev);
        if (aconf == NULL) {
            printf("Failed to allocate config\n");
            exit(EXIT_FAILURE);
        }

        /* create the threads */
        ThreadVars *tv_receiveafp =
            TmThreadCreatePacketHandler("ReceiveAFP",
                                        "packetpool", "packetpool",
                                        "pickup-queue", "simple",
                                        "pktacqloop");
        if (tv_receiveafp == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceiveAFP");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceiveAFP\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receiveafp, tm_module, (void *)aconf);

        TmThreadSetCPU(tv_receiveafp, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receiveafp) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Using %d live device(s).", nlive);

        for (thread = 0; thread < nlive; thread++) {
            char *live_dev = LiveGetDevice(thread);
            char *tnamec = NULL;
            AFPIfaceConfig *aconf;

            if (live_dev == NULL) {
                printf("Failed to lookup live dev %d\n", thread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("live_dev %s", live_dev);

            aconf = ParseAFPConfig(live_dev);
            if (aconf == NULL) {
                printf("Failed to allocate config %d\n", thread);
                exit(EXIT_FAILURE);
            }

            snprintf(tname, sizeof(tname),"RecvAFP-%s", live_dev);
            tnamec = SCStrdup(tname);

            /* create the threads */
            ThreadVars *tv_receiveafp =
                TmThreadCreatePacketHandler(tnamec,
                                            "packetpool", "packetpool",
                                            "pickup-queue", "simple",
                                            "pktacqloop");
            if (tv_receiveafp == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("ReceiveAFP");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName failed for ReceiveAFP\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receiveafp, tm_module, (void *)aconf);

            TmThreadSetCPU(tv_receiveafp, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receiveafp) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }
    }

#if defined(__SC_CUDA_SUPPORT__)
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        ThreadVars *tv_decode1 =
            TmThreadCreatePacketHandler("Decode",
                                        "pickup-queue", "simple",
                                        "decode-queue1", "simple",
                                        "1slot");
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadsCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodeAFP");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_decode1, tm_module, NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_cuda_PB =
            TmThreadCreate("CUDA_PB",
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

        ThreadVars *tv_stream1 =
            TmThreadCreatePacketHandler("Stream1",
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
        Tm1SlotSetFunc(tv_stream1, tm_module, NULL);

        TmThreadSetCPU(tv_stream1, STREAM_CPU_SET);

        if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ThreadVars *tv_decode1 =
            TmThreadCreatePacketHandler("Decode & Stream",
                                        "pickup-queue", "simple",
                                        "stream-queue1", "simple",
                                        "varslot");
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadsCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodeAFP");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
            exit(EXIT_FAILURE);
        }
        TmVarSlotSetFuncAppend(tv_decode1, tm_module, NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmVarSlotSetFuncAppend(tv_decode1, tm_module, NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }

#else
    ThreadVars *tv_decode1 =
        TmThreadCreatePacketHandler("Decode & Stream",
                                    "pickup-queue", "simple",
                                    "stream-queue1", "simple",
                                    "varslot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodeAFP");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

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

        char *thread_name = SCStrdup(tname);
        SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        "stream-queue1", "simple",
                                        "verdict-queue", "simple",
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

    ThreadVars *tv_rreject =
        TmThreadCreatePacketHandler("RespondReject",
                                    "verdict-queue", "simple",
                                    "alert-queue", "simple",
                                    "1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_rreject, tm_module, NULL);

    TmThreadSetCPU(tv_rreject, REJECT_CPU_SET);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs =
        TmThreadCreatePacketHandler("Outputs",
                                    "alert-queue", "simple",
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

#endif
    SCReturnInt(0);
}

int RunModeIdsAFPAutoFp(DetectEngineCtx *de_ctx)
{
    SCEnter();

/* We include only if AF_PACKET is enabled */
#ifdef HAVE_AF_PACKET

    char tname[12];
    char qname[12];
    char queues[2048] = "";
    int thread;
    char *live_dev = NULL;
    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    /* always create at least one thread */
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    RunModeInitialize();

    TimeModeSetLive();

    for (thread = 0; thread < thread_max; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", sizeof(queues));

        snprintf(qname, sizeof(qname),"pickup%"PRIu16, thread+1);
        strlcat(queues, qname, sizeof(queues));
    }
    SCLogDebug("queues %s", queues);

    if (nlive == 1) {
        AFPIfaceConfig *aconf;
        int afp_thread;

        if (ConfGet("af-packet.live-interface", &live_dev) == 0) {
            SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                    "interface from command line");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("live_dev %s", live_dev);

        aconf = ParseAFPConfig(live_dev);
        if (aconf == NULL) {
            printf("Failed to allocate config %d\n", thread);
            exit(EXIT_FAILURE);
        }

        SCLogInfo("Going to use %" PRId32 " AF_PACKET receive thread(s)",
                aconf->threads);
        /* create the threads */
        for (afp_thread = 0; afp_thread < aconf->threads; afp_thread++) {
            snprintf(tname, sizeof(tname), "RxAFP%"PRIu16, afp_thread+1);
            char *thread_name = SCStrdup(tname);

            ThreadVars *tv_receive =
                TmThreadCreatePacketHandler(thread_name,
                        "packetpool", "packetpool",
                        queues, "flow", "pktacqloop");
            if (tv_receive == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            TmModule *tm_module = TmModuleGetByName("ReceiveAFP");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName failed for ReceiveAFP\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

            tm_module = TmModuleGetByName("DecodeAFP");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

            TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }
    } else { /* Multiple input device */
        SCLogInfo("Using %d live device(s).", nlive);
        int lthread;

        for (lthread = 0; lthread < nlive; lthread++) {
            char *live_dev = LiveGetDevice(lthread);
            AFPIfaceConfig *aconf;

            if (live_dev == NULL) {
                printf("Failed to lookup live dev %d\n", lthread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("live_dev %s", live_dev);

            aconf = ParseAFPConfig(live_dev);
            if (aconf == NULL) {
                printf("Failed to allocate config %d\n", lthread);
                exit(EXIT_FAILURE);
            }

            for (thread = 0; thread < aconf->threads; thread++) {
                snprintf(tname, sizeof(tname), "RxAFP%s%"PRIu16, live_dev, thread+1);
                char *thread_name = SCStrdup(tname);

                ThreadVars *tv_receive =
                    TmThreadCreatePacketHandler(thread_name,
                            "packetpool", "packetpool",
                            queues, "flow", "pktacqloop");
                if (tv_receive == NULL) {
                    printf("ERROR: TmThreadsCreate failed\n");
                    exit(EXIT_FAILURE);
                }
                TmModule *tm_module = TmModuleGetByName("ReceiveAFP");
                if (tm_module == NULL) {
                    printf("ERROR: TmModuleGetByName failed for ReceiveAFP\n");
                    exit(EXIT_FAILURE);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

                tm_module = TmModuleGetByName("DecodeAFP");
                if (tm_module == NULL) {
                    printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
                    exit(EXIT_FAILURE);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

                TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

                if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                    printf("ERROR: TmThreadSpawn failed\n");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "Detect%"PRIu16, thread+1);
        snprintf(qname, sizeof(qname), "pickup%"PRIu16, thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        char *thread_name = SCStrdup(tname);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("StreamTcp");
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

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        char *thread_group_name = SCStrdup("Detect");
        if (thread_group_name == NULL) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        /* add outputs as well */
        SetupOutputs(tv_detect_ncpu);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }

#endif /* HAVE_AF_PACKET */

    SCReturnInt(0);
}

/**
 * \brief Single thread version of the AF_PACKET processing.
 */
int RunModeIdsAFPSingle(DetectEngineCtx *de_ctx)
{
    int nafp = LiveGetDeviceCount();
    char *afp_dev = NULL;
    char *afp_devc = NULL;

    SCEnter();
#ifdef HAVE_AF_PACKET

    if (nafp > 1) {
        SCLogError(SC_ERR_RUNMODE,
                   "Can't use single runmode with multiple device");
        exit(EXIT_FAILURE);
    }

    RunModeInitialize();
    TimeModeSetLive();

    if (ConfGet("af-packet.live-interface", &afp_dev) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                "interface from command line");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("afp_dev %s", afp_dev);
    afp_devc = SCStrdup(afp_dev);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler("AFPacket",
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveAFP");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveAFP\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, afp_devc);

    tm_module = TmModuleGetByName("DecodeAFP");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeAFP failed\n");
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

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}
