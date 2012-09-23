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
 * Helper function for runmode.
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
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"

#include "util-runmodes.h"

int RunModeSetLiveCaptureAuto(DetectEngineCtx *de_ctx,
                              ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev)
{
    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();
    TmModule *tm_module;
    char tname[16];
    int thread;

    if ((nlive <= 1) && (live_dev != NULL)) {
        void *aconf;
        SCLogDebug("live_dev %s", live_dev);

        aconf = ConfigParser(live_dev);
        if (aconf == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Single dev: Failed to allocate config");
            exit(EXIT_FAILURE);
        }

        if (ModThreadsCount(aconf) > 1) {
            SCLogWarning(SC_ERR_UNIMPLEMENTED, "'Auto' running mode does not honor 'threads'"
                         " variable (set on '%s'). Please use another mode as"
                         " 'autofp' or 'worker'",
                         live_dev);
        }

        /* create the threads */
        ThreadVars *tv_receive =
            TmThreadCreatePacketHandler(recv_mod_name,
                    "packetpool", "packetpool",
                    "pickup-queue", "simple",
                    "pktacqloop");
        if (tv_receive == NULL) {
            SCLogError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

        TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Using %d live device(s).", nlive);

        for (thread = 0; thread < nlive; thread++) {
            char *live_dev = LiveGetDeviceName(thread);
            char *tnamec = NULL;
            void *aconf;

            if (live_dev == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Multidev: Failed to lookup live dev %d", thread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("live_dev %s", live_dev);

            aconf = ConfigParser(live_dev);
            if (aconf == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate config for %s (%d)",
                       live_dev, thread);
                exit(EXIT_FAILURE);
            }

            if (ModThreadsCount(aconf) > 1) {
                SCLogWarning(SC_ERR_UNIMPLEMENTED, "'Auto' running mode does not honor 'threads'"
                         " variable (set on '%s'). Please use another mode as"
                         " 'autofp' or 'worker'",
                         live_dev);
            }

            snprintf(tname, sizeof(tname),"%s-%s", thread_name, live_dev);
            tnamec = SCStrdup(tname);
            if (unlikely(tnamec == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
                exit(EXIT_FAILURE);
            }

            /* create the threads */
            ThreadVars *tv_receive =
                TmThreadCreatePacketHandler(tnamec,
                        "packetpool", "packetpool",
                        "pickup-queue", "simple",
                        "pktacqloop");
            if (tv_receive == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName(recv_mod_name);
            if (tm_module == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, (void *)aconf);

            TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                SCLogError(SC_ERR_INVALID_VALUE, "TmThreadSpawn failed");
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
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed for Decode1");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_cuda_PB =
            TmThreadCreate("CUDA_PB",
                    "decode-queue1", "simple",
                    "cuda-pb-queue1", "simple",
                    "custom", SCCudaPBTmThreadsSlot1, 0);
        if (tv_cuda_PB == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed for CUDA_PB");
            exit(EXIT_FAILURE);
        }
        tv_cuda_PB->type = TVT_PPT;

        tm_module = TmModuleGetByName("CudaPacketBatcher");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName CudaPacketBatcher failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_cuda_PB, tm_module, (void *)de_ctx);

        TmThreadSetCPU(tv_cuda_PB, DETECT_CPU_SET);

        if (TmThreadSpawn(tv_cuda_PB) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_stream1 =
            TmThreadCreatePacketHandler("Stream1",
                    "cuda-pb-queue1", "simple",
                    "stream-queue1", "simple",
                    "1slot");
        if (tv_stream1 == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed for Stream1");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_stream1, tm_module, NULL);

        TmThreadSetCPU(tv_stream1, STREAM_CPU_SET);

        if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    } else {
        ThreadVars *tv_decode1 =
            TmThreadCreatePacketHandler("Decode & Stream",
                    "pickup-queue", "simple",
                    "stream-queue1", "simple",
                    "varslot");
        if (tv_decode1 == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed for Decode1");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

        TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
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
        SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed for Decode1");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName(decode_mod_name);
    if (tm_module == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

    TmThreadSetCPU(tv_decode1, DECODE_CPU_SET);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }
#endif

    /* always create at least one thread */
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname),"Detect%"PRIu16, thread+1);

        char *thread_name = SCStrdup(tname);

        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                    "stream-queue1", "simple",
                    "verdict-queue", "simple",
                    "1slot");
        if (tv_detect_ncpu == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppendDelayed(tv_detect_ncpu, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    ThreadVars *tv_rreject =
        TmThreadCreatePacketHandler("RespondReject",
                "verdict-queue", "simple",
                "alert-queue", "simple",
                "1slot");
    if (tv_rreject == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_rreject, tm_module, NULL);

    TmThreadSetCPU(tv_rreject, REJECT_CPU_SET);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs =
        TmThreadCreatePacketHandler("Outputs",
                "alert-queue", "simple",
                "packetpool", "packetpool",
                "varslot");
    if (tv_outputs == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadCreatePacketHandler for Outputs failed");
        exit(EXIT_FAILURE);
    }

    SetupOutputs(tv_outputs);

    TmThreadSetCPU(tv_outputs, OUTPUT_CPU_SET);

    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int RunModeSetLiveCaptureAutoFp(DetectEngineCtx *de_ctx,
                              ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev)
{
    char tname[12];
    char qname[12];
    char queues[2048] = "";
    int thread;
    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    /* always create at least one thread */
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    for (thread = 0; thread < thread_max; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", sizeof(queues));

        snprintf(qname, sizeof(qname),"pickup%"PRIu16, thread+1);
        strlcat(queues, qname, sizeof(queues));
    }
    SCLogDebug("queues %s", queues);

    if ((nlive <= 1) && (live_dev != NULL)) {
        void *aconf;
        int threads_count;

        SCLogDebug("live_dev %s", live_dev);

        aconf = ConfigParser(live_dev);
        if (aconf == NULL) {
            SCLogError(SC_ERR_RUNMODE, "Failed to allocate config for %s (%d)",
                   live_dev, thread);
            exit(EXIT_FAILURE);
        }

        threads_count = ModThreadsCount(aconf);
        SCLogInfo("Going to use %" PRId32 " %s receive thread(s)",
                  threads_count, recv_mod_name);

        /* create the threads */
        for (thread = 0; thread < threads_count; thread++) {
            snprintf(tname, sizeof(tname), "%s%"PRIu16, thread_name, thread+1);
            char *thread_name = SCStrdup(tname);
            if (unlikely(thread_name == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
                exit(EXIT_FAILURE);
            }
            ThreadVars *tv_receive =
                TmThreadCreatePacketHandler(thread_name,
                        "packetpool", "packetpool",
                        queues, "flow", "pktacqloop");
            if (tv_receive == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
                exit(EXIT_FAILURE);
            }
            TmModule *tm_module = TmModuleGetByName(recv_mod_name);
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE,
                    "TmModuleGetByName failed for %s",
                    recv_mod_name);
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

            tm_module = TmModuleGetByName(decode_mod_name);
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE,
                        "TmModuleGetByName %s failed", decode_mod_name);
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

            TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
                exit(EXIT_FAILURE);
            }
        }
    } else { /* Multiple input device */
        SCLogInfo("Using %d live device(s).", nlive);
        int lthread;

        for (lthread = 0; lthread < nlive; lthread++) {
            char *live_dev = LiveGetDeviceName(lthread);
            void *aconf;
            int threads_count;

            if (live_dev == NULL) {
                SCLogError(SC_ERR_RUNMODE, "Failed to lookup live dev %d", lthread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("live_dev %s", live_dev);

            aconf = ConfigParser(live_dev);
            if (aconf == NULL) {
                SCLogError(SC_ERR_RUNMODE, "Multidev: Failed to allocate config for %s (%d)",
                       live_dev, lthread);
                exit(EXIT_FAILURE);
            }

            threads_count = ModThreadsCount(aconf);
            for (thread = 0; thread < threads_count; thread++) {
                snprintf(tname, sizeof(tname), "%s%s%"PRIu16, thread_name,
                         live_dev, thread+1);
                char *thread_name = SCStrdup(tname);
                if (unlikely(thread_name == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
                    exit(EXIT_FAILURE);
                }
                ThreadVars *tv_receive =
                    TmThreadCreatePacketHandler(thread_name,
                            "packetpool", "packetpool",
                            queues, "flow", "pktacqloop");
                if (tv_receive == NULL) {
                    SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
                    exit(EXIT_FAILURE);
                }
                TmModule *tm_module = TmModuleGetByName(recv_mod_name);
                if (tm_module == NULL) {
                    SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName failed for %s", recv_mod_name);
                    exit(EXIT_FAILURE);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

                tm_module = TmModuleGetByName(decode_mod_name);
                if (tm_module == NULL) {
                    SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
                    exit(EXIT_FAILURE);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

                TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

                if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
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
        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppendDelayed(tv_detect_ncpu, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        /* add outputs as well */
        SetupOutputs(tv_detect_ncpu);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

static int RunModeSetLiveCaptureWorkersForDevice(DetectEngineCtx *de_ctx,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev, void *aconf,
                              unsigned char single_mode)
{
    int thread;
    int threads_count;

    if (single_mode) {
        threads_count = 1;
    } else {
        threads_count = ModThreadsCount(aconf);
        SCLogInfo("Going to use %" PRId32 " thread(s)", threads_count);
    }

    /* create the threads */
    for (thread = 0; thread < threads_count; thread++) {
        char tname[20];
        char *n_thread_name = NULL;
        ThreadVars *tv = NULL;
        TmModule *tm_module = NULL;

        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s", thread_name);
        } else {
            snprintf(tname, sizeof(tname), "%s%s%"PRIu16,
                     thread_name, live_dev, thread+1);
        }
        n_thread_name = SCStrdup(tname);
        if (unlikely(n_thread_name == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
            exit(EXIT_FAILURE);
        }
        tv = TmThreadCreatePacketHandler(n_thread_name,
                "packetpool", "packetpool",
                "packetpool", "packetpool",
                "pktacqloop");
        if (tv == NULL) {
            SCLogError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, aconf);

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppendDelayed(tv, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        SetupOutputs(tv);

        TmThreadSetCPU(tv, DETECT_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

int RunModeSetLiveCaptureWorkers(DetectEngineCtx *de_ctx,
                              ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev)
{
    int nlive = LiveGetDeviceCount();
    void *aconf;
    int ldev;

    for (ldev = 0; ldev < nlive; ldev++) {
        char *live_dev_c = NULL;
        if (live_dev != NULL) {
            aconf = ConfigParser(live_dev);
            live_dev_c = SCStrdup(live_dev);
            if (unlikely(live_dev_c == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate interface name");
                exit(EXIT_FAILURE);
            }
        } else {
            live_dev_c = LiveGetDeviceName(ldev);
            aconf = ConfigParser(live_dev_c);
        }
        RunModeSetLiveCaptureWorkersForDevice(de_ctx,
                ModThreadsCount,
                recv_mod_name,
                decode_mod_name,
                thread_name,
                live_dev_c,
                aconf,
                0);
    }

    return 0;
}

int RunModeSetLiveCaptureSingle(DetectEngineCtx *de_ctx,
                              ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev)
{
    int nlive = LiveGetDeviceCount();
    void *aconf;

    if (nlive > 1) {
        SCLogError(SC_ERR_RUNMODE,
                "Can't use single runmode with multiple device");
        exit(EXIT_FAILURE);
    }

    if (live_dev != NULL) {
        aconf = ConfigParser(live_dev);
    } else {
        char *live_dev_c = LiveGetDeviceName(0);
        aconf = ConfigParser(live_dev_c);
        /* \todo Set threads number in config to 1 */
    }

    return RunModeSetLiveCaptureWorkersForDevice(de_ctx,
                                 ModThreadsCount,
                                 recv_mod_name,
                                 decode_mod_name,
                                 thread_name,
                                 live_dev,
                                 aconf,
                                 1);
}


int RunModeSetIPSAuto(DetectEngineCtx *de_ctx,
                      ConfigIPSParserFunc ConfigParser,
                      char *recv_mod_name,
                      char *verdict_mod_name,
                      char *decode_mod_name)
{
    SCEnter();
    char tname[16];
    TmModule *tm_module ;
    char *cur_queue = NULL;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nqueue = LiveGetDeviceCount();

    for (int i = 0; i < nqueue; i++) {
        /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            printf("ERROR: Invalid queue number\n");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Recv-Q%s", cur_queue);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: Can't create thread name failed\n");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_receivenfq =
            TmThreadCreatePacketHandler(thread_name,
                                        "packetpool", "packetpool",
                                        "pickup-queue", "simple",
                                        "1slot_noinout");
        if (tv_receivenfq == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for %s\n", recv_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivenfq, tm_module, (void *) ConfigParser(i));

        TmThreadSetCPU(tv_receivenfq, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receivenfq) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }

    /* decode and stream */
    ThreadVars *tv_decode =
        TmThreadCreatePacketHandler("Decode1",
                                    "pickup-queue", "simple",
                                    "decode-queue", "simple",
                                    "varslot");
    if (tv_decode == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName(decode_mod_name);
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName %s failed\n", decode_mod_name);
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode,tm_module,NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode, tm_module, NULL);

    TmThreadSetCPU(tv_decode, DECODE_CPU_SET);

    if (TmThreadSpawn(tv_decode) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    /* always create at least one thread */
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    int thread;
    for (thread = 0; thread < thread_max; thread++) {
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Detect%"PRIu16, thread+1);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: thead name creation failed\n");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("Assigning %s affinity", thread_name);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        "decode-queue", "simple",
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
        TmSlotSetFuncAppendDelayed(tv_detect_ncpu, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }

    /* create the threads */
    for (int i = 0; i < nqueue; i++) {
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Verdict%"PRIu16, i);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: thead name creation failed\n");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_verdict =
            TmThreadCreatePacketHandler(thread_name,
                                        "verdict-queue", "simple",
                                        "alert-queue", "simple",
                                        "varslot");
        if (tv_verdict == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName %s failed\n", verdict_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, (void *)ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, NULL);

        TmThreadSetCPU(tv_verdict, VERDICT_CPU_SET);

        if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    };

    ThreadVars *tv_outputs =
        TmThreadCreatePacketHandler("Outputs",
                                    "alert-queue", "simple",
                                    "packetpool", "packetpool",
                                    "varslot");

    if (tv_outputs == NULL) {
        printf("ERROR: TmThreadCreatePacketHandler for Outputs failed\n");
        exit(EXIT_FAILURE);
    }

    TmThreadSetCPU(tv_outputs, OUTPUT_CPU_SET);

    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;

}

int RunModeSetIPSAutoFp(DetectEngineCtx *de_ctx,
                        ConfigIPSParserFunc ConfigParser,
                        char *recv_mod_name,
                        char *verdict_mod_name,
                        char *decode_mod_name)
{
    SCEnter();
    char tname[16];
    char qname[16];
    TmModule *tm_module ;
    char *cur_queue = NULL;
    char queues[2048] = "";
    int thread;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nqueue = LiveGetDeviceCount();

    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    /* always create at least one thread */
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    for (thread = 0; thread < thread_max; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", sizeof(queues));

        snprintf(qname, sizeof(qname),"pickup%"PRIu16, thread+1);
        strlcat(queues, qname, sizeof(queues));
    }
    SCLogDebug("queues %s", queues);

    for (int i = 0; i < nqueue; i++) {
    /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            printf("ERROR: Invalid queue number\n");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Recv-Q%s", cur_queue);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            printf("ERROR: thead name creation failed\n");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_receive =
            TmThreadCreatePacketHandler(thread_name,
                    "packetpool", "packetpool",
                    queues, "flow", "pktacqloop");
        if (tv_receive == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName failed for %s", recv_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receive, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

        TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }

    }
    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "Detect%"PRIu16, thread+1);
        snprintf(qname, sizeof(qname), "pickup%"PRIu16, thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate thread name");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(thread_name,
                                        qname, "flow",
                                        "verdict-queue", "simple",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppendDelayed(tv_detect_ncpu, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        TmThreadSetCPU(tv_detect_ncpu, DETECT_CPU_SET);

        SetupOutputs(tv_detect_ncpu);

        char *thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    /* create the threads */
    for (int i = 0; i < nqueue; i++) {
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Verdict%"PRIu16, i);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        ThreadVars *tv_verdict =
            TmThreadCreatePacketHandler(thread_name,
                                        "verdict-queue", "simple",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_verdict == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName %s failed\n", verdict_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, (void *)ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, NULL);

        TmThreadSetCPU(tv_verdict, VERDICT_CPU_SET);

        if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    };
    return 0;
}

int RunModeSetIPSWorker(DetectEngineCtx *de_ctx,
        ConfigIPSParserFunc ConfigParser,
        char *recv_mod_name,
        char *verdict_mod_name,
        char *decode_mod_name)
{
    char tname[16];
    ThreadVars *tv = NULL;
    TmModule *tm_module = NULL;
    char *cur_queue = NULL;

    int nqueue = LiveGetDeviceCount();

    for (int i = 0; i < nqueue; i++) {
        /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            printf("ERROR: Invalid queue number\n");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Worker-Q%s", cur_queue);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        tv = TmThreadCreatePacketHandler(thread_name,
                "packetpool", "packetpool",
                "packetpool", "packetpool",
                "pktacqloop");
        if (tv == NULL) {
            SCLogError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName StreamTcp failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppendDelayed(tv, tm_module,
                                   (void *)de_ctx, de_ctx->delayed_detect);

        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
            exit(EXIT_FAILURE);
        }

        TmSlotSetFuncAppend(tv, tm_module, (void *)de_ctx);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        SetupOutputs(tv);

        TmThreadSetCPU(tv, DETECT_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
