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
#include "runmode-ipfw.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "source-pfring.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

static const char *default_mode;

const char *RunModeIpsIPFWGetDefaultMode(void)
{
    return default_mode;
}

void RunModeIpsIPFWRegister(void)
{
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_IPFW, "auto",
                              "Multi threaded IPFW IPS mode",
                              RunModeIpsIPFWAuto);

    return;
}

/**
 * \brief RunModeIpsIPFWAuto set up the following thread packet handlers:
 *        - Receive thread (from IPFW)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Veredict thread (IPFW)
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
int RunModeIpsIPFWAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();
    char tname[12];
    uint16_t cpu = 0;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    RunModeInitialize();

    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receiveipfw =
        TmThreadCreatePacketHandler("ReceiveIPFW",
                                    "packetpool", "packetpool",
                                    "pickup-queue", "simple",
                                    "1slot_noinout");
    if (tv_receiveipfw == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveIPFW\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receiveipfw, tm_module, NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_receiveipfw, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_receiveipfw, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_receiveipfw) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 =
        TmThreadCreatePacketHandler("Decode1",
                                    "pickup-queue", "simple",
                                    "decode-queue1", "simple",
                                    "1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodeIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeIPFW failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_decode1, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_decode1, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 =
        TmThreadCreatePacketHandler("Stream1",
                                    "decode-queue1", "simple",
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
    TmSlotSetFuncAppend(tv_stream1, tm_module, NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_stream1, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_stream1, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
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

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_detect_ncpu, (int)cpu);
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

    ThreadVars *tv_verdict =
        TmThreadCreatePacketHandler("Verdict",
                                    "verdict-queue", "simple",
                                    "respond-queue", "simple",
                                    "1slot");
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("VerdictIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName VerdictIPFW failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_verdict, tm_module, NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_verdict, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_verdict, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject =
        TmThreadCreatePacketHandler("RespondReject",
                                    "respond-queue", "simple",
                                    "alert-queue1", "simple",
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

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_rreject, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_rreject, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
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

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_outputs, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_outputs, PRIO_MEDIUM);
    }
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
