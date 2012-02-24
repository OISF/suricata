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
#include "runmode-erf-dag.h"
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

const char *RunModeErfDagGetDefaultMode(void)
{
    return default_mode;
}

void RunModeErfDagRegister(void)
{
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_DAG, "auto",
                              "Multi threaded Erf dag mode",
                              RunModeErfDagAuto);

    return;
}

/**
 *
 * \brief   Sets up support for reading from a DAG card.
 *
 * \param   de_ctx
 * \param   file
 * \notes   Currently only supports a single interface.
 */
int RunModeErfDagAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();
    char tname[12];
    uint16_t cpu = 0;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    RunModeInitialize();

    char *iface = NULL;
    if (ConfGet("erf-dag.iface", &iface) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving erf-dag.iface from Conf");
        exit(EXIT_FAILURE);
    }
    SCLogDebug("iface %s", iface);

    TimeModeSetOffline();

    /* @TODO/JNM: We need to create a separate processing pipeliine for each
     * interface supported by the
     */

    ThreadVars *tv_receiveerf =
        TmThreadCreatePacketHandler("ReceiveErfDag",
                                    "packetpool","packetpool",
                                    "pickup-queue","simple",
                                    "1slot");
    if (tv_receiveerf == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveErfDag");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveErfDag\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_receiveerf, tm_module, iface);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_receiveerf, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_receiveerf, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_receiveerf) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 =
        TmThreadCreatePacketHandler("Decode & Stream",
                                    "pickup-queue","simple",
                                    "stream-queue1","simple",
                                    "varslot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodeErfDag");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeErfDag failed\n");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv_decode1, tm_module, NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
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
                                        "stream-queue1","simple",
                                        "alert-queue1","simple",
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

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
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

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_outputs, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_outputs, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
