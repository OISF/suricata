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
#include "runmode-nfq.h"
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

const char *RunModeIpsNFQGetDefaultMode(void)
{
    return default_mode;
}

void RunModeIpsNFQRegister(void)
{
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_NFQ, "auto",
                              "Multi threaded NFQ IPS mode",
                              RunModeIpsNFQAuto);

    return;
}

/**
 * \brief RunModeIpsNFQAuto set up the following thread packet handlers:
 *        - Receive thread (from NFQ)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Veredict thread (NFQ)
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
int RunModeIpsNFQAuto(DetectEngineCtx *de_ctx)
{
    SCEnter();
#ifdef NFQ
    char tname[16];
    TmModule *tm_module ;
    int cur_queue = 0;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nqueue = NFQGetQueueCount();

    RunModeInitialize();

    TimeModeSetLive();

    for (int i = 0; i < nqueue; i++) {
    /* create the threads */
        cur_queue = NFQGetQueueNum(i);
        if (cur_queue == -1) {
            printf("ERROR: Invalid thread number\n");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "RecvNFQ-Q%"PRIu16, cur_queue);
        if (tname == NULL) {
            printf("ERROR: Unable to build thread name\n");
            exit(EXIT_FAILURE);
        }

        char *thread_name = SCStrdup(tname);
        ThreadVars *tv_receivenfq =
            TmThreadCreatePacketHandler(thread_name,
                                        "packetpool", "packetpool",
                                        "pickup-queue", "simple",
                                        "1slot_noinout");
        if (tv_receivenfq == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceiveNFQ");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceiveNFQ\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_receivenfq, tm_module, (void *) NFQGetThread(i));

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

    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeNFQ failed\n");
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
    }

    /* create the threads */
    for (int i = 0; i < nqueue; i++) {
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "VerdictNFQ%"PRIu16, i);
        if (tname == NULL) {
            printf("ERROR: Unable to build thread name\n");
            exit(EXIT_FAILURE);
        }

        char *thread_name = SCStrdup(tname);
        ThreadVars *tv_verdict =
            TmThreadCreatePacketHandler(thread_name,
                                        "verdict-queue", "simple",
                                        "alert-queue", "simple",
                                        "varslot");
        if (tv_verdict == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("VerdictNFQ");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName VerdictNFQ failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, (void *)NFQGetThread(i));

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

#endif /* NFQ */
    return 0;
}
