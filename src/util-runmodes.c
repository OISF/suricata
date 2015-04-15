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

#include "detect-engine.h"
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

#include "flow-hash.h"

/** set to true if flow engine and stream engine run in different
 *  threads. */
static int runmode_flow_stream_async = 0;

void RunmodeSetFlowStreamAsync(void)
{
    runmode_flow_stream_async = 1;
    FlowDisableTcpReuseHandling();
}

int RunmodeGetFlowStreamAsync(void)
{
    return runmode_flow_stream_async;
}

/** \brief create a queue string for autofp to pass to
 *         the flow queue handler.
 *
 *  The string will be "pickup1,pickup2,pickup3\0"
 */
char *RunmodeAutoFpCreatePickupQueuesString(int n)
{
    char *queues = NULL;
    /* 13 because pickup12345, = 12 + \0 */
    size_t queues_size = n * 13;
    int thread;
    char qname[TM_QUEUE_NAME_MAX];

    queues = SCMalloc(queues_size);
    if (unlikely(queues == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "failed to alloc queues buffer: %s", strerror(errno));
        return NULL;
    }
    memset(queues, 0x00, queues_size);

    for (thread = 0; thread < n; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", queues_size);

        snprintf(qname, sizeof(qname), "pickup%"PRIu16, thread+1);
        strlcat(queues, qname, queues_size);
    }

    SCLogDebug("%d %"PRIuMAX", queues %s", n, (uintmax_t)queues_size, queues);
    return queues;
}

/**
 */
int RunModeSetLiveCaptureAutoFp(ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              char *recv_mod_name,
                              char *decode_mod_name, char *thread_name,
                              const char *live_dev)
{
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    char *queues = NULL;
    int thread = 0;
    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();
    int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
    /* always create at least one thread */
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    RunmodeSetFlowStreamAsync();

    queues = RunmodeAutoFpCreatePickupQueuesString(thread_max);
    if (queues == NULL) {
        SCLogError(SC_ERR_RUNMODE, "RunmodeAutoFpCreatePickupQueuesString failed");
         exit(EXIT_FAILURE);
    }

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
            char visual_devname[14] = "";
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
                LiveSafeDeviceName(live_dev, visual_devname);
                snprintf(tname, sizeof(tname), "%s%s%"PRIu16, thread_name,
                         visual_devname, thread+1);
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

        if (DetectEngineEnabled()) {
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);
        }

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

    SCFree(queues);
    return 0;
}

/**
 */
static int RunModeSetLiveCaptureWorkersForDevice(ConfigIfaceThreadsCountFunc ModThreadsCount,
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
        char tname[TM_THREAD_NAME_MAX];
        char *n_thread_name = NULL;
        char visual_devname[13] = "";
        ThreadVars *tv = NULL;
        TmModule *tm_module = NULL;

        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s", thread_name);
        } else {
            LiveSafeDeviceName(live_dev, visual_devname);
            SCLogInfo("New dev name %s", visual_devname);
            snprintf(tname, sizeof(tname), "%s%s%"PRIu16,
                     thread_name, visual_devname, thread+1);
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

        if (DetectEngineEnabled()) {
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv, tm_module, NULL);
        }

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

int RunModeSetLiveCaptureWorkers(ConfigIfaceParserFunc ConfigParser,
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
        RunModeSetLiveCaptureWorkersForDevice(ModThreadsCount,
                recv_mod_name,
                decode_mod_name,
                thread_name,
                live_dev_c,
                aconf,
                0);
    }

    return 0;
}

int RunModeSetLiveCaptureSingle(ConfigIfaceParserFunc ConfigParser,
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

    return RunModeSetLiveCaptureWorkersForDevice(
                                 ModThreadsCount,
                                 recv_mod_name,
                                 decode_mod_name,
                                 thread_name,
                                 live_dev,
                                 aconf,
                                 1);
}


/**
 */
int RunModeSetIPSAutoFp(ConfigIPSParserFunc ConfigParser,
                        char *recv_mod_name,
                        char *verdict_mod_name,
                        char *decode_mod_name)
{
    SCEnter();
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    TmModule *tm_module ;
    char *cur_queue = NULL;
    char *queues = NULL;
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

    RunmodeSetFlowStreamAsync();

    queues = RunmodeAutoFpCreatePickupQueuesString(thread_max);
    if (queues == NULL) {
        SCLogError(SC_ERR_RUNMODE, "RunmodeAutoFpCreatePickupQueuesString failed");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nqueue; i++) {
    /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            SCLogError(SC_ERR_RUNMODE, "invalid queue number");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "Recv-Q%s", cur_queue);

        char *thread_name = SCStrdup(tname);
        if (unlikely(thread_name == NULL)) {
            SCLogError(SC_ERR_RUNMODE, "thread name creation failed");
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

        if (DetectEngineEnabled()) {
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);
        }

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
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, (void *)ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, NULL);

        TmThreadSetCPU(tv_verdict, VERDICT_CPU_SET);

        if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    SCFree(queues);
    return 0;
}

/**
 */
int RunModeSetIPSWorker(ConfigIPSParserFunc ConfigParser,
        char *recv_mod_name,
        char *verdict_mod_name,
        char *decode_mod_name)
{
    char tname[TM_THREAD_NAME_MAX];
    ThreadVars *tv = NULL;
    TmModule *tm_module = NULL;
    char *cur_queue = NULL;

    int nqueue = LiveGetDeviceCount();

    for (int i = 0; i < nqueue; i++) {
        /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            SCLogError(SC_ERR_RUNMODE, "invalid queue number");
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

        if (DetectEngineEnabled()) {
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName Detect failed");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv, tm_module, NULL);
        }

        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
            exit(EXIT_FAILURE);
        }

        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
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
