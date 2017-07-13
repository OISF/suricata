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

        snprintf(qname, sizeof(qname), "pickup%d", thread+1);
        strlcat(queues, qname, queues_size);
    }

    SCLogDebug("%d %"PRIuMAX", queues %s", n, (uintmax_t)queues_size, queues);
    return queues;
}

/**
 */
int RunModeSetLiveCaptureAutoFp(ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              const char *recv_mod_name,
                              const char *decode_mod_name,
                              const char *thread_name,
                              const char *live_dev)
{
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    char *queues = NULL;
    uint16_t thread = 0;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nlive = LiveGetDeviceCount();
    int thread_max = TmThreadGetNbThreads(WORKER_CPU_SET);
    /* always create at least one thread */
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
            snprintf(tname, sizeof(tname), "%s#%02d", thread_name, thread+1);
            ThreadVars *tv_receive =
                TmThreadCreatePacketHandler(tname,
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
            const char *dev = LiveGetDeviceName(lthread);
            const char *visual_devname = LiveGetShortName(dev);
            void *aconf;
            int threads_count;

            if (dev == NULL) {
                SCLogError(SC_ERR_RUNMODE, "Failed to lookup live dev %d", lthread);
                exit(EXIT_FAILURE);
            }
            SCLogDebug("dev %s", dev);

            aconf = ConfigParser(dev);
            if (aconf == NULL) {
                SCLogError(SC_ERR_RUNMODE, "Multidev: Failed to allocate config for %s (%d)",
                       dev, lthread);
                exit(EXIT_FAILURE);
            }

            threads_count = ModThreadsCount(aconf);
            for (thread = 0; thread < threads_count; thread++) {
                snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                         thread+1, visual_devname);

                ThreadVars *tv_receive =
                    TmThreadCreatePacketHandler(tname,
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

    for (thread = 0; thread < (uint16_t)thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02u", thread_name_workers, thread+1);
        snprintf(qname, sizeof(qname), "pickup%u", thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

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
                              const char *recv_mod_name,
                              const char *decode_mod_name, const char *thread_name,
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
        ThreadVars *tv = NULL;
        TmModule *tm_module = NULL;
        const char *visual_devname = LiveGetShortName(live_dev);

        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s#01-%s", thread_name, visual_devname);
        } else {
            snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                     thread+1, visual_devname);
        }
        tv = TmThreadCreatePacketHandler(tname,
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

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        TmThreadSetCPU(tv, WORKER_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

int RunModeSetLiveCaptureWorkers(ConfigIfaceParserFunc ConfigParser,
                              ConfigIfaceThreadsCountFunc ModThreadsCount,
                              const char *recv_mod_name,
                              const char *decode_mod_name, const char *thread_name,
                              const char *live_dev)
{
    int nlive = LiveGetDeviceCount();
    void *aconf;
    int ldev;

    for (ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev_c = NULL;
        if ((nlive <= 1) && (live_dev != NULL)) {
            aconf = ConfigParser(live_dev);
            live_dev_c = live_dev;
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
                              const char *recv_mod_name,
                              const char *decode_mod_name, const char *thread_name,
                              const char *live_dev)
{
    int nlive = LiveGetDeviceCount();
    const char *live_dev_c = NULL;
    void *aconf;

    if (nlive > 1) {
        SCLogError(SC_ERR_RUNMODE,
                "Can't use the 'single' runmode with multiple devices");
        exit(EXIT_FAILURE);
    }

    if (live_dev != NULL) {
        aconf = ConfigParser(live_dev);
        live_dev_c = live_dev;
    } else {
        aconf = ConfigParser(live_dev_c);
        live_dev_c = LiveGetDeviceName(0);
    }

    return RunModeSetLiveCaptureWorkersForDevice(
                                 ModThreadsCount,
                                 recv_mod_name,
                                 decode_mod_name,
                                 thread_name,
                                 live_dev_c,
                                 aconf,
                                 1);
}


/**
 */
int RunModeSetIPSAutoFp(ConfigIPSParserFunc ConfigParser,
                        const char *recv_mod_name,
                        const char *verdict_mod_name,
                        const char *decode_mod_name)
{
    SCEnter();
    char tname[TM_THREAD_NAME_MAX];
    char qname[TM_QUEUE_NAME_MAX];
    TmModule *tm_module ;
    const char *cur_queue = NULL;
    char *queues = NULL;
    uint16_t thread;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int nqueue = LiveGetDeviceCount();

    int thread_max = TmThreadGetNbThreads(WORKER_CPU_SET);
    /* always create at least one thread */
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

    for (int i = 0; i < nqueue; i++) {
    /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            SCLogError(SC_ERR_RUNMODE, "invalid queue number");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "%s-Q%s", thread_name_autofp, cur_queue);

        ThreadVars *tv_receive =
            TmThreadCreatePacketHandler(tname,
                    "packetpool", "packetpool",
                    queues, "flow", "pktacqloop");
        if (tv_receive == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName(recv_mod_name);
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
    for (thread = 0; thread < (uint16_t)thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02u", thread_name_workers, thread+1);
        snprintf(qname, sizeof(qname), "pickup%u", thread+1);

        SCLogDebug("tname %s, qname %s", tname, qname);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "verdict-queue", "simple",
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

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    /* create the threads */
    for (int i = 0; i < nqueue; i++) {
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "%s#%02d", thread_name_verdict, i);

        ThreadVars *tv_verdict =
            TmThreadCreatePacketHandler(tname,
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
        const char *recv_mod_name,
        const char *verdict_mod_name,
        const char *decode_mod_name)
{
    char tname[TM_THREAD_NAME_MAX];
    ThreadVars *tv = NULL;
    TmModule *tm_module = NULL;
    const char *cur_queue = NULL;

    int nqueue = LiveGetDeviceCount();

    for (int i = 0; i < nqueue; i++) {
        /* create the threads */
        cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            SCLogError(SC_ERR_RUNMODE, "invalid queue number");
            exit(EXIT_FAILURE);
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "%s-Q%s", thread_name_workers, cur_queue);

        tv = TmThreadCreatePacketHandler(tname,
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

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
            exit(EXIT_FAILURE);
        }

        TmSlotSetFuncAppend(tv, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        TmThreadSetCPU(tv, WORKER_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            SCLogError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
