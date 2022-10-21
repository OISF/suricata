/* Copyright (C) 2011-2019 Open Information Security Foundation
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
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-af-packet.h"
#include "output.h"
#include "log-httplog.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
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
    if (n > 1024)
        return NULL;

    /* 13 because pickup12345, = 12 + \0 */
    size_t queues_size = n * 13;
    char qname[TM_QUEUE_NAME_MAX];

    char *queues = SCMalloc(queues_size);
    if (unlikely(queues == NULL)) {
        SCLogError(SC_ENOMEM, "failed to alloc queues buffer: %s", strerror(errno));
        return NULL;
    }
    memset(queues, 0x00, queues_size);

    for (int thread = 0; thread < n; thread++) {
        if (strlen(queues) > 0)
            strlcat(queues, ",", queues_size);

        snprintf(qname, sizeof(qname), "pickup%d", (int16_t)thread+1);
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

    /* Available cpus */
    int nlive = LiveGetDeviceCount();
    uint16_t thread_max = TmThreadsGetWorkerThreadMax();

    char *queues = RunmodeAutoFpCreatePickupQueuesString(thread_max);
    if (queues == NULL) {
        FatalError(SC_ERR_RUNMODE, "RunmodeAutoFpCreatePickupQueuesString failed");
    }

    if ((nlive <= 1) && (live_dev != NULL)) {
        SCLogDebug("live_dev %s", live_dev);

        void *aconf = ConfigParser(live_dev);
        if (aconf == NULL) {
            FatalError(SC_ERR_RUNMODE, "Failed to allocate config for %s",
                   live_dev);
        }

        int threads_count = ModThreadsCount(aconf);
        SCLogInfo("Going to use %" PRId32 " %s receive thread(s)",
                  threads_count, recv_mod_name);

        /* create the threads */
        for (int thread = 0; thread < threads_count; thread++) {
            snprintf(tname, sizeof(tname), "%s#%02d", thread_name, thread+1);
            ThreadVars *tv_receive =
                TmThreadCreatePacketHandler(tname,
                        "packetpool", "packetpool",
                        queues, "flow", "pktacqloop");
            if (tv_receive == NULL) {
                FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
            }
            TmModule *tm_module = TmModuleGetByName(recv_mod_name);
            if (tm_module == NULL) {
                FatalError(SC_ERR_RUNMODE,
                    "TmModuleGetByName failed for %s",
                    recv_mod_name);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

            tm_module = TmModuleGetByName(decode_mod_name);
            if (tm_module == NULL) {
                FatalError(SC_ERR_RUNMODE,
                        "TmModuleGetByName %s failed", decode_mod_name);
            }
            TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

            TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

            if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
            }
        }
    } else { /* Multiple input device */
        SCLogInfo("Using %d live device(s).", nlive);

        for (int lthread = 0; lthread < nlive; lthread++) {
            const char *dev = LiveGetDeviceName(lthread);
            const char *visual_devname = LiveGetShortName(dev);

            if (dev == NULL) {
                FatalError(SC_ERR_RUNMODE, "Failed to lookup live dev %d", lthread);
            }
            SCLogDebug("dev %s", dev);

            void *aconf = ConfigParser(dev);
            if (aconf == NULL) {
                FatalError(SC_ERR_RUNMODE, "Multidev: Failed to allocate config for %s (%d)",
                       dev, lthread);
            }

            int threads_count = ModThreadsCount(aconf);
            for (int thread = 0; thread < threads_count; thread++) {
                char *printable_threadname = SCMalloc(sizeof(char) * (strlen(thread_name)+5+strlen(dev)));
                if (unlikely(printable_threadname == NULL)) {
                    FatalError(SC_ENOMEM, "failed to alloc printable thread name: %s",
                            strerror(errno));
                }
                snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                         thread+1, visual_devname);
                snprintf(printable_threadname, strlen(thread_name)+5+strlen(dev),
                         "%s#%02d-%s", thread_name, thread+1,
                         dev);

                ThreadVars *tv_receive =
                    TmThreadCreatePacketHandler(tname,
                            "packetpool", "packetpool",
                            queues, "flow", "pktacqloop");
                if (tv_receive == NULL) {
                    FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
                }
                tv_receive->printable_name = printable_threadname;
                TmModule *tm_module = TmModuleGetByName(recv_mod_name);
                if (tm_module == NULL) {
                    FatalError(SC_ERR_RUNMODE, "TmModuleGetByName failed for %s", recv_mod_name);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, aconf);

                tm_module = TmModuleGetByName(decode_mod_name);
                if (tm_module == NULL) {
                    FatalError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
                }
                TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

                TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

                if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
                    FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
                }
            }
        }
    }

    for (uint16_t thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02u", thread_name_workers, (uint16_t)(thread + 1));
        snprintf(qname, sizeof(qname), "pickup%u", (uint16_t)(thread + 1));

        SCLogDebug("tname %s, qname %s", tname, qname);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
        }
        TmModule *tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
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
    int threads_count;
    uint16_t thread_max = TmThreadsGetWorkerThreadMax();

    if (single_mode) {
        threads_count = 1;
    } else {
        threads_count = MIN(ModThreadsCount(aconf), thread_max);
        SCLogInfo("Going to use %" PRId32 " thread(s) for device %s", threads_count, live_dev);
    }

    /* create the threads */
    for (int thread = 0; thread < threads_count; thread++) {
        char tname[TM_THREAD_NAME_MAX];
        TmModule *tm_module = NULL;
        const char *visual_devname = LiveGetShortName(live_dev);
        char *printable_threadname = SCMalloc(sizeof(char) * (strlen(thread_name)+5+strlen(live_dev)));
        if (unlikely(printable_threadname == NULL)) {
            FatalError(SC_ENOMEM, "failed to alloc printable thread name: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s#01-%s", thread_name, visual_devname);
            snprintf(printable_threadname, strlen(thread_name)+5+strlen(live_dev), "%s#01-%s",
                     thread_name, live_dev);
        } else {
            snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                     thread+1, visual_devname);
            snprintf(printable_threadname, strlen(thread_name)+5+strlen(live_dev), "%s#%02d-%s",
                     thread_name, thread+1, live_dev);
        }
        ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                "packetpool", "packetpool",
                "packetpool", "packetpool",
                "pktacqloop");
        if (tv == NULL) {
            FatalError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
        }
        tv->printable_name = printable_threadname;

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_EINVAL, "TmModuleGetByName failed for %s", recv_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, aconf);

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_EINVAL, "TmModuleGetByName %s failed", decode_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        TmThreadSetCPU(tv, WORKER_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            FatalError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
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
        FatalError(SC_ERR_RUNMODE,
                "Can't use the 'single' runmode with multiple devices");
    }

    if (live_dev != NULL) {
        aconf = ConfigParser(live_dev);
        live_dev_c = live_dev;
    } else {
        live_dev_c = LiveGetDeviceName(0);
        aconf = ConfigParser(live_dev_c);
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
    TmModule *tm_module ;

    /* Available cpus */
    const int nqueue = LiveGetDeviceCount();

    uint16_t thread_max = TmThreadsGetWorkerThreadMax();

    char *queues = RunmodeAutoFpCreatePickupQueuesString(thread_max);
    if (queues == NULL) {
        FatalError(SC_ERR_RUNMODE, "RunmodeAutoFpCreatePickupQueuesString failed");
    }

    /* create the threads */
    for (int i = 0; i < nqueue; i++) {
        const char *cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            FatalError(SC_ERR_RUNMODE, "invalid queue number");
        }
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "%s-%s", thread_name_autofp, cur_queue);

        ThreadVars *tv_receive =
            TmThreadCreatePacketHandler(tname,
                    "packetpool", "packetpool",
                    queues, "flow", "pktacqloop");
        if (tv_receive == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
        }
        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName failed for %s", recv_mod_name);
        }
        TmSlotSetFuncAppend(tv_receive, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", decode_mod_name);
        }
        TmSlotSetFuncAppend(tv_receive, tm_module, NULL);

        TmThreadSetCPU(tv_receive, RECEIVE_CPU_SET);

        if (TmThreadSpawn(tv_receive) != TM_ECODE_OK) {
            FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        }

    }
    for (int thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname), "%s#%02u", thread_name_workers, (uint16_t)(thread + 1));
        char qname[TM_QUEUE_NAME_MAX];
        snprintf(qname, sizeof(qname), "pickup%u", (uint16_t)(thread + 1));

        SCLogDebug("tname %s, qname %s", tname, qname);

        ThreadVars *tv_detect_ncpu =
            TmThreadCreatePacketHandler(tname,
                                        qname, "flow",
                                        "verdict-queue", "simple",
                                        "varslot");
        if (tv_detect_ncpu == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
        }

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv_detect_ncpu, tm_module, NULL);

        TmThreadSetCPU(tv_detect_ncpu, WORKER_CPU_SET);

        TmThreadSetGroupName(tv_detect_ncpu, "Detect");

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
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
            FatalError(SC_ERR_RUNMODE, "TmThreadsCreate failed");
        }
        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, (void *)ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
        }
        TmSlotSetFuncAppend(tv_verdict, tm_module, NULL);

        TmThreadSetCPU(tv_verdict, VERDICT_CPU_SET);

        if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
            FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
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
    TmModule *tm_module = NULL;
    const int nqueue = LiveGetDeviceCount();

    for (int i = 0; i < nqueue; i++) {
        /* create the threads */
        const char *cur_queue = LiveGetDeviceName(i);
        if (cur_queue == NULL) {
            FatalError(SC_ERR_RUNMODE, "invalid queue number");
        }

        char tname[TM_THREAD_NAME_MAX];
        memset(tname, 0, sizeof(tname));
        snprintf(tname, sizeof(tname), "%s-%s", thread_name_workers, cur_queue);

        ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                "packetpool", "packetpool",
                "packetpool", "packetpool",
                "pktacqloop");
        if (tv == NULL) {
            FatalError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
        }

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_EINVAL, "TmModuleGetByName failed for %s", recv_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_EINVAL, "TmModuleGetByName %s failed", decode_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName(verdict_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName %s failed", verdict_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, (void *) ConfigParser(i));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for RespondReject failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        TmThreadSetCPU(tv, WORKER_CPU_SET);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            FatalError(SC_ERR_RUNMODE, "TmThreadSpawn failed");
        }
    }

    return 0;
}
