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

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-napatech.h"
#include "log-httplog.h"
#include "output.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "runmode-napatech.h"

static const char *default_mode = NULL;

int RunModeNapatechAuto2(DetectEngineCtx *de_ctx);
const char *RunModeNapatechGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatechRegister(void)
{
#ifdef HAVE_NAPATECH
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH, "auto",
            "Multi threaded Napatech  mode",
            RunModeNapatechAuto2);
    return;
#endif
}

int RunModeNapatechAuto(DetectEngineCtx *de_ctx) {
#ifdef HAVE_NAPATECH
    int i;
    uint16_t feed, cpu;
    char tname [128];
    char *feedName  = NULL;
    char *threadName  = NULL;
    char *inQueueName  = NULL;
    char *outQueueName  = NULL;
    char *thread_group_name = NULL;

    RunModeInitialize ();
    TimeModeSetLive();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    char *device = NULL;
    if (ConfGet("napatech.adapter", &device) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.adapter from Conf");
        exit(EXIT_FAILURE);
    }

    uint16_t adapter = atoi (device);
    SCLogDebug("Napatech adapter %s", adapter);


    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;

    int32_t feed_count = napatech_count (adapter);
    if (feed_count <= 0) {
        printf("ERROR: No Napatech feeds defined for adapter %i\n", adapter);
        exit(EXIT_FAILURE);
    }

    for (feed=0; feed < feed_count; feed++) {
        snprintf(tname, sizeof(tname),"%"PRIu16":%"PRIu16, adapter, feed);
        feedName = SCStrdup(tname);
        if (unlikely(feedName == NULL)) {
        fprintf(stderr, "ERROR: Alloc feed name\n");
        exit(EXIT_FAILURE);
        }

        snprintf(tname, sizeof(tname),"Feed%"PRIu16,feed);
        threadName = SCStrdup(tname);
        if (unlikely(threadName == NULL)) {
        fprintf(stderr, "ERROR: Alloc thread name\n");
        exit(EXIT_FAILURE);
        }


        snprintf(tname, sizeof(tname),"feed-queue%"PRIu16,feed);
        outQueueName = SCStrdup(tname);
        if (unlikely(outQueueName == NULL)) {
        fprintf(stderr, "ERROR: Alloc output queue name\n");
        exit(EXIT_FAILURE);
        }

        /* create the threads */
        ThreadVars *tv_napatechFeed = TmThreadCreatePacketHandler(threadName,"packetpool",
                "packetpool",outQueueName,
                "simple","pktacqloop");
        if (tv_napatechFeed == NULL) {
            fprintf(stderr, "ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("NapatechFeed");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for NapatechFeed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend (tv_napatechFeed,tm_module,feedName);

        tm_module = TmModuleGetByName("NapatechDecode");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for NapatechDecode\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_napatechFeed,tm_module,feedName);

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_napatechFeed, feed);
        }

        if (TmThreadSpawn(tv_napatechFeed) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
        /*
         * -------------------------------------------
         */

        /* hard code it for now */
        uint16_t detect=0;
        /* always create at least one thread */
        int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
        if (thread_max == 0)
            thread_max = ncpus * threading_detect_ratio;
        if (thread_max < 1)
            thread_max = 1;

        for (i=0; i< thread_max; i++)
        {
            snprintf(tname, sizeof(tname),"Detect%"PRIu16"/%"PRIu16,feed,detect++);
            threadName = SCStrdup(tname);
            if (unlikely(threadName == NULL)) {
            fprintf(stderr, "ERROR: can not strdup thread name\n");
            exit(EXIT_FAILURE);
            }
            snprintf(tname, sizeof(tname),"feed-queue%"PRIu16,feed);
            inQueueName = SCStrdup(tname);
            if (unlikely(inQueueName == NULL)) {
            fprintf(stderr, "ERROR: can not strdup in queue name\n");
            exit(EXIT_FAILURE);
            }

            ThreadVars *tv_detect = TmThreadCreatePacketHandler(threadName,
                    inQueueName,"simple",
                    "packetpool","packetpool","varslot");
            if (tv_detect == NULL) {
                fprintf(stderr,"ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }

            tm_module = TmModuleGetByName("StreamTcp");
            if (tm_module == NULL) {
                fprintf(stderr, "ERROR: TmModuleGetByName StreamTcp failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect,tm_module,NULL);

            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                fprintf(stderr, "ERROR: TmModuleGetByName Detect failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect,tm_module,(void *)de_ctx);

            thread_group_name = SCStrdup("Detect");
            if (unlikely(thread_group_name == NULL)) {
            fprintf(stderr, "Error allocating memory\n");
            exit(EXIT_FAILURE);
            }
            tv_detect->thread_group_name = thread_group_name;

            SetupOutputs(tv_detect);
            thread_group_name = SCStrdup("Outputs");
            if (unlikely(thread_group_name == NULL)) {
            fprintf(stderr, "Error allocating memory\n");
            exit(EXIT_FAILURE);
            }
            tv_detect->thread_group_name = thread_group_name;

            if (TmThreadSpawn(tv_detect) != TM_ECODE_OK) {
                fprintf(stderr, "ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }

    }
#endif
    return 0;
}

int RunModeNapatechAuto2(DetectEngineCtx *de_ctx) {
#ifdef HAVE_NAPATECH
    int i;
    uint16_t feed, cpu;
    char tname [128];
    char *feedName  = NULL;
    char *threadName  = NULL;
    char *inQueueName  = NULL;
    char *outQueueName  = NULL;
    char *thread_group_name = NULL;

    RunModeInitialize ();
    TimeModeSetLive();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    char *device = NULL;
    if (ConfGet("napatech.adapter", &device) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.adapter from Conf");
        exit(EXIT_FAILURE);
    }

    uint16_t adapter = atoi (device);
    SCLogDebug("Napatech adapter %s", adapter);


    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;

    int32_t feed_count = napatech_count (adapter);
    if (feed_count <= 0) {
        printf("ERROR: No Napatech feeds defined for adapter %i\n", adapter);
        exit(EXIT_FAILURE);
    }

    for (feed=0; feed < feed_count; feed++) {
        snprintf(tname, sizeof(tname),"%"PRIu16":%"PRIu16, adapter, feed);
        feedName = SCStrdup(tname);
        if (unlikely(feedName == NULL)) {
        fprintf(stderr, "ERROR: can not strdup feed name\n");
        exit(EXIT_FAILURE);
        }

        snprintf(tname, sizeof(tname),"Feed%"PRIu16,feed);
        threadName = SCStrdup(tname);
        if (unlikely(threadName == NULL)) {
        fprintf(stderr, "ERROR: can not strdup in thread name\n");
        exit(EXIT_FAILURE);
        }

        snprintf(tname, sizeof(tname),"feed-queue%"PRIu16,feed);
        outQueueName = SCStrdup(tname);
        if (unlikely(outQueueName == NULL)) {
        fprintf(stderr, "ERROR: can not strdup out queue name\n");
        exit(EXIT_FAILURE);
        }

        /* create the threads */
        ThreadVars *tv_napatechFeed = TmThreadCreatePacketHandler(threadName,"packetpool",
                "packetpool","packetpool",
                "packetpool","pktacqloop");
        if (tv_napatechFeed == NULL) {
            fprintf(stderr, "ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        TmModule *tm_module = TmModuleGetByName("NapatechFeed");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for NapatechFeed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend (tv_napatechFeed,tm_module,feedName);

        tm_module = TmModuleGetByName("NapatechDecode");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for NapatechDecode\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_napatechFeed,tm_module,feedName);

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_napatechFeed, feed);
        }

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_napatechFeed,tm_module,NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_napatechFeed,tm_module,(void *)de_ctx);

        thread_group_name = SCStrdup("Detect");
        if (unlikely(thread_group_name == NULL)) {
        fprintf(stderr, "Error allocating memory\n");
        exit(EXIT_FAILURE);
        }
        tv_napatechFeed->thread_group_name = thread_group_name;

        SetupOutputs(tv_napatechFeed);
        thread_group_name = SCStrdup("Outputs");
        if (unlikely(thread_group_name == NULL)) {
        fprintf(stderr, "Error allocating memory\n");
        exit(EXIT_FAILURE);
        }
        tv_napatechFeed->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_napatechFeed) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

#if 0
        /*
         * -------------------------------------------
         */

        /* hard code it for now */
        uint16_t detect=0;
        /* always create at least one thread */
        int thread_max = TmThreadGetNbThreads(DETECT_CPU_SET);
        if (thread_max == 0)
            thread_max = ncpus * threading_detect_ratio;
        if (thread_max < 1)
            thread_max = 1;

        for (i=0; i< thread_max; i++)
        {
            snprintf(tname, sizeof(tname),"Detect%"PRIu16"/%"PRIu16,feed,detect++);
            threadName = SCStrdup(tname);
            snprintf(tname, sizeof(tname),"feed-queue%"PRIu16,feed);
            inQueueName = SCStrdup(tname);

            ThreadVars *tv_detect = TmThreadCreatePacketHandler(threadName,
                    inQueueName,"simple",
                    "packetpool","packetpool","varslot");
            if (tv_detect == NULL) {
                fprintf(stderr,"ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }

            tm_module = TmModuleGetByName("StreamTcp");
            if (tm_module == NULL) {
                fprintf(stderr, "ERROR: TmModuleGetByName StreamTcp failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect,tm_module,NULL);

            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                fprintf(stderr, "ERROR: TmModuleGetByName Detect failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect,tm_module,(void *)de_ctx);

            thread_group_name = SCStrdup("Detect");
            if (thread_group_name == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                exit(EXIT_FAILURE);
            }
            tv_detect->thread_group_name = thread_group_name;

            SetupOutputs(tv_detect);
            thread_group_name = SCStrdup("Outputs");
            if (thread_group_name == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                exit(EXIT_FAILURE);
            }
            tv_detect->thread_group_name = thread_group_name;

            if (TmThreadSpawn(tv_detect) != TM_ECODE_OK) {
                fprintf(stderr, "ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }
#endif
    }
#endif /* HAVE_NAPATECH */
    return 0;
}

