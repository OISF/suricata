/* Copyright (C) 2011-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 *
 * Tilera TILE-Gx runmode support
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-tile.h"
#include "output.h"
#include "source-mpipe.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"

#ifdef HAVE_MPIPE
/* Number of configured parallel pipelines. */
int tile_num_pipelines;
#endif

/*
 * runmode support for tilegx
 */

static const char *mpipe_default_mode = "workers";

const char *RunModeTileMpipeGetDefaultMode(void)
{
    return mpipe_default_mode;
}

void RunModeTileMpipeRegister(void)
{
#ifdef HAVE_MPIPE
    RunModeRegisterNewRunMode(RUNMODE_TILERA_MPIPE, "workers",
                              "Workers tilegx mpipe mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeTileMpipeWorkers);
    mpipe_default_mode = "workers";
#endif
}

#ifdef HAVE_MPIPE

void *ParseMpipeConfig(const char *iface)
{
    ConfNode *if_root;
    ConfNode *mpipe_node;
    MpipeIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *copymodestr;
    char *out_iface = NULL;

    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));

    /* Find initial node */
    mpipe_node = ConfGetNode("mpipe.inputs");
    if (mpipe_node == NULL) {
        SCLogInfo("Unable to find mpipe config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(mpipe_node, "interface", iface);
    if (if_root == NULL) {
        SCLogInfo("Unable to find mpipe config for "
                  "interface %s, using default value",
                  iface);
        return aconf;
    }

    if (ConfGetChildValue(if_root, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }
    aconf->copy_mode = MPIPE_COPY_MODE_NONE;
    if (ConfGetChildValue(if_root, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("MPIPE IPS mode activated %s->%s",
                      iface,
                      aconf->out_iface);
            aconf->copy_mode = MPIPE_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("MPIPE TAP mode activated %s->%s",
                      iface,
                      aconf->out_iface);
            aconf->copy_mode = MPIPE_COPY_MODE_TAP;
        } else {
            SCLogError(SC_ERR_RUNMODE, "Invalid mode (expected tap or ips)");
            exit(EXIT_FAILURE);
        }
    }
    return aconf;
}

/**
 * \brief RunModeTileMpipeWorkers set up to process all modules in each thread.
 *
 * \param iface pointer to the name of the interface from which we will
 *              fetch the packets
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
int RunModeTileMpipeWorkers(void)
{
    SCEnter();
    char tname[TM_THREAD_NAME_MAX];
    char *thread_name;
    TmModule *tm_module;
    int pipe;

    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    TimeModeSetLive();

    unsigned int pipe_max = 1;
    if (ncpus > 1)
        pipe_max = ncpus - 1;

    intmax_t threads;

    if (ConfGetInt("mpipe.threads", &threads) == 1) {
        tile_num_pipelines = threads;
    } else {
        tile_num_pipelines = pipe_max;
    }
    SCLogInfo("%d Tilera worker threads", tile_num_pipelines);

    ReceiveMpipeInit();

    char *mpipe_dev = NULL;
    int nlive = LiveGetDeviceCount();
    if (nlive > 0) {
        SCLogInfo("Using %d live device(s).", nlive);
        /*mpipe_dev = LiveGetDevice(0);*/
    } else {
        /*
         * Attempt to get interface from config file
         * overrides -i from command line.
         */
        if (ConfGet("mpipe.interface", &mpipe_dev) == 0) {
            if (ConfGet("mpipe.single_mpipe_dev", &mpipe_dev) == 0) {
                SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                           "mpipe.single_mpipe_dev from Conf");
                exit(EXIT_FAILURE);
            }
        }
    }

    /* Get affinity for worker */
    cpu_set_t cpus;
    //int result = tmc_cpus_get_my_affinity(&cpus);
    int result = tmc_cpus_get_dataplane_cpus(&cpus);
    if (result < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "tmc_cpus_get_my_affinity() returned=%d", result);
        SCReturnInt(TM_ECODE_FAILED);
    }

    for (pipe = 0; pipe < tile_num_pipelines; pipe++) {
        char *mpipe_devc;

        if (nlive > 0) {
            mpipe_devc = SCStrdup("multi");
        } else {
            mpipe_devc = SCStrdup(mpipe_dev);
        }
        if (unlikely(mpipe_devc == NULL)) {
            printf("ERROR: SCStrdup failed for ReceiveMpipe\n");
            exit(EXIT_FAILURE);
        }

        snprintf(tname, sizeof(tname), "%s#%02d", thread_name_workers, pipe+1);

        /* create the threads */
        ThreadVars *tv_worker =
             TmThreadCreatePacketHandler(tname,
                                         "packetpool", "packetpool",
                                         "packetpool", "packetpool", 
                                         "pktacqloop");
        if (tv_worker == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceiveMpipe");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceiveMpipe\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker, tm_module, (void *)mpipe_devc);

	/* Bind to a single cpu. */
	int pipe_cpu = tmc_cpus_find_nth_cpu(&cpus, pipe);
	tv_worker->rank = pipe;

        TmThreadSetCPUAffinity(tv_worker, pipe_cpu);

        tm_module = TmModuleGetByName("DecodeMpipe");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeMpipe failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

        SetupOutputs(tv_worker);

        if (TmThreadSpawn(tv_worker) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

#endif
