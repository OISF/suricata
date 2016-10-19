/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Maxim Uvarov <maxim.uvarov@linaro.org>, Linaro
 *
 * OpenDataPlane runmode support
 */

#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-netmap.h"
#include "log-httplog.h"
#include "output.h"
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
#include "util-ioctl.h"

#ifdef HAVE_ODP

#include "source-odp.h"
#include <odp_api.h>

/* Maximum ODP packet size */
#define POOL_SIZE 9000
/** Number of packets in the pool */
#define POOL_NUM  1000

odp_instance_t instance;

static const char *default_mode_workers = NULL;

const char *RunModeODPGetDefaultMode()
{
    return default_mode_workers;
}

static int GetODPNumThreads(const char *iface_name)
{
    intmax_t max_workers = 0; /* get available ODP worker cpus from config */
    ConfNode *node;
    odp_cpumask_t cpumask;
    ConfNode *if_default = NULL;
    ConfNode *if_root = NULL;
    int ret;
    char *threads;

    node = ConfGetNode("odp");
    if (node == NULL) {
        SCLogInfo("Unable to find ODP node in config");
    } else {
        if_root = ConfFindDeviceConfig(node, iface_name);
        if_default = ConfFindDeviceConfig(node, "default");
        ret = ConfGetChildValueWithDefault(if_root, if_default, "threads", &threads);
	if (ret) {
		max_workers = atol(threads);
                SCLogInfo("Using odp.threads:%ld from config for %s\n",  max_workers, iface_name);
                return odp_cpumask_default_worker(&cpumask, (int)max_workers);
	}
    }

    SCLogInfo("No odp.max-workers in config, using 1 ODP worker thread per interface\n");
    return odp_cpumask_default_worker(&cpumask, 1);
}

static void *ParseODPConfig(const char *iface_name)
{
    ODPIfaceConfig *conf;
    odp_pool_t pool;
    odp_pktio_t pktio;
    odp_pktio_param_t pktio_param;
    odp_pktin_queue_param_t pktin_param;


    conf = SCMalloc(sizeof(*conf));
    if (conf == NULL) {
        SCLogError(SC_ERR_RUNMODE, "Error: alloc config\n");
        return NULL;
    }

    (void) SC_ATOMIC_SET(conf->threads, GetODPNumThreads(iface_name));

    pool = odp_pool_lookup("packet_pool");
    if (ODP_POOL_INVALID == pool) {
        SCLogError(SC_ERR_RUNMODE, "Error: unable to lookup pool\n");
        return NULL;
    }

    odp_pktio_param_init(&pktio_param);
    pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
    pktio_param.out_mode = ODP_PKTOUT_MODE_DISABLED;

    pktio = odp_pktio_open(iface_name, pool, &pktio_param);
    if (ODP_PKTIO_INVALID == pktio) {
        SCLogError(SC_ERR_RUNMODE, "Error: pktio create failed for %s\n", iface_name);
        return NULL;
    }

    odp_pktin_queue_param_init(&pktin_param);

    if (odp_pktin_queue_config(pktio, &pktin_param)) {
        SCLogError(SC_ERR_RUNMODE, "Error: queue_config failed for %s\n", iface_name);
        return NULL;
    }

    if (odp_pktio_start(pktio)) {
        SCLogError(SC_ERR_RUNMODE, "Error: unable to start pktio for %s\n", iface_name);
        return NULL;
    }

    SCLogDebug("%s initialised for %s\n", __func__, iface_name);
    return conf;
}

static int ODPConfigGeThreadsCount(void *conf)
{
   ODPIfaceConfig *ocfg = (ODPIfaceConfig *)conf;
   return SC_ATOMIC_GET(ocfg->threads);
}

void RunModeIdsODPRegister(void)
{
    default_mode_workers = "default";
    RunModeRegisterNewRunMode(RUNMODE_ODP, "default",
            "default odp mode",
            RunModeIdsODPWorkers);
    return;
}

int RunModeIdsODPWorkers(void)
{

    odp_pool_param_t pool_params;
    odp_pool_t pool;
    int ret;
    char *live_dev = NULL;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("interface", &live_dev);
    SCLogInfo("Using odp.interface=%s\n", live_dev);

    ret = odp_init_global(&instance, NULL, NULL);
    if (ret) {
        SCLogError(SC_ERR_RUNMODE, "error in odp_init_global");
        exit(EXIT_FAILURE);
    }

    ret = odp_init_local(instance, ODP_THREAD_WORKER);
    if (ret) {
        SCLogError(SC_ERR_RUNMODE, "error in odp_init_local");
        exit(EXIT_FAILURE);
    }

    odp_pool_param_init(&pool_params);
    pool_params.pkt.seg_len = POOL_SIZE;
    pool_params.pkt.len     = POOL_SIZE;
    pool_params.pkt.num     = POOL_NUM;
    pool_params.type        = ODP_POOL_PACKET;

    pool = odp_pool_create("packet_pool", &pool_params);
    if (pool == ODP_POOL_INVALID) {
        SCLogError(SC_ERR_RUNMODE, "error in odp_pool_create");
        exit(EXIT_FAILURE);
    }

    ret = RunModeSetLiveCaptureWorkers(
            ParseODPConfig,
            ODPConfigGeThreadsCount,
            "ReceiveODP",
            "DecodeODP", "ODPPkt",
            live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("%s initialised", __func__);
    SCReturnInt(0);
}
#endif /* HAVE_ODP */
