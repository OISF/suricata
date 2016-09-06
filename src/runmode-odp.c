/* Copyright (C) 2016 Linaro
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
 * \author Maxim Uvarov <maxim.uvarov@linaro.org>
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

/** packet size in the pool pluse
 * Suricata Packet struct size */
#define POOL_SIZE 9000
/** Number of packets in the pool */
#define POOL_NUM  1000

odp_instance_t instance;
extern int max_pending_packets;

static const char *default_mode_workers = NULL;

const char *RunModeODPGetDefaultMode()
{
    return default_mode_workers;
}

static void *ParseODPConfig(const char *iface_name)
{
    ODPIfaceConfig *conf = SCMalloc(sizeof(*conf));

    if (unlikely(conf == NULL)) {
        return NULL;
    }

    return conf;
}

static int ODPConfigGeThreadsCount(void *conf)
{
    odp_cpumask_t cpumask;
    int max_cpus = 0; /* all available worker cpus */

    return odp_cpumask_default_worker(&cpumask, max_cpus);
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
    odp_pktio_param_t pktio_param;
    odp_pool_param_t pool_params;
    odp_pool_t pool;
    odp_pktio_t pktio;
    odp_pktin_queue_param_t pktin_param;
    int ret;
    char *live_dev = NULL;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("odp.live-interface", &live_dev);

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

    ret = RunModeSetLiveCaptureWorkers(
            ParseODPConfig,
            ODPConfigGeThreadsCount,
            "ReceiveODP",
            "DecodeODP", "ODPPkt",
            live_dev);
    if (ret != 0) {
        printf("%s()%d fail to set capture mode\n", __func__, __LINE__);
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
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

    odp_pktio_param_init(&pktio_param);
    pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
    pktio_param.out_mode = ODP_PKTIN_MODE_SCHED;

    pktio = odp_pktio_open(live_dev, pool, &pktio_param);
    if (pktio == ODP_PKTIO_INVALID) {
        fprintf(stderr, "Error: pktio create failed for %s\n", "eth0");
        exit(EXIT_FAILURE);
    }

    odp_pktin_queue_param_init(&pktin_param);

    if (odp_pktin_queue_config(pktio, &pktin_param))
        printf("pktin config fail\n");

    ret = odp_pktio_start(pktio);
    if (ret)
        fprintf(stderr, "Error: unable to start\n");

    SCLogDebug("RunModeIdsODPWorkers initialised");
    SCReturnInt(0);
}
#endif /* HAVE_ODP */
