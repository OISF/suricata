/* Copyright (C) 2026 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * DPDK threading utilities
 */

#include "suricata-common.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-dpdk-threading.h"
#include "util-debug.h"
#include "runmodes.h"
#include "util-dpdk-common.h"

#ifdef HAVE_DPDK

static thread_local bool stacksize_warn_once = false;

/**
 * \brief Wrapper function to convert ThreadVars thread function signature
 *        from void* (*)(void*) to int (*)(void*) for DPDK EAL threads.
 */
static int DpdkEalThreadWrapper(void *arg)
{
    ThreadVars *tv = (ThreadVars *)arg;
    tv->tm_func(tv);
    return 0;
}
#endif /* HAVE_DPDK */

void DpdkThreadSpawn(ThreadVars *tv)
{
#ifdef HAVE_DPDK
    if (threading_set_stack_size && SCConfGetNode("dpdk.eal-params.huge-worker-stack") == NULL) {
        if (!stacksize_warn_once) {
            stacksize_warn_once = true;
            SCLogWarning("DPDK worker threads do not support Suricata-configured stack size. "
                         "Use additional DPDK EAL argument huge-worker-stack:[size in kB without a "
                         "unit] "
                         "to also set stack size for DPDK worker threads.");
        }
    }
    if (!(tv->thread_setup_flags & THREAD_SET_AFFTYPE)) {
        FatalError("%s: DPDK requires set threading affinity setting", tv->iface_name);
    }
    ThreadsAffinityType *taf = &thread_affinity[tv->cpu_affinity];
    if (!RunmodeIsWorkers() || !(tv->cpu_affinity == WORKER_CPU_SET)) {
        FatalError("%s: DPDK EAL threads can only initialize worker threads", tv->iface_name);
    }

    ThreadsAffinityType *if_taf = FindAffinityByInterface(taf, tv->iface_name);
    if (if_taf) {
        taf = if_taf;
    }

    if (UtilAffinityGetAffinedCPUNum(taf) == 0) {
        if (!taf->nocpu_warned) {
            SCLogWarning("No CPU affinity set for %s", AffinityGetYamlPath(taf));
            taf->nocpu_warned = true;
        }
    }

    if (taf->mode_flag != EXCLUSIVE_AFFINITY) {
        FatalError("%s: DPDK requires exclusive affinity setting", tv->iface_name);
    }

    /* If CPU is in a set overwrite the default thread prio */
    if (CPU_ISSET(tv->lcore_id, &taf->lowprio_cpu)) {
        tv->thread_priority = PRIO_LOW;
    } else if (CPU_ISSET(tv->lcore_id, &taf->medprio_cpu)) {
        tv->thread_priority = PRIO_MEDIUM;
    } else if (CPU_ISSET(tv->lcore_id, &taf->hiprio_cpu)) {
        tv->thread_priority = PRIO_HIGH;
    } else {
        tv->thread_priority = taf->prio;
    }
    tv->thread_setup_flags =
            THREAD_SET_PRIORITY; // affinity is handled, prio handles the thread itself

    tv->lcore_id = AffinityGetNextCPU(tv, taf);

    SCLogPerf("Setting prio %d for thread \"%s\" to cpu/core "
              "%d, thread id %lu",
            tv->thread_priority, tv->name, tv->lcore_id, SCGetThreadIdLong());

    int ret = rte_eal_remote_launch(DpdkEalThreadWrapper, (void *)tv, tv->lcore_id);
    if (ret != 0) {
        FatalError("Unable to create DPDK EAL thread %s with rte_eal_remote_launch(): retval %d",
                tv->name, ret);
    }
#endif /* HAVE_DPDK */
}

void DpdkThreadJoin(ThreadVars *tv)
{
#ifdef HAVE_DPDK
    int ret = rte_eal_wait_lcore(tv->lcore_id);
    if (ret < 0) {
        SCLogError("%s: error waiting for DPDK lcore %" PRIu32 " (%s) to finish (%s)",
                tv->iface_name, tv->lcore_id, tv->name, rte_strerror(-ret));
    }
#endif /* HAVE_DPDK */
}
