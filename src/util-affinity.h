/* Copyright (C) 2010 Open Information Security Foundation
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
 */

#ifndef SURICATA_UTIL_AFFINITY_H
#define SURICATA_UTIL_AFFINITY_H
#include "suricata-common.h"
#include "conf.h"
#include "threads.h"
#include "threadvars.h"

#ifdef HAVE_HWLOC
#include <hwloc.h>
#endif /* HAVE_HWLOC */

#if defined OS_FREEBSD
#include <sched.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/cpuset.h>
#include <sys/thr.h>
#define cpu_set_t cpuset_t
#elif defined __OpenBSD__
#include <sched.h>
#include <sys/param.h>
#include <sys/resource.h>
#elif defined OS_DARWIN
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/thread_policy.h>
#define cpu_set_t thread_affinity_policy_data_t
#define CPU_SET(cpu_id, new_mask) (*(new_mask)).affinity_tag = (cpu_id + 1)
#define CPU_ISSET(cpu_id, new_mask) ((*(new_mask)).affinity_tag == (cpu_id + 1))
#define CPU_ZERO(new_mask) (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL
#endif

enum {
    RECEIVE_CPU_SET,
    WORKER_CPU_SET,
    VERDICT_CPU_SET,
    MANAGEMENT_CPU_SET,
    MAX_CPU_SET
};

enum {
    BALANCED_AFFINITY,
    EXCLUSIVE_AFFINITY,
    MAX_AFFINITY
};

#define MAX_NUMA_NODES 16

typedef struct ThreadsAffinityType_ {
    const char *name;
    struct ThreadsAffinityType_ **children;
    struct ThreadsAffinityType_ *parent; // e.g. worker-cpu-set for interfaces
    SCMutex taf_mutex;

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    cpu_set_t cpu_set;
    cpu_set_t lowprio_cpu;
    cpu_set_t medprio_cpu;
    cpu_set_t hiprio_cpu;
#endif
    int prio;
    uint32_t nb_threads;
    uint32_t nb_children;
    uint32_t nb_children_capacity;
    uint16_t lcpu[MAX_NUMA_NODES]; /* use by exclusive mode */
    uint8_t mode_flag;
    // a flag to avoid multiple warnings when no CPU is set
    bool nocpu_warned;
} ThreadsAffinityType;

/** store thread affinity mode for all type of threads */
#ifndef _THREAD_AFFINITY
extern ThreadsAffinityType thread_affinity[MAX_CPU_SET];
#endif

char *AffinityGetYamlPath(ThreadsAffinityType *taf);
void AffinitySetupLoadFromConfig(void);
ThreadsAffinityType *GetOrAllocAffinityTypeForIfaceOfName(
        const char *name, const char *interface_name);
ThreadsAffinityType *GetAffinityTypeForNameAndIface(const char *name, const char *interface_name);
ThreadsAffinityType *FindAffinityByInterface(
        ThreadsAffinityType *parent, const char *interface_name);

void TopologyDestroy(void);
uint16_t AffinityGetNextCPU(ThreadVars *tv, ThreadsAffinityType *taf);
uint16_t UtilAffinityGetAffinedCPUNum(ThreadsAffinityType *taf);
#ifdef HAVE_DPDK
uint16_t UtilAffinityCpusOverlap(ThreadsAffinityType *taf1, ThreadsAffinityType *taf2);
void UtilAffinityCpusExclude(ThreadsAffinityType *mod_taf, ThreadsAffinityType *static_taf);
#endif /* HAVE_DPDK */

int BuildCpusetWithCallback(
        const char *name, SCConfNode *node, void (*Callback)(int i, void *data), void *data);

#ifdef UNITTESTS
void ThreadingAffinityRegisterTests(void);
#endif

#endif /* SURICATA_UTIL_AFFINITY_H */
