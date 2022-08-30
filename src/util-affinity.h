/* Copyright (C) 2010-2022 Open Information Security Foundation
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

#ifndef __UTIL_AFFINITY_H__
#define __UTIL_AFFINITY_H__
#include "suricata-common.h"
#include "conf.h"

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

typedef struct ThreadsAffinityType_ {
    const char *name;
    uint8_t mode_flag;
    int prio;
    uint32_t nb_threads;
    SCMutex taf_mutex;
    uint16_t lcpu; /* use by exclusive mode */

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    cpu_set_t cpu_set;
    cpu_set_t lowprio_cpu;
    cpu_set_t medprio_cpu;
    cpu_set_t hiprio_cpu;
#endif
} ThreadsAffinityType;

/** store thread affinity mode for all type of threads */
#ifndef _THREAD_AFFINITY
extern ThreadsAffinityType thread_affinity[MAX_CPU_SET];
#endif

void AffinitySetupLoadFromConfig(void);
ThreadsAffinityType * GetAffinityTypeFromName(const char *name);

uint16_t AffinityGetNextCPU(ThreadsAffinityType *taf);

void BuildCpusetWithCallback(const char *name, ConfNode *node,
                             void (*Callback)(int i, void * data),
                             void *data);

#endif /* __UTIL_AFFINITY_H__ */
