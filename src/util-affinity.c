/* Copyright (C) 2010-2016 Open Information Security Foundation
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

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 *
 *  CPU affinity related code and helper.
 */

#include "suricata-common.h"
#define _THREAD_AFFINITY
#include "util-affinity.h"
#include "conf.h"
#include "runmodes.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-debug.h"

ThreadsAffinityType thread_affinity[MAX_CPU_SET] = {
    {
            .name = "receive-cpu-set",
            .mode_flag = EXCLUSIVE_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = 0,
    },
    {
            .name = "worker-cpu-set",
            .mode_flag = EXCLUSIVE_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = 0,
    },
    {
            .name = "verdict-cpu-set",
            .mode_flag = BALANCED_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = 0,
    },
    {
            .name = "management-cpu-set",
            .mode_flag = BALANCED_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = 0,
    },

};

int thread_affinity_init_done = 0;

/**
 * \brief find affinity by its name
 * \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType * GetAffinityTypeFromName(const char *name)
{
    int i;
    for (i = 0; i < MAX_CPU_SET; i++) {
        if (!strcmp(thread_affinity[i].name, name)) {
            return &thread_affinity[i];
        }
    }
    return NULL;
}

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
static void AffinitySetupInit(void)
{
    int i, j;
    int ncpu = UtilCpuGetNumProcessorsConfigured();

    SCLogDebug("Initialize CPU affinity setup");
    /* be conservative relatively to OS: use all cpus by default */
    for (i = 0; i < MAX_CPU_SET; i++) {
        cpu_set_t *cs = &thread_affinity[i].cpu_set;
        CPU_ZERO(cs);
        for (j = 0; j < ncpu; j++) {
            CPU_SET(j, cs);
        }
        SCMutexInit(&thread_affinity[i].taf_mutex, NULL);
    }
}

void BuildCpusetWithCallback(
        const char *name, SCConfNode *node, void (*Callback)(int i, void *data), void *data)
{
    SCConfNode *lnode;
    TAILQ_FOREACH(lnode, &node->head, next) {
        uint32_t i;
        uint32_t a, b;
        uint32_t stop = 0;
        uint32_t max = UtilCpuGetNumProcessorsOnline();
        if (max > 0) {
            max--;
        }
        if (!strcmp(lnode->val, "all")) {
            a = 0;
            b = max;
            stop = 1;
        } else if (strchr(lnode->val, '-') != NULL) {
            char *sep = strchr(lnode->val, '-');
            if (StringParseUint32(&a, 10, sep - lnode->val, lnode->val) < 0) {
                SCLogError("%s: invalid cpu range (start invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (StringParseUint32(&b, 10, strlen(sep) - 1, sep + 1) < 0) {
                SCLogError("%s: invalid cpu range (end invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (a > b) {
                SCLogError("%s: invalid cpu range (bad order): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (b > max) {
                SCLogError("%s: upper bound (%d) of cpu set is too high, only %d cpu(s)", name, b,
                        max + 1);
            }
        } else {
            if (StringParseUint32(&a, 10, strlen(lnode->val), lnode->val) < 0) {
                SCLogError("%s: invalid cpu range (not an integer): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            b = a;
        }
        for (i = a; i<= b; i++) {
            Callback(i, data);
        }
        if (stop) {
            break;
        }
    }
}

static void AffinityCallback(int i, void *data)
{
    CPU_SET(i, (cpu_set_t *)data);
}

static void BuildCpuset(const char *name, SCConfNode *node, cpu_set_t *cpu)
{
    BuildCpusetWithCallback(name, node, AffinityCallback, (void *) cpu);
}

/**
 * \brief Get the appropriate set name for a given affinity value.
 */
static const char *GetAffinitySetName(const char *val)
{
    if (strcmp(val, "decode-cpu-set") == 0 || strcmp(val, "stream-cpu-set") == 0 ||
            strcmp(val, "reject-cpu-set") == 0 || strcmp(val, "output-cpu-set") == 0) {
        return NULL;
    }

    return (strcmp(val, "detect-cpu-set") == 0) ? "worker-cpu-set" : val;
}

/**
 * \brief Set up CPU sets for the given affinity type.
 */
static void SetupCpuSets(ThreadsAffinityType *taf, SCConfNode *affinity, const char *setname)
{
    CPU_ZERO(&taf->cpu_set);

    SCConfNode *cpu_node = SCConfNodeLookupChild(affinity->head.tqh_first, "cpu");
    if (cpu_node != NULL) {
        BuildCpuset(setname, cpu_node, &taf->cpu_set);
    } else {
        SCLogWarning("Unable to find 'cpu' node for set %s", setname);
    }
}

/**
 * \brief Build a priority CPU set for the given priority level.
 */
static void BuildPriorityCpuset(ThreadsAffinityType *taf, SCConfNode *prio_node,
        const char *priority, cpu_set_t *cpuset, const char *setname)
{
    SCConfNode *node = SCConfNodeLookupChild(prio_node, priority);
    if (node != NULL) {
        BuildCpuset(setname, node, cpuset);
    } else {
        SCLogDebug("Unable to find '%s' priority for set %s", priority, setname);
    }
}

/**
 * \brief Set up the default priority for the given affinity type.
 * \retval 0 on success, -1 on error
 */
static int SetupDefaultPriority(
        ThreadsAffinityType *taf, SCConfNode *prio_node, const char *setname)
{
    SCConfNode *default_node = SCConfNodeLookupChild(prio_node, "default");
    if (default_node == NULL) {
        return 0;
    }

    if (strcmp(default_node->val, "low") == 0) {
        taf->prio = PRIO_LOW;
    } else if (strcmp(default_node->val, "medium") == 0) {
        taf->prio = PRIO_MEDIUM;
    } else if (strcmp(default_node->val, "high") == 0) {
        taf->prio = PRIO_HIGH;
    } else {
        SCLogError("Unknown default CPU affinity priority: %s", default_node->val);
        return -1;
    }

    SCLogConfig("Using default priority '%s' for set %s", default_node->val, setname);
    return 0;
}

/**
 * \brief Set up priority CPU sets for the given affinity type.
 * \retval 0 on success, -1 on error
 */
static int SetupAffinityPriority(
        ThreadsAffinityType *taf, SCConfNode *affinity, const char *setname)
{
    CPU_ZERO(&taf->lowprio_cpu);
    CPU_ZERO(&taf->medprio_cpu);
    CPU_ZERO(&taf->hiprio_cpu);

    SCConfNode *prio_node = SCConfNodeLookupChild(affinity->head.tqh_first, "prio");
    if (prio_node == NULL) {
        return 0;
    }

    BuildPriorityCpuset(taf, prio_node, "low", &taf->lowprio_cpu, setname);
    BuildPriorityCpuset(taf, prio_node, "medium", &taf->medprio_cpu, setname);
    BuildPriorityCpuset(taf, prio_node, "high", &taf->hiprio_cpu, setname);
    return SetupDefaultPriority(taf, prio_node, setname);
}

/**
 * \brief Set up CPU affinity mode for the given affinity type.
 * \retval 0 on success, -1 on error
 */
static int SetupAffinityMode(ThreadsAffinityType *taf, SCConfNode *affinity)
{
    SCConfNode *mode_node = SCConfNodeLookupChild(affinity->head.tqh_first, "mode");
    if (mode_node == NULL) {
        return 0;
    }

    if (strcmp(mode_node->val, "exclusive") == 0) {
        taf->mode_flag = EXCLUSIVE_AFFINITY;
    } else if (strcmp(mode_node->val, "balanced") == 0) {
        taf->mode_flag = BALANCED_AFFINITY;
    } else {
        SCLogError("Unknown CPU affinity mode: %s", mode_node->val);
        return -1;
    }
    return 0;
}

/**
 * \brief Set up the number of threads for the given affinity type.
 * \retval 0 on success, -1 on error
 */
static int SetupAffinityThreads(ThreadsAffinityType *taf, SCConfNode *affinity)
{
    SCConfNode *threads_node = SCConfNodeLookupChild(affinity->head.tqh_first, "threads");
    if (threads_node == NULL) {
        return 0;
    }

    if (StringParseUint32(&taf->nb_threads, 10, 0, threads_node->val) < 0 || taf->nb_threads == 0) {
        SCLogError("Invalid thread count: %s", threads_node->val);
        return -1;
    }
    return 0;
}

static bool AllCPUsUsed(ThreadsAffinityType *taf)
{
    if (taf->lcpu < UtilCpuGetNumProcessorsOnline()) {
        return false;
    }
    return true;
}

static void ResetCPUs(ThreadsAffinityType *taf)
{
    taf->lcpu = 0;
}

static uint16_t GetNextAvailableCPU(ThreadsAffinityType *taf)
{
    uint16_t cpu = taf->lcpu;
    int attempts = 0;

    while (!CPU_ISSET(cpu, &taf->cpu_set) && attempts < 2) {
        cpu = (cpu + 1) % UtilCpuGetNumProcessorsOnline();
        if (cpu == 0)
            attempts++;
    }

    taf->lcpu = cpu + 1;

    if (attempts == 2) {
        SCLogError(
                "cpu_set does not contain available CPUs, CPU affinity configuration is invalid");
    }

    return cpu;
}
#endif /* OS_WIN32 and __OpenBSD__ */

/**
 * \brief Extract CPU affinity configuration from current config file
 */
void AffinitySetupLoadFromConfig(void)
{
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    if (thread_affinity_init_done == 0) {
        AffinitySetupInit();
        thread_affinity_init_done = 1;
    }

    SCLogDebug("Loading threading.cpu-affinity from config");
    SCConfNode *root = SCConfGetNode("threading.cpu-affinity");
    if (root == NULL) {
        SCLogInfo("Cannot find threading.cpu-affinity node in config");
        return;
    }

    SCConfNode *affinity;
    TAILQ_FOREACH(affinity, &root->head, next) {
        const char *setname = GetAffinitySetName(affinity->val);
        if (setname == NULL) {
            continue;
        }

        ThreadsAffinityType *taf = GetAffinityTypeFromName(setname);
        if (taf == NULL) {
            SCLogError("Failed to allocate CPU affinity type: %s", setname);
            continue;
        }

        SCLogConfig("Found CPU affinity definition for \"%s\"", setname);

        SetupCpuSets(taf, affinity, setname);
        if (SetupAffinityPriority(taf, affinity, setname) < 0) {
            SCLogError("Failed to setup priority for CPU affinity type: %s", setname);
            continue;
        }
        if (SetupAffinityMode(taf, affinity) < 0) {
            SCLogError("Failed to setup mode for CPU affinity type: %s", setname);
            continue;
        }
        if (SetupAffinityThreads(taf, affinity) < 0) {
            SCLogError("Failed to setup threads for CPU affinity type: %s", setname);
            continue;
        }
    }
#endif /* OS_WIN32 and __OpenBSD__ */
}

/**
 * \brief Return next cpu to use for a given thread family
 * \retval the cpu to used given by its id
 */
uint16_t AffinityGetNextCPU(ThreadsAffinityType *taf)
{
    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    SCMutexLock(&taf->taf_mutex);
    ncpu = GetNextAvailableCPU(taf);

    if (AllCPUsUsed(taf)) {
        ResetCPUs(taf);
    }

    SCLogDebug("Setting affinity on CPU %d", ncpu);
    SCMutexUnlock(&taf->taf_mutex);
#endif /* OS_WIN32 and __OpenBSD__ */
    return ncpu;
}

/**
 * \brief Return the total number of CPUs in a given affinity
 * \retval the number of affined CPUs
 */
uint16_t UtilAffinityGetAffinedCPUNum(ThreadsAffinityType *taf)
{
    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    SCMutexLock(&taf->taf_mutex);
    for (int i = UtilCpuGetNumProcessorsOnline(); i >= 0; i--)
        if (CPU_ISSET(i, &taf->cpu_set)) {
            ncpu++;
        }
    SCMutexUnlock(&taf->taf_mutex);
#endif
    return ncpu;
}

#ifdef HAVE_DPDK
/**
 * Find if CPU sets overlap
 * \return 1 if CPUs overlap, 0 otherwise
 */
uint16_t UtilAffinityCpusOverlap(ThreadsAffinityType *taf1, ThreadsAffinityType *taf2)
{
    ThreadsAffinityType tmptaf;
    CPU_ZERO(&tmptaf);
    SCMutexInit(&tmptaf.taf_mutex, NULL);

    cpu_set_t tmpcset;

    SCMutexLock(&taf1->taf_mutex);
    SCMutexLock(&taf2->taf_mutex);
    CPU_AND(&tmpcset, &taf1->cpu_set, &taf2->cpu_set);
    SCMutexUnlock(&taf2->taf_mutex);
    SCMutexUnlock(&taf1->taf_mutex);

    for (int i = UtilCpuGetNumProcessorsOnline(); i >= 0; i--)
        if (CPU_ISSET(i, &tmpcset)) {
            return 1;
        }
    return 0;
}

/**
 * Function makes sure that CPUs of different types don't overlap by excluding
 * one affinity type from the other
 * \param mod_taf - CPU set to be modified
 * \param static_taf - static CPU set to be used only for evaluation
 */
void UtilAffinityCpusExclude(ThreadsAffinityType *mod_taf, ThreadsAffinityType *static_taf)
{
    cpu_set_t tmpset;
    SCMutexLock(&mod_taf->taf_mutex);
    SCMutexLock(&static_taf->taf_mutex);
    CPU_XOR(&tmpset, &mod_taf->cpu_set, &static_taf->cpu_set);
    SCMutexUnlock(&static_taf->taf_mutex);
    mod_taf->cpu_set = tmpset;
    SCMutexUnlock(&mod_taf->taf_mutex);
}
#endif /* HAVE_DPDK */
