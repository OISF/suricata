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

    SCLogDebug("Initialize affinity setup\n");
    /* be conservative relatively to OS: use all cpus by default */
    for (i = 0; i < MAX_CPU_SET; i++) {
        cpu_set_t *cs = &thread_affinity[i].cpu_set;
        CPU_ZERO(cs);
        for (j = 0; j < ncpu; j++) {
            CPU_SET(j, cs);
        }
        SCMutexInit(&thread_affinity[i].taf_mutex, NULL);
    }
    return;
}

void BuildCpusetWithCallback(const char *name, ConfNode *node,
                             void (*Callback)(int i, void * data),
                             void *data)
{
    ConfNode *lnode;
    TAILQ_FOREACH(lnode, &node->head, next) {
        int i;
        long int a,b;
        int stop = 0;
        int max = UtilCpuGetNumProcessorsOnline() - 1;
        if (!strcmp(lnode->val, "all")) {
            a = 0;
            b = max;
            stop = 1;
        } else if (strchr(lnode->val, '-') != NULL) {
            char *sep = strchr(lnode->val, '-');
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != sep) {
                SCLogError("%s: invalid cpu range (start invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            b = strtol(sep + 1, &end, 10);
            if (end != sep + strlen(sep)) {
                SCLogError("%s: invalid cpu range (end invalid): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (a > b) {
                SCLogError("%s: invalid cpu range (bad order): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            if (b > max) {
                SCLogError("%s: upper bound (%ld) of cpu set is too high, only %d cpu(s)", name, b,
                        max + 1);
            }
        } else {
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != lnode->val + strlen(lnode->val)) {
                SCLogError("%s: invalid cpu range (not an integer): \"%s\"", name, lnode->val);
                exit(EXIT_FAILURE);
            }
            b = a;
        }
        for (i = a; i<= b; i++) {
            Callback(i, data);
        }
        if (stop)
            break;
    }
}

static void AffinityCallback(int i, void *data)
{
    CPU_SET(i, (cpu_set_t *)data);
}

static void BuildCpuset(const char *name, ConfNode *node, cpu_set_t *cpu)
{
    BuildCpusetWithCallback(name, node, AffinityCallback, (void *) cpu);
}
#endif /* OS_WIN32 and __OpenBSD__ */

/**
 * \brief Extract cpu affinity configuration from current config file
 */

void AffinitySetupLoadFromConfig(void)
{
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    ConfNode *root = ConfGetNode("threading.cpu-affinity");
    ConfNode *affinity;

    if (thread_affinity_init_done == 0) {
        AffinitySetupInit();
        thread_affinity_init_done = 1;
    }

    SCLogDebug("Load affinity from config\n");
    if (root == NULL) {
        SCLogInfo("can't get cpu-affinity node");
        return;
    }

    TAILQ_FOREACH(affinity, &root->head, next) {
        if (strcmp(affinity->val, "decode-cpu-set") == 0 ||
            strcmp(affinity->val, "stream-cpu-set") == 0 ||
            strcmp(affinity->val, "reject-cpu-set") == 0 ||
            strcmp(affinity->val, "output-cpu-set") == 0) {
            continue;
        }

        const char *setname = affinity->val;
        if (strcmp(affinity->val, "detect-cpu-set") == 0)
            setname = "worker-cpu-set";

        ThreadsAffinityType *taf = GetAffinityTypeFromName(setname);
        ConfNode *node = NULL;
        ConfNode *nprio = NULL;

        if (taf == NULL) {
            FatalError("unknown cpu-affinity type");
        } else {
            SCLogConfig("Found affinity definition for \"%s\"", setname);
        }

        CPU_ZERO(&taf->cpu_set);
        node = ConfNodeLookupChild(affinity->head.tqh_first, "cpu");
        if (node == NULL) {
            SCLogInfo("unable to find 'cpu'");
        } else {
            BuildCpuset(setname, node, &taf->cpu_set);
        }

        CPU_ZERO(&taf->lowprio_cpu);
        CPU_ZERO(&taf->medprio_cpu);
        CPU_ZERO(&taf->hiprio_cpu);
        nprio = ConfNodeLookupChild(affinity->head.tqh_first, "prio");
        if (nprio != NULL) {
            node = ConfNodeLookupChild(nprio, "low");
            if (node == NULL) {
                SCLogDebug("unable to find 'low' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->lowprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "medium");
            if (node == NULL) {
                SCLogDebug("unable to find 'medium' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->medprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "high");
            if (node == NULL) {
                SCLogDebug("unable to find 'high' prio using default value");
            } else {
                BuildCpuset(setname, node, &taf->hiprio_cpu);
            }
            node = ConfNodeLookupChild(nprio, "default");
            if (node != NULL) {
                if (!strcmp(node->val, "low")) {
                    taf->prio = PRIO_LOW;
                } else if (!strcmp(node->val, "medium")) {
                    taf->prio = PRIO_MEDIUM;
                } else if (!strcmp(node->val, "high")) {
                    taf->prio = PRIO_HIGH;
                } else {
                    FatalError("unknown cpu_affinity prio");
                }
                SCLogConfig("Using default prio '%s' for set '%s'",
                        node->val, setname);
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "mode");
        if (node != NULL) {
            if (!strcmp(node->val, "exclusive")) {
                taf->mode_flag = EXCLUSIVE_AFFINITY;
            } else if (!strcmp(node->val, "balanced")) {
                taf->mode_flag = BALANCED_AFFINITY;
            } else {
                FatalError("unknown cpu_affinity node");
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "threads");
        if (node != NULL) {
            if (StringParseUint32(&taf->nb_threads, 10, 0, (const char *)node->val) < 0) {
                FatalError("invalid value for threads "
                           "count: '%s'",
                        node->val);
            }
            if (! taf->nb_threads) {
                FatalError("bad value for threads count");
            }
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
    int iter = 0;
    SCMutexLock(&taf->taf_mutex);
    ncpu = taf->lcpu;
    while (!CPU_ISSET(ncpu, &taf->cpu_set) && iter < 2) {
        ncpu++;
        if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
            ncpu = 0;
            iter++;
        }
    }
    if (iter == 2) {
        SCLogError("cpu_set does not contain "
                   "available cpus, cpu affinity conf is invalid");
    }
    taf->lcpu = ncpu + 1;
    if (taf->lcpu >= UtilCpuGetNumProcessorsOnline())
        taf->lcpu = 0;
    SCMutexUnlock(&taf->taf_mutex);
    SCLogDebug("Setting affinity on CPU %d", ncpu);
#endif /* OS_WIN32 and __OpenBSD__ */
    return ncpu;
}

uint16_t UtilAffinityGetAffinedCPUNum(ThreadsAffinityType *taf)
{
    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    SCMutexLock(&taf->taf_mutex);
    for (int i = UtilCpuGetNumProcessorsOnline(); i >= 0; i--)
        if (CPU_ISSET(i, &taf->cpu_set))
            ncpu++;
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
        if (CPU_ISSET(i, &tmpcset))
            return 1;
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
    SCMutexLock(&mod_taf->taf_mutex);
    SCMutexLock(&static_taf->taf_mutex);
    int max_cpus = UtilCpuGetNumProcessorsOnline();
    for (int cpu = 0; cpu < max_cpus; cpu++) {
        if (CPU_ISSET(cpu, &mod_taf->cpu_set) && CPU_ISSET(cpu, &static_taf->cpu_set)) {
            CPU_CLR(cpu, &mod_taf->cpu_set);
        }
    }
    SCMutexUnlock(&static_taf->taf_mutex);
    SCMutexUnlock(&mod_taf->taf_mutex);
}
#endif /* HAVE_DPDK */
