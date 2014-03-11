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

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 *
 *  CPU affinity related code and helper.
 */

#include "suricata-common.h"
#define _THREAD_AFFINITY
#include "util-affinity.h"
#include "util-cpu.h"
#include "conf.h"
#include "threads.h"
#include "queue.h"
#include "runmodes.h"

ThreadsAffinityType thread_affinity[MAX_CPU_SET] = {
    {
        .name = "receive-cpu-set",
        .mode_flag = EXCLUSIVE_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = 0,
    },
    {
        .name = "decode-cpu-set",
        .mode_flag = BALANCED_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = 0,
    },
    {
        .name = "stream-cpu-set",
        .mode_flag = BALANCED_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = 0,
    },
    {
        .name = "detect-cpu-set",
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
        .name = "reject-cpu-set",
        .mode_flag = BALANCED_AFFINITY,
        .prio = PRIO_MEDIUM,
        .lcpu = 0,
    },
    {
        .name = "output-cpu-set",
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

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__
static void AffinitySetupInit()
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

static void build_cpuset(char *name, ConfNode *node, cpu_set_t *cpu)
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
        } else if (index(lnode->val, '-') != NULL) {
            char *sep = index(lnode->val, '-');
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != sep) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "%s: invalid cpu range (start invalid): \"%s\"",
                        name,
                        lnode->val);
                exit(EXIT_FAILURE);
            }
            b = strtol(sep + 1, &end, 10);
            if (end != sep + strlen(sep)) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "%s: invalid cpu range (end invalid): \"%s\"",
                        name,
                        lnode->val);
                exit(EXIT_FAILURE);
            }
            if (a > b) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "%s: invalid cpu range (bad order): \"%s\"",
                        name,
                        lnode->val);
                exit(EXIT_FAILURE);
            }
            if (b > max) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "%s: upper bound (%ld) of cpu set is too high, only %d cpu(s)",
                           name,
                           b, max + 1);
            }
        } else {
            char *end;
            a = strtoul(lnode->val, &end, 10);
            if (end != lnode->val + strlen(lnode->val)) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "%s: invalid cpu range (not an integer): \"%s\"",
                        name,
                        lnode->val);
                exit(EXIT_FAILURE);
            }
            b = a;
        }
        for (i = a; i<= b; i++) {
            CPU_SET(i, cpu);
        }
        if (stop)
            break;
    }
}
#endif /* OS_WIN32 and __OpenBSD__ */

/**
 * \brief Extract cpu affinity configuration from current config file
 */

void AffinitySetupLoadFromConfig()
{
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__
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
        ThreadsAffinityType *taf = GetAffinityTypeFromName(affinity->val);
        ConfNode *node = NULL;
        ConfNode *nprio = NULL;

        if (taf == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "unknown cpu-affinity type");
            exit(EXIT_FAILURE);
        } else {
            SCLogInfo("Found affinity definition for \"%s\"",
                      affinity->val);
        }

        CPU_ZERO(&taf->cpu_set);
        node = ConfNodeLookupChild(affinity->head.tqh_first, "cpu");
        if (node == NULL) {
            SCLogInfo("unable to find 'cpu'");
        } else {
            build_cpuset(affinity->val, node, &taf->cpu_set);
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
                build_cpuset(affinity->val, node, &taf->lowprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "medium");
            if (node == NULL) {
                SCLogDebug("unable to find 'medium' prio using default value");
            } else {
                build_cpuset(affinity->val, node, &taf->medprio_cpu);
            }

            node = ConfNodeLookupChild(nprio, "high");
            if (node == NULL) {
                SCLogDebug("unable to find 'high' prio using default value");
            } else {
                build_cpuset(affinity->val, node, &taf->hiprio_cpu);
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
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "unknown cpu_affinity prio");
                    exit(EXIT_FAILURE);
                }
                SCLogInfo("Using default prio '%s'", node->val);
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "mode");
        if (node != NULL) {
            if (!strcmp(node->val, "exclusive")) {
                taf->mode_flag = EXCLUSIVE_AFFINITY;
            } else if (!strcmp(node->val, "balanced")) {
                taf->mode_flag = BALANCED_AFFINITY;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "unknown cpu_affinity node");
                exit(EXIT_FAILURE);
            }
        }

        node = ConfNodeLookupChild(affinity->head.tqh_first, "threads");
        if (node != NULL) {
            taf->nb_threads = atoi(node->val);
            if (! taf->nb_threads) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "bad value for threads count");
                exit(EXIT_FAILURE);
            }
        }
    }
#endif /* OS_WIN32 and __OpenBSD__ */
}

/**
 * \brief Return next cpu to use for a given thread family
 * \retval the cpu to used given by its id
 */
int AffinityGetNextCPU(ThreadsAffinityType *taf)
{
    int ncpu = 0;

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__
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
        SCLogError(SC_ERR_INVALID_ARGUMENT, "cpu_set does not contains available cpus, cpu afinity conf is invalid");
    }
    taf->lcpu = ncpu + 1;
    if (taf->lcpu >= UtilCpuGetNumProcessorsOnline())
        taf->lcpu = 0;
    SCMutexUnlock(&taf->taf_mutex);
    SCLogInfo("Setting affinity on CPU %d", ncpu);
#endif /* OS_WIN32 and __OpenBSD__ */
    return ncpu;
}
