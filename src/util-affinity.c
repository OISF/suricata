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

static hwloc_topology_t topology = NULL;

// int DeviceGetNumaID(hwloc_topology_t topology, hwloc_obj_t obj) {
//     hwloc_obj_t numa_node = NULL;
//     while ((numa_node = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_NUMANODE, numa_node)) != NULL) {
//         SCLogNotice("another numa");
//     }

//     hwloc_obj_t parent = obj->parent;
//     while (parent) {
//         printf("Object type: %s\n", hwloc_obj_type_string(parent->type));
//         if (parent->type == HWLOC_OBJ_NUMANODE) {
//             return parent->logical_index;
//         }
//         parent = parent->parent;
//     }

//     return -1;
// }
int DeviceGetNumaID(hwloc_topology_t topology, hwloc_obj_t obj) {
    hwloc_obj_t non_io_ancestor = hwloc_get_non_io_ancestor_obj(topology, obj);
    if (non_io_ancestor == NULL) {
        fprintf(stderr, "Failed to find non-IO ancestor object.\n");
        return -1;
    }

    // Iterate over NUMA nodes and check their nodeset
    hwloc_obj_t numa_node = NULL;
    while ((numa_node = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_NUMANODE, numa_node)) != NULL) {
        if (hwloc_bitmap_isset(non_io_ancestor->nodeset, numa_node->os_index)) {
            return numa_node->logical_index;
        }
    }

    return -1;
}

void get_numa_nodes_from_pcie(hwloc_topology_t topology, hwloc_obj_t pcie_obj) {
    hwloc_obj_t nodes[16]; // Assuming a maximum of 16 NUMA nodes
    unsigned num_nodes = 16;
    struct hwloc_location location;
    
    location.type = HWLOC_LOCATION_TYPE_OBJECT;
    location.location.object = pcie_obj;

    int result = hwloc_get_local_numanode_objs(topology, &location, &num_nodes, nodes, 0);
    if (result == 0 && num_nodes > 0) {
        printf("NUMA nodes for PCIe device:\n");
        for (unsigned i = 0; i < num_nodes; i++) {
            printf("NUMA node %d\n", nodes[i]->logical_index);
        }
    } else {
        printf("No NUMA node found for PCIe device.\n");
    }
}



// Static function to find the NUMA node of a given hwloc object
static hwloc_obj_t find_numa_node(hwloc_topology_t topology, hwloc_obj_t obj) {
    if (!obj) {
        fprintf(stderr, "Invalid hwloc object.\n");
        return NULL;
    }

    hwloc_obj_t parent = obj->parent;
    while (parent) {
        printf("Object type: %s\n", hwloc_obj_type_string(parent->type));
        if (parent->type == HWLOC_OBJ_PACKAGE || parent->type == HWLOC_OBJ_NUMANODE) {
            break;
        }
        parent = parent->parent;
    }

    if (parent == NULL) {
        fprintf(stderr, "No parent found for the given object.\n");
        return NULL;
    }

    // Iterate over all NUMA nodes and check if they intersect with the given object
    hwloc_obj_t numa_node = NULL;
    while ((numa_node = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_NUMANODE, numa_node)) != NULL) {
        if (hwloc_bitmap_intersects(parent->cpuset, numa_node->cpuset)) {
            return numa_node;
        }
    }

    return NULL;
}

hwloc_obj_t find_pcie_address(hwloc_topology_t topology, const char *interface_name) {
    hwloc_obj_t obj = NULL;

    while ((obj = hwloc_get_next_osdev(topology, obj)) != NULL) {
        if (obj->attr->osdev.type == HWLOC_OBJ_OSDEV_NETWORK && strcmp(obj->name, interface_name) == 0) {
            hwloc_obj_t parent = obj->parent;
            while (parent) {
                if (parent->type == HWLOC_OBJ_PCI_DEVICE) {
                    return parent;
                }
                parent = parent->parent;
            }
        }
    }
    return NULL;
}

// Static function to deparse PCIe interface string name to individual components
static void deparse_pcie_address(const char *pcie_address, unsigned int *domain, unsigned int *bus, unsigned int *device, unsigned int *function) {
    *domain = 0; // Default domain to 0 if not provided

    // Handle both full and short PCIe address formats
    if (sscanf(pcie_address, "%x:%x:%x.%x", domain, bus, device, function) != 4) {
        if (sscanf(pcie_address, "%x:%x.%x", bus, device, function) != 3) {
            fprintf(stderr, "Error parsing PCIe address: %s\n", pcie_address);
            exit(EXIT_FAILURE);
        }
    }
}

// Function to convert PCIe address to hwloc object
hwloc_obj_t get_hwloc_object_from_pcie_address(hwloc_topology_t topology, const char *pcie_address) {
    hwloc_obj_t obj = NULL;
    unsigned int domain, bus, device, function;
    deparse_pcie_address(pcie_address, &domain, &bus, &device, &function);
    while ((obj = hwloc_get_next_pcidev(topology, obj)) != NULL) {
        if (obj->attr->pcidev.domain == domain && obj->attr->pcidev.bus == bus && obj->attr->pcidev.dev == device && obj->attr->pcidev.func == function) {
            return obj;
        }
    }
    return NULL;
}

// Function to print hwloc object attributes
void print_hwloc_object(hwloc_obj_t obj) {
    if (!obj) {
        printf("No object found for the given PCIe address.\n");
        return;
    }

    printf("Object type: %s\n", hwloc_obj_type_string(obj->type));
    printf("Logical index: %u\n", obj->logical_index);
    printf("Depth: %u\n", obj->depth);
    printf("Attributes:\n");
    if (obj->type == HWLOC_OBJ_PCI_DEVICE) {
        printf("  Domain: %04x\n", obj->attr->pcidev.domain);
        printf("  Bus: %02x\n", obj->attr->pcidev.bus);
        printf("  Device: %02x\n", obj->attr->pcidev.dev);
        printf("  Function: %01x\n", obj->attr->pcidev.func);
        printf("  Class ID: %04x\n", obj->attr->pcidev.class_id);
        printf("  Vendor ID: %04x\n", obj->attr->pcidev.vendor_id);
        printf("  Device ID: %04x\n", obj->attr->pcidev.device_id);
        printf("  Subvendor ID: %04x\n", obj->attr->pcidev.subvendor_id);
        printf("  Subdevice ID: %04x\n", obj->attr->pcidev.subdevice_id);
        printf("  Revision: %02x\n", obj->attr->pcidev.revision);
        printf("  Link speed: %f GB/s\n", obj->attr->pcidev.linkspeed);
    } else {
        printf("  No PCI device attributes available.\n");
    }
}


/**
 * \brief Return next cpu to use for a given thread family
 * \retval the cpu to used given by its id
 */
uint16_t AffinityGetNextCPU(ThreadsAffinityType *taf)
{
    if (topology == NULL) {
        if (hwloc_topology_init(&topology) == -1) {
            FatalError("Failed to initialize topology");
        }

        // hwloc_topology_get_flags

        int ret = hwloc_topology_set_flags(topology, HWLOC_TOPOLOGY_FLAG_WHOLE_SYSTEM);
        ret = hwloc_topology_set_io_types_filter(topology,  HWLOC_TYPE_FILTER_KEEP_ALL);
        if (ret == -1) {
            FatalError("Failed to set topology flags");
            hwloc_topology_destroy(topology);
        }

        if (hwloc_topology_load(topology) == -1) {
            FatalError("Failed to load topology");
            hwloc_topology_destroy(topology);
        }
    }

    hwloc_obj_t obj1 = get_hwloc_object_from_pcie_address(topology, "0000:17:00.0");
    // print_hwloc_object(obj1);

    obj1 = find_pcie_address(topology, "ens1f1");
    if (obj1 != NULL) {
        static char pcie_address[32];
        snprintf(pcie_address, sizeof(pcie_address), "%04x:%02x:%02x.%x", obj1->attr->pcidev.domain, obj1->attr->pcidev.bus, obj1->attr->pcidev.dev, obj1->attr->pcidev.func);
        SCLogNotice("PCIe addr of ens1f0 is %s with NUMA id %d or %p", pcie_address, DeviceGetNumaID(topology, obj1), find_numa_node(topology, obj1));
    }

    get_numa_nodes_from_pcie(topology, obj1);
    
    int core_id = 3; // Example core ID
    int depth = hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE);
    hwloc_obj_t numa_node = NULL;

    while ((numa_node = hwloc_get_next_obj_by_depth(topology, depth, numa_node)) != NULL) {
        hwloc_cpuset_t cpuset = hwloc_bitmap_alloc();
        hwloc_bitmap_copy(cpuset, numa_node->cpuset);

        if (hwloc_bitmap_isset(cpuset, core_id)) {
            printf("Core %d belongs to NUMA node %d\n", core_id, numa_node->logical_index);
            hwloc_bitmap_free(cpuset);
            break;
        }
        hwloc_bitmap_free(cpuset);
    }

    FatalError("ok enough");
    


    // if (topology != NULL) {
    //     int numa = get_numa_node_for_net_device(topology, "ens1f0");
    //     FatalError("NUMA node for ens1f0: %d\n", numa);
    // }
    // hwloc_topology_destroy(topology);

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


// uint16_t AffinityGetNextCPUFromNUMANode(ThreadsAffinityType *taf, int numa_node) {
//     uint16_t ncpu = 0;
// #if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
//     int iter = 0;
//     SCMutexLock(&taf->taf_mutex);
//     ncpu = taf->lcpu;

//     // Check for CPUs within the preferred NUMA node first
//     while (!CPU_ISSET(ncpu, &taf->cpu_set) || hwloc_get_obj_by_os_index(topology, HWLOC_OBJ_PU, ncpu)->nodeset->first != numa_node) {
//         ncpu++;
//         if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
//             ncpu = 0;
//             iter++;
//         }
//         if (iter >= 2) {
//             break;
//         }
//     }

//     if (iter == 2) {
//         // Fallback to any available CPU if no CPU found within the preferred NUMA node
//         ncpu = taf->lcpu;
//         while (!CPU_ISSET(ncpu, &taf->cpu_set) && iter < 2) {
//             ncpu++;
//             if (ncpu >= UtilCpuGetNumProcessorsOnline()) {
//                 ncpu = 0;
//                 iter++;
//             }
//         }
//         if (iter == 2) {
//             SCLogError("cpu_set does not contain "
//                        "available cpus, cpu affinity conf is invalid");
//         }
//     }

//     taf->lcpu = ncpu + 1;
//     if (taf->lcpu >= UtilCpuGetNumProcessorsOnline())
//         taf->lcpu = 0;
//     SCMutexUnlock(&taf->taf_mutex);
//     SCLogDebug("Setting affinity on CPU %d", ncpu);
// #endif /* OS_WIN32 and __OpenBSD__ */
//     return ncpu;
// }

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
    cpu_set_t tmpset;
    SCMutexLock(&mod_taf->taf_mutex);
    SCMutexLock(&static_taf->taf_mutex);
    CPU_XOR(&tmpset, &mod_taf->cpu_set, &static_taf->cpu_set);
    SCMutexUnlock(&static_taf->taf_mutex);
    mod_taf->cpu_set = tmpset;
    SCMutexUnlock(&mod_taf->taf_mutex);
}
#endif /* HAVE_DPDK */
