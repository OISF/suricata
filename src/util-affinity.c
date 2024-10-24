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
            .lcpu = { 0 },
    },
    {
            .name = "worker-cpu-set",
            .mode_flag = EXCLUSIVE_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = { 0 },
    },
    {
            .name = "verdict-cpu-set",
            .mode_flag = BALANCED_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = { 0 },
    },
    {
            .name = "management-cpu-set",
            .mode_flag = BALANCED_AFFINITY,
            .prio = PRIO_MEDIUM,
            .lcpu = { 0 },
    },

};

int thread_affinity_init_done = 0;

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
static hwloc_topology_t topology = NULL;
#endif /* OS_WIN32 and __OpenBSD__ */

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

static ThreadsAffinityType *AllocAndInitAffinityType(
        const char *name, const char *interface_name, ThreadsAffinityType *parent)
{
    ThreadsAffinityType *new_affinity = SCCalloc(1, sizeof(ThreadsAffinityType));
    if (new_affinity == NULL) {
        FatalError("Unable to allocate memory for new affinity type");
    }

    new_affinity->name = strdup(interface_name);
    new_affinity->parent = parent;
    new_affinity->mode_flag = EXCLUSIVE_AFFINITY;
    new_affinity->prio = PRIO_MEDIUM;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        new_affinity->lcpu[i] = 0;
    }

    if (parent != NULL) {
        if (parent->nb_children == parent->nb_children_capacity) {
            parent->nb_children_capacity *= 2;
            parent->children = SCRealloc(
                    parent->children, parent->nb_children_capacity * sizeof(ThreadsAffinityType *));
            if (parent->children == NULL) {
                FatalError("Unable to reallocate memory for children affinity types");
            }
        }
        parent->children[parent->nb_children++] = new_affinity;
    }

    return new_affinity;
}

ThreadsAffinityType *FindAffinityByInterface(
        ThreadsAffinityType *parent, const char *interface_name)
{
    for (uint32_t i = 0; i < parent->nb_children; i++) {
        if (strcmp(parent->children[i]->name, interface_name) == 0) {
            return parent->children[i];
        }
    }
    return NULL;
}

/**
 * \brief find affinity by its name and interface name, if children are not allowed, then those are
 * alloced and initialized. \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType *GetAffinityTypeForNameAndIface(const char *name, const char *interface_name)
{
    int i;
    ThreadsAffinityType *parent_affinity = NULL;

    for (i = 0; i < MAX_CPU_SET; i++) {
        if (strcmp(thread_affinity[i].name, name) == 0) {
            parent_affinity = &thread_affinity[i];
            break;
        }
    }

    if (parent_affinity == NULL) {
        SCLogError("Affinity with name \"%s\" not found", name);
        return NULL;
    }

    if (interface_name != NULL) {
        ThreadsAffinityType *child_affinity =
                FindAffinityByInterface(parent_affinity, interface_name);
        // found or not found, it is returned
        return child_affinity;
    }

    return parent_affinity;
}

/**
 * \brief find affinity by its name and interface name, if children are not allowed, then those are
 * alloced and initialized. \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType *GetOrAllocAffinityTypeForIfaceOfName(
        const char *name, const char *interface_name)
{
    int i;
    ThreadsAffinityType *parent_affinity = NULL;

    for (i = 0; i < MAX_CPU_SET; i++) {
        if (strcmp(thread_affinity[i].name, name) == 0) {
            parent_affinity = &thread_affinity[i];
            break;
        }
    }

    if (parent_affinity == NULL) {
        SCLogError("Affinity with name \"%s\" not found", name);
        return NULL;
    }

    if (interface_name != NULL) {
        ThreadsAffinityType *child_affinity =
                FindAffinityByInterface(parent_affinity, interface_name);
        if (child_affinity != NULL) {
            return child_affinity;
        }

        // If not found, allocate and initialize a new child affinity
        return AllocAndInitAffinityType(name, interface_name, parent_affinity);
    }

    return parent_affinity;
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
static void SetupCpuSets(ThreadsAffinityType *taf, ConfNode *affinity, const char *setname)
{
    CPU_ZERO(&taf->cpu_set);

    ConfNode *cpu_node = ConfNodeLookupChild(affinity->head.tqh_first, "cpu");
    if (cpu_node != NULL) {
        BuildCpuset(setname, cpu_node, &taf->cpu_set);
    } else {
        SCLogInfo("Unable to find 'cpu' node for set %s", setname);
    }
}

/**
 * \brief Build a priority CPU set for the given priority level.
 */
static void BuildPriorityCpuset(ThreadsAffinityType *taf, ConfNode *prio_node, const char *priority,
        cpu_set_t *cpuset, const char *setname)
{
    ConfNode *node = ConfNodeLookupChild(prio_node, priority);
    if (node != NULL) {
        BuildCpuset(setname, node, cpuset);
    } else {
        SCLogDebug("Unable to find '%s' priority for set %s", priority, setname);
    }
}

/**
 * \brief Set up the default priority for the given affinity type.
 */
static void SetupDefaultPriority(ThreadsAffinityType *taf, ConfNode *prio_node, const char *setname)
{
    ConfNode *default_node = ConfNodeLookupChild(prio_node, "default");
    if (default_node == NULL)
        return;

    if (strcmp(default_node->val, "low") == 0) {
        taf->prio = PRIO_LOW;
    } else if (strcmp(default_node->val, "medium") == 0) {
        taf->prio = PRIO_MEDIUM;
    } else if (strcmp(default_node->val, "high") == 0) {
        taf->prio = PRIO_HIGH;
    } else {
        FatalError("Unknown default CPU affinity priority: %s", default_node->val);
    }

    SCLogConfig("Using default priority '%s' for set %s", default_node->val, setname);
}

/**
 * \brief Set up priority CPU sets for the given affinity type.
 */
static void SetupAffinityPriority(ThreadsAffinityType *taf, ConfNode *affinity, const char *setname)
{
    CPU_ZERO(&taf->lowprio_cpu);
    CPU_ZERO(&taf->medprio_cpu);
    CPU_ZERO(&taf->hiprio_cpu);

    ConfNode *prio_node = ConfNodeLookupChild(affinity->head.tqh_first, "prio");
    if (prio_node == NULL)
        return;

    BuildPriorityCpuset(taf, prio_node, "low", &taf->lowprio_cpu, setname);
    BuildPriorityCpuset(taf, prio_node, "medium", &taf->medprio_cpu, setname);
    BuildPriorityCpuset(taf, prio_node, "high", &taf->hiprio_cpu, setname);

    SetupDefaultPriority(taf, prio_node, setname);
}

/**
 * \brief Set up CPU affinity mode for the given affinity type.
 */
static void SetupAffinityMode(ThreadsAffinityType *taf, ConfNode *affinity)
{
    ConfNode *mode_node = ConfNodeLookupChild(affinity->head.tqh_first, "mode");
    if (mode_node == NULL)
        return;

    if (strcmp(mode_node->val, "exclusive") == 0) {
        taf->mode_flag = EXCLUSIVE_AFFINITY;
    } else if (strcmp(mode_node->val, "balanced") == 0) {
        taf->mode_flag = BALANCED_AFFINITY;
    } else {
        FatalError("Unknown CPU affinity mode: %s", mode_node->val);
    }
}

/**
 * \brief Set up the number of threads for the given affinity type.
 */
static void SetupAffinityThreads(ThreadsAffinityType *taf, ConfNode *affinity)
{
    ConfNode *threads_node = ConfNodeLookupChild(affinity->head.tqh_first, "threads");
    if (threads_node == NULL)
        return;

    if (StringParseUint32(&taf->nb_threads, 10, 0, threads_node->val) < 0 || taf->nb_threads == 0) {
        FatalError("Invalid thread count: %s", threads_node->val);
    }
}

/**
 * \brief Check if the set name corresponds to a worker CPU set.
 */
static bool IsWorkerCpuSet(const char *setname)
{
    return (strcmp(setname, "worker-cpu-set") == 0);
}

/**
 * \brief Set up affinity configuration for a single interface.
 */
static void SetupSingleIfaceAffinity(ThreadsAffinityType *taf, ConfNode *iface_node)
{
    const char *interface_name = NULL;
    ConfNode *cpu_node = NULL, *mode_node = NULL, *prio_node = NULL, *threads_node = NULL;
    ConfNode *child;
    TAILQ_FOREACH (child, &iface_node->head, next) {
        if (strcmp(child->name, "interface") == 0) {
            interface_name = child->val;
        } else if (strcmp(child->name, "cpu") == 0) {
            cpu_node = child;
        } else if (strcmp(child->name, "mode") == 0) {
            mode_node = child;
        } else if (strcmp(child->name, "prio") == 0) {
            prio_node = child;
        } else if (strcmp(child->name, "threads") == 0) {
            threads_node = child;
        }
    }

    if (interface_name == NULL) {
        return;
    }

    ThreadsAffinityType *iface_taf =
            GetOrAllocAffinityTypeForIfaceOfName(taf->name, interface_name);
    if (iface_taf == NULL) {
        FatalError("Unknown CPU affinity type for interface: %s", interface_name);
    }

    SetupCpuSets(iface_taf, cpu_node, interface_name);
    SetupAffinityPriority(iface_taf, prio_node, interface_name);
    SetupAffinityMode(iface_taf, mode_node);
    SetupAffinityThreads(iface_taf, threads_node);
}

/**
 * \brief Set up per-interface affinity configurations.
 */
static void SetupPerIfaceAffinity(ThreadsAffinityType *taf, ConfNode *affinity)
{
    ConfNode *per_iface_node = ConfNodeLookupChild(affinity->head.tqh_first, "per-iface");
    if (per_iface_node == NULL)
        return;

    ConfNode *iface_node;
    TAILQ_FOREACH (iface_node, &per_iface_node->head, next) {
        SetupSingleIfaceAffinity(taf, iface_node);
    }
}

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

    SCLogDebug("Loading CPU affinity from config...\n");

    ConfNode *root = ConfGetNode("threading.cpu-affinity");
    if (root == NULL) {
        SCLogInfo("Cannot find cpu-affinity node in config");
        return;
    }

    ConfNode *affinity;
    TAILQ_FOREACH(affinity, &root->head, next) {
        const char *setname = GetAffinitySetName(affinity->val);
        if (setname == NULL)
            continue;

        ThreadsAffinityType *taf = GetOrAllocAffinityTypeForIfaceOfName(setname, NULL);
        if (taf == NULL) {
            FatalError("Unknown CPU affinity type: %s", setname);
        }

        SCLogConfig("Found affinity definition for \"%s\"", setname);

        SetupCpuSets(taf, affinity, setname);
        SetupAffinityPriority(taf, affinity, setname);
        SetupAffinityMode(taf, affinity);
        SetupAffinityThreads(taf, affinity);

        if (IsWorkerCpuSet(setname)) {
            SetupPerIfaceAffinity(taf, affinity);
        }
    }
#endif /* OS_WIN32 and __OpenBSD__ */
}

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun

static int HwLocDeviceNumaGet(hwloc_topology_t topology, hwloc_obj_t obj)
{
#if HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5
    // TODO: test this block of code or remove it
    hwloc_obj_t nodes[MAX_NUMA_NODES]; // Assuming a maximum of 16 NUMA nodes
    unsigned num_nodes = MAX_NUMA_NODES;
    struct hwloc_location location;

    location.type = HWLOC_LOCATION_TYPE_OBJECT;
    location.location.object = obj;

    int result = hwloc_get_local_numanode_objs(topology, &location, &num_nodes, nodes, 0);
    if (result == 0 && num_nodes > 0 && num_nodes <= MAX_NUMA_NODES) {
        return nodes[0]->logical_index;
        // printf("NUMA nodes for PCIe device:\n");
        // for (unsigned i = 0; i < num_nodes; i++) {
        //     printf("NUMA node %d\n", nodes[i]->logical_index);
        // }
    }
    return -1;
#endif /* HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5 */

    hwloc_obj_t non_io_ancestor = hwloc_get_non_io_ancestor_obj(topology, obj);
    if (non_io_ancestor == NULL) {
        fprintf(stderr, "Failed to find non-IO ancestor object.\n");
        return -1;
    }

    // Iterate over NUMA nodes and check their nodeset
    hwloc_obj_t numa_node = NULL;
    while ((numa_node = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_NUMANODE, numa_node)) !=
            NULL) {
        if (hwloc_bitmap_isset(non_io_ancestor->nodeset, numa_node->os_index)) {
            return numa_node->logical_index;
        }
    }

    return -1;
}

static hwloc_obj_t HwLocDeviceGetByKernelName(hwloc_topology_t topology, const char *interface_name)
{
    hwloc_obj_t obj = NULL;

    while ((obj = hwloc_get_next_osdev(topology, obj)) != NULL) {
        if (obj->attr->osdev.type == HWLOC_OBJ_OSDEV_NETWORK &&
                strcmp(obj->name, interface_name) == 0) {
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
/**
 * \brief Parse PCIe address string to individual components
 * \param[in] pcie_address PCIe address string
 * \param[out] domain Domain component
 * \param[out] bus Bus component
 * \param[out] device Device component
 * \param[out] function Function component
 */
static void PcieAddressToComponents(const char *pcie_address, unsigned int *domain,
        unsigned int *bus, unsigned int *device, unsigned int *function)
{
    // Handle both full and short PCIe address formats
    if (sscanf(pcie_address, "%x:%x:%x.%x", domain, bus, device, function) != 4) {
        if (sscanf(pcie_address, "%x:%x.%x", bus, device, function) != 3) {
            FatalError("Error parsing PCIe address: %s", pcie_address);
        }
        *domain = 0; // Default domain to 0 if not provided
    }
}

// Function to convert PCIe address to hwloc object
static hwloc_obj_t HwLocDeviceGetByPcie(hwloc_topology_t topology, const char *pcie_address)
{
    hwloc_obj_t obj = NULL;
    unsigned int domain, bus, device, function;
    PcieAddressToComponents(pcie_address, &domain, &bus, &device, &function);
    while ((obj = hwloc_get_next_pcidev(topology, obj)) != NULL) {
        if (obj->attr->pcidev.domain == domain && obj->attr->pcidev.bus == bus &&
                obj->attr->pcidev.dev == device && obj->attr->pcidev.func == function) {
            return obj;
        }
    }
    return NULL;
}

static void HwlocObjectDump(hwloc_obj_t obj, const char *iface_name)
{
    if (!obj) {
        SCLogDebug("No object found for the given PCIe address.\n");
        return;
    }

    static char pcie_address[32];
    snprintf(pcie_address, sizeof(pcie_address), "%04x:%02x:%02x.%x", obj->attr->pcidev.domain,
            obj->attr->pcidev.bus, obj->attr->pcidev.dev, obj->attr->pcidev.func);
    SCLogDebug("Interface (%s / %s) has NUMA ID %d", iface_name, pcie_address,
            HwLocDeviceNumaGet(topology, obj));

    SCLogDebug("Object type: %s\n", hwloc_obj_type_string(obj->type));
    SCLogDebug("Logical index: %u\n", obj->logical_index);
    SCLogDebug("Depth: %u\n", obj->depth);
    SCLogDebug("Attributes:\n");
    if (obj->type == HWLOC_OBJ_PCI_DEVICE) {
        SCLogDebug("  Domain: %04x\n", obj->attr->pcidev.domain);
        SCLogDebug("  Bus: %02x\n", obj->attr->pcidev.bus);
        SCLogDebug("  Device: %02x\n", obj->attr->pcidev.dev);
        SCLogDebug("  Function: %01x\n", obj->attr->pcidev.func);
        SCLogDebug("  Class ID: %04x\n", obj->attr->pcidev.class_id);
        SCLogDebug("  Vendor ID: %04x\n", obj->attr->pcidev.vendor_id);
        SCLogDebug("  Device ID: %04x\n", obj->attr->pcidev.device_id);
        SCLogDebug("  Subvendor ID: %04x\n", obj->attr->pcidev.subvendor_id);
        SCLogDebug("  Subdevice ID: %04x\n", obj->attr->pcidev.subdevice_id);
        SCLogDebug("  Revision: %02x\n", obj->attr->pcidev.revision);
        SCLogDebug("  Link speed: %f GB/s\n", obj->attr->pcidev.linkspeed);
    } else {
        SCLogDebug("  No PCI device attributes available.\n");
    }
}

static bool CPUIsFromNuma(uint16_t ncpu, uint16_t numa)
{
    int core_id = ncpu;
    int depth = hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE);
    hwloc_obj_t numa_node = NULL;

    while ((numa_node = hwloc_get_next_obj_by_depth(topology, depth, numa_node)) != NULL) {
        hwloc_cpuset_t cpuset = hwloc_bitmap_alloc();
        hwloc_bitmap_copy(cpuset, numa_node->cpuset);

        if (hwloc_bitmap_isset(cpuset, core_id)) {
            SCLogDebug("Core %d - NUMA %d", core_id, numa_node->logical_index);
            hwloc_bitmap_free(cpuset);
            break;
        }
        hwloc_bitmap_free(cpuset);
    }

    if (numa == numa_node->logical_index)
        return true;

    return false;
}

static bool TopologyShouldAutooptimize(ThreadVars *tv, ThreadsAffinityType *taf)
{
    bool cond;
    SCMutexLock(&taf->taf_mutex);
    cond = tv->type == TVT_PPT && tv->iface_name &&
           (strcmp(tv->iface_name, taf->name) == 0 || strcmp("worker-cpu-set", taf->name) == 0);
    SCMutexUnlock(&taf->taf_mutex);
    return cond;
}

static void TopologyInitialize(void)
{
    if (topology == NULL) {
        if (hwloc_topology_init(&topology) == -1) {
            FatalError("Failed to initialize topology");
        }

        if (hwloc_topology_set_flags(topology, HWLOC_TOPOLOGY_FLAG_WHOLE_SYSTEM) == -1 ||
                hwloc_topology_set_io_types_filter(topology, HWLOC_TYPE_FILTER_KEEP_ALL) == -1 ||
                hwloc_topology_load(topology) == -1) {
            FatalError("Failed to set/load topology");
        }
    }
}

void TopologyDestroy()
{
    if (topology != NULL) {
        hwloc_topology_destroy(topology);
        topology = NULL;
    }
}

static int InterfaceGetNumaNode(ThreadVars *tv)
{
    hwloc_obj_t if_obj = HwLocDeviceGetByKernelName(topology, tv->iface_name);
    if (if_obj == NULL) {
        if_obj = HwLocDeviceGetByPcie(topology, tv->iface_name);
    }

    if (if_obj != NULL) {
        HwlocObjectDump(if_obj, tv->iface_name);
    }

    return HwLocDeviceNumaGet(topology, if_obj);
}

static int16_t FindCPUInNumaNode(int numa_node, ThreadsAffinityType *taf)
{
    if (taf->lcpu[numa_node] >= UtilCpuGetNumProcessorsOnline()) {
        return -1;
    }

    uint16_t cpu = taf->lcpu[numa_node];
    while (cpu < UtilCpuGetNumProcessorsOnline() &&
            (!CPU_ISSET(cpu, &taf->cpu_set) || !CPUIsFromNuma(cpu, numa_node))) {
        cpu++;
    }

    taf->lcpu[numa_node] = (CPU_ISSET(cpu, &taf->cpu_set) && CPUIsFromNuma(cpu, numa_node))
                                   ? cpu + 1
                                   : UtilCpuGetNumProcessorsOnline();
    return (CPU_ISSET(cpu, &taf->cpu_set) && CPUIsFromNuma(cpu, numa_node)) ? cpu : -1;
}

static bool AllCPUsUsed(ThreadsAffinityType *taf)
{
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        if (taf->lcpu[i] < UtilCpuGetNumProcessorsOnline()) {
            return false;
        }
    }
    return true;
}

static void ResetCPUs(ThreadsAffinityType *taf)
{
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        taf->lcpu[i] = 0;
    }
}

static int16_t CPUSelectFromNuma(int iface_numa, ThreadsAffinityType *taf)
{
    if (iface_numa != -1) {
        return FindCPUInNumaNode(iface_numa, taf);
    }
    return -1;
}

static int16_t CPUSelectAlternative(ThreadsAffinityType *taf)
{
    for (int nid = 0; nid < MAX_NUMA_NODES; nid++) {
        int cpu = FindCPUInNumaNode(nid, taf);
        if (cpu != -1) {
            return cpu;
        }
    }
    return -1;
}

static uint16_t CPUSelectDefault(ThreadsAffinityType *taf)
{
    uint16_t cpu = taf->lcpu[0];
    int attempts = 0;

    while (!CPU_ISSET(cpu, &taf->cpu_set) && attempts < 2) {
        cpu = (cpu + 1) % UtilCpuGetNumProcessorsOnline();
        if (cpu == 0)
            attempts++;
    }

    taf->lcpu[0] = cpu + 1;

    if (attempts == 2) {
        SCLogError(
                "cpu_set does not contain available CPUs, CPU affinity configuration is invalid");
    }

    return cpu;
}

static uint16_t GetNextAvailableCPU(int iface_numa, ThreadsAffinityType *taf)
{
    int16_t cpu = CPUSelectFromNuma(iface_numa, taf);
    if (iface_numa == -1 || cpu == -1) {
        cpu = CPUSelectAlternative(taf);
        if (cpu == -1) {
            ResetCPUs(taf);
        }
    }

    if (cpu != -1)
        return cpu;

    cpu = CPUSelectDefault(taf);

    return cpu;
}

#endif /* OS_WIN32 and __OpenBSD__ */

uint16_t AffinityGetNextCPU(ThreadVars *tv, ThreadsAffinityType *taf)
{
    uint16_t next_cpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    int iface_numa = -1;
    if (TopologyShouldAutooptimize(tv, taf)) {
        TopologyInitialize();
        iface_numa = InterfaceGetNumaNode(tv);
    }

    SCMutexLock(&taf->taf_mutex);
    next_cpu = GetNextAvailableCPU(iface_numa, taf);

    if (AllCPUsUsed(taf)) {
        ResetCPUs(taf);
    }

    SCLogDebug("Setting affinity on CPU %d", cpu);
    SCMutexUnlock(&taf->taf_mutex);
#endif /* OS_WIN32 and __OpenBSD__ */

    return next_cpu;
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
