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
#include "suricata.h"
#define _THREAD_AFFINITY
#include "util-affinity.h"
#include "conf.h"
#include "runmodes.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-dpdk.h"

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
#ifdef HAVE_HWLOC
static hwloc_topology_t topology = NULL;
#endif /* HAVE_HWLOC */
#endif /* OS_WIN32 and __OpenBSD__ */

static ThreadsAffinityType *AllocAndInitAffinityType(
        const char *name, const char *interface_name, ThreadsAffinityType *parent)
{
    ThreadsAffinityType *new_affinity = SCCalloc(1, sizeof(ThreadsAffinityType));
    if (new_affinity == NULL) {
        FatalError("Unable to allocate memory for new CPU affinity type");
    }

    new_affinity->name = SCStrdup(interface_name);
    if (new_affinity->name == NULL) {
        FatalError("Unable to allocate memory for new CPU affinity type name");
    }
    new_affinity->parent = parent;
    new_affinity->mode_flag = EXCLUSIVE_AFFINITY;
    new_affinity->prio = PRIO_MEDIUM;
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        new_affinity->lcpu[i] = 0;
    }

    if (parent != NULL) {
        if (parent->nb_children == parent->nb_children_capacity) {
            if (parent->nb_children_capacity == 0) {
                parent->nb_children_capacity = 2;
            } else {
                parent->nb_children_capacity *= 2;
            }
            void *p = SCRealloc(
                    parent->children, parent->nb_children_capacity * sizeof(ThreadsAffinityType *));
            if (p == NULL) {
                FatalError("Unable to reallocate memory for children CPU affinity types");
            }
            parent->children = p;
        }
        parent->children[parent->nb_children++] = new_affinity;
    }

    return new_affinity;
}

ThreadsAffinityType *FindAffinityByInterface(
        ThreadsAffinityType *parent, const char *interface_name)
{
    if (parent == NULL || interface_name == NULL || parent->nb_children == 0 ||
            parent->children == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < parent->nb_children; i++) {
        if (parent->children[i] && parent->children[i]->name &&
                strcmp(parent->children[i]->name, interface_name) == 0) {
            return parent->children[i];
        }
    }
    return NULL;
}

/**
 * \brief Find affinity by name (*-cpu-set name) and an interface name.
 * \param name the name of the affinity (e.g. worker-cpu-set, receive-cpu-set).
 * The name is required and cannot be NULL.
 * \param interface_name the name of the interface.
 * If NULL, the affinity is looked up by name only.
 *  \retval a pointer to the affinity or NULL if not found
 */
ThreadsAffinityType *GetAffinityTypeForNameAndIface(const char *name, const char *interface_name)
{
    if (name == NULL || *name == '\0') {
        return NULL;
    }

    ThreadsAffinityType *parent_affinity = NULL;
    for (int i = 0; i < MAX_CPU_SET; i++) {
        if (thread_affinity[i].name != NULL && strcmp(thread_affinity[i].name, name) == 0) {
            parent_affinity = &thread_affinity[i];
            break;
        }
    }

    if (parent_affinity == NULL) {
        SCLogError("CPU affinity with name \"%s\" not found", name);
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
 * \brief Finds affinity by its name and interface name.
 * Interfaces are children of cpu-set names. If the queried interface is not
 * found, then it is allocated, initialized and assigned to the queried cpu-set.
 * \param name the name of the affinity (e.g. worker-cpu-set, receive-cpu-set).
 * The name is required and cannot be NULL.
 * \param interface_name the name of the interface.
 * If NULL, the affinity is looked up by name only.
 * \retval a pointer to the affinity or NULL if not found
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
        SCLogError("CPU affinity with name \"%s\" not found", name);
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

int BuildCpusetWithCallback(
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
                return -1;
            }
            if (StringParseUint32(&b, 10, strlen(sep) - 1, sep + 1) < 0) {
                SCLogError("%s: invalid cpu range (end invalid): \"%s\"", name, lnode->val);
                return -1;
            }
            if (a > b) {
                SCLogError("%s: invalid cpu range (bad order): \"%s\"", name, lnode->val);
                return -1;
            }
            if (b > max) {
                SCLogError("%s: upper bound (%d) of cpu set is too high, only %d cpu(s)", name, b,
                        max + 1);
            }
        } else {
            if (StringParseUint32(&a, 10, strlen(lnode->val), lnode->val) < 0) {
                SCLogError("%s: invalid cpu range (not an integer): \"%s\"", name, lnode->val);
                return -1;
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
    return 0;
}

static void AffinityCallback(int i, void *data)
{
    CPU_SET(i, (cpu_set_t *)data);
}

static int BuildCpuset(const char *name, SCConfNode *node, cpu_set_t *cpu)
{
    return BuildCpusetWithCallback(name, node, AffinityCallback, (void *)cpu);
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
    SCConfNode *cpu_node = SCConfNodeLookupChild(affinity, "cpu");
    if (cpu_node != NULL) {
        if (BuildCpuset(setname, cpu_node, &taf->cpu_set) < 0) {
            SCLogWarning("Failed to parse CPU set for %s", setname);
        }
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
        if (BuildCpuset(setname, node, cpuset) < 0) {
            SCLogWarning("Failed to parse %s priority CPU set for %s", priority, setname);
        }
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
    SCConfNode *prio_node = SCConfNodeLookupChild(affinity, "prio");
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
    SCConfNode *mode_node = SCConfNodeLookupChild(affinity, "mode");
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
    SCConfNode *threads_node = SCConfNodeLookupChild(affinity, "threads");
    if (threads_node == NULL) {
        return 0;
    }

    if (StringParseUint32(&taf->nb_threads, 10, 0, threads_node->val) < 0 || taf->nb_threads == 0) {
        SCLogError("Invalid thread count: %s", threads_node->val);
        return -1;
    }
    return 0;
}

/**
 * \brief Get the YAML path for the given affinity type.
 * The path is built using the parent name (if available) and the affinity name.
 * Do not free the returned string.
 * \param taf the affinity type - if NULL, the path is built for the root node
 * \return a string containing the YAML path, or NULL if the path is too long
 */
char *AffinityGetYamlPath(ThreadsAffinityType *taf)
{
    static char rootpath[] = "threading.cpu-affinity";
    static char path[1024] = { 0 };
    char subpath[256] = { 0 };

    if (taf == NULL) {
        return rootpath;
    }

    if (taf->parent != NULL) {
        long r = snprintf(
                subpath, sizeof(subpath), "%s.interface-specific-cpu-set.", taf->parent->name);
        if (r < 0 || r >= (long)sizeof(subpath)) {
            SCLogError("Unable to build YAML path for CPU affinity %s.%s", taf->parent->name,
                    taf->name);
            return NULL;
        }
    } else {
        subpath[0] = '\0';
    }

    long r = snprintf(path, sizeof(path), "%s.%s%s", rootpath, subpath, taf->name);
    if (r < 0 || r >= (long)sizeof(path)) {
        SCLogError("Unable to build YAML path for CPU affinity %s", taf->name);
        return NULL;
    }

    return path;
}

static void ResetCPUs(ThreadsAffinityType *taf)
{
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        taf->lcpu[i] = 0;
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
 * \brief Check if the set name corresponds to a receive CPU set.
 */
static bool IsReceiveCpuSet(const char *setname)
{
    return (strcmp(setname, "receive-cpu-set") == 0);
}

/**
 * \brief Set up affinity configuration for a single interface.
 */
/**
 * \brief Set up affinity configuration for a single interface.
 * \retval 0 on success, -1 on error
 */
static int SetupSingleIfaceAffinity(ThreadsAffinityType *taf, SCConfNode *iface_node)
{
    // offload to Setup function
    SCConfNode *child_node;
    const char *interface_name = NULL;
    TAILQ_FOREACH (child_node, &iface_node->head, next) {
        if (strcmp(child_node->name, "interface") == 0) {
            interface_name = child_node->val;
            break;
        }
    }
    if (interface_name == NULL) {
        return 0;
    }

    ThreadsAffinityType *iface_taf =
            GetOrAllocAffinityTypeForIfaceOfName(taf->name, interface_name);
    if (iface_taf == NULL) {
        SCLogError("Failed to allocate CPU affinity type for interface: %s", interface_name);
        return -1;
    }

    SetupCpuSets(iface_taf, iface_node, interface_name);
    if (SetupAffinityPriority(iface_taf, iface_node, interface_name) < 0) {
        return -1;
    }
    if (SetupAffinityMode(iface_taf, iface_node) < 0) {
        return -1;
    }
    if (SetupAffinityThreads(iface_taf, iface_node) < 0) {
        return -1;
    }
    return 0;
}

/**
 * \brief Set up per-interface affinity configurations.
 * \retval 0 on success, -1 on error
 */
static int SetupPerIfaceAffinity(ThreadsAffinityType *taf, SCConfNode *affinity)
{
    char if_af[] = "interface-specific-cpu-set";
    SCConfNode *per_iface_node = SCConfNodeLookupChild(affinity, if_af);
    if (per_iface_node == NULL) {
        return 0;
    }

    SCConfNode *iface_node;
    TAILQ_FOREACH (iface_node, &per_iface_node->head, next) {
        if (strcmp(iface_node->val, "interface") == 0) {
            if (SetupSingleIfaceAffinity(taf, iface_node) < 0) {
                return -1;
            }
        } else {
            SCLogWarning("Unknown node in %s: %s", if_af, iface_node->name);
        }
    }
    return 0;
}

/**
 * \brief Check if CPU affinity configuration node follows format used in Suricata 7 and below
 * \retval true if CPU affinity uses Suricata <=7.0, false if it uses the new format (Suricata
 * >=8.0)
 */
static bool AffinityConfigIsDeprecated(void)
{
    static bool threading_affinity_deprecated = false;
    if (thread_affinity_init_done == 0) {
        // reset the flag
        threading_affinity_deprecated = false;
    } else {
        return threading_affinity_deprecated;
    }

    SCConfNode *root = SCConfGetNode(AffinityGetYamlPath(NULL));
    if (root == NULL) {
        return threading_affinity_deprecated;
    }

    SCConfNode *affinity;
    TAILQ_FOREACH (affinity, &root->head, next) {
        // If a child does not contain "-cpu-set", then the conf is deprecated
        // Names in the deprecated format (list of *-cpu-sets) contain
        // list item IDs - "0" : "management-cpu-set", "1" : "worker-cpu-set"
        if (strstr(affinity->name, "-cpu-set") == NULL) {
            threading_affinity_deprecated = true;
            return threading_affinity_deprecated;
        }
    }

    return threading_affinity_deprecated;
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
        if (AffinityConfigIsDeprecated()) {
            SCLogWarning("CPU affinity configuration uses a deprecated structure and will not be "
                         "supported in a future major release (Suricata 9.0) Redmine ticket #7721. "
                         "Please update your %s to the new format. "
                         "See notes in %s/upgrade.html#upgrading-7-0-to-8-0",
                    AffinityGetYamlPath(NULL), GetDocURL());
        }
        thread_affinity_init_done = 1;
    }

    SCLogDebug("Loading %s from config", AffinityGetYamlPath(NULL));
    SCConfNode *root = SCConfGetNode(AffinityGetYamlPath(NULL));
    if (root == NULL) {
        SCLogInfo("Cannot find %s node in config", AffinityGetYamlPath(NULL));
        return;
    }

    SCConfNode *affinity;
    TAILQ_FOREACH(affinity, &root->head, next) {
        char *v = AffinityConfigIsDeprecated() ? affinity->val : affinity->name;
        const char *setname = GetAffinitySetName(v);
        if (setname == NULL) {
            continue;
        }

        ThreadsAffinityType *taf = GetOrAllocAffinityTypeForIfaceOfName(setname, NULL);
        if (taf == NULL) {
            SCLogError("Failed to allocate CPU affinity type: %s", setname);
            continue;
        }

        SCLogConfig("Found CPU affinity definition for \"%s\"", setname);

        SCConfNode *aff_query_node =
                AffinityConfigIsDeprecated() ? affinity->head.tqh_first : affinity;
        SetupCpuSets(taf, aff_query_node, setname);
        if (SetupAffinityPriority(taf, aff_query_node, setname) < 0) {
            SCLogError("Failed to setup priority for CPU affinity type: %s", setname);
            continue;
        }
        if (SetupAffinityMode(taf, aff_query_node) < 0) {
            SCLogError("Failed to setup mode for CPU affinity type: %s", setname);
            continue;
        }
        if (SetupAffinityThreads(taf, aff_query_node) < 0) {
            SCLogError("Failed to setup threads for CPU affinity type: %s", setname);
            continue;
        }

        if (!AffinityConfigIsDeprecated() &&
                (IsWorkerCpuSet(setname) || IsReceiveCpuSet(setname))) {
            if (SetupPerIfaceAffinity(taf, affinity) < 0) {
                SCLogError("Failed to setup per-interface affinity for CPU affinity type: %s",
                        setname);
                continue;
            }
        }
    }
#endif /* OS_WIN32 and __OpenBSD__ */
}

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
#ifdef HAVE_HWLOC
static int HwLocDeviceNumaGet(hwloc_topology_t topo, hwloc_obj_t obj)
{
#if HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5
    hwloc_obj_t nodes[MAX_NUMA_NODES];
    unsigned num_nodes = MAX_NUMA_NODES;
    struct hwloc_location location;

    location.type = HWLOC_LOCATION_TYPE_OBJECT;
    location.location.object = obj;

    int result = hwloc_get_local_numanode_objs(topo, &location, &num_nodes, nodes, 0);
    if (result == 0 && num_nodes > 0 && num_nodes <= MAX_NUMA_NODES) {
        return nodes[0]->logical_index;
    }
    return -1;
#endif /* HWLOC_VERSION_MAJOR >= 2 && HWLOC_VERSION_MINOR >= 5 */

    hwloc_obj_t non_io_ancestor = hwloc_get_non_io_ancestor_obj(topo, obj);
    if (non_io_ancestor == NULL) {
        return -1;
    }

    // Iterate over NUMA nodes and check their nodeset
    hwloc_obj_t numa_node = NULL;
    while ((numa_node = hwloc_get_next_obj_by_type(topo, HWLOC_OBJ_NUMANODE, numa_node)) != NULL) {
        if (hwloc_bitmap_isset(non_io_ancestor->nodeset, numa_node->os_index)) {
            return numa_node->logical_index;
        }
    }

    return -1;
}

static hwloc_obj_t HwLocDeviceGetByKernelName(hwloc_topology_t topo, const char *interface_name)
{
    hwloc_obj_t obj = NULL;

    while ((obj = hwloc_get_next_osdev(topo, obj)) != NULL) {
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
static int PcieAddressToComponents(const char *pcie_address, unsigned int *domain,
        unsigned int *bus, unsigned int *device, unsigned int *function)
{
    // Handle both full and short PCIe address formats
    if (sscanf(pcie_address, "%x:%x:%x.%x", domain, bus, device, function) != 4) {
        if (sscanf(pcie_address, "%x:%x.%x", bus, device, function) != 3) {
            return -1;
        }
        *domain = 0; // Default domain to 0 if not provided
    }
    return 0;
}

// Function to convert PCIe address to hwloc object
static hwloc_obj_t HwLocDeviceGetByPcie(hwloc_topology_t topo, const char *pcie_address)
{
    hwloc_obj_t obj = NULL;
    unsigned int domain, bus, device, function;
    int r = PcieAddressToComponents(pcie_address, &domain, &bus, &device, &function);
    if (r == 0) {
        while ((obj = hwloc_get_next_pcidev(topo, obj)) != NULL) {
            if (obj->attr->pcidev.domain == domain && obj->attr->pcidev.bus == bus &&
                    obj->attr->pcidev.dev == device && obj->attr->pcidev.func == function) {
                return obj;
            }
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

static bool TopologyShouldAutopin(ThreadVars *tv, ThreadsAffinityType *taf)
{
    bool cond;
    SCMutexLock(&taf->taf_mutex);
    cond = tv->type == TVT_PPT && tv->iface_name &&
           (strcmp(tv->iface_name, taf->name) == 0 ||
                   (strcmp("worker-cpu-set", taf->name) == 0 && RunmodeIsWorkers()) ||
                   (strcmp("receive-cpu-set", taf->name) == 0 && RunmodeIsAutofp()));
    SCMutexUnlock(&taf->taf_mutex);
    return cond;
}

/**
 * \brief Initialize the hardware topology.
 * \retval 0 on success, -1 on error
 */
static int TopologyInitialize(void)
{
    if (topology == NULL) {
        if (hwloc_topology_init(&topology) == -1) {
            SCLogError("Failed to initialize topology");
            return -1;
        }

        if (hwloc_topology_set_flags(topology, HWLOC_TOPOLOGY_FLAG_WHOLE_SYSTEM) == -1 ||
                hwloc_topology_set_io_types_filter(topology, HWLOC_TYPE_FILTER_KEEP_ALL) == -1 ||
                hwloc_topology_load(topology) == -1) {
            SCLogError("Failed to set/load topology");
            hwloc_topology_destroy(topology);
            topology = NULL;
            return -1;
        }
    }
    return 0;
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

    if (if_obj != NULL && SCLogGetLogLevel() == SC_LOG_DEBUG) {
        HwlocObjectDump(if_obj, tv->iface_name);
    }

    int32_t numa_id = HwLocDeviceNumaGet(topology, if_obj);
    if (numa_id < 0 && SCRunmodeGet() == RUNMODE_DPDK) {
        // DPDK fallback for e.g. net_bonding (vdev) PMDs
        int32_t r = DPDKDeviceNameSetSocketID(tv->iface_name, &numa_id);
        if (r < 0) {
            numa_id = -1;
        }
    }

    if (numa_id < 0) {
        SCLogDebug("Unable to find NUMA node for interface %s", tv->iface_name);
    }

    return numa_id;
}
#endif /* HAVE_HWLOC */

static bool CPUIsFromNuma(uint16_t ncpu, uint16_t numa)
{
#ifdef HAVE_HWLOC
    int core_id = ncpu;
    int depth = hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE);
    hwloc_obj_t numa_node = NULL;
    bool found = false;
    uint16_t found_numa = 0;

    // Invalid depth or no NUMA nodes available
    if (depth == HWLOC_TYPE_DEPTH_UNKNOWN) {
        return false;
    }

    while ((numa_node = hwloc_get_next_obj_by_depth(topology, depth, numa_node)) != NULL) {
        hwloc_cpuset_t cpuset = hwloc_bitmap_alloc();
        if (cpuset == NULL) {
            SCLogDebug("Failed to allocate cpuset");
            continue;
        }
        hwloc_bitmap_copy(cpuset, numa_node->cpuset);

        if (hwloc_bitmap_isset(cpuset, core_id)) {
            SCLogDebug("Core %d - NUMA %d", core_id, numa_node->logical_index);
            found = true;
            found_numa = numa_node->logical_index;
            hwloc_bitmap_free(cpuset);
            break;
        }
        hwloc_bitmap_free(cpuset);
    }

    // After loop, check if we found the CPU and match the requested NUMA node
    if (found && numa == found_numa) {
        return true;
    }

    // CPU was not found in any NUMA node or did not match requested NUMA
#endif /* HAVE_HWLOC */

    return false;
}

static int16_t FindCPUInNumaNode(int numa_node, ThreadsAffinityType *taf)
{
    if (numa_node < 0) {
        return -1;
    }

    if (taf->lcpu[numa_node] >= UtilCpuGetNumProcessorsOnline()) {
        return -1;
    }

    uint16_t cpu = taf->lcpu[numa_node];
    while (cpu < UtilCpuGetNumProcessorsOnline() &&
            (!CPU_ISSET(cpu, &taf->cpu_set) || !CPUIsFromNuma(cpu, (uint16_t)numa_node))) {
        cpu++;
    }

    taf->lcpu[numa_node] =
            (CPU_ISSET(cpu, &taf->cpu_set) && CPUIsFromNuma(cpu, (uint16_t)numa_node))
                    ? cpu + 1
                    : UtilCpuGetNumProcessorsOnline();
    return (CPU_ISSET(cpu, &taf->cpu_set) && CPUIsFromNuma(cpu, (uint16_t)numa_node)) ? (int16_t)cpu
                                                                                      : -1;
}

static int16_t CPUSelectFromNuma(int iface_numa, ThreadsAffinityType *taf)
{
    if (iface_numa != -1) {
        return FindCPUInNumaNode(iface_numa, taf);
    }
    return -1;
}

static int16_t CPUSelectAlternative(int iface_numa, ThreadsAffinityType *taf)
{
    for (int nid = 0; nid < MAX_NUMA_NODES; nid++) {
        if (iface_numa == nid) {
            continue;
        }

        int16_t cpu = FindCPUInNumaNode(nid, taf);
        if (cpu != -1) {
            SCLogPerf("CPU %d from NUMA %d assigned to a network interface located on NUMA %d", cpu,
                    nid, iface_numa);
            return cpu;
        }
    }
    return -1;
}

/**
 * \brief Select the next available CPU for the given affinity type.
 * taf->cpu_set is a bit array where each bit represents a CPU core.
 * The function iterates over the bit array and returns the first available CPU.
 * If last used CPU core index is higher than the indexes of available cores,
 * we reach the end of the array, and we reset the CPU selection.
 * On the second reset attempt, the function bails out with a default value.
 * The second attempt should only happen with an empty CPU set.
 */
static uint16_t CPUSelectDefault(ThreadsAffinityType *taf)
{
    uint16_t cpu = taf->lcpu[0];
    int attempts = 0;
    while (!CPU_ISSET(cpu, &taf->cpu_set) && attempts < 2) {
        cpu = (cpu + 1) % UtilCpuGetNumProcessorsOnline();
        if (cpu == 0) {
            attempts++;
        }
    }

    taf->lcpu[0] = cpu + 1;
    return cpu;
}

static uint16_t CPUSelectFromNumaOrDefault(int iface_numa, ThreadsAffinityType *taf)
{
    uint16_t attempts = 0;
    int16_t cpu = -1;
    while (attempts < 2) {
        cpu = CPUSelectFromNuma(iface_numa, taf);
        if (cpu == -1) {
            cpu = CPUSelectAlternative(iface_numa, taf);
            if (cpu == -1) {
                // All CPUs from all NUMAs are used at this point
                ResetCPUs(taf);
                attempts++;
            }
        }

        if (cpu >= 0) {
            return (uint16_t)cpu;
        }
    }
    return CPUSelectDefault(taf);
}

static uint16_t GetNextAvailableCPU(int iface_numa, ThreadsAffinityType *taf)
{
    if (iface_numa < 0) {
        return CPUSelectDefault(taf);
    }

    return CPUSelectFromNumaOrDefault(iface_numa, taf);
}

static bool AutopinEnabled(void)
{
    int autopin = 0;
    if (SCConfGetBool("threading.autopin", &autopin) != 1) {
        return false;
    }
    return (bool)autopin;
}

#endif /* OS_WIN32 and __OpenBSD__ */

uint16_t AffinityGetNextCPU(ThreadVars *tv, ThreadsAffinityType *taf)
{
    uint16_t ncpu = 0;
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    int iface_numa = -1;
    if (AutopinEnabled()) {
#ifdef HAVE_HWLOC
        if (TopologyShouldAutopin(tv, taf)) {
            if (TopologyInitialize() < 0) {
                SCLogError("Failed to initialize topology for CPU affinity");
                return ncpu;
            }
            iface_numa = InterfaceGetNumaNode(tv);
        }
#else
        static bool printed = false;
        if (!printed) {
            printed = true;
            SCLogWarning(
                    "threading.autopin option is enabled but hwloc support is not compiled in. "
                    "Make sure to pass --enable-hwloc to configure when building Suricata.");
        }
#endif /* HAVE_HWLOC */
    }

    SCMutexLock(&taf->taf_mutex);
    ncpu = GetNextAvailableCPU(iface_numa, taf);
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
