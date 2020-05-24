/* Entire code has been written taking into consideration the following system topology.
 * It may not work on different topologies.
 *
 * depth 0:           1 Machine (type #0)
 *  depth 1:          1 Package (type #1)
 *   depth 2:         1 L3Cache (type #6)
 *    depth 3:        4 L2Cache (type #5)
 *     depth 4:       4 L1dCache (type #4)
 *      depth 5:      4 L1iCache (type #9)
 *       depth 6:     4 Core (type #2)
 *        depth 7:    8 PU (type #3)
 * Special depth -3:  1 NUMANode (type #13)
 * Special depth -4:  2 Bridge (type #14)
 * Special depth -5:  4 PCIDev (type #15)
 * Special depth -6:  3 OSDev (type #16)
 *
 * Catches:
 * - There may be shorter ways to connect the appropriate NUMA to the network interface.
 * - Code is not generic. Works for the above topology.
 *
 * */

#include "suricata-common.h"
#include "util-debug.h"
#include "util-hwloc.h"
#include "util-device.h"

#ifdef HAVE_HWLOC

void HwlocTopologySetTypeFilter(hwloc_topology_t);
const char *HwlocGetNetworkDeviceName(void);

void HwlocTopologySetTypeFilter(hwloc_topology_t topology)
{
    // IMPORTANT for newer versions else interfaces are not detected
    hwloc_topology_set_type_filter(
            topology, HWLOC_OBJ_PCI_DEVICE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    hwloc_topology_set_type_filter(topology, HWLOC_OBJ_OS_DEVICE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    hwloc_topology_set_type_filter(topology, HWLOC_OBJ_BRIDGE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    // OR (acc to docs the following should work but it doesnt detect my wifi interface)
    // hwloc_topology_set_io_types_filter(topology, HWLOC_TYPE_FILTER_KEEP_ALL);
}

const char *HwlocGetNetworkDeviceName(void)
{
    int nlive = LiveGetDeviceNameCount();
    SCLogInfo("Number of live devices: %d", nlive);
    const char *live_dev = NULL;
    for (int ldev = 0; ldev < nlive; ldev++) {
        live_dev = LiveGetDeviceNameName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "No live device found");
            return NULL;
        }
    }
    // Since we are just talking about one interface for PoC
    return live_dev;
}

void PrintNUMAnodes(void)
{
    hwloc_topology_t topology;
    hwloc_obj_t obj, nobj, cobj;

    // Initialize topology
    hwloc_topology_init(&topology);
    // Set filters required for detection of different types of objects
    // like PCI, Bridge and OS Devices (eth0, etc)
    HwlocTopologySetTypeFilter(topology);

    // Load the topology. This is where the actual detection occurs.
    hwloc_topology_load(topology);

    // Unnecessary but good to match with the topology you see with lstopo
    // on cmdline. If certain objects are missing for some reason, depth may be
    // lower than expected.
    int topodepth = hwloc_topology_get_depth(topology);
    SCLogInfo("Topology depth: %d", topodepth);

    // Basic test
    // 00:14.3 is the bus ID for my WiFi interface
    obj = hwloc_get_pcidev_by_busidstring(topology, "00:14.3");
    if (obj == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "The device with given bus ID was not found");
        goto end;
    }
    // Not sure why name and subtype is NULL.
    // Maybe because the docs say that libpciaccess is required for this and without
    // it info like name etc will be missing.
    SCLogDebug("Hwloc obj name: %s subtype: %s", obj->name, obj->subtype);

    // Get the interface Suricata is running on currently.
    const char *iface = HwlocGetNetworkDeviceName();
    if (iface == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Current network interface name not found");
        goto end;
    }
    SCLogDebug("Current network interface name: %s", iface);

    // Network interfaces are registered as "OS devices" so we find the children
    // from the root which are OS devices.
    for (obj = hwloc_get_next_osdev(topology, NULL); obj;
            obj = hwloc_get_next_osdev(topology, obj)) {
        if (strcmp(obj->name, iface) == 0) {
            SCLogDebug("Found '%s' object in osdev traversal", obj->name);
            // Network interfaces are marked as IO devices (sub: OS devices) which are at times
            // (e.g. my system topology) not a part of a package but outside of the entire
            // Machine object so it needs to find the first non IO ancestor.
            nobj = hwloc_get_non_io_ancestor_obj(topology, obj);
            SCLogDebug("Ancestor obj type: %d", nobj->type);
            // In case the network interface is outside of the entire Machine object like mine
            if (nobj->type == HWLOC_OBJ_MACHINE) {
                SCLogDebug("It is indeed HWLOC_OBJ_MACHINE");
                // Find out the children inside it, NUMA must be there.
                // IMPORTANT: Memory objects are not listed in the main children list,
                // but rather in the dedicated Memory children list.
                for (cobj = hwloc_get_next_child(topology, nobj, NULL); cobj;
                        cobj = hwloc_get_next_child(topology, cobj, NULL)) {
                    SCLogDebug("Child's type: %d", cobj->type);
                    SCLogDebug("Mem arity for cobj: %d", cobj->memory_arity);
                    // Check memory specific first child
                    if (cobj->memory_first_child != NULL) {
                        // There are several other types of objects like bridge,
                        // package, machine, etc that are not printed as of now
                        if (cobj->memory_first_child->type == HWLOC_OBJ_NUMANODE) {
                            SCLogInfo("FOUND THE NUMA node");
                        }
                    }
                }
            }
        } else {
            // If we find another OS Device than the one Suricata is running on
            // then continue to the next OS Device.
            continue;
        }
    }

    // When IO devices are inside the machine in a topology, following
    // seems to work. Here, we find the first non IO ancestral obj and
    // go to its parent back to back until we find the numa node
    for (hwloc_obj_t pobj = obj; pobj; pobj = pobj->parent) {
        SCLogNotice("pobj type: %d/%s", pobj->type, pobj->name);
        if (pobj->type == HWLOC_OBJ_NUMANODE) {
            SCLogNotice("NUMANODE");
        }
        if (pobj->type == HWLOC_OBJ_BRIDGE) {
            SCLogNotice("BRIDGE");
        }
        if (pobj->type == HWLOC_OBJ_PACKAGE) {
            SCLogNotice("PACKAGE");
        }
        if (pobj->type == HWLOC_OBJ_MACHINE) {
            SCLogNotice("MACHINE");
        }
    }

end:
    hwloc_topology_destroy(topology);
}

#endif /* HAVE_HWLOC */
