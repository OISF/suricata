/* Copyright (C) 2023 Open Information Security Foundation
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
 */

#include "suricata.h"
#include "util-debug.h"
#include "util-hugepages.h"
#include "util-path.h"

static uint16_t SystemHugepageSizesCntPerNodeGet(uint16_t node_index);
static uint16_t SystemNodeCountGet(void);
static void SystemHugepagePerNodeGetHugepageSizes(
        uint16_t node_index, uint16_t hp_sizes_cnt, uint32_t *hp_sizes);
static HugepageInfo *SystemHugepageHugepageInfoCreate(uint16_t hp_size_cnt);
static int16_t SystemHugepagePerNodeGetHugepageInfo(uint16_t node_index, NodeInfo *node);
static void SystemHugepageHugepageInfoDestroy(HugepageInfo *h);
static void SystemHugepageNodeInfoDestroy(NodeInfo *n);
static void SystemHugepageNodeInfoDump(NodeInfo *n);
static void SystemHugepageSnapshotDump(SystemHugepageSnapshot *s);

typedef enum OSHugepageAction_ {
    OS_UNKNOWN, // unknown/unsupported OS
    OS_LINUX_SYS_DEVICES,
} OSHugepageAction;

static OSHugepageAction SystemHugepageDetermineOS(void)
{
    // try Linux
    if (SCPathExists("/sys/devices/system/node/")) {
        return OS_LINUX_SYS_DEVICES;
    }

    return OS_UNKNOWN;
}

static bool SystemHugepageSupported(void)
{
    if (SystemHugepageDetermineOS() != OS_UNKNOWN)
        return true;
    return false;
}

/**
 * \brief Linux-specific function to detect number of NUMA nodes on the system
 * \returns number of NUMA nodes, 0 on error
 */
static uint16_t SystemNodeCountGetLinux(void)
{
    char dir_path[] = "/sys/devices/system/node/";
    DIR *dir = opendir(dir_path);
    if (dir == NULL)
        FatalError("unable to open %s", dir_path);

    uint16_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char d_name[] = "node";
        if (SCIsRegularDirectory(entry) && strncmp(entry->d_name, d_name, strlen(d_name)) == 0)
            count++;
    }
    closedir(dir);
    return count;
}

/**
 * \brief Linux-specific function to detect number of unique hugepage sizes
 * \param[in] node_index index of the NUMA node
 * \returns number of hugepage sizes, 0 on error
 */
static uint16_t SystemHugepageSizesCntPerNodeGetLinux(uint16_t node_index)
{
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/sys/devices/system/node/node%d/hugepages/", node_index);
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        SCLogInfo("unable to open %s", dir_path);
        return 0;
    }

    uint16_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char d_name[] = "hugepages-";
        if (SCIsRegularDirectory(entry) && strncmp(entry->d_name, d_name, strlen(d_name)) == 0)
            count++;
    }
    closedir(dir);
    return count;
}

/**
 * \brief Linux-specific function to detect unique hugepage sizes
 * \note Arrays `hugepages` and `hp_sizes` are expected to have the same size
 * \param[in] node_index index of the NUMA node
 * \param[in] hp_sizes_cnt number of the unique hugepage sizes
 * \param[out] hp_sizes a pointer to the array of hugepage sizes
 */
static void SystemHugepagePerNodeGetHugepageSizesLinux(
        uint16_t node_index, uint16_t hp_sizes_cnt, uint32_t *hp_sizes)
{
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/sys/devices/system/node/node%d/hugepages/", node_index);
    DIR *dir = opendir(dir_path);
    if (dir == NULL)
        FatalError("unable to open %s", dir_path);

    uint16_t index = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (SCIsRegularDirectory(entry) && strncmp(entry->d_name, "hugepages-", 10) == 0) {
            sscanf(entry->d_name, "hugepages-%ukB", &(hp_sizes[index]));
            index++;
        }
    }
    closedir(dir);
}

/**
 * \brief Linux-specific function to detect number of unique hugepage sizes
 * \note Arrays `hugepages` and `hp_sizes` are expected to have the same size
 * \param[out] hugepages a pointer to the array of hugepage info structures
 * \param[in] hp_sizes a pointer to the array of hugepage sizes
 * \param[in] hp_sizes_cnt number of hugepage sizes
 * \param[in] node_index index of the NUMA node
 * \returns 0 on success, negative number on error
 */
static int16_t SystemHugepagePerNodeGetHugepageInfoLinux(
        HugepageInfo *hugepages, uint32_t *hp_sizes, uint16_t hp_sizes_cnt, uint16_t node_index)
{
    for (int16_t i = 0; i < hp_sizes_cnt; i++) {
        hugepages[i].size_kb = hp_sizes[i];
        char path[256];
        snprintf(path, sizeof(path),
                "/sys/devices/system/node/node%hu/hugepages/hugepages-%ukB/nr_hugepages",
                node_index, hp_sizes[i]);
        FILE *f = fopen(path, "r");
        if (!f) {
            SCLogInfo("unable to open %s", path);
            return -SC_ENOENT;
        }
        if (fscanf(f, "%hu", &hugepages[i].allocated) != 1) {
            SCLogInfo("failed to read the total number of allocated hugepages (%ukB) on node %hu",
                    hp_sizes[i], node_index);
            fclose(f);
            return -SC_EINVAL;
        }
        fclose(f);

        snprintf(path, sizeof(path),
                "/sys/devices/system/node/node%hu/hugepages/hugepages-%ukB/free_hugepages",
                node_index, hp_sizes[i]);
        f = fopen(path, "r");
        if (!f) {
            SCLogInfo("unable to open %s", path);
            return -SC_ENOENT;
        }
        if (fscanf(f, "%hu", &hugepages[i].free) != 1) {
            SCLogInfo("failed to read the total number of free hugepages (%ukB) on node %hu",
                    hp_sizes[i], node_index);
            fclose(f);
            return -SC_EINVAL;
        }
        fclose(f);
    }

    return 0;
}

/**
 * \brief The function gathers information about hugepages on a given node
 * \param[in] node_index index of the NUMA node
 * \param[out] node a pointer to the structure to hold hugepage info
 * \returns 0 on success, negative number on error
 */
static int16_t SystemHugepagePerNodeGetHugepageInfo(uint16_t node_index, NodeInfo *node)
{
    uint16_t hp_sizes_cnt = SystemHugepageSizesCntPerNodeGet(node_index);
    if (hp_sizes_cnt == 0) {
        SCLogInfo("hugepages not found for node %d", node_index);
        return -SC_ENOENT;
    }
    uint32_t *hp_sizes = SCCalloc(hp_sizes_cnt, sizeof(*hp_sizes));
    if (hp_sizes == NULL) {
        FatalError("failed to allocate memory for hugepage info");
    }
    SystemHugepagePerNodeGetHugepageSizes(node_index, hp_sizes_cnt, hp_sizes);

    node->hugepages = SystemHugepageHugepageInfoCreate(hp_sizes_cnt);
    node->num_hugepage_sizes = hp_sizes_cnt;

    int16_t ret = 0;
    if (SystemHugepageDetermineOS() == OS_LINUX_SYS_DEVICES)
        ret = SystemHugepagePerNodeGetHugepageInfoLinux(
                node->hugepages, hp_sizes, node->num_hugepage_sizes, node_index);

    SCFree(hp_sizes);
    return ret;
}

/**
 * \brief The function detects number of NUMA nodes on the system
 * \returns 0 if detection is unsuccessful, otherwise number of detected nodes
 */
static uint16_t SystemNodeCountGet(void)
{
    if (SystemHugepageDetermineOS() == OS_LINUX_SYS_DEVICES)
        return SystemNodeCountGetLinux();
    return 0;
}

/**
 * \brief The function detects the number of unique hugepage sizes
 * \returns 0 if detection is unsuccessful, otherwise number of hugepage sizes
 */
static uint16_t SystemHugepageSizesCntPerNodeGet(uint16_t node_index)
{
    if (SystemHugepageDetermineOS() == OS_LINUX_SYS_DEVICES)
        return SystemHugepageSizesCntPerNodeGetLinux(node_index);
    return 0;
}

/**
 * \brief The function fills an array with unique hugepage sizes
 * \note Arrays `hugepages` and `hp_sizes` are expected to have the same size
 * \param[in] node_index index of the NUMA node
 * \param[in] hp_sizes_cnt number of hugepage sizes
 * \param[out] hp_sizes a pointer to the array of hugepage sizes
 */
static void SystemHugepagePerNodeGetHugepageSizes(
        uint16_t node_index, uint16_t hp_sizes_cnt, uint32_t *hp_sizes)
{
    if (SystemHugepageDetermineOS() == OS_LINUX_SYS_DEVICES)
        SystemHugepagePerNodeGetHugepageSizesLinux(node_index, hp_sizes_cnt, hp_sizes);
}

static HugepageInfo *SystemHugepageHugepageInfoCreate(uint16_t hp_size_cnt)
{
    HugepageInfo *h = SCCalloc(hp_size_cnt, sizeof(*h));
    if (h == NULL) {
        FatalError("failed to allocate hugepage info array");
    }
    return h;
}

static void SystemHugepageHugepageInfoDestroy(HugepageInfo *h)
{
    if (h != NULL)
        SCFree(h);
}

static void SystemHugepageNodeInfoDestroy(NodeInfo *n)
{
    if (n == NULL)
        return;

    SystemHugepageHugepageInfoDestroy(n->hugepages);
}

static void SystemHugepageNodeInfoDump(NodeInfo *n)
{
    if (n == NULL)
        return;

    for (uint16_t i = 0; i < n->num_hugepage_sizes; i++) {
        SCLogDebug("Hugepage size - %dkB - allocated: %d free: %d", n->hugepages[i].size_kb,
                n->hugepages[i].allocated, n->hugepages[i].free);
    }
}

/**
 * \brief The function prints out the hugepage snapshot
 * \param[in] s a pointer to the snapshot
 */
static void SystemHugepageSnapshotDump(SystemHugepageSnapshot *s)
{
    if (s == NULL)
        return;

    for (uint16_t i = 0; i < s->num_nodes; i++) {
        SCLogDebug("NUMA Node %d", i);
        SystemHugepageNodeInfoDump(&(s->nodes[i]));
    }
}

void SystemHugepageSnapshotDestroy(SystemHugepageSnapshot *s)
{
    if (s == NULL)
        return;

    for (uint16_t i = 0; i < s->num_nodes; i++) {
        SystemHugepageNodeInfoDestroy(&(s->nodes[i]));
    }
    SCFree(s->nodes);
    SCFree(s);
}

/**
 * \brief The function creates a snapshot of the system's hugepage usage
 *        per NUMA node and per hugepage size.
 *        The snapshot is used to evaluate the system's hugepage usage after
 *        initialization of Suricata.
 * \returns a pointer to the snapshot, NULL on error
 */
SystemHugepageSnapshot *SystemHugepageSnapshotCreate(void)
{
    if (!SystemHugepageSupported())
        return NULL;

    uint16_t node_cnt = SystemNodeCountGet();
    if (node_cnt == 0) {
        SCLogInfo("hugepage snapshot failed - cannot obtain number of NUMA nodes in the system");
        return NULL;
    }
    NodeInfo *nodes = SCCalloc(node_cnt, sizeof(*nodes));
    if (nodes == NULL) {
        FatalError("failed to allocate memory for NUMA node info");
    }

    SystemHugepageSnapshot *s = SCCalloc(1, sizeof(*s));
    if (s == NULL) {
        SCFree(nodes);
        FatalError("failed to allocate memory for NUMA node snapshot");
    }
    s->num_nodes = node_cnt;
    s->nodes = nodes;

    for (uint16_t i = 0; i < s->num_nodes; i++) {
        int16_t ret = SystemHugepagePerNodeGetHugepageInfo(i, &s->nodes[i]);
        if (ret != 0) {
            SystemHugepageSnapshotDestroy(s);
            return NULL;
        }
    }

    return s;
}

/**
 * \brief The function compares two hugepage snapshots and prints out
 *        recommendations for hugepage configuration
 * \param[in] pre_s  a pointer to the snapshot taken before Suricata initialization
 * \param[in] post_s a pointer to the snapshot taken after Suricata initialization
 */
void SystemHugepageEvaluateHugepages(SystemHugepageSnapshot *pre_s, SystemHugepageSnapshot *post_s)
{
    if (!SystemHugepageSupported() || pre_s == NULL || post_s == NULL)
        return;

    SCLogDebug("Hugepages before initialization");
    SystemHugepageSnapshotDump(pre_s);

    SCLogDebug("Hugepages after initialization");
    SystemHugepageSnapshotDump(post_s);

    if (pre_s->num_nodes != post_s->num_nodes)
        FatalError("Number of NUMA nodes changed during hugepage evaluation");

    for (int32_t i = 0; i < post_s->num_nodes; i++) {
        if (pre_s->nodes[i].num_hugepage_sizes != post_s->nodes[i].num_hugepage_sizes)
            FatalError("Number of NUMA node hugepage sizes changed during hugepage evaluation");

        for (int32_t j = 0; j < post_s->nodes->num_hugepage_sizes; j++) {
            HugepageInfo *prerun_hp = &pre_s->nodes[i].hugepages[j];
            HugepageInfo *postrun_hp = &post_s->nodes[i].hugepages[j];

            if (prerun_hp->free == 0) {
                continue; // this HP size on this node has no HPs allocated
            } else if (prerun_hp->free < postrun_hp->free) {
                SCLogWarning(
                        "Hugepage usage decreased while it should only increase/stay the same");
            } else if (prerun_hp->free > 0 && prerun_hp->free == postrun_hp->free) {
                SCLogPerf("%ukB hugepages on NUMA node %u are unused and can be deallocated",
                        postrun_hp->size_kb, i);
            } else { // assumes this is an active NUMA node because at least some hugepages were
                     // used
                // speculative hint only for 2048kB pages as e.g. 1 GB pages can leave a lot of room
                // for additional allocations
                if (postrun_hp->size_kb == 2048 && postrun_hp->free == 0) {
                    SCLogPerf("all %ukB hugepages used on NUMA node %d - consider increasing to "
                              "prevent memory allocation from other NUMA nodes",
                            postrun_hp->size_kb, i);
                }

                float free_hugepages_ratio = (float)postrun_hp->free / (float)prerun_hp->free;
                if (free_hugepages_ratio > 0.5) {
                    int32_t used_hps = prerun_hp->free - postrun_hp->free;
                    SCLogPerf("Hugepages on NUMA node %u can be set to %.0lf (only using %u/%u "
                              "%ukB hugepages)",
                            i, ceil((prerun_hp->free - postrun_hp->free) * 1.15), used_hps,
                            prerun_hp->free, postrun_hp->size_kb);
                }
            }
        }
    }
}
