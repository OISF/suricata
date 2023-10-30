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

#include <dirent.h>

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
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
#endif /* !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun */

void SystemHugepageSnapshotDestroy(SystemHugepageSnapshot *s)
{
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    if (s == NULL)
        return;

    for (uint16_t i = 0; i < s->num_nodes; i++) {
        SystemHugepageNodeInfoDestroy(&(s->nodes[i]));
    }
    SCFree(s->nodes);
    SCFree(s);
#endif /* !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun */
}

SystemHugepageSnapshot *SystemHugepageSnapshotCreate(void)
{
#if defined __CYGWIN__ || defined OS_WIN32 || defined __OpenBSD__ || defined sun
    return NULL;
#else
    if (run_mode != RUNMODE_DPDK)
        return NULL;

    uint16_t node_cnt = SystemNodeCountGet();
    if (node_cnt == 0) {
        SCLogError("failed to obtain number of NUMA nodes in the system");
        return NULL;
    }
    NodeInfo *nodes = SCCalloc(node_cnt, sizeof(*nodes));
    if (nodes == NULL) {
        FatalError("failed to allocate memory for NUMA node info");
        return NULL;
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
#endif /* defined __CYGWIN__ || defined OS_WIN32 || defined __OpenBSD__ || defined sun */
}

void SystemHugepageEvaluateHugepages(SystemHugepageSnapshot *pre_s, SystemHugepageSnapshot *post_s)
{
    if (run_mode != RUNMODE_DPDK)
        return;

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
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
                SCLogPerf("Hugepages on NUMA node %u are unused and can be deallocated", i);
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
#endif /* !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun */
}

// block of all hugepage-specific internal functions
#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun

/**
 * \brief The function attempts to detect number of NUMA nodes on the system
 * \returns 0 if detection is unsuccessful, otherwise number of detected nodes
 */
static uint16_t SystemNodeCountGet(void)
{
    char dir_path[] = "/sys/devices/system/node/";
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        SCLogError("unable to open %s", dir_path);
        return 0;
    }

    uint16_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char d_name[] = "node";
        if (entry->d_type == DT_DIR && strncmp(entry->d_name, d_name, strlen(d_name)) == 0)
            count++;
    }
    closedir(dir);
    return count;
}

/**
 * \brief The function attempts to detect number of unique hugepage sizes
 * \returns 0 if detection is unsuccessful, otherwise number of hugepage sizes
 */
static uint16_t SystemHugepageSizesCntPerNodeGet(uint16_t node_index)
{
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/sys/devices/system/node/node%d/hugepages/", node_index);
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        SCLogError("unable to open %s", dir_path);
        return 0;
    }

    uint16_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char d_name[] = "hugepages-";
        if (entry->d_type == DT_DIR && strncmp(entry->d_name, d_name, strlen(d_name)) == 0)
            count++;
    }
    closedir(dir);
    return count;
}

static void SystemHugepagePerNodeGetHugepageSizes(
        uint16_t node_index, uint16_t hp_sizes_cnt, uint32_t *hp_sizes)
{
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/sys/devices/system/node/node%d/hugepages/", node_index);
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        SCLogError("unable to open %s", dir_path);
        return;
    }
    uint16_t index = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strncmp(entry->d_name, "hugepages-", 10) == 0) {
            sscanf(entry->d_name, "hugepages-%ukB", &(hp_sizes[index]));
            index++;
        }
    }
    closedir(dir);
}

static HugepageInfo *SystemHugepageHugepageInfoCreate(uint16_t hp_size_cnt)
{
    HugepageInfo *h = SCCalloc(hp_size_cnt, sizeof(*h));
    if (h == NULL) {
        FatalError("failed to allocate hugepage info array");
    }
    return h;
}

static int16_t SystemHugepagePerNodeGetHugepageInfo(uint16_t node_index, NodeInfo *node)
{
    uint16_t hp_sizes_cnt = SystemHugepageSizesCntPerNodeGet(node_index);
    if (hp_sizes_cnt == 0) {
        SCLogError("hugepages not found for node %d", node_index);
        return -1;
    }
    uint32_t *hp_sizes = SCCalloc(hp_sizes_cnt, sizeof(*hp_sizes));
    if (hp_sizes == NULL) {
        FatalError("failed to allocate memory for hugepage info");
    }
    SystemHugepagePerNodeGetHugepageSizes(node_index, hp_sizes_cnt, hp_sizes);

    node->hugepages = SystemHugepageHugepageInfoCreate(hp_sizes_cnt);
    node->num_hugepage_sizes = hp_sizes_cnt;

    for (int16_t i = 0; i < hp_sizes_cnt; i++) {
        node->hugepages[i].size_kb = hp_sizes[i];
        char path[256];
        snprintf(path, sizeof(path),
                "/sys/devices/system/node/node%hd/hugepages/hugepages-%ukB/nr_hugepages",
                node_index, hp_sizes[i]);
        FILE *f = fopen(path, "r");
        if (!f) {
            SCLogError("unable to open %s", path);
            SCFree(hp_sizes);
            fclose(f);
            return -1;
        }
        if (fscanf(f, "%hd", &node->hugepages[i].allocated) != 1) {
            SCLogError("failed to read the total number of allocated hugepages (%ukB) on node %hd",
                    hp_sizes[i], node_index);
            fclose(f);
            SCFree(hp_sizes);
            return -1;
        }
        fclose(f);

        snprintf(path, sizeof(path),
                "/sys/devices/system/node/node%hd/hugepages/hugepages-%ukB/free_hugepages",
                node_index, hp_sizes[i]);
        f = fopen(path, "r");
        if (!f) {
            SCLogError("unable to open %s", path);
            SCFree(hp_sizes);
            fclose(f);
            return -1;
        }
        if (fscanf(f, "%hd", &node->hugepages[i].free) != 1) {
            SCLogError("failed to read the total number of free hugepages (%ukB) on node %hd",
                    hp_sizes[i], node_index);
            SCFree(hp_sizes);
            fclose(f);
            return -1;
        }
        fclose(f);
    }

    SCFree(hp_sizes);
    return 0;
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

static void SystemHugepageSnapshotDump(SystemHugepageSnapshot *s)
{
    if (s == NULL)
        return;

    for (uint16_t i = 0; i < s->num_nodes; i++) {
        SCLogDebug("NUMA Node %d", i);
        SystemHugepageNodeInfoDump(&(s->nodes[i]));
    }
}

#endif /* !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun */
