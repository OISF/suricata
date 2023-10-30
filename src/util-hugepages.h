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

#ifndef UTIL_HUGEPAGES_H
#define UTIL_HUGEPAGES_H

typedef struct {
    uint32_t size_kb;
    uint16_t allocated;
    uint16_t free;
} HugepageInfo;

// Structure to hold information about individual NUMA nodes in the system and
// and their respective allocated hugepages
// So for e.g. NUMA node 0 there can be 2 hugepage_size - 2 MB and 1 GB
// Each hugepage size will then have a record of number of allocated/free hpages
typedef struct {
    uint16_t num_hugepage_sizes;
    HugepageInfo *hugepages;
} NodeInfo;

// Structure to hold information about all hugepage sizes residing on all NUMA
// nodes in the system
typedef struct {
    uint16_t num_nodes;
    NodeInfo *nodes;
} SystemHugepageSnapshot;

SystemHugepageSnapshot *SystemHugepageSnapshotCreate(void);
void SystemHugepageSnapshotDestroy(SystemHugepageSnapshot *s);
void SystemHugepageEvaluateHugepages(SystemHugepageSnapshot *pre_s, SystemHugepageSnapshot *post_s);

#endif /* UTIL_HUGEPAGES_H */
