/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#ifndef HASH_TABLE_BYPASS_H
#define HASH_TABLE_BYPASS_H

#include <stdlib.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_table.h>
#include <rte_table_hash.h>
#include <rte_table_hash_func.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>
#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-bypass.h"

struct rte_table_hash;

struct __attribute__((aligned(64))) BypassHashTableData {
    struct FlowKeyDirection fd;
    uint64_t pktstosrc;
    uint64_t bytestosrc;
    uint64_t pktstodst;
    uint64_t bytestodst;
};

void BypassHashTableSetOps(struct rte_table_ops ops_);
struct rte_table_hash *BypassHashTableInit(const char *name, uint32_t bt_entries);
void BypassHashTableDeinit(struct rte_table_hash **bt);
int BypassHashTableLookup(struct rte_table_hash *bt, const void **keys, uint32_t num_keys,
        uint64_t *hit_mask, void *data[]);
int BypassHashTableDelete(struct rte_table_hash *bt, void *keys, int32_t *key_found, void *data);
int BypassHashTableDeleteBulk(
        struct rte_table_hash *bt, void **keys, uint32_t keys_cnt, int32_t *keys_deleted);
int BypassHashTableAdd(struct rte_table_hash *bt, void *key, void *entry);
int BypassHashTableAddBulk(
        struct rte_table_hash *bt, void **keys, uint32_t keys_cnt, void **entries);
enum FlowDirectionEnum BypassHashTableGetDirection(
        struct FlowKeyDirection *fd1, struct FlowKeyDirection *fd2);
void BypassHashTableUpdateStats(
        struct BypassHashTableData *b_data, struct FlowKeyDirection *fk_dir, uint16_t pkt_len);

#endif // HASH_TABLE_BYPASS_H
