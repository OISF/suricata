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

#include <sys/types.h>
#include <rte_errno.h>
#include <rte_table_hash_func.h>
#include <rte_table_hash.h>

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

#include "hash-table-bypass.h"
#include "dev-conf.h"
#include "logger.h"

static struct rte_table_ops bt_ops;

// always needs to be called the first
void BypassHashTableSetOps(struct rte_table_ops ops_)
{
    bt_ops = ops_;
}

struct rte_table_hash *BypassHashTableInit(const char *name, uint32_t bt_entries)
{
    struct rte_table_hash *t = NULL;
    uint32_t key_size = sizeof(FlowKey);
    uint32_t elm_size = sizeof(struct BypassHashTableData);
    uint32_t elms_per_bkt = RTE_MAX(4, 1u);
    uint32_t bkts = bt_entries / elms_per_bkt;

    if (bt_ops.f_create == NULL) {
        rte_panic("Bypass hash table create operation not set!\n");
    }

    struct rte_table_hash_params params = {
        .name = name,
        .key_size = key_size,
        .key_offset = 0,
        .key_mask = NULL,
        .n_keys = bt_entries,
        .n_buckets = bkts,
        .f_hash = rte_table_hash_crc_key64,
        .seed = 0x6d5a6d5a6d5a6d5a, // irrelevant, this will not hash the same as Toeplitz
    };

    Log().debug("Bypass Hash Table - key size %u element size %u elements total %u buckets %u "
                "elements in bucket %u",
            key_size, elm_size, params.n_keys, params.n_buckets,
            params.n_keys / params.n_buckets);

    t = bt_ops.f_create(&params, (int)rte_socket_id(), elm_size);
    if (t == NULL) {
        Log().error(
                EINVAL, "Error (%s): Failed to create bypass hash table", rte_strerror(rte_errno));
        return NULL;
    }

    return t;
}

void BypassHashTableDeinit(struct rte_table_hash **bt)
{
    int retval;
    if (bt == NULL || (*bt) == NULL)
        return;

    retval = bt_ops.f_free((void *)*bt);
    if (retval != 0) {
        Log().warning(rte_errno, "Unable to deinit bypass hash table");
        return;
    }

    (*bt) = NULL;
}

// returns number of successful lookups
int BypassHashTableLookup(struct rte_table_hash *bt, const void **keys, uint32_t num_keys,
        uint64_t *hit_mask, void *data[])
{
    if (num_keys == 0) {
        *hit_mask = 0;
        return 0;
    }

    int retval;
    uint64_t keys_mask = 0xffffffffffffffff >> (64 - num_keys);
    retval = bt_ops.f_lookup((void *)bt, (struct rte_mbuf **)keys, keys_mask, hit_mask, data);
    return retval == 0 ? __builtin_popcount(*hit_mask) : retval;
}

int BypassHashTableDelete(struct rte_table_hash *bt, void *keys, int32_t *key_found, void *data)
{
    int retval = bt_ops.f_delete(bt, keys, key_found, data);
    if (retval != 0) {
        Log().info("Error (%s): Bypass Hash Table delete operation failed", rte_strerror(-retval));
    }
    return retval;
}

int BypassHashTableDeleteBulk(
        struct rte_table_hash *bt, void **keys, uint32_t keys_cnt, int32_t *keys_deleted)
{
    if (keys_cnt == 0)
        return 0;

    if (bt_ops.f_delete_bulk == NULL) {
        *keys_deleted = 0;
        int32_t kf, retval;
        for (int i = 0; i < keys_cnt; i++) {
            retval = BypassHashTableDelete(bt, keys[i], &kf, NULL);
            if (retval == 0 && kf)
                *keys_deleted |= 1 << i;
            else if (retval < 0)
                return retval;
        }
        return __builtin_popcount(*keys_deleted);
    } else {
        int retval;
        retval = bt_ops.f_delete_bulk(bt, keys, keys_cnt, keys_deleted, NULL);
        return retval == 0 ? __builtin_popcount(*keys_deleted) : retval;
    }
}

int BypassHashTableAdd(struct rte_table_hash *bt, void *key, void *entry)
{
    int32_t key_found;
    void *entry_ptr;

    int retval = bt_ops.f_add(bt, key, entry, &key_found, &entry_ptr);

    if (retval != 0 || entry_ptr == NULL || key_found) {
        if (retval != 0)
            Log().debug("Error (%s): Bypass Hash Table add operation failed", rte_strerror(-retval));

        if (entry_ptr == NULL)
            Log().debug("Error - entry ptr null");

        if (key_found)
            Log().debug("Error - key found already!");
    } else {
        Log().debug("Flow bypassed with entry ptr: %p", entry_ptr);
    }
    return retval;
}

int BypassHashTableAddBulk(
        struct rte_table_hash *bt, void **keys, uint32_t keys_cnt, void **entries)
{
    if (keys_cnt == 0)
        return 0;

    if (bt_ops.f_add_bulk == NULL) {
        int ret;
        uint16_t keys_added = 0;
        for (int i = 0; i < keys_cnt; i++) {
            ret = BypassHashTableAdd(bt, keys[i], entries[i]);
            if (ret == 0)
                keys_added++;
        }
        return (int)keys_added;
    } else {
        int32_t keys_found, retval;
        void *inserted_entries_ptr[32]; // 32 based on int key_found (32 bits int)
        retval = bt_ops.f_add_bulk(bt, keys, entries, keys_cnt, &keys_found, inserted_entries_ptr);
        return retval == 0 ? __builtin_popcount(keys_found) : retval;
    }
}

enum FlowDirectionEnum BypassHashTableGetDirection(
        struct FlowKeyDirection *fd1, struct FlowKeyDirection *fd2)
{
    if (fd1->src_port == fd2->src_port && fd1->src_addr == fd2->src_addr) {
        return TO_DST;
    } else {
        return TO_SRC;
    }
}

void BypassHashTableUpdateStats(
        struct BypassHashTableData *b_data, struct FlowKeyDirection *fk_dir, uint16_t pkt_len)
{
    if (BypassHashTableGetDirection(fk_dir, &b_data->fd) == TO_SRC) {
        b_data->bytestodst += pkt_len;
        b_data->pktstodst++;
    } else {
        b_data->bytestosrc += pkt_len;
        b_data->pktstosrc++;
    }
}
