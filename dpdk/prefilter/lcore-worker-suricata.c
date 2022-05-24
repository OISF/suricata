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

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>

#include "lcore-worker-suricata.h"
#include "lcores-manager.h"
#include "lcore-worker.h"
#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "logger.h"
#include "util-prefilter.h"

#include <rte_ethdev.h>
#include <rte_malloc.h>

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
#include "runmode-dpdk.h"
#include "source-dpdk.h"

// The flag is used to set mbuf offload flags
// Prefilter receives from 2 NICs but aggregates the traffic into a single DPDK ring
// This flag notes, from which NIC it was received, so the other NIC is for transmitting the packet.
#define PKT_ORIGIN_PORT1 PKT_FIRST_FREE

// not used - explanation above MessagesCheckBulk
static void MessagesHandleAddBulk(struct lcore_values *lv, struct FlowKeyDirection *msgs_flow_dirs,
        FlowKey **msgs_flow_keys, uint32_t msgs_lookup_hitmask, struct PFMessage **msgs_add,
        const uint8_t *msgs_add_indices, uint8_t msgs_add_cnt,
        FlowKey **msgs_add_flow_keys, // only to get the array, otherwise not needed
        struct BypassHashTableData **bt_data_add)
{
    int ret;
    uint8_t msgs_add_flow_keys_cnt = 0;

    for (uint8_t i = 0; i < msgs_add_cnt; i++) {
        // construct an array of key-values to add (which are not in the table)
        if (msgs_lookup_hitmask & (1 << msgs_add_indices[i]))
            continue; // do not want to add a key that's already there

        msgs_add_flow_keys[msgs_add_flow_keys_cnt] = msgs_flow_keys[msgs_add_indices[i]];
        *(bt_data_add[i]) = (struct BypassHashTableData){ .fd = msgs_flow_dirs[msgs_add_indices[i]],
            .pktstodst = 0,
            .pktstosrc = 0,
            .bytestodst = 0,
            .bytestosrc = 0 };
        msgs_add_flow_keys_cnt++;
    }

    ret = BypassHashTableAddBulk(
            lv->bt, (void **)msgs_add_flow_keys, msgs_add_flow_keys_cnt, (void **)bt_data_add);
    if (ret < 0) {
        Log().notice("Bulk add to bypass hash table failed!");
    } else if (ret != msgs_add_flow_keys_cnt) {
        Log().info("Unable to add all keys to bypass hash table");
        // no after operation handling required (arrays on stack)
    } else {
        Log().debug("Successfully added %d bypass keys to the bypass hash table",
                msgs_add_flow_keys_cnt);
    }
    rte_mempool_put_bulk(lv->message_mp, (void **)msgs_add, msgs_add_cnt);
}

// not used - explanation above MessagesCheckBulk
static void MessagesHandleSoftDeleteBulk(struct lcore_values *lv, struct PFMessage **msgs,
        uint32_t msgs_lookup_hitmask, struct BypassHashTableData **flow_data,
        const uint8_t *msgs_soft_del_indices, uint8_t msgs_soft_del_cnt,
        FlowKey **flow_keys_delete, // only to get the array, not an input
        FlowKey *flow_keys_unified, // only to get the array, not an input
        struct PFMessage **msgs_out // only to get the array, not an input
)
{
    // parse soft delete messages
    uint32_t msgs_sent;
    uint8_t msgs_out_cnt = 0;
    uint8_t flow_keys_delete_cnt = 0;
    int ret;

    for (uint8_t i = 0; i < (uint8_t)(msgs_soft_del_cnt); i++) {
        msgs_out[msgs_out_cnt] = msgs[msgs_soft_del_indices[i]];
        flow_keys_unified[i] = msgs_out[msgs_out_cnt]->fk;
        if (msgs_lookup_hitmask & (1 << msgs_soft_del_indices[i])) {
            Log().debug("Flow to check found in the bypass table");
            PFMessageEvictBypassInit(msgs_out[msgs_out_cnt]);
            FlowKeyReconstruct(
                    &msgs_out[msgs_out_cnt]->fk, &flow_data[msgs_soft_del_indices[i]]->fd);
            msgs_out[msgs_out_cnt]->bypass_evict_msg.tosrcpktcnt =
                    flow_data[msgs_soft_del_indices[i]]->pktstosrc;
            msgs_out[msgs_out_cnt]->bypass_evict_msg.tosrcbytecnt =
                    flow_data[msgs_soft_del_indices[i]]->bytestosrc;
            msgs_out[msgs_out_cnt]->bypass_evict_msg.todstpktcnt =
                    flow_data[msgs_soft_del_indices[i]]->pktstodst;
            msgs_out[msgs_out_cnt]->bypass_evict_msg.todstbytecnt =
                    flow_data[msgs_soft_del_indices[i]]->bytestodst;
            msgs_out_cnt++;
        } else {
            Log().debug("Flow to delete not found in the bypass table");
            PFMessageErrorFlowNotFoundBypassInit(msgs_out[msgs_out_cnt]);
            FlowKeyReconstruct(
                    &msgs_out[msgs_out_cnt]->fk, &flow_data[msgs_soft_del_indices[i]]->fd);
            msgs_out_cnt++;
        }
    }

    for (int i = 0; i < msgs_out_cnt; i++) {
        Log().debug("Sending evict message with stats "
                    "B to src %u Pkts to src %u "
                    "B to dst %u Pkts to dst %u",
                msgs_out[i]->bypass_evict_msg.tosrcbytecnt,
                msgs_out[i]->bypass_evict_msg.tosrcpktcnt,
                msgs_out[i]->bypass_evict_msg.todstbytecnt,
                msgs_out[i]->bypass_evict_msg.todstpktcnt);
    }

    msgs_sent = rte_ring_enqueue_bulk(lv->results_ring, (void **)msgs_out, msgs_out_cnt, NULL);
    if (msgs_sent < msgs_out_cnt) {
        rte_mempool_put_bulk(
                lv->message_mp, (void **)(msgs_out + msgs_sent), msgs_out_cnt - msgs_sent);
        Log().notice(
                "unable to enqueue all messages to results ring (%d of %d)", ret, msgs_out_cnt);
    }

    // only doing further operations if I was able to send the message
    for (uint32_t i = 0; i < msgs_sent; i++) {
        if (msgs_out[i]->msg_type == PF_MESSAGE_BYPASS_EVICT) {
            if (msgs_out[i]->bypass_evict_msg.tosrcpktcnt == 0 &&
                    msgs_out[i]->bypass_evict_msg.todstpktcnt == 0) {
                flow_keys_delete[flow_keys_delete_cnt] = &flow_keys_unified[i];
                flow_keys_delete_cnt++;
            } else {
                flow_data[msgs_soft_del_indices[i]]->pktstosrc = 0;
                flow_data[msgs_soft_del_indices[i]]->bytestosrc = 0;
                flow_data[msgs_soft_del_indices[i]]->pktstodst = 0;
                flow_data[msgs_soft_del_indices[i]]->bytestodst = 0;
            }
        }
    }

    int32_t keys_deleted;
    ret = BypassHashTableDeleteBulk(
            lv->bt, (void **)flow_keys_delete, flow_keys_delete_cnt, &keys_deleted);
    if (ret < 0) {
        Log().notice("Bulk delete in bypass hash table failed");
    } else if (ret != flow_keys_delete_cnt) {
        Log().warning(ENOENT, "Some keys to delete were not present in the bypass hash table");
    } else {
        Log().debug("Deleted %d keys from the bypass hash table", flow_keys_delete_cnt);
    }
}

// handles incoming messages in bulks but there can be problems with the operation order
// where e.g. all add operations are done first and then all delete operations are done
// You can either accept this or implement protection for operation order.

// not updated for hard delete - maybe just delete that?
static void MessagesCheckBulk(struct lcore_values *lv)
{
    struct PFMessage *msgs[BURST_SIZE];
    uint32_t msgs_cnt;
    FlowKey *msgs_flow_keys[sizeof(msgs) / sizeof(msgs[0])];
    struct FlowKeyDirection msgs_flow_dirs[sizeof(msgs) / sizeof(msgs[0])];

    struct PFMessage *msgs_add[sizeof(msgs) / sizeof(msgs[0])];
    uint8_t msgs_add_indices[sizeof(msgs) / sizeof(msgs[0])];
    uint16_t msgs_add_cnt = 0;
    struct PFMessage *msgs_soft_del[sizeof(msgs) / sizeof(msgs[0])];
    uint8_t msgs_soft_del_indices[sizeof(msgs) / sizeof(msgs[0])];
    uint16_t msgs_soft_del_cnt = 0;

    FlowKey *msgs_add_flow_keys[sizeof(msgs) / sizeof(msgs[0])];
    uint8_t msgs_add_flow_keys_cnt = 0;
    struct BypassHashTableData data_base[BURST_SIZE];
    struct BypassHashTableData *bt_data_add[BURST_SIZE];
    for (int i = 0; i < BURST_SIZE; i++) {
        bt_data_add[i] = &data_base[i];
    }
    uint64_t msgs_hit_mask = 0;
    struct BypassHashTableData *flow_data[sizeof(msgs) / sizeof(msgs[0])];

    FlowKey *flow_keys_delete[sizeof(msgs) / sizeof(msgs[0])];
    FlowKey flow_keys_unified[sizeof(msgs) / sizeof(msgs[0])];
    struct PFMessage *msgs_out[sizeof(msgs) / sizeof(msgs[0])];

    msgs_cnt = rte_ring_dequeue_burst(lv->tasks_ring, (void **)msgs, BURST_SIZE, NULL);

    // sort messages and unify flow keys
    for (uint8_t i = 0; i < (uint8_t)msgs_cnt; i++) {
        msgs_flow_dirs[i] = FlowKeyUnify(&msgs[i]->fk);
        msgs_flow_keys[i] = &msgs[i]->fk;

        if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_ADD) {
            msgs_add[msgs_add_cnt] = msgs[i];
            msgs_add_indices[msgs_add_cnt] = i;
            msgs_add_cnt++;
        } else if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_SOFT_DELETE) {
            msgs_soft_del[msgs_soft_del_cnt] = msgs[i];
            msgs_soft_del_indices[msgs_soft_del_cnt] = i;
            msgs_soft_del_cnt++;
        }
    }

    BypassHashTableLookup(
            lv->bt, (const void **)msgs_flow_keys, msgs_cnt, &msgs_hit_mask, (void **)flow_data);

    if (msgs_add_cnt > 0) {
        MessagesHandleAddBulk(lv, msgs_flow_dirs, msgs_flow_keys, msgs_hit_mask, msgs_add,
                msgs_add_indices, msgs_add_cnt, msgs_add_flow_keys, bt_data_add);
    }

    if (msgs_soft_del_cnt > 0) {
        MessagesHandleSoftDeleteBulk(lv, msgs, msgs_hit_mask, flow_data, msgs_soft_del_indices,
                msgs_soft_del_cnt, flow_keys_delete, flow_keys_unified, msgs_out);
    }
}

static void MessagesHandleAddSingle(struct PFMessage *msg, struct FlowKeyDirection *fd,
        struct rte_table_hash *bt, struct rte_mempool *msg_mp, struct lcore_stats *stats)
{
    int ret;
    struct BypassHashTableData bypass_data_obj = {
        .fd = *fd,
        .pktstodst = 0,
        .pktstosrc = 0,
        .bytestodst = 0,
        .bytestosrc = 0,
    };

    ret = BypassHashTableAdd(bt, (void *)&msg->fk, (void *)&bypass_data_obj);
    if (ret == 0) {
        stats->flow_bypass_success++;
        Log().debug("Bypassed a flow!");
    }
}

static void MessagesHandleNotFoundSingle(struct PFMessage *msg, struct FlowKeyDirection *fd,
        struct rte_ring *rslts_ring, struct rte_mempool *msg_mp, struct lcore_stats *stats)
{
    int ret;

    PFMessageErrorFlowNotFoundBypassInit(msg);
    FlowKeyReconstruct(&msg->fk, fd);
    ret = rte_ring_enqueue(rslts_ring, (void *)msg);
    if (ret != 0) {
        rte_mempool_generic_put(msg_mp, (void **)&msg, 1, NULL);
        stats->msgs_mempool_put++;
        stats->msgs_enq_fail++;
    } else {
        stats->msgs_type_tx[PF_MESSAGE_BYPASS_FLOW_NOT_FOUND]++;
    }
}

static void MessagesHandleSoftDeleteSingle(struct PFMessage *msg, struct FlowKeyDirection *fd,
        struct BypassHashTableData *flow_data, struct rte_table_hash *bt,
        struct rte_ring *rslts_ring, struct rte_mempool *msg_mp, struct lcore_stats *stats)
{
    int ret;
    FlowKey k_to_del = msg->fk;

    PFMessageEvictBypassInit(msg);
    FlowKeyReconstruct(&msg->fk, fd);
    msg->bypass_evict_msg.tosrcpktcnt = flow_data->pktstosrc;
    msg->bypass_evict_msg.tosrcbytecnt = flow_data->bytestosrc;
    msg->bypass_evict_msg.todstpktcnt = flow_data->pktstodst;
    msg->bypass_evict_msg.todstbytecnt = flow_data->bytestodst;

    ret = rte_ring_enqueue(rslts_ring, (void *)msg);
    if (ret != 0) {
        stats->msgs_mempool_put++;
        stats->msgs_enq_fail++;
        rte_mempool_generic_put(msg_mp, (void **)&msg, 1, NULL);
    } else {
        stats->msgs_type_tx[PF_MESSAGE_BYPASS_EVICT]++;
        if (flow_data->pktstosrc == 0 && flow_data->pktstodst == 0) {
            int key_found;
            BypassHashTableDelete(bt, &k_to_del, &key_found, NULL);
            if (key_found) {
                stats->flow_bypass_del_success++;
                Log().debug("Timed out flow record deleted from flow table");
            } else {
                stats->flow_bypass_del_fail++;
                Log().debug("Attempt to delete timed out flow record failed");
            }
        } else {
            stats->flow_bypass_update++;
            flow_data->pktstosrc = 0;
            flow_data->bytestosrc = 0;
            flow_data->pktstodst = 0;
            flow_data->bytestodst = 0;
        }
    }
}

static void MessagesHandleSoftDeleteSingleOnStatsDump(struct PFMessage *msg, struct FlowKeyDirection *fd,
        struct BypassHashTableData *flow_data, struct rte_table_hash *bt,
        struct rte_ring *rslts_ring, struct rte_mempool *msg_mp, struct lcore_stats *stats)
{
    int ret;
    FlowKey k_to_del = msg->fk;

    PFMessageForceEvictBypassInit(msg);

    FlowKeyReconstruct(&msg->fk, fd);
    msg->bypass_force_evict_msg.tosrcpktcnt = flow_data->pktstosrc;
    msg->bypass_force_evict_msg.tosrcbytecnt = flow_data->bytestosrc;
    msg->bypass_force_evict_msg.todstpktcnt = flow_data->pktstodst;
    msg->bypass_force_evict_msg.todstbytecnt = flow_data->bytestodst;


    ret = rte_ring_enqueue(rslts_ring, (void *)msg);
    if (ret != 0) {
        stats->msgs_mempool_put++;
        stats->msgs_enq_fail++;
        rte_mempool_generic_put(msg_mp, (void **)&msg, 1, NULL);
    } else {
        stats->msgs_type_tx[PF_MESSAGE_BYPASS_FORCE_EVICT]++;
        int key_found;
        BypassHashTableDelete(bt, &k_to_del, &key_found, NULL);
        if (key_found) {
            stats->flow_bypass_del_success++;
            Log().debug("Flow deleted on dump of the bypass table");
        } else {
            stats->flow_bypass_del_fail++;
            Log().debug("Attempt to delete flow record failed on bypass table dump");
        }
    }
}

static void MessagesCheckSingle(struct lcore_values *lv)
{
    struct PFMessage *msgs[BURST_SIZE];
    uint32_t msgs_cnt;
    FlowKey *msgs_flow_keys[sizeof(msgs) / sizeof(msgs[0])];
    struct FlowKeyDirection msgs_flow_dirs[sizeof(msgs) / sizeof(msgs[0])];
    uint64_t msgs_lookup_hitmask = 0;
    struct BypassHashTableData *flow_data[sizeof(msgs) / sizeof(msgs[0])];

    msgs_cnt = rte_ring_dequeue_burst(lv->tasks_ring, (void **)msgs, BURST_SIZE, NULL);
    lv->stats.msgs_deq += msgs_cnt;

    /* can be an interesting if we are able to tolerate some operation conflicts
    // unify flow keys
    for (uint8_t i = 0; i < (uint8_t)msgs_cnt; i++) {
        msgs_flow_dirs[i] = FlowKeyUnify(&msgs[i]->fk);
        msgs_flow_keys[i] = &msgs[i]->fk;
    }
    BypassHashTableLookup(lv->bt, (const void **)msgs_flow_keys,
            msgs_cnt, &msgs_lookup_hitmask,
            (void **)flow_data);
    */

    uint32_t flow_found;
    for (uint32_t i = 0; i < msgs_cnt; i++) {
        msgs_flow_dirs[i] = FlowKeyUnify(&msgs[i]->fk);
        msgs_flow_keys[i] = &msgs[i]->fk;
        BypassHashTableLookup(lv->bt, (const void **)&msgs_flow_keys[i], 1, &msgs_lookup_hitmask,
                (void **)flow_data);

        flow_found = msgs_lookup_hitmask & (1 << i);
        if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_ADD) {
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_ADD]++;
            if (!flow_found) {
                MessagesHandleAddSingle(
                        msgs[i], &msgs_flow_dirs[i], lv->bt, lv->message_mp, &lv->stats);
                Log().debug("Flow bypassed");
            } else {
                lv->stats.flow_bypass_exists++;
                Log().debug("Flow already bypassed");
            }
            lv->stats.msgs_mempool_put++;
            rte_mempool_generic_put(lv->message_mp, (void **)&msgs[i], 1, NULL);
        } else if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_SOFT_DELETE) {
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_SOFT_DELETE]++;
            if (flow_found) {
                Log().debug("Flow updating - todst B %lu todst pkts %lu tosrc B %lu tosrc pkts %lu",
                        flow_data[i]->bytestodst, flow_data[i]->pktstodst, flow_data[i]->bytestosrc,
                        flow_data[i]->pktstosrc);
                MessagesHandleSoftDeleteSingle(msgs[i], &msgs_flow_dirs[i], flow_data[i], lv->bt,
                        lv->results_ring, lv->message_mp, &lv->stats);
            } else {
                MessagesHandleNotFoundSingle(
                        msgs[i], &msgs_flow_dirs[i], lv->results_ring, lv->message_mp, &lv->stats);
                Log().debug("Flow not found, unable to get stats");
            }
        } else if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_HARD_DELETE) {
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_HARD_DELETE]++;
            if (flow_found) {
                int32_t flow_del = 0;
                BypassHashTableDelete(lv->bt, msgs_flow_keys[i], &flow_del, NULL);
                if (flow_del) {
                    lv->stats.flow_bypass_del_success++;
                    Log().debug("Timed out flow record deleted from flow table");
                } else {
                    lv->stats.flow_bypass_del_fail++;
                    Log().debug("Attempt to delete timed out flow record failed");
                }
            }
            rte_mempool_generic_put(lv->message_mp, (void **)&msgs[i], 1, NULL);
        } else {
            Log().error(EINVAL, "Unknown message");
            lv->stats.msgs_mempool_put++;
            rte_mempool_generic_put(lv->message_mp, (void **)&msgs[i], 1, NULL);
        }
    }
}

struct lcore_values *ThreadSuricataInit(struct lcore_init *init_vals)
{
    int ret;
    const char *name = NULL;
    struct ring_list_entry *re = (struct ring_list_entry *)init_vals->re;
    struct ring_list_entry_suricata *suri_entry =
            (struct ring_list_entry_suricata *)re->pre_ring_conf;

    struct lcore_values *lv = rte_calloc("struct lcore_values", 1, sizeof(struct lcore_values), 0);
    if (lv == NULL) {
        Log().error(EINVAL,
                "Error (%s): memory allocation error of lcore_values for ring %s lcoreid %u",
                rte_strerror(rte_errno), re->main_ring.name_base, rte_lcore_id());
        return NULL;
    }

    lv->port1_addr = suri_entry->nic_conf.port1_pcie;
    lv->port1_id = suri_entry->nic_conf.port1_id;

    lv->port2_addr = suri_entry->nic_conf.port2_pcie;
    lv->port2_id = suri_entry->nic_conf.port2_id;

    lv->socket_id = rte_socket_id();
    lv->qid = init_vals->lcore_id;
    lv->opmode = re->opmode;
    lv->ring_offset_start = init_vals->ring_offset_start;
    lv->rings_cnt = init_vals->rings_cnt;

    lv->rings_from_pf =
            rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);
    lv->rings_to_pf = rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);

    // find rings
    for (uint16_t i = 0; i < init_vals->rings_cnt; i++) {
        uint16_t ring_id = lv->ring_offset_start + i;
        struct rte_ring *r;
        name = DevConfRingGetRxName(re->main_ring.name_base, ring_id);
        r = rte_ring_lookup(name);
        if (r == NULL) {
            Log().error(
                    EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
            return NULL;
        }

        lv->rings_from_pf[i] = r;

        if (re->opmode != IDS) {
            name = DevConfRingGetTxName(re->main_ring.name_base, ring_id);
            r = rte_ring_lookup(name);
            if (r == NULL) {
                Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno),
                        name);
                return NULL;
            }

            lv->rings_to_pf[i] = r;
        }
    }

    name = DevConfRingGetTaskName(re->msgs.task_ring.name_base, init_vals->lcore_id);
    lv->tasks_ring = rte_ring_lookup(name);
    if (lv->tasks_ring == NULL) {
        Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
        return NULL;
    }

    name = DevConfRingGetResultName(re->msgs.result_ring.name_base, 0);
    lv->results_ring = rte_ring_lookup(name);
    if (lv->results_ring == NULL) {
        Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
        return NULL;
    }

    name = DevConfMempoolGetMessageMPName(re->msgs.mempool.name, 0);
    lv->message_mp = rte_mempool_lookup(name);
    if (lv->message_mp == NULL) {
        Log().error(EINVAL, "Error (%s): unable to find mempool %s", rte_strerror(rte_errno), name);
        return NULL;
    }

    // allocate pkt ring buffer
    lv->tmp_ring_bufs = rte_calloc("ring_buffer", sizeof(ring_buffer), init_vals->rings_cnt, 0);
    if (lv->tmp_ring_bufs == NULL) {
        Log().error(EINVAL,
                "Error (%s): Unable to allocate memory for ring queues of ring %s lcoreid %u",
                rte_strerror(-ret), re->main_ring.name_base, lv->qid);
        return NULL;
    }

    lv->fke_arr = rte_calloc("FlowKeyExtended", sizeof(FlowKeyExtended), BURST_SIZE * 2, 0);
    if (lv->fke_arr == NULL) {
        Log().error(EINVAL,
                "Error (%s): Unable to allocate memory for an array of FlowKeyExtended of ring "
                "entry %s "
                "lcoreid %u",
                rte_strerror(-ret), re->main_ring.name_base, lv->qid);
        return NULL;
    }

    lv->fk_arr = rte_calloc("FlowKey *", sizeof(FlowKey *), BURST_SIZE * 2, 0);
    if (lv->fk_arr == NULL) {
        Log().error(EINVAL,
                "Error (%s): Unable to allocate memory for an array of FlowKey pointers of ring "
                "entry %s "
                "lcoreid %u",
                rte_strerror(-ret), re->main_ring.name_base, lv->qid);
        return NULL;
    }
    for (int i = 0; i < BURST_SIZE * 2; i++) {
        lv->fk_arr[i] = &lv->fke_arr[i].fk;
    }

    lv->state = init_vals->state;
    LcoreStateSet(lv->state, LCORE_INIT_DONE);
    lv->bt = init_vals->bypass_table;

    return lv;
}

/**
 * Distributes mbufs to rings leading to the secondary app (Suricata)
 * @param pkt
 * @param rings
 * @param rings_cnt
 * @param pkt_origin_port1 - mark the mbuf with the port of origin
 * @return returns to which ring it was added
 */
static uint32_t MbufAddToRing(
        struct rte_mbuf *pkt, ring_buffer *rings, uint16_t rings_cnt, bool pkt_origin_port1)
{
    // RSS distribution among NIC queues uses `mod` operation,
    // using the `mod` operation on packets received on the NIC queue
    // would result in wrong distribution. Because of that, RSS hash is shifted
    // to get a fresh value unaffected by the previous `mod` operation.
    // e.g. if 2 NIC queues should distribute packets to 4 workers (1 queue to 4 workers)
    // then NIC queue no. 1 receives packets with odd hash. Applying `mod 2` on that hash
    // would only result in odd results.
    uint32_t pkt_rss_hash = pkt->hash.rss >> 8;
    uint16_t queue_id = pkt_rss_hash % rings_cnt;
    uint16_t buf_len = rings[queue_id].len;
    Log().debug("port%s pkt - pkt_rss_hash orig %u pkt_rss_hash edit %u queue %d/%d lcore %d",
            pkt_origin_port1 == true ? "1" : "2", pkt->hash.rss, pkt_rss_hash, queue_id, rings_cnt,
            rte_lcore_id());
    rings[queue_id].buf[buf_len] = pkt;
    if (pkt_origin_port1 == true)
        rings[queue_id].buf[buf_len]->ol_flags |= PKT_ORIGIN_PORT1;
    else
        rings[queue_id].buf[buf_len]->ol_flags &= ~PKT_ORIGIN_PORT1;

    rings[queue_id].len = buf_len + 1;
    return queue_id;
}

/**
 * Divides incoming packets (mbufs) between packets that can be potentially bypassed and
 * packets that cannot be currently bypassed.
 * @param pkts - incoming pkts
 * @param pkt_cnt
 * @param inspect_pkts - expected passed array
 * @param fke_arr - extracted flow keys for lookup
 * @param no_inspect_rings - for packets that can not be bypassed, pkts are inserted in these rings
 * directly (e.g. pkt can't be parsed)
 * @param rings_cnt - number of rings
 * @param on_port1 - marks packets (that can not be bypassed) with port origin
 * @return number of packets for bypass
 */
static uint16_t MbufsBypassSort(struct rte_mbuf **pkts, uint16_t pkt_cnt,
        struct rte_mbuf **inspect_pkts, FlowKeyExtended *fke_arr, ring_buffer *no_inspect_rings,
        uint16_t rings_cnt, bool on_port1)
{
    int ret;
    uint16_t fke_len = 0;
    for (uint16_t i = 0; i < pkt_cnt; i++) {
        ret = FlowKeyExtendedInitFromMbuf(&fke_arr[fke_len], pkts[i]);
        Log().debug("conversion mbuf to FlowKey: %s", ret == 0 ? "success" : "failure");
        if (ret != 0) {
            MbufAddToRing(pkts[i], no_inspect_rings, rings_cnt, on_port1);
        } else {
            inspect_pkts[fke_len] = pkts[i];
            fke_len++;
        }
    }
    return fke_len;
}

// return number of *transmitted* packets
static uint32_t PktsHandleBypassed(struct rte_mbuf **pkts, uint16_t pkt_cnt, enum PFOpMode mode,
        const uint16_t *const pid, const uint16_t *const qid)
{
    if (mode == IDS) {
        rte_pktmbuf_free_bulk(pkts, pkt_cnt);
    } else if (mode == IPS) {
        uint16_t pkts_tx;
        if (pid == NULL || qid == NULL) {
            Log().error(EINVAL, "Error: port or queue id not specified for bypassed packets");
        }
        Log().debug("Tx %d pkts from %p to port %d qid %d", pkt_cnt, pkts, *pid, *qid);
        pkts_tx = rte_eth_tx_burst(*pid, *qid, pkts, pkt_cnt);
        if (pkts_tx < pkt_cnt) {
            rte_pktmbuf_free_bulk(pkts + pkts_tx, pkt_cnt - pkts_tx);
        }
        return pkts_tx;
    } else {
        Log().error(EINVAL, "unknown operation mode");
        exit(1);
    }
    return 0;
}

static void PktsHandleBypassedIDS(struct rte_mbuf **pkts, uint16_t pkt_cnt)
{
    PktsHandleBypassed(pkts, pkt_cnt, IDS, NULL, NULL);
}

// return number of transmitted packets
static uint32_t PktsHandleBypassedIPS(
        struct rte_mbuf **pkts, uint16_t pkt_cnt, uint16_t port_id, uint16_t queue_id)
{
    return PktsHandleBypassed(pkts, pkt_cnt, IPS, &port_id, &queue_id);
}

static uint32_t PktsBypassSort(struct rte_mbuf **pkts, uint32_t pkt_cnt, struct rte_mbuf **bypassed,
        struct lcore_values *lv, uint64_t hmask, struct BypassHashTableData **b_data,
        FlowKeyExtended *fke_arr, bool pkt_origin_port1)
{
    uint32_t bypassed_cnt = 0;
    for (uint32_t i = 0; i < pkt_cnt; i++) {
        if (hmask & (1 << i)) {
            Log().debug("Putting pkt %d (%p) to free array 0x%x", i, pkts[i], hmask);
            BypassHashTableUpdateStats(b_data[i], &fke_arr[i].fd, pkts[i]->pkt_len);
            bypassed[bypassed_cnt++] = pkts[i];
            continue;
        }
        Log().debug("Putting pkt %d (%p) to Suri array 0x%x", i, pkts[i], hmask);
        MbufAddToRing(pkts[i], lv->tmp_ring_bufs, lv->rings_cnt, pkt_origin_port1);
    }
    return bypassed_cnt;
}

static void PktsReceiveIDS(struct lcore_values *lv)
{
    uint16_t ret;
    struct rte_mbuf *pkts[2 * BURST_SIZE] = { NULL };
    struct rte_mbuf *pkts_to_inspect[2 * BURST_SIZE] = { NULL };
    struct rte_mbuf *pkts_to_bypass[2 * BURST_SIZE] = { NULL };
    struct BypassHashTableData *bypass_data[2 * BURST_SIZE];
    uint32_t pkt_count1 = 0;
    uint16_t pkts_to_inspect_cnt1 = 0, pkts_to_bypass_len = 0;
    uint64_t bypass_hit_mask;

    pkt_count1 = rte_eth_rx_burst(lv->port1_id, lv->qid, pkts, BURST_SIZE);
    if (pkt_count1 <= 0)
        return;

    lv->stats.pkts_p1_rx += pkt_count1;

    pkts_to_inspect_cnt1 = MbufsBypassSort(
            pkts, pkt_count1, pkts_to_inspect, lv->fke_arr, lv->tmp_ring_bufs, lv->rings_cnt, true);
    lv->stats.pkts_inspected += pkts_to_inspect_cnt1;

    // todo: optimization -  possibly make looked up keys unique to reduce key set to lookup
    ret = BypassHashTableLookup(lv->bt, (const void **)lv->fk_arr, pkts_to_inspect_cnt1,
            &bypass_hit_mask, (void **)bypass_data);
    lv->stats.pkts_bypassed += ret;
    pkts_to_bypass_len = PktsBypassSort(pkts_to_inspect, pkts_to_inspect_cnt1, pkts_to_bypass, lv,
            bypass_hit_mask, bypass_data, lv->fke_arr, true);

    // packets have been filtered out from the bypassed ones, freeing the byppassed
    if (pkts_to_bypass_len > 0) {
        PktsHandleBypassedIDS(pkts_to_bypass, pkts_to_bypass_len);
    }
}

static void PktsReceiveIPS(struct lcore_values *lv)
{
    int ret;
    uint32_t pkt_count1 = 0, pkt_count2 = 0;
    uint16_t pkts_to_bypass_cnt1 = 0, pkts_to_bypass_cnt2 = 0;
    uint16_t pkts_to_inspect_cnt1 = 0, pkts_to_inspect_cnt2 = 0;
    uint64_t bypass_hit_mask = 0;

    pkt_count1 = rte_eth_rx_burst(lv->port1_id, lv->qid, lv->pkts, BURST_SIZE);
    // todo: to maximally use the rx array,
    //  the second rx_burst can receive (BURST_SIZE + BURST_SIZE - pkt_count1)
    pkt_count2 = rte_eth_rx_burst(lv->port2_id, lv->qid, &lv->pkts[pkt_count1], BURST_SIZE);
    if (pkt_count1 <= 0 && pkt_count2 <= 0)
        return;

    lv->stats.pkts_p1_rx += pkt_count1;
    lv->stats.pkts_p2_rx += pkt_count2;

    pkts_to_inspect_cnt1 = MbufsBypassSort(
            lv->pkts, pkt_count1, lv->pkts_to_inspect, lv->fke_arr.fk, lv->fke_arr.fd, lv->tmp_ring_bufs, lv->rings_cnt, true);
    pkts_to_inspect_cnt2 =
            MbufsBypassSort(lv->pkts + pkt_count1, pkt_count2, &lv->pkts_to_inspect[pkts_to_inspect_cnt1],
                    &lv->fke_arr.fk[pkts_to_inspect_cnt1], &lv->fke_arr.fd[pkts_to_inspect_cnt1], lv->tmp_ring_bufs, lv->rings_cnt, false);
    lv->stats.pkts_inspected += pkts_to_inspect_cnt1 + pkts_to_inspect_cnt2;

    // todo: optimization -  possibly make looked up keys unique to reduce key set to lookup
    ret = BypassHashTableLookup(lv->bt, (const void **)lv->fk_arr,
            pkts_to_inspect_cnt1 + pkts_to_inspect_cnt2, &bypass_hit_mask, (void **)lv->bypass_data);
    lv->stats.pkts_bypassed += ret;

    pkts_to_bypass_cnt1 = PktsBypassSort(lv->pkts_to_inspect, pkts_to_inspect_cnt1, lv->pkts_to_bypass, lv,
            bypass_hit_mask, lv->bypass_data, lv->fke_arr.fd, true);
    pkts_to_bypass_cnt2 = PktsBypassSort(&lv->pkts_to_inspect[pkts_to_inspect_cnt1],
            pkts_to_inspect_cnt2, &lv->pkts_to_bypass[pkts_to_bypass_cnt1], lv,
            (bypass_hit_mask >> pkts_to_inspect_cnt1), &lv->bypass_data[pkts_to_inspect_cnt1],
            &lv->fke_arr.fd[pkts_to_inspect_cnt1], false);

    // packets have been filtered out from the bypassed ones, freeing the byppassed
    if (pkts_to_bypass_cnt1 > 0) {
        pkt_count1 =
                PktsHandleBypassedIPS(lv->pkts_to_bypass, pkts_to_bypass_cnt1, lv->port2_id, lv->qid);
        lv->stats.pkts_p2_tx_total += pkts_to_bypass_cnt1;
        lv->stats.pkts_p2_tx_success += pkt_count1;
        Log().debug("P2: Transmitted or freed %d of %d bypassed packets", pkt_count1,
                pkts_to_bypass_cnt1);
    }

    if (pkts_to_bypass_cnt2 > 0) {
        pkt_count2 = PktsHandleBypassedIPS(
                &lv->pkts_to_bypass[pkts_to_bypass_cnt1], pkts_to_bypass_cnt2, lv->port1_id, lv->qid);
        lv->stats.pkts_p1_tx_total += pkts_to_bypass_cnt2;
        lv->stats.pkts_p1_tx_success += pkt_count2;
        Log().debug("P1: Transmitted or freed %d of %d bypassed packets", pkt_count2,
                pkts_to_bypass_cnt2);
    }
}

// Warning: function relies on resetting the buffer lengths!
static void PktsReceive(struct lcore_values *lv)
{
    if (lv->opmode == IDS) {
        PktsReceiveIDS(lv);
    } else if (lv->opmode == IPS) {
        PktsReceiveIPS(lv);
    }
}

static void PktsEnqueue(struct lcore_values *lv)
{
    uint32_t pkt_count;
    uint16_t stats_index;

    for (uint16_t i = 0; i < lv->rings_cnt; i++) {
        stats_index = MIN(i, MAX_WORKERS_TO_PREFILTER_LCORE);
        lv->stats.pkts_to_ring_enq_total[stats_index] += lv->tmp_ring_bufs[i].len;
        if (lv->tmp_ring_bufs[i].len > 2 * BURST_SIZE)
            Log().error(EINVAL, "Ring buffer length over the buffer");

        pkt_count = rte_ring_enqueue_burst(lv->rings_from_pf[i], (void **)lv->tmp_ring_bufs[i].buf,
                lv->tmp_ring_bufs[i].len, NULL);
        lv->stats.pkts_to_ring_enq_success[stats_index] += pkt_count;
        if (pkt_count > 0) {
            Log().debug("ENQ %d packet/s to rxring %s", pkt_count, lv->rings_from_pf[i]->name);
        }

        // todo: optimization - aggregate non-enqueued pkts from all rings and free all at once
        if (pkt_count < lv->tmp_ring_bufs[i].len) {
            Log().debug("ENQ failed: %d of %d packet/s were put into rxring %s", pkt_count,
                    lv->tmp_ring_bufs[i].len, lv->rings_from_pf[i]->name);

            if (lv->opmode == IDS) {
                PktsHandleBypassedIDS(
                        &lv->tmp_ring_bufs[i].buf[pkt_count], lv->tmp_ring_bufs[i].len - pkt_count);
            } else if (lv->opmode == IPS) {
                for (uint16_t j = pkt_count; j < lv->tmp_ring_bufs[i].len; j++) {
                    PktsHandleBypassedIPS(
                            &lv->tmp_ring_bufs[i].buf[j],
                            1,
                            lv->tmp_ring_bufs[i].buf[j]->ol_flags & PKT_ORIGIN_PORT1 ? lv->port2_id : lv->port1_id,
                            lv->qid);
                }
            }
        }

        lv->tmp_ring_bufs[i].len = 0;
    }
}

static uint16_t PktsTx(
        struct rte_mbuf **pkts, uint16_t pkts_cnt, struct lcore_values *lv, uint16_t port_id)
{
    uint16_t tx_cnt;
    Log().debug("Sending %d pkts to P%dQ%d", pkts_cnt, port_id, lv->qid);
    tx_cnt = rte_eth_tx_burst(port_id, lv->qid, pkts, pkts_cnt);
    return tx_cnt;
}

static void PktsDeq(struct lcore_values *lv, uint16_t ring_id)
{
    uint16_t stats_index;
    stats_index = MIN(ring_id, MAX_WORKERS_TO_PREFILTER_LCORE);
    lv->tmp_ring_bufs[ring_id].len = rte_ring_dequeue_burst(
            lv->rings_to_pf[ring_id], (void **)lv->tmp_ring_bufs[ring_id].buf, BURST_SIZE, NULL);
    lv->stats.pkts_from_ring_deq_success[stats_index] += lv->tmp_ring_bufs[ring_id].len;
    if (lv->tmp_ring_bufs[ring_id].len > 0) {
        Log().debug("DEQ %d packet/s from txring %s\n", lv->tmp_ring_bufs[ring_id].len,
                lv->rings_to_pf[ring_id]->name);
    }
}

static void PktsAssignToPorts(struct rte_mbuf **pkts, uint32_t pkt_cnt,
        struct rte_mbuf **port1_pkts, uint32_t *port1_pkt_cnt, struct rte_mbuf **port2_pkts,
        uint32_t *port2_pkt_cnt)
{
    for (uint32_t i = 0; i < pkt_cnt; i++) {
        // assign to the reversed port of the origin port
        if (pkts[i]->ol_flags & PKT_ORIGIN_PORT1) {
            port2_pkts[(*port2_pkt_cnt)] = pkts[i];
            (*port2_pkt_cnt)++;
        } else {
            port1_pkts[(*port1_pkt_cnt)] = pkts[i];
            (*port1_pkt_cnt)++;
        }
    }
}

static void PktsDeqAndTx(struct lcore_values *lv)
{
    struct rte_mbuf *pkts_p1[BURST_SIZE * 3];
    struct rte_mbuf *pkts_p2[BURST_SIZE * 3];

    uint32_t pkt_count1 = 0, pkt_count2 = 0, pkt_count;

    for (uint16_t ring_id = 0; ring_id < lv->rings_cnt; ring_id++) {
        PktsDeq(lv, ring_id);
        PktsAssignToPorts(lv->tmp_ring_bufs[ring_id].buf, lv->tmp_ring_bufs[ring_id].len, pkts_p1,
                &pkt_count1, pkts_p2, &pkt_count2);

        if (pkt_count1 > BURST_SIZE) { // continuously transmit pkts
            lv->stats.pkts_p1_tx_total += pkt_count1;
            pkt_count = PktsTx(pkts_p1, pkt_count1, lv, lv->port1_id);
            if (pkt_count < pkt_count1) {
                rte_pktmbuf_free_bulk(pkts_p1 + pkt_count, pkt_count1 - pkt_count);
            }
            lv->stats.pkts_p1_tx_success += pkt_count;
            pkt_count1 = 0;
        }

        if (pkt_count2 > BURST_SIZE) {
            lv->stats.pkts_p2_tx_total += pkt_count2;
            pkt_count = PktsTx(pkts_p2, pkt_count2, lv, lv->port2_id);
            if (pkt_count < pkt_count2) {
                rte_pktmbuf_free_bulk(pkts_p2 + pkt_count, pkt_count2 - pkt_count);
            }
            lv->stats.pkts_p2_tx_success += pkt_count;
            pkt_count2 = 0;
        }

        lv->tmp_ring_bufs[ring_id].len = 0;
    }

    // transmit the remaining pkts
    if (pkt_count1 > 0) {
        lv->stats.pkts_p1_tx_total += pkt_count1;
        pkt_count = PktsTx(pkts_p1, pkt_count1, lv, lv->port1_id);
        if (pkt_count < pkt_count1) {
            rte_pktmbuf_free_bulk(pkts_p1 + pkt_count, pkt_count1 - pkt_count);
        }
        lv->stats.pkts_p1_tx_success += pkt_count;
        pkt_count1 = 0;
    }

    if (pkt_count2 > 0) {
        lv->stats.pkts_p2_tx_total += pkt_count2;
        pkt_count = PktsTx(pkts_p2, pkt_count2, lv, lv->port2_id);
        if (pkt_count < pkt_count2) {
            rte_pktmbuf_free_bulk(pkts_p2 + pkt_count, pkt_count2 - pkt_count);
        }
        lv->stats.pkts_p2_tx_success += pkt_count;
        pkt_count2 = 0;
    }
}

void ThreadSuricataRun(struct lcore_values *lv)
{
    memset(&lv->stats, 0, sizeof(lv->stats)); // null the stats

    Log().notice("Lcore %u receiving from %s (p%d)", lv->qid, lv->port1_addr, lv->port1_id);
    if (lv->opmode != IDS)
        Log().notice("Lcore %u receiving from %s (p%d)", lv->qid, lv->port2_addr, lv->port2_id);

    while (!LcoreStateCheck(lv->state, LCORE_RUN)) {
        rte_delay_us_sleep(1000);
        if (LcoreStateCheck(lv->state, LCORE_STOP))
            return;
    }
    LcoreStateSet(lv->state, LCORE_RUNNING);

    while (!ShouldStop()) {
        PktsReceive(lv);
        PktsEnqueue(lv);

        if (lv->opmode != IDS) {
            PktsDeqAndTx(lv);
        }

        MessagesCheckSingle(lv);
    }

    // not sure if needed
    LcoreStateSet(lv->state, LCORE_RUNNING_DONE);
}

void ThreadSuricataStatsDump(struct lcore_values *lv)
{

    struct PFMessage *msgs[BURST_SIZE];
    uint32_t msgs_cnt;
    FlowKey *msgs_flow_keys[sizeof(msgs) / sizeof(msgs[0])];
    struct FlowKeyDirection msgs_flow_dirs[sizeof(msgs) / sizeof(msgs[0])];
    uint64_t msgs_lookup_hitmask = 0;
    struct BypassHashTableData *flow_data[sizeof(msgs) / sizeof(msgs[0])];


    while (LcoreStateCheck(lv->state, LCORE_STAT_DUMP)) {
        msgs_cnt = rte_ring_dequeue_burst(lv->tasks_ring, (void **)msgs, BURST_SIZE, NULL);
        lv->stats.msgs_deq += msgs_cnt;

        uint32_t flow_found;
        for (uint32_t i = 0; i < msgs_cnt; i++) {
            msgs_flow_dirs[i] = FlowKeyUnify(&msgs[i]->fk);
            msgs_flow_keys[i] = &msgs[i]->fk;
            msgs_lookup_hitmask = 0;
            BypassHashTableLookup(lv->bt, (const void **)&msgs_flow_keys[i], 1, &msgs_lookup_hitmask,
                    (void **)flow_data);

            flow_found = msgs_lookup_hitmask;
            if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_SOFT_DELETE) {
                lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_SOFT_DELETE]++;
                Log().debug("Flow dumping - flow %s val 0x%x", msgs_lookup_hitmask != 0 ? "found" : "not found", msgs_lookup_hitmask);

                if (msgs_lookup_hitmask) {
                    Log().debug("Flow dumping - todst B %lu todst pkts %lu tosrc B %lu tosrc pkts %lu",
                            flow_data[0]->bytestodst, flow_data[0]->pktstodst, flow_data[0]->bytestosrc,
                            flow_data[0]->pktstosrc);
                    MessagesHandleSoftDeleteSingleOnStatsDump(msgs[i], &msgs_flow_dirs[i],
                            flow_data[0], lv->bt, lv->results_ring, lv->message_mp, &lv->stats);
                } else {
                    MessagesHandleNotFoundSingle(
                            msgs[i], &msgs_flow_dirs[i], lv->results_ring, lv->message_mp, &lv->stats);
                    Log().debug("Flow not found, unable to get stats");
                }
            } else if (msgs[i]->msg_type == PF_MESSAGE_BYPASS_HARD_DELETE) {
                lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_HARD_DELETE]++;
                if (flow_found) {
                    Log().debug("deleting hard delete flow on dump");
                    BypassHashTableDelete(lv->bt, &msgs_flow_keys[i], (int32_t *)&flow_found, NULL);
                    if (flow_found) {
                        lv->stats.flow_bypass_del_success++;
                        Log().debug("Timed out flow record  hard deleted from flow table");
                    } else {
                        lv->stats.flow_bypass_del_fail++;
                        Log().debug("Attempt to delete timed out flow record failed");
                    }
                }
                rte_mempool_generic_put(lv->message_mp, (void **)&msgs[i], 1, NULL);
            } else {
                Log().error(EINVAL, "Unknown message");
                lv->stats.msgs_mempool_put++;
                rte_mempool_generic_put(lv->message_mp, (void **)&msgs[i], 1, NULL);
            }
        }


    }
}

void ThreadSuricataStatsExit(struct lcore_values *lv, struct pf_stats *stats)
{
    Log().info("Lcore %d PORT 1 rx: %lu tx all: %lu tx success: %lu", rte_lcore_id(),
            lv->stats.pkts_p1_rx, lv->stats.pkts_p1_tx_total, lv->stats.pkts_p1_tx_success);
    Log().info("Lcore %d PORT 2 rx: %lu tx all: %lu tx success: %lu", rte_lcore_id(),
            lv->stats.pkts_p2_rx, lv->stats.pkts_p2_tx_total, lv->stats.pkts_p2_tx_success);

    uint64_t enq_total, enq_success, deq_success = enq_total = enq_success = 0;
    for (uint16_t i = 0; i < (uint16_t)MIN(lv->rings_cnt, MAX_WORKERS_TO_PREFILTER_LCORE); i++) {
        enq_total += lv->stats.pkts_to_ring_enq_total[i];
        enq_success += lv->stats.pkts_to_ring_enq_success[i];
        deq_success += lv->stats.pkts_from_ring_deq_success[i];
    }

    Log().info("Lcore %d PKTS: inspected %lu, bypassed %lu enqueued to Suricata - total %lu "
               "successful %lu, dequeued from Suricata %lu",
            rte_lcore_id(), lv->stats.pkts_inspected, lv->stats.pkts_bypassed, enq_total,
            enq_success, deq_success);

    uint64_t msgs_enq_total = 0;
    for (uint16_t i = 0; i < (uint16_t)PF_MESSAGE_CNT; i++) {
        msgs_enq_total += lv->stats.msgs_type_tx[i];
    }
    Log().info("Lcore %d MSGS: received %lu sent %lu failed msg enqueues %lu mempool putbacks %lu "
               "adds %lu soft deletes %lu hard deletes %lu evicts %lu forced evicts (dumps) %lu updates %lu "
               "not found %lu",
            rte_lcore_id(), lv->stats.msgs_deq, msgs_enq_total, lv->stats.msgs_enq_fail,
            lv->stats.msgs_mempool_put,
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_ADD] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_ADD],
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_SOFT_DELETE] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_SOFT_DELETE],
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_HARD_DELETE] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_HARD_DELETE],
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_EVICT] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_EVICT],
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_UPDATE] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_UPDATE],
            lv->stats.msgs_type_rx[PF_MESSAGE_BYPASS_FLOW_NOT_FOUND] +
                    lv->stats.msgs_type_tx[PF_MESSAGE_BYPASS_FLOW_NOT_FOUND]);

    Log().info("Lcore %d BYPASS: adds %lu updates %lu deletes %lu repeated adding %lu delete "
               "fails %lu",
            rte_lcore_id(), lv->stats.flow_bypass_success, lv->stats.flow_bypass_update,
            lv->stats.flow_bypass_del_success, lv->stats.flow_bypass_exists,
            lv->stats.flow_bypass_del_fail);
}

void ThreadSuricataDeinit(struct lcore_init *vals, struct lcore_values *lv)
{
    if (vals != NULL)
        rte_free(vals);
    if (lv != NULL) {
        rte_free(lv);
    }
}