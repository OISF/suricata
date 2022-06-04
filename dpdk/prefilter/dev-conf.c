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

#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_table_hash.h>

#include "dev-conf.h"
#include "logger.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>
#include <rte_table_hash_func.h>
#include "suricata-common.h"
#include "util-dpdk.h"
#include "util-dpdk-bypass.h"
#include "lcores-manager.h"
#include "lcore-worker.h"

struct DeviceConfigurer devconf;
ring_tailq_t tailq_ring_head = TAILQ_HEAD_INITIALIZER(tailq_ring_head);

void RingListInitHead(void)
{
    TAILQ_INIT(&tailq_ring_head);
}

int RingListAddConf(const struct ring_list_entry *re)
{
    struct ring_list_entry *ring_entry =
            rte_calloc("struct ring_list_entry", sizeof(struct ring_list_entry), 1, 0);
    if (ring_entry == NULL) {
        Log().error(ENOMEM, "No memory for ring entry\n");
        return -ENOMEM;
    }
    memcpy(ring_entry, re, sizeof(struct ring_list_entry));

    TAILQ_INSERT_TAIL(&tailq_ring_head, ring_entry, entries);
    return 0;
}

void RingListDeinit(void)
{
    struct ring_list_entry *re;
    while (!TAILQ_EMPTY(&tailq_ring_head)) {
        re = TAILQ_FIRST(&tailq_ring_head);
        TAILQ_REMOVE(&tailq_ring_head, re, entries);

        if (re->pre_ring_conf != NULL)
            rte_free(re->pre_ring_conf);

        rte_free(re);
    }
}

void DevConfInit(struct DeviceConfigurer ops)
{
    devconf = ops;
}

int DevConfStartAll(void)
{
    return devconf.StartAll();
}

int DevConfStopAll(void)
{
    return devconf.StopAll();
}

void DevConfDeinit(void)
{
    devconf.Deinit();
    RingListDeinit();
}

// after call to this function, it is assumed that RingList is populated
int DevConfConfigureBy(void *conf)
{
    return devconf.ConfigureBy(conf);
}

const char *DevConfBypassHashTableGetName(const char *base, uint16_t t_id)
{
    static char buffer[RTE_HASH_NAMESIZE];

    snprintf(buffer, sizeof(buffer), "bt_%s_%u", base, t_id);
    Log().debug("From bt_%s_%u created hash table name %s", base, t_id, buffer);

    return buffer;
}

const char *DevConfMempoolGetMessageMPName(const char *base, uint16_t mp_id)
{
    static char buffer[RTE_MEMPOOL_NAMESIZE];

    snprintf(buffer, RTE_MEMPOOL_NAMESIZE, "%s_%u", base, mp_id);
    Log().debug("From msg_mp_%s_%u created mempool name %s", base, mp_id, buffer);

    return buffer;
}

const char *DevConfRingGetTaskName(const char *base, uint16_t ring_id)
{
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, RTE_RING_NAMESIZE, "tasks_%s_%u", base, ring_id);
    Log().debug("From tasks_%s_%u created ring name %s", base, ring_id, buffer);

    return buffer;
}

const char *DevConfRingGetResultName(const char *base, uint16_t ring_id)
{
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, RTE_RING_NAMESIZE, "results_%s_%u", base, ring_id);
    Log().debug("From results_%s_%u created ring name %s", base, ring_id, buffer);

    return buffer;
}

const char *DevConfRingGetRxName(const char *base, uint16_t ring_id)
{
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, RTE_RING_NAMESIZE, "rx_%s_%u", base, ring_id);
    Log().debug("From rx_%s_%u created ring name %s", base, ring_id, buffer);

    return buffer;
}

const char *DevConfRingGetTxName(const char *base, uint16_t ring_id)
{
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, RTE_RING_NAMESIZE, "tx_%s_%u", base, ring_id);
    Log().debug("From tx_%s_%u created ring name %s", base, ring_id, buffer);

    return buffer;
}

static uint32_t DevConfRingListLength(void)
{
    struct ring_list_entry *re;
    uint16_t ring_list_len = 0;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        ring_list_len++;
    }
    return ring_list_len;
}

static uint32_t DevConfRingListWorkersCount(void)
{
    struct ring_list_entry *re;
    uint16_t ring_list_worker_cnt = 0;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        ring_list_worker_cnt += re->pf_cores_cnt;
    }
    return ring_list_worker_cnt;
}

static uint32_t DevConfRingListSecondaryCoresCount(void)
{
    struct ring_list_entry *re;
    uint16_t ring_list_sec_cores_cnt = 0;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        ring_list_sec_cores_cnt += re->sec_app_cores_cnt;
    }
    return ring_list_sec_cores_cnt;
}

int DevConfThreadingInit(void)
{
    uint32_t worker_cnt = DevConfRingListWorkersCount();
    ctx.lcores_state.lcores_arr = (struct ctx_lcore_resources *)rte_calloc(
            "struct ctx_lcore_resources", sizeof(struct ctx_lcore_resources), worker_cnt, 0);
    if (ctx.lcores_state.lcores_arr == NULL) {
        Log().error(ENOMEM,
                "Memory allocation failed for an array of ring configuration entry resources");
        return -ENOMEM;
    }

    ctx.lcores_state.lcores_arr_capa = worker_cnt;
    ctx.lcores_state.lcores_arr_len = 0;
    return 0;
}

int DevConfMessagesInit(void)
{
    struct ring_list_entry *re;
    uint16_t ring_list_entry_id = 0;

    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        // tasks ring
        uint16_t tasks_rings_cnt = re->pf_cores_cnt;
        ctx.ring_conf_entries[ring_list_entry_id].rings_tasks.ring_arr =
                (struct rte_ring **)rte_calloc(
                        "struct rte_ring *", sizeof(struct rte_ring *), tasks_rings_cnt, 0);
        if (ctx.ring_conf_entries[ring_list_entry_id].rings_tasks.ring_arr == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for an array of \"tasks\" rings");
            return -ENOMEM;
        }
        ctx.ring_conf_entries[ring_list_entry_id].rings_tasks.ring_arr_len = tasks_rings_cnt;

        for (int ring_id = 0; ring_id < tasks_rings_cnt; ring_id++) {
            const char *r_name;
            struct rte_ring *r = NULL;
            r_name = DevConfRingGetTaskName(re->msgs.task_ring.name_base, ring_id);
            // TODO: optimize ring flags
            r = rte_ring_create(r_name, re->msgs.task_ring.elem_cnt, (int)rte_socket_id(),
                    0); // RING_F_MP_RTS_ENQ | RING_F_SC_DEQ
            if (r == NULL) {
                Log().error(rte_errno, "Error (%s) cannot create task ring %s",
                        rte_strerror(rte_errno), r_name);
                return -rte_errno;
            }
            ctx.ring_conf_entries[ring_list_entry_id].rings_tasks.ring_arr[ring_id] = r;
            Log().debug("Created ring %s of size %u at %p", r_name, re->msgs.task_ring.elem_cnt, r);
        }

        // results ring
        uint16_t results_ring_cnt = 1;
        ctx.ring_conf_entries[ring_list_entry_id].rings_result.ring_arr =
                (struct rte_ring **)rte_calloc(
                        "struct rte_ring *", sizeof(struct rte_ring *), results_ring_cnt, 0);
        if (ctx.ring_conf_entries[ring_list_entry_id].rings_result.ring_arr == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for an array of \"results\" rings");
            return -ENOMEM;
        }
        ctx.ring_conf_entries[ring_list_entry_id].rings_result.ring_arr_len = results_ring_cnt;

        for (int ring_id = 0; ring_id < results_ring_cnt; ring_id++) {
            const char *r_name;
            struct rte_ring *r = NULL;
            r_name = DevConfRingGetResultName(re->msgs.result_ring.name_base, ring_id);
            // TODO: optimize ring flags
            r = rte_ring_create(r_name, re->msgs.result_ring.elem_cnt, (int)rte_socket_id(),
                    0); // RING_F_MP_RTS_ENQ | RING_F_MP_RTS_ENQ
            if (r == NULL) {
                Log().error(rte_errno, "Error (%s) cannot create results ring %s",
                        rte_strerror(rte_errno), r_name);
                return -rte_errno;
            }
            ctx.ring_conf_entries[ring_list_entry_id].rings_result.ring_arr[ring_id] = r;
            Log().debug(
                    "Created ring %s of size %u at %p", r_name, re->msgs.result_ring.elem_cnt, r);
        }

        // tasks/resutls (bypass) messages mempool
        uint16_t message_mempools_cnt = 1;
        ctx.ring_conf_entries[ring_list_entry_id].mempools_messages.mempool_arr =
                (struct rte_mempool **)rte_calloc("struct rte_mempool *",
                        sizeof(struct rte_mempool *), message_mempools_cnt, 0);
        if (ctx.ring_conf_entries[ring_list_entry_id].mempools_messages.mempool_arr == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for an array of \"message\" mempools");
            return -ENOMEM;
        }
        ctx.ring_conf_entries[ring_list_entry_id].mempools_messages.mempool_arr_len =
                message_mempools_cnt;

        for (int mp_id = 0; mp_id < message_mempools_cnt; mp_id++) {
            const char *mp_name;
            struct rte_mempool *mp = NULL;
            mp_name = DevConfMempoolGetMessageMPName(re->msgs.mempool.name, mp_id);
            uint16_t elt_sz = sizeof(struct PFMessage);
            mp = rte_mempool_create(mp_name, re->msgs.mempool.entries, elt_sz,
                    re->msgs.mempool.cache_entries, 0, NULL, NULL, NULL, NULL, (int)rte_socket_id(),
                    0);
            if (mp == NULL) {
                Log().error(rte_errno, "Error (%s) cannot create message mempool %s",
                        rte_strerror(rte_errno), mp_name);
                return -rte_errno;
            }
            ctx.ring_conf_entries[ring_list_entry_id].mempools_messages.mempool_arr[mp_id] = mp;
            Log().debug(
                    "Created mempool %s of size %u (cache size %u) with element size of %u at %p",
                    mp_name, re->msgs.mempool.entries, re->msgs.mempool.cache_entries, elt_sz, mp);
        }

        ring_list_entry_id++;
    }

    return 0;
}

int DevConfSharedConfInit(void)
{
    struct PFConf *pf;
    uint32_t conf_size = sizeof(struct PFConf) +
                         DevConfRingListSecondaryCoresCount() * sizeof(struct PFConfRingEntry);
    Log().notice("Confsize: %u pfconf sz: %u pfconf re %u wrkrs %u", conf_size,
            sizeof(struct PFConf), sizeof(struct PFConfRingEntry), DevConfRingListWorkersCount());
    const struct rte_memzone *mz;
    struct ring_list_entry *re;
    uint16_t ring_list_entry_id = 0;

    mz = rte_memzone_reserve(PREFILTER_CONF_MEMZONE_NAME, conf_size, (int)rte_socket_id(),
            RTE_MEMZONE_2MB | RTE_MEMZONE_SIZE_HINT_ONLY);
    if (mz == NULL) {
        Log().error(rte_errno, "Error (%s): failed to reserve memzone " PREFILTER_CONF_MEMZONE_NAME,
                rte_strerror(rte_errno));
        return -rte_errno;
    } else {
        ctx.shared_conf = mz;
    }
    Log().debug("Reserved memzone %s on 0x%p size of %d", PREFILTER_CONF_MEMZONE_NAME, mz->addr,
            conf_size);

    pf = mz->addr;
    pf->ring_entries = (void *)pf + sizeof(struct PFConf);
    pf->ring_entries_cnt = 0;

    Log().notice("pf %p pf->re %p", pf, pf->ring_entries);

    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        const char *name;
        struct rte_ring *ring;
        struct rte_mempool *mp;
        Log().notice("Ring entry %s", re->main_ring.name_base);
        for (int i = 0; i < re->sec_app_cores_cnt; i++) {
            pf->ring_entries[pf->ring_entries_cnt].pf_lcores = re->pf_cores_cnt;
            Log().notice("pf %p pf->re %p", pf, pf->ring_entries);

            name = DevConfRingGetRxName(re->main_ring.name_base, i);
            ring = rte_ring_lookup(name);
            if (ring == NULL) {
                Log().error(rte_errno, "Error (%s): Unable to find ring %s",
                        rte_strerror(rte_errno), name);
                return -rte_errno;
            }
            strlcpy(pf->ring_entries[pf->ring_entries_cnt].rx_ring_name, name,
                    sizeof(pf->ring_entries[pf->ring_entries_cnt].rx_ring_name));
            Log().notice("pf %p pf->re %p", pf, pf->ring_entries);
            Log().notice("Found %s", name);

            uint32_t lcore_id =
                    LcoreManagerGetLcoreIdFromRingId(i, re->sec_app_cores_cnt, re->pf_cores_cnt);
            name = DevConfRingGetTaskName(re->msgs.task_ring.name_base, lcore_id);
            Log().notice("Looking up %s", name);
            ring = rte_ring_lookup(name);
            Log().notice("Looked up %s", name);
            if (ring == NULL) {
                Log().error(rte_errno, "Error (%s): Unable to find ring %s",
                        rte_strerror(rte_errno), name);
                return -rte_errno;
            }
            Log().notice(
                    "Storing %s entries %d at %p", name, pf->ring_entries_cnt, pf->ring_entries);
            Log().notice("pf %p pf->re %p", pf, pf->ring_entries);
            pf->ring_entries[pf->ring_entries_cnt].tasks_ring = ring;
            Log().notice("Found %s", name);

            name = DevConfRingGetResultName(re->msgs.result_ring.name_base, 0);
            ring = rte_ring_lookup(name);
            if (ring == NULL) {
                Log().error(rte_errno, "Error (%s): Unable to find ring %s",
                        rte_strerror(rte_errno), name);
                return -rte_errno;
            }
            pf->ring_entries[pf->ring_entries_cnt].results_ring = ring;
            Log().notice("Found %s", name);

            name = DevConfMempoolGetMessageMPName(re->msgs.mempool.name, 0);
            mp = rte_mempool_lookup(name);
            if (mp == NULL) {
                Log().error(rte_errno, "Error (%s): Unable to find mempool %s",
                        rte_strerror(rte_errno), name);
                return -rte_errno;
            }
            pf->ring_entries[pf->ring_entries_cnt].message_mp = mp;
            Log().notice("Found %s", name);

            pf->ring_entries_cnt++;
        }
    }

    Log().notice("Configuration zone initialized");
    return 0;
}

int DevConfCtxResourcesInit(void)
{
    uint16_t ring_list_len = DevConfRingListLength();
    ctx.ring_conf_entries = (struct ctx_ring_conf_list_entry_resource *)rte_calloc(
            "struct ctx_ring_conf_list_entry_resource",
            sizeof(struct ctx_ring_conf_list_entry_resource), ring_list_len, 0);
    if (ctx.ring_conf_entries == NULL) {
        Log().error(ENOMEM,
                "Memory allocation failed for an array of ring configuration entry resources");
        return -ENOMEM;
    }
    ctx.ring_conf_entries_cnt = ring_list_len;
    return 0;
}

int DevConfRingsInit(void)
{
    struct ring_list_entry *re;
    uint16_t ring_list_entry_id = 0;

    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        const char *r_name;
        ctx.ring_conf_entries[ring_list_entry_id].rings_from_pf.ring_arr =
                (struct rte_ring **)rte_calloc(
                        "struct rte_ring *", sizeof(struct rte_ring *), re->sec_app_cores_cnt, 0);
        if (ctx.ring_conf_entries[ring_list_entry_id].rings_from_pf.ring_arr == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for an array of \"from PF\" rings");
            return -ENOMEM;
        }
        ctx.ring_conf_entries[ring_list_entry_id].rings_from_pf.ring_arr_len =
                re->sec_app_cores_cnt;

        if (re->opmode != IDS) {
            ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr =
                    (struct rte_ring **)rte_calloc("struct rte_ring *", sizeof(struct rte_ring *),
                            re->sec_app_cores_cnt, 0);
            if (ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr == NULL) {
                Log().error(ENOMEM, "Memory allocation failed for an array of \"to PF\" rings");
                return -ENOMEM;
            }
            ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr_len =
                    re->sec_app_cores_cnt;
        } else {
            ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr = NULL;
            ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr_len = 0;
        }

        for (int ring_id = 0; ring_id < re->sec_app_cores_cnt; ring_id++) {
            struct rte_ring *r = NULL;
            r_name = DevConfRingGetRxName(re->main_ring.name_base, ring_id);
            r = rte_ring_create(r_name, re->main_ring.elem_cnt, (int)rte_socket_id(),
                    RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (r == NULL) {
                Log().error(rte_errno, "Error (%s) cannot create rx ring %s",
                        rte_strerror(rte_errno), r_name);
                return -rte_errno;
            }
            ctx.ring_conf_entries[ring_list_entry_id].rings_from_pf.ring_arr[ring_id] = r;

            if (ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr != NULL) {
                r_name = DevConfRingGetTxName(re->main_ring.name_base, ring_id);
                r = rte_ring_create(r_name, re->main_ring.elem_cnt, (int)rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
                if (r == NULL) {
                    Log().error(rte_errno, "Error (%s) cannot create tx ring %s",
                            rte_strerror(rte_errno), r_name);
                    return -rte_errno;
                }
                ctx.ring_conf_entries[ring_list_entry_id].rings_to_pf.ring_arr[ring_id] = r;
            }
        }

        return 0;
    }
}
