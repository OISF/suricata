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

#include "dev-conf.h"
#include "logger.h"

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

int DevConfRingsInit(void *ptr)
{
    struct resource_ctx *ctx = (struct resource_ctx *)ptr;

    struct ring_list_entry *re;
    uint16_t ring_list_entry_id = 0;
    uint16_t ring_list_len = 0;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        ring_list_len++;
    }

    ctx->main_rings = (struct main_ring *)rte_calloc(
            "struct main_ring", sizeof(struct main_ring), ring_list_len, 0);
    if (ctx->main_rings == NULL) {
        Log().error(ENOMEM, "Memory allocation failed for an array of main ring structures");
        return -ENOMEM;
    }
    ctx->main_rings_cnt = ring_list_len;

    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        const char *r_name;

        ctx->main_rings[ring_list_entry_id].ring_from_pf_arr = (struct rte_ring **)rte_calloc(
                "struct rte_ring *", sizeof(struct rte_ring *), re->sec_app_cores_cnt, 0);
        if (ctx->main_rings[ring_list_entry_id].ring_from_pf_arr == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for an array of main rings");
            return -ENOMEM;
        }
        ctx->main_rings[ring_list_entry_id].ring_from_pf_arr_len = re->sec_app_cores_cnt;

        if (re->opmode != IDS) {
            ctx->main_rings[ring_list_entry_id].ring_to_pf_arr = (struct rte_ring **)rte_calloc(
                    "struct rte_ring *", sizeof(struct rte_ring *), re->sec_app_cores_cnt, 0);
            if (ctx->main_rings[ring_list_entry_id].ring_to_pf_arr == NULL) {
                Log().error(ENOMEM, "Memory allocation failed for an array of main rings");
                return -ENOMEM;
            }
            ctx->main_rings[ring_list_entry_id].ring_to_pf_arr_len = re->sec_app_cores_cnt;
        } else {
            ctx->main_rings[ring_list_entry_id].ring_to_pf_arr = NULL;
            ctx->main_rings[ring_list_entry_id].ring_to_pf_arr_len = 0;
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
            ctx->main_rings[ring_list_entry_id].ring_from_pf_arr[ring_id] = r;

            if (ctx->main_rings[ring_list_entry_id].ring_to_pf_arr != NULL) {
                r_name = DevConfRingGetTxName(re->main_ring.name_base, ring_id);
                r = rte_ring_create(r_name, re->main_ring.elem_cnt, (int)rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
                if (r == NULL) {
                    Log().error(rte_errno, "Error (%s) cannot create tx ring %s",
                            rte_strerror(rte_errno), r_name);
                    return -rte_errno;
                }
                ctx->main_rings[ring_list_entry_id].ring_to_pf_arr[ring_id] = r;
            }
        }

        return 0;
    }
}
