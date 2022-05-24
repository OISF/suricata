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

#ifndef DEV_CONF_H
#define DEV_CONF_H

#include <sys/queue.h>
#include <stdint-gcc.h>

#include "prefilter.h"

typedef int (*start_ring)(void *ring_conf);
typedef int (*stop_ring)(void *ring_conf);

#define PREFILTER_CONFIG_OPERATION_MODE_PIPELINE "pipeline"
#define PREFILTER_CONFIG_OPERATION_MODE_IPS      "ips"
#define PREFILTER_CONFIG_OPERATION_MODE_IDS      "ids"

enum PFOpMode {
    PIPELINE,
    IDS,
    IPS,
};

struct ring_conf {
    const char *name_base;
    uint32_t elem_cnt;
};

struct table_conf {
    const char *name;
    uint32_t entries;
};

struct mempool_conf {
    const char *name;
    uint32_t entries;
    uint16_t cache_entries;
};

struct msgs_conf {
    struct ring_conf task_ring;
    struct ring_conf result_ring;
    struct mempool_conf mempool;
};

struct ring_list_entry {
    uint16_t sec_app_cores_cnt;
    uint16_t pf_cores_cnt;
    struct ring_conf main_ring;
    enum PFOpMode opmode;
    struct msgs_conf msgs;
    struct table_conf bypass_table_base;
    struct mempool_conf bypass_mempool;
    void *pre_ring_conf; // here should be stored either raw config or everything not covered before
    start_ring start;
    stop_ring stop;
    TAILQ_ENTRY(ring_list_entry) entries;
    TAILQ_HEAD(, ring_list_entry) head;
};

typedef TAILQ_HEAD(ring_tailq_head, ring_list_entry) ring_tailq_t;
extern ring_tailq_t tailq_ring_head;

typedef int (*start_all)(void);
typedef int (*stop_all)(void);
typedef int (*configure_by)(void *conf);
typedef void (*deinit)(void);

struct DeviceConfigurer {
    configure_by ConfigureBy;
    deinit Deinit;
    start_all StartAll;
    stop_all StopAll;
};

const char *DevConfBypassHashTableGetName(const char *base, uint16_t t_id);
const char *DevConfMempoolGetMessageMPName(const char *base, uint16_t mp_id);
const char *DevConfRingGetTaskName(const char *base, uint16_t ring_id);
const char *DevConfRingGetResultName(const char *base, uint16_t ring_id);
const char *DevConfRingGetRxName(const char *base, uint16_t ring_id);
const char *DevConfRingGetTxName(const char *base, uint16_t ring_id);

void DevConfInit(struct DeviceConfigurer ops);
int DevConfHashTablesInit(void);
int DevConfSharedConfInit(void);
int DevConfCtxResourcesInit(void);
int DevConfMessagesInit(void);
int DevConfRingsInit(void);
int DevConfThreadingInit(void);
int DevConfStartAll(void);
int DevConfStopAll(void);
int DevConfConfigureBy(void *conf);
void DevConfDeinit(void);

void RingListInitHead(void);
int RingListAddConf(const struct ring_list_entry *re);
void RingListDeinit(void);

#endif // DEV_CONF_H
