/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 */

#ifndef SURICATA_UTIL_FLOW_RATE_H
#define SURICATA_UTIL_FLOW_RATE_H

typedef struct FlowRateConfig_ {
    uint64_t bytes;
    SCTime_t interval;
} FlowRateConfig;

typedef struct FlowRateDirStore_ {
    /* Ring buffer to store byte count per second in */
    uint64_t *buf;
    /* Total sum of bytes per direction */
    uint64_t sum;
    /* Last index that was updated in the buffer */
    uint16_t last_idx;
    /* Size of the ring; should be same for both directions */
    uint16_t size;
    /* start timestamp to define and track the beginning of buffer */
    SCTime_t start_ts;
    /* last timestamp that was processed in the buffer */
    SCTime_t last_ts;
} FlowRateDirStore;

typedef struct FlowRateStore_ {
    FlowRateDirStore dir[2];
} FlowRateStore;

extern FlowRateConfig flow_rate_config;

bool FlowRateStorageEnabled(void);
void FlowRateRegisterFlowStorage(void);
FlowRateStore *FlowRateStoreInit(void);
FlowStorageId FlowRateGetStorageID(void);
void FlowRateStoreUpdate(FlowRateStore *, SCTime_t, uint32_t, int);
bool FlowRateIsExceeding(FlowRateStore *, int);

#ifdef UNITTESTS
void FlowRateRegisterTests(void);
#endif

#endif
