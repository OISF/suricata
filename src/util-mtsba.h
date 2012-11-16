/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \file Multi thread single buffer access.
 *
 *       An API that allows multiple threads to simultaneously access a single
 *       buffer and write to it.
 *
 *       Current version allows only serial reads from the buffer.
 *       When the need arises, the API will be updated to allow multiple
 *       non-sequential reads.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_MTSBA__H__
#define __UTIL_MTSBA__H__

#include "util-atomic.h"

typedef struct MTSBA_CulledInfo_ {
    uint32_t no_of_items;

    uint32_t d_buffer_start_offset;
    uint32_t d_buffer_len;

    /* we use no_of_items to determine the no of items here */
    uint32_t op_buffer_start_offset;

    uint8_t d_buffer_reset;
    uint8_t op_buffer_reset;
} MTSBA_CulledInfo;

typedef struct MTSBA_Slice_ {
    uint32_t start_offset;
    uint32_t end_offset;
    uint8_t *buffer;
    SC_ATOMIC_DECLARE(uint8_t, done);

    struct MTSBA_Slice_ *next;
} MTSBA_Slice;

typedef struct MTSBA_Data_ {
    uint8_t *d_buffer;
    uint32_t d_buffer_len;
    uint32_t d_buffer_write;
    uint32_t d_buffer_read;

    /* debug only.  Can be removed */
    uint32_t no_of_items;

    /* these 2 buffers below - o_buffer and p_buffer should be
     * used/updated in tandem */
    uint32_t *o_buffer;
    void **p_buffer;
    uint32_t op_buffer_len;
    uint32_t op_buffer_write;
    uint32_t op_buffer_read;

    /* slice lists used by writers */
    MTSBA_Slice *slice_head;
    MTSBA_Slice *slice_tail;

    /* mutex used by the entire struct */
    SCMutex m;
} MTSBA_Data;

void MTSBA_ReportCulledConsumption(MTSBA_Data *mtsba_data,
                                   MTSBA_CulledInfo *culled_info);
void MTSBA_CullCompletedSlices(MTSBA_Data *mtsba_data,
                               MTSBA_CulledInfo *culled_info);
MTSBA_Slice *MTSBA_GetSlice(MTSBA_Data *data, uint32_t len, void *p);
void MTSBA_DeRegister(MTSBA_Data *mtsba_data);
MTSBA_Data* MTSBA_RegisterNew(const char *buffer_len_str);
void MTSBA_Init(void);
void MTSBA_RegisterUnittests(void);

#endif /* __UTIL_MTSBA__H__ */
