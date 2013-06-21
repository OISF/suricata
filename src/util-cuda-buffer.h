/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \file API to allow buffering of data.
 *
 *       Introduced with cuda as the primary objective.  Allows multiple
 *       threads to simultaneously access a single buffer and write to it.
 *
 *       Current version allows only serial reads from the buffer.
 *       When the need arises, the API will be updated to allow multiple
 *       non-sequential reads.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifdef __SC_CUDA_SUPPORT__

#ifndef __UTIL_CUDA_BUFFER_H__
#define __UTIL_CUDA_BUFFER_H__

#include "util-atomic.h"

/**
 * \brief Used by consumers to retrieve the data buffered.
 */
typedef struct CudaBufferCulledInfo_ {
    uint32_t no_of_items;

    uint32_t d_buffer_start_offset;
    uint32_t d_buffer_len;

    /* we use no_of_items to determine the no of items here */
    uint32_t op_buffer_start_offset;

    uint8_t d_buffer_reset;
    uint8_t op_buffer_reset;
} CudaBufferCulledInfo;

/**
 * /brief A slice which contains details on where to buffer data by a
 *        writer.
 */
typedef struct CudaBufferSlice_ {
    uint32_t start_offset;
    uint32_t end_offset;
    uint8_t *buffer;
    SC_ATOMIC_DECLARE(uint8_t, done);

    struct CudaBufferSlice_ *next;
} CudaBufferSlice;

typedef struct CudaBufferData_ {
    /* the data buffer */
    uint8_t *d_buffer;
    uint32_t d_buffer_len;
    uint32_t d_buffer_write;
    uint32_t d_buffer_read;

    /* debug only.  Can be removed */
    uint32_t no_of_items;

    /* these 2 buffers below - o_buffer and p_buffer should be
     * used/updated in tandem
     * p_buffer is the ptr buffer that points to a data instance that
     * represents it's corresponding data stored in d_buffer.
     * o_buffer is the corresponding entry to the one in p_buffer, which
     * holds the offset to the corresponding entry in d_buffer. */
    uint32_t *o_buffer;
    void **p_buffer;
    uint32_t op_buffer_len;
    uint32_t op_buffer_write;
    uint32_t op_buffer_read;

    /* slice lists used by writers */
    CudaBufferSlice *slice_head;
    CudaBufferSlice *slice_tail;

    /* mutex used by the entire struct */
    SCMutex m;
} CudaBufferData;

void CudaBufferReportCulledConsumption(CudaBufferData *cb_data,
                                       CudaBufferCulledInfo *culled_info);
void CudaBufferCullCompletedSlices(CudaBufferData *cb_data,
                                   CudaBufferCulledInfo *culled_info, uint32_t size_limit);
CudaBufferSlice *CudaBufferGetSlice(CudaBufferData *data, uint32_t len, void *p);
void CudaBufferDeRegister(CudaBufferData *cb_data);
CudaBufferData *CudaBufferRegisterNew(uint8_t *d_buffer, uint32_t d_buffer_len,
                                      uint32_t *o_buffer, void **p_buffer,
                                      uint32_t op_buffer_no_of_items);
void CudaBufferInit(void);
void CudaBufferRegisterUnittests(void);

#endif /* __UTIL_CUDA_BUFFER_H__ */

#endif /* __SC_CUDA_SUPPORT__ */
