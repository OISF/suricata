/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifdef __SC_CUDA_SUPPORT__

#ifndef __UTIL_CUDA_VARS__H__
#define __UTIL_CUDA_VARS__H__

#include "util-cuda-buffer.h"
#include "util-mpm.h"
#include "threads.h"

typedef struct CudaThreadVars_ {
    /* cb - CudaBuffer */
    CudaBufferData *cuda_ac_cb;

    MpmCtx *mpm_proto_other_ctx;

    MpmCtx *mpm_proto_tcp_ctx_ts;
    MpmCtx *mpm_proto_udp_ctx_ts;

    MpmCtx *mpm_proto_tcp_ctx_tc;
    MpmCtx *mpm_proto_udp_ctx_tc;

    uint16_t data_buffer_size_max_limit;
    uint16_t data_buffer_size_min_limit;

    uint8_t mpm_is_cuda;
} CudaThreadVars;

typedef struct CudaPacketVars_ {
    uint8_t cuda_mpm_enabled;
    uint8_t cuda_done;
    uint16_t cuda_gpu_matches;
    SCMutex cuda_mutex;
    SCCondT cuda_cond;
    uint32_t cuda_results[(UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MAX_LIMIT_DEFAULT * 2) + 1];
} CudaPacketVars;

void CudaVarsSetDeCtx(struct DetectEngineCtx_ *de_ctx);
int CudaThreadVarsInit(CudaThreadVars *ctv);

#endif /* __UTIL_CUDA_VARS__H__ */

#endif /* __SC_CUDA_SUPPORT__ */
