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

#include "suricata-common.h"
#ifdef __SC_CUDA_SUPPORT__
#include "suricata.h"
#include "util-mpm.h"
#include "util-cuda-handlers.h"
#include "util-cuda-vars.h"
#include "detect-engine-mpm.h"
#include "util-debug.h"
#include "util-mpm-ac.h"

static DetectEngineCtx *cuda_de_ctx = NULL;

void CudaVarsSetDeCtx(DetectEngineCtx *de_ctx)
{
    if (cuda_de_ctx != NULL) {
        SCLogError(SC_ERR_FATAL, "CudaVarsSetDeCtx() called more than once.  "
                   "This function should be called only once during the "
                   "lifetime of the engine.");
        exit(EXIT_FAILURE);
    }

    cuda_de_ctx = de_ctx;

    return;
}

int CudaThreadVarsInit(CudaThreadVars *ctv)
{
    if (PatternMatchDefaultMatcher() != MPM_AC_CUDA)
        return 0;

    MpmCudaConf *conf = CudaHandlerGetCudaProfile("mpm");
    if (conf == NULL) {
        SCLogError(SC_ERR_AC_CUDA_ERROR, "Error obtaining cuda mpm profile.");
        return -1;
    }

    ctv->mpm_is_cuda = 1;
    ctv->cuda_ac_cb = CudaHandlerModuleGetData(MPM_AC_CUDA_MODULE_NAME, MPM_AC_CUDA_MODULE_CUDA_BUFFER_NAME);
    ctv->data_buffer_size_max_limit = conf->data_buffer_size_max_limit;
    ctv->data_buffer_size_min_limit = conf->data_buffer_size_min_limit;
    ctv->mpm_proto_tcp_ctx_ts = MpmFactoryGetMpmCtxForProfile(cuda_de_ctx, cuda_de_ctx->sgh_mpm_context_proto_tcp_packet, 0);
    ctv->mpm_proto_tcp_ctx_tc = MpmFactoryGetMpmCtxForProfile(cuda_de_ctx, cuda_de_ctx->sgh_mpm_context_proto_tcp_packet, 1);
    ctv->mpm_proto_udp_ctx_ts = MpmFactoryGetMpmCtxForProfile(cuda_de_ctx, cuda_de_ctx->sgh_mpm_context_proto_udp_packet, 0);
    ctv->mpm_proto_udp_ctx_tc = MpmFactoryGetMpmCtxForProfile(cuda_de_ctx, cuda_de_ctx->sgh_mpm_context_proto_udp_packet, 1);
    ctv->mpm_proto_other_ctx = MpmFactoryGetMpmCtxForProfile(cuda_de_ctx, cuda_de_ctx->sgh_mpm_context_proto_other_packet, 0);

    return 0;
}

#endif
