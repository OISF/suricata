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
 *
 * NVIDIA CUDA utility functions - last referenced Cuda Toolkit 4.2
 */

/* compile in, only if we have a CUDA enabled device on the machine, with the
 * toolkit and the driver installed */

#include "suricata-common.h"
#ifdef __SC_CUDA_SUPPORT__

#include <cuda.h>
#include "util-cuda.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"

#define CASE_CODE(E) case E: return #E

typedef enum SCCudaAPIS_ {
    /* init api */
    SC_CUDA_CU_INIT,

    /* version management api */
    SC_CUDA_CU_DRIVER_GET_VERSION,

    /* device management api */
    SC_CUDA_CU_DEVICE_COMPUTE_CAPABILITY,
    SC_CUDA_CU_DEVICE_GET,
    SC_CUDA_CU_DEVICE_GET_ATTRIBUTE,
    SC_CUDA_CU_DEVICE_GET_COUNT,
    SC_CUDA_CU_DEVICE_GET_NAME,
    SC_CUDA_CU_DEVICE_GET_PROPERTIES,
    SC_CUDA_CU_DEVICE_TOTAL_MEM,

    /* context management api */
    SC_CUDA_CU_CTX_CREATE,
    SC_CUDA_CU_CTX_DESTROY,
    SC_CUDA_CU_CTX_GET_API_VERSION,
    SC_CUDA_CU_CTX_GET_CACHE_CONFIG,
    SC_CUDA_CU_CTX_GET_CURRENT,
    SC_CUDA_CU_CTX_GET_DEVICE,
    SC_CUDA_CU_CTX_GET_LIMIT,
    SC_CUDA_CU_CTX_POP_CURRENT,
    SC_CUDA_CU_CTX_PUSH_CURRENT,
    SC_CUDA_CU_CTX_SET_CACHE_CONFIG,
    SC_CUDA_CU_CTX_SET_CURRENT,
    SC_CUDA_CU_CTX_SET_LIMIT,
    SC_CUDA_CU_CTX_SYNCHRONIZE,
    SC_CUDA_CU_CTX_ATTACH,
    SC_CUDA_CU_CTX_DETACH,

    /* module management api */
    SC_CUDA_CU_MODULE_GET_FUNCTION,
    SC_CUDA_CU_MODULE_GET_GLOBAL,
    SC_CUDA_CU_MODULE_GET_SURF_REF,
    SC_CUDA_CU_MODULE_GET_TEX_REF,
    SC_CUDA_CU_MODULE_LOAD,
    SC_CUDA_CU_MODULE_LOAD_DATA,
    SC_CUDA_CU_MODULE_LOAD_DATA_EX,
    SC_CUDA_CU_MODULE_LOAD_FAT_BINARY,
    SC_CUDA_CU_MODULE_UNLOAD,

    /* memory management api */
    SC_CUDA_CU_ARRAY_3D_CREATE,
    SC_CUDA_CU_ARRAY_3D_GET_DESCRIPTOR,
    SC_CUDA_CU_ARRAY_CREATE,
    SC_CUDA_CU_ARRAY_DESTROY,
    SC_CUDA_CU_ARRAY_GET_DESCRIPTOR,
    SC_CUDA_CU_DEVICE_GET_BY_PCI_BUS_ID,
    SC_CUDA_CU_DEVICE_GET_PCI_BUS_ID,
    SC_CUDA_CU_IPC_CLOSE_MEM_HANDLE,
    SC_CUDA_CU_IPC_GET_EVENT_HANDLE,
    SC_CUDA_CU_IPC_GET_MEM_HANDLE,
    SC_CUDA_CU_IPC_OPEN_EVENT_HANDLE,
    SC_CUDA_CU_IPC_OPEN_MEM_HANDLE,
    SC_CUDA_CU_MEM_ALLOC,
    SC_CUDA_CU_MEM_ALLOC_HOST,
    SC_CUDA_CU_MEM_ALLOC_PITCH,
    SC_CUDA_CU_MEMCPY,
    SC_CUDA_CU_MEMCPY_2D,
    SC_CUDA_CU_MEMCPY_2D_ASYNC,
    SC_CUDA_CU_MEMCPY_2D_UNALIGNED,
    SC_CUDA_CU_MEMCPY_3D,
    SC_CUDA_CU_MEMCPY_3D_ASYNC,
    SC_CUDA_CU_MEMCPY_3D_PEER,
    SC_CUDA_CU_MEMCPY_3D_PEER_ASYNC,
    SC_CUDA_CU_MEMCPY_ASYNC,
    SC_CUDA_CU_MEMCPY_A_TO_A,
    SC_CUDA_CU_MEMCPY_A_TO_D,
    SC_CUDA_CU_MEMCPY_A_TO_H,
    SC_CUDA_CU_MEMCPY_A_TO_H_ASYNC,
    SC_CUDA_CU_MEMCPY_D_TO_A,
    SC_CUDA_CU_MEMCPY_D_TO_D,
    SC_CUDA_CU_MEMCPY_D_TO_D_ASYNC,
    SC_CUDA_CU_MEMCPY_D_TO_H,
    SC_CUDA_CU_MEMCPY_D_TO_H_ASYNC,
    SC_CUDA_CU_MEMCPY_H_TO_A,
    SC_CUDA_CU_MEMCPY_H_TO_A_ASYNC,
    SC_CUDA_CU_MEMCPY_H_TO_D,
    SC_CUDA_CU_MEMCPY_H_TO_D_ASYNC,
    SC_CUDA_CU_MEMCPY_PEER,
    SC_CUDA_CU_MEMCPY_PEER_ASYNC,
    SC_CUDA_CU_MEM_FREE,
    SC_CUDA_CU_MEM_FREE_HOST,
    SC_CUDA_CU_MEM_GET_ADDRESS_RANGE,
    SC_CUDA_CU_MEM_GET_INFO,
    SC_CUDA_CU_MEM_HOST_ALLOC,
    SC_CUDA_CU_MEM_HOST_GET_DEVICE_POINTER,
    SC_CUDA_CU_MEM_HOST_GET_FLAGS,
    SC_CUDA_CU_MEM_HOST_REGISTER,
    SC_CUDA_CU_MEM_HOST_UNREGISTER,
    SC_CUDA_CU_MEMSET_D16,
    SC_CUDA_CU_MEMSET_D16_ASYNC,
    SC_CUDA_CU_MEMSET_D2_D16,
    SC_CUDA_CU_MEMSET_D2_D16_ASYNC,
    SC_CUDA_CU_MEMSET_D2_D32,
    SC_CUDA_CU_MEMSET_D2_D32_ASYNC,
    SC_CUDA_CU_MEMSET_D2_D8,
    SC_CUDA_CU_MEMSET_D2_D8_ASYNC,
    SC_CUDA_CU_MEMSET_D32,
    SC_CUDA_CU_MEMSET_D32_ASYNC,
    SC_CUDA_CU_MEMSET_D8,
    SC_CUDA_CU_MEMSET_D8_ASYNC,

    /* unified addresssing */
    SC_CUDA_CU_POINTER_GET_ATTRIBUTE,

    /* stream management api */
    SC_CUDA_CU_STREAM_CREATE,
    SC_CUDA_CU_STREAM_DESTROY,
    SC_CUDA_CU_STREAM_QUERY,
    SC_CUDA_CU_STREAM_SYNCHRONIZE,
    SC_CUDA_CU_STREAM_WAIT_EVENT,

    /* event management api */
    SC_CUDA_CU_EVENT_CREATE,
    SC_CUDA_CU_EVENT_DESTROY,
    SC_CUDA_CU_EVENT_ELAPSED_TIME,
    SC_CUDA_CU_EVENT_QUERY,
    SC_CUDA_CU_EVENT_RECORD,
    SC_CUDA_CU_EVENT_SYNCHRONIZE,

    /* execution control api */
    SC_CUDA_CU_FUNC_GET_ATTRIBUTE,
    SC_CUDA_CU_FUNC_SET_CACHE_CONFIG,
    SC_CUDA_CU_LAUNCH_KERNEL,
    SC_CUDA_CU_FUNC_SET_BLOCK_SHAPE,
    SC_CUDA_CU_FUNC_SET_SHARED_SIZE,
    SC_CUDA_CU_LAUNCH,
    SC_CUDA_CU_LAUNCH_GRID,
    SC_CUDA_CU_LAUNCH_GRID_ASYNC,
    SC_CUDA_CU_PARAM_SETF,
    SC_CUDA_CU_PARAM_SETI,
    SC_CUDA_CU_PARAM_SET_SIZE,
    SC_CUDA_CU_PARAM_SET_TEX_REF,
    SC_CUDA_CU_PARAM_SETV,

    /* texture reference api */
    SC_CUDA_CU_TEX_REF_CREATE,
    SC_CUDA_CU_TEX_REF_DESTROY,
    SC_CUDA_CU_TEX_REF_GET_ADDRESS,
    SC_CUDA_CU_TEX_REF_GET_ADDRESS_MODE,
    SC_CUDA_CU_TEX_REF_GET_ARRAY,
    SC_CUDA_CU_TEX_REF_GET_FILTER_MODE,
    SC_CUDA_CU_TEX_REF_GET_FLAGS,
    SC_CUDA_CU_TEX_REF_GET_FORMAT,
    SC_CUDA_CU_TEX_REF_SET_ADDRESS,
    SC_CUDA_CU_TEX_REF_SET_ADDRESS_2D,
    SC_CUDA_CU_TEX_REF_SET_ADDRESS_MODE,
    SC_CUDA_CU_TEX_REF_SET_ARRAY,
    SC_CUDA_CU_TEX_REF_SET_FILTER_MODE,
    SC_CUDA_CU_TEX_REF_SET_FLAGS,
    SC_CUDA_CU_TEX_REF_SET_FORMAT,
} SCCudaAPIS;

SCEnumCharMap sc_cuda_api_names_string_map[] = {
    /* init api */
    { "cuInit",                    SC_CUDA_CU_INIT },

    /* version management api */
    { "cuDriverGetVersion",        SC_CUDA_CU_DRIVER_GET_VERSION },

    /* device management api */
    { "cuDeviceComputeCapability", SC_CUDA_CU_DEVICE_COMPUTE_CAPABILITY },
    { "cuDeviceGet",               SC_CUDA_CU_DEVICE_GET },
    { "cuDeviceGetAttribute",      SC_CUDA_CU_DEVICE_GET_ATTRIBUTE },
    { "cuDeviceGetCount",          SC_CUDA_CU_DEVICE_GET_COUNT },
    { "cuDeviceGetName",           SC_CUDA_CU_DEVICE_GET_NAME },
    { "cuDeviceGetProperties",     SC_CUDA_CU_DEVICE_GET_PROPERTIES },
    { "cuDeviceTotalMem",          SC_CUDA_CU_DEVICE_TOTAL_MEM },

    /* context management api */
    { "cuCtxCreate",               SC_CUDA_CU_CTX_CREATE },
    { "cuCtxDestroy",              SC_CUDA_CU_CTX_DESTROY },
    { "cuCtxGetApiVersion",        SC_CUDA_CU_CTX_GET_API_VERSION },
    { "cuCtxGetCacheConfig",       SC_CUDA_CU_CTX_GET_CACHE_CONFIG },
    { "cuCtxGetCurrent",           SC_CUDA_CU_CTX_GET_CURRENT },
    { "cuCtxGetDevice",            SC_CUDA_CU_CTX_GET_DEVICE },
    { "cuCtxGetLimit",             SC_CUDA_CU_CTX_GET_LIMIT },
    { "cuCtxPopCurrent",           SC_CUDA_CU_CTX_POP_CURRENT },
    { "cuCtxPushCurrent",          SC_CUDA_CU_CTX_PUSH_CURRENT },
    { "cuCtxSetCacheConfig",       SC_CUDA_CU_CTX_SET_CACHE_CONFIG },
    { "cuCtxSetCurrent",           SC_CUDA_CU_CTX_SET_CURRENT },
    { "cuCtxSetLimit",             SC_CUDA_CU_CTX_SET_LIMIT },
    { "cuCtxSynchronize",          SC_CUDA_CU_CTX_SYNCHRONIZE },
    { "cuCtxAttach",               SC_CUDA_CU_CTX_ATTACH },
    { "cuCtxDetach",               SC_CUDA_CU_CTX_DETACH },

    /* module management api */
    { "cuModuleGetFunction",       SC_CUDA_CU_MODULE_GET_FUNCTION },
    { "cuModuleGetGlobal",         SC_CUDA_CU_MODULE_GET_GLOBAL },
    { "cuModuleGetSurfRef",        SC_CUDA_CU_MODULE_GET_SURF_REF },
    { "cuModuleGetTexRef",         SC_CUDA_CU_MODULE_GET_TEX_REF },
    { "cuModuleLoad",              SC_CUDA_CU_MODULE_LOAD },
    { "cuModuleLoadData",          SC_CUDA_CU_MODULE_LOAD_DATA },
    { "cuModuleLoadDataEx",        SC_CUDA_CU_MODULE_LOAD_DATA_EX },
    { "cuModuleLoadFatBinary",     SC_CUDA_CU_MODULE_LOAD_FAT_BINARY },
    { "cuModuleUnload",            SC_CUDA_CU_MODULE_UNLOAD },

    /* memory management api */
    { "cuArray3DCreate",           SC_CUDA_CU_ARRAY_3D_CREATE },
    { "cuArray3DGetDescriptor",    SC_CUDA_CU_ARRAY_3D_GET_DESCRIPTOR },
    { "cuArrayCreate",             SC_CUDA_CU_ARRAY_CREATE },
    { "cuArrayDestroy",            SC_CUDA_CU_ARRAY_DESTROY },
    { "cuArrayGetDescriptor",      SC_CUDA_CU_ARRAY_GET_DESCRIPTOR },
    { "cuDeviceGetByPCIBusId",     SC_CUDA_CU_DEVICE_GET_BY_PCI_BUS_ID },
    { "cuDeviceGetPCIBusId",       SC_CUDA_CU_DEVICE_GET_PCI_BUS_ID },
    { "cuIpcCloseMemHandle",       SC_CUDA_CU_IPC_CLOSE_MEM_HANDLE },
    { "cuIpcGetEventHandle",       SC_CUDA_CU_IPC_GET_MEM_HANDLE },
    { "cuIpcGetMemHandle",         SC_CUDA_CU_IPC_GET_MEM_HANDLE },
    { "cuIpcOpenEventHandle",      SC_CUDA_CU_IPC_OPEN_EVENT_HANDLE },
    { "cuIpcOpenMemHandle",        SC_CUDA_CU_IPC_OPEN_MEM_HANDLE },
    { "cuMemAlloc",                SC_CUDA_CU_MEM_ALLOC },
    { "cuMemAllocHost",            SC_CUDA_CU_MEM_ALLOC_HOST },
    { "cuMemAllocPitch",           SC_CUDA_CU_MEM_ALLOC_PITCH },
    { "cuMemcpy",                  SC_CUDA_CU_MEMCPY },
    { "cuMemcpy2D",                SC_CUDA_CU_MEMCPY_2D },
    { "cuMemcpy2DAsync",           SC_CUDA_CU_MEMCPY_2D_ASYNC },
    { "cuMemcpy2DUnaligned",       SC_CUDA_CU_MEMCPY_2D_UNALIGNED },
    { "cuMemcpy3D",                SC_CUDA_CU_MEMCPY_3D },
    { "cuMemcpy3DAsync",           SC_CUDA_CU_MEMCPY_3D_ASYNC },
    { "cuMemcpy3DPeer",            SC_CUDA_CU_MEMCPY_3D_PEER },
    { "cuMemcpy3DPeerAsync",       SC_CUDA_CU_MEMCPY_3D_PEER_ASYNC },
    { "cuMemcpyAsync",             SC_CUDA_CU_MEMCPY_ASYNC },
    { "cuMemcpyAtoA",              SC_CUDA_CU_MEMCPY_A_TO_A },
    { "cuMemcpyAtoD",              SC_CUDA_CU_MEMCPY_A_TO_D },
    { "cuMemcpyAtoH",              SC_CUDA_CU_MEMCPY_A_TO_H },
    { "cuMemcpyAtoHAsync",         SC_CUDA_CU_MEMCPY_A_TO_H_ASYNC },
    { "cuMemcpyDtoA",              SC_CUDA_CU_MEMCPY_D_TO_A },
    { "cuMemcpyDtoD",              SC_CUDA_CU_MEMCPY_D_TO_D },
    { "cuMemcpyDtoDAsync",         SC_CUDA_CU_MEMCPY_D_TO_D_ASYNC },
    { "cuMemcpyDtoH",              SC_CUDA_CU_MEMCPY_D_TO_H },
    { "cuMemcpyDtoHAsync",         SC_CUDA_CU_MEMCPY_D_TO_H_ASYNC },
    { "cuMemcpyHtoA",              SC_CUDA_CU_MEMCPY_H_TO_A },
    { "cuMemcpyHtoAAsync",         SC_CUDA_CU_MEMCPY_H_TO_A_ASYNC },
    { "cuMemcpyHtoD",              SC_CUDA_CU_MEMCPY_H_TO_D },
    { "cuMemcpyHtoDAsync",         SC_CUDA_CU_MEMCPY_H_TO_D_ASYNC },
    { "cuMemcpyPeer",              SC_CUDA_CU_MEMCPY_PEER },
    { "cuMemcpyPeerAsync",         SC_CUDA_CU_MEMCPY_PEER_ASYNC },
    { "cuMemFree",                 SC_CUDA_CU_MEM_FREE },
    { "cuMemFreeHost",             SC_CUDA_CU_MEM_FREE_HOST },
    { "cuMemGetAddressRange",      SC_CUDA_CU_MEM_GET_ADDRESS_RANGE },
    { "cuMemGetInfo",              SC_CUDA_CU_MEM_GET_INFO },
    { "cuMemHostAlloc",            SC_CUDA_CU_MEM_HOST_ALLOC },
    { "cuMemHostGetDevicePointer", SC_CUDA_CU_MEM_HOST_GET_DEVICE_POINTER },
    { "cuMemHostGetFlags",         SC_CUDA_CU_MEM_HOST_GET_FLAGS },
    { "cuMemHostRegister",         SC_CUDA_CU_MEM_HOST_REGISTER },
    { "cuMemHostUnregister",       SC_CUDA_CU_MEM_HOST_UNREGISTER },
    { "cuMemsetD16",               SC_CUDA_CU_MEMSET_D16 },
    { "cuMemsetD16Async",          SC_CUDA_CU_MEMSET_D16_ASYNC },
    { "cuMemsetD2D16",             SC_CUDA_CU_MEMSET_D2_D16 },
    { "cuMemsetD2D16Async",        SC_CUDA_CU_MEMSET_D2_D16_ASYNC },
    { "cuMemsetD2D32",             SC_CUDA_CU_MEMSET_D2_D32 },
    { "cuMemsetD2D32Async",        SC_CUDA_CU_MEMSET_D2_D32_ASYNC },
    { "cuMemsetD2D8",              SC_CUDA_CU_MEMSET_D2_D8 },
    { "cuMemsetD2D8Async",         SC_CUDA_CU_MEMSET_D2_D8_ASYNC },
    { "cuMemsetD32",               SC_CUDA_CU_MEMSET_D32 },
    { "cuMemsetD32Async",          SC_CUDA_CU_MEMSET_D32_ASYNC },
    { "cuMemsetD8",                SC_CUDA_CU_MEMSET_D8 },
    { "cuMemsetD8Async",           SC_CUDA_CU_MEMSET_D8_ASYNC },

    /* unified addressing */
    { "cuPointerGetAttribute",     SC_CUDA_CU_POINTER_GET_ATTRIBUTE },

    /* stream management api */
    { "cuStreamCreate",            SC_CUDA_CU_STREAM_CREATE },
    { "cuStreamDestroy",           SC_CUDA_CU_STREAM_DESTROY },
    { "cuStreamQuery",             SC_CUDA_CU_STREAM_QUERY },
    { "cuStreamSynchronize",       SC_CUDA_CU_STREAM_SYNCHRONIZE },
    { "cuStreamWaitEvent",         SC_CUDA_CU_STREAM_WAIT_EVENT },

    /* event management api */
    { "cuEventCreate",             SC_CUDA_CU_EVENT_CREATE },
    { "cuEventDestroy",            SC_CUDA_CU_EVENT_DESTROY },
    { "cuEventElapseTime",         SC_CUDA_CU_EVENT_ELAPSED_TIME },
    { "cuEventQuery",              SC_CUDA_CU_EVENT_QUERY },
    { "cuEventRecord",             SC_CUDA_CU_EVENT_RECORD },
    { "cuEventSynchronize",        SC_CUDA_CU_EVENT_SYNCHRONIZE },

    /* execution control api */
    { "cuFuncGetAttribute",        SC_CUDA_CU_FUNC_GET_ATTRIBUTE },
    { "cuFuncSetCacheConfig",      SC_CUDA_CU_FUNC_SET_CACHE_CONFIG },
    { "cuLaunchKernel",            SC_CUDA_CU_LAUNCH_KERNEL },
    { "cuFuncSetBlockShape",       SC_CUDA_CU_FUNC_SET_BLOCK_SHAPE },
    { "cuFuncSetSharedSize",       SC_CUDA_CU_FUNC_SET_SHARED_SIZE },
    { "cuLaunch",                  SC_CUDA_CU_LAUNCH },
    { "cuLaunchGrid",              SC_CUDA_CU_LAUNCH_GRID },
    { "cuLaunchGridAsync",         SC_CUDA_CU_LAUNCH_GRID_ASYNC },
    { "cuParamSetf",               SC_CUDA_CU_PARAM_SETF },
    { "cuParamSeti",               SC_CUDA_CU_PARAM_SETI },
    { "cuParamSetSize",            SC_CUDA_CU_PARAM_SET_SIZE },
    { "cuSetTexRef",               SC_CUDA_CU_PARAM_SET_TEX_REF },
    { "cuSetv",                    SC_CUDA_CU_PARAM_SETV },

    /* texture reference api */
    { "cuTexRefCreate",            SC_CUDA_CU_TEX_REF_CREATE},
    { "cuTexRefDestroy",           SC_CUDA_CU_TEX_REF_DESTROY},
    { "cuTexRefGetAddress",        SC_CUDA_CU_TEX_REF_GET_ADDRESS},
    { "cuTexRefGetAddressMode",    SC_CUDA_CU_TEX_REF_GET_ADDRESS_MODE},
    { "cuTexRefGetArray",          SC_CUDA_CU_TEX_REF_GET_ARRAY},
    { "cuTexRefGetFilterMode",     SC_CUDA_CU_TEX_REF_GET_FILTER_MODE},
    { "cuTexRefGetFlags",          SC_CUDA_CU_TEX_REF_GET_FLAGS},
    { "cuTexRefGetFormat",         SC_CUDA_CU_TEX_REF_GET_FORMAT},
    { "cuTexRefSetAddress",        SC_CUDA_CU_TEX_REF_SET_ADDRESS},
    { "cuTexRefSetAddress2D",      SC_CUDA_CU_TEX_REF_SET_ADDRESS_2D},
    { "cuTexRefSetAddressMode",    SC_CUDA_CU_TEX_REF_SET_ADDRESS_MODE},
    { "cuTexRefSetArray",          SC_CUDA_CU_TEX_REF_SET_ARRAY},
    { "cuTexRefSetFilterMode",     SC_CUDA_CU_TEX_REF_SET_FILTER_MODE},
    { "cuTexRefSetFlags",          SC_CUDA_CU_TEX_REF_SET_FLAGS},
    { "cuTexRefSetFormat",         SC_CUDA_CU_TEX_REF_SET_FORMAT},

    { NULL, -1 },
};

static SCCudaDevices *devices = NULL;

/*****************************Error_Handling_API*******************************/

/**
 * \internal
 * \brief Maps the error enums from SCCudaAPIS to strings using the preprocessor
 *        #ENUM_VALUE.  This is mainly needed for logging purposes to log the
 *        error codes.
 *
 * \param err The error_code for which the string has to be returned.
 *
 * \retval The string equivalent of the error code.
 */
static const char *SCCudaGetErrorCodeInString(int err)
{
    switch (err) {
        CASE_CODE(CUDA_SUCCESS);
        CASE_CODE(CUDA_ERROR_INVALID_VALUE);
        CASE_CODE(CUDA_ERROR_OUT_OF_MEMORY);
        CASE_CODE(CUDA_ERROR_NOT_INITIALIZED);
        CASE_CODE(CUDA_ERROR_DEINITIALIZED);
        CASE_CODE(CUDA_ERROR_PROFILER_DISABLED);
        CASE_CODE(CUDA_ERROR_PROFILER_NOT_INITIALIZED);
        CASE_CODE(CUDA_ERROR_PROFILER_ALREADY_STARTED);
        CASE_CODE(CUDA_ERROR_PROFILER_ALREADY_STOPPED);
        CASE_CODE(CUDA_ERROR_NO_DEVICE);
        CASE_CODE(CUDA_ERROR_INVALID_DEVICE);
        CASE_CODE(CUDA_ERROR_INVALID_IMAGE);
        CASE_CODE(CUDA_ERROR_INVALID_CONTEXT);
        /* deprecated error code as of 3.2 */
        CASE_CODE(CUDA_ERROR_CONTEXT_ALREADY_CURRENT);
        CASE_CODE(CUDA_ERROR_MAP_FAILED);
        CASE_CODE(CUDA_ERROR_UNMAP_FAILED);
        CASE_CODE(CUDA_ERROR_ARRAY_IS_MAPPED);
        CASE_CODE(CUDA_ERROR_ALREADY_MAPPED);
        CASE_CODE(CUDA_ERROR_NO_BINARY_FOR_GPU);
        CASE_CODE(CUDA_ERROR_ALREADY_ACQUIRED);
        CASE_CODE(CUDA_ERROR_NOT_MAPPED);
        CASE_CODE(CUDA_ERROR_NOT_MAPPED_AS_ARRAY);
        CASE_CODE(CUDA_ERROR_NOT_MAPPED_AS_POINTER);
        CASE_CODE(CUDA_ERROR_ECC_UNCORRECTABLE);
        CASE_CODE(CUDA_ERROR_UNSUPPORTED_LIMIT);
        CASE_CODE(CUDA_ERROR_CONTEXT_ALREADY_IN_USE);
        CASE_CODE(CUDA_ERROR_INVALID_SOURCE);
        CASE_CODE(CUDA_ERROR_FILE_NOT_FOUND);
        CASE_CODE(CUDA_ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND);
        CASE_CODE(CUDA_ERROR_SHARED_OBJECT_INIT_FAILED);
        CASE_CODE(CUDA_ERROR_OPERATING_SYSTEM);
        CASE_CODE(CUDA_ERROR_INVALID_HANDLE);
        CASE_CODE(CUDA_ERROR_NOT_FOUND);
        CASE_CODE(CUDA_ERROR_NOT_READY);
        CASE_CODE(CUDA_ERROR_LAUNCH_FAILED);
        CASE_CODE(CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES);
        CASE_CODE(CUDA_ERROR_LAUNCH_TIMEOUT);
        CASE_CODE(CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING);
        CASE_CODE(CUDA_ERROR_PEER_ACCESS_ALREADY_ENABLED);
        CASE_CODE(CUDA_ERROR_PEER_ACCESS_NOT_ENABLED);
        CASE_CODE(CUDA_ERROR_PRIMARY_CONTEXT_ACTIVE);
        CASE_CODE(CUDA_ERROR_CONTEXT_IS_DESTROYED);
        CASE_CODE(CUDA_ERROR_ASSERT);
        CASE_CODE(CUDA_ERROR_TOO_MANY_PEERS);
        CASE_CODE(CUDA_ERROR_HOST_MEMORY_ALREADY_REGISTERED);
        CASE_CODE(CUDA_ERROR_HOST_MEMORY_NOT_REGISTERED);
        CASE_CODE(CUDA_ERROR_UNKNOWN);
        default:
            return "CUDA_UNKNOWN_ERROR_CODE";
    }
}

/**
 * \internal
 * \brief A generic function that handles the return values from the CUDA driver
 *        API.
 *
 * \param result   The result from the CUDA driver API call.
 * \param api_type An enum value SCCudaAPIS corresponing to the API for which the
 *                 result was returned.  The enum is needed to map the api type to
 *                 a string for logging purposes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCCudaHandleRetValue(CUresult result, SCCudaAPIS api_type)
{
    if (result == CUDA_SUCCESS) {
        SCLogDebug("%s executed successfully",
                   SCMapEnumValueToName(api_type, sc_cuda_api_names_string_map));
        return 0;
    } else {
        SCLogError(SC_ERR_CUDA_ERROR, "%s failed.  Returned errocode - %s",
                   SCMapEnumValueToName(api_type, sc_cuda_api_names_string_map),
                   SCCudaGetErrorCodeInString(result));
        return -1;
    }
}

/*****************************Cuda_Initialization_API**************************/

/**
 * \internal
 * \brief Inits the cuda driver API.
 *
 * \param flags Currently should be 0.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaInit(unsigned int flags)
{
    CUresult result = cuInit(flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_INIT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/*****************************Version_Management_API***************************/

/**
 * \brief Returns in *driver_version the version number of the installed CUDA
 *        driver. This function automatically returns CUDA_ERROR_INVALID_VALUE
 *        if the driver_version argument is NULL.
 *
 * \param driver_version Returns the CUDA driver version.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDriverGetVersion(int *driver_version)
{
    CUresult result = 0;

    if (driver_version == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "driver_version NULL");
        goto error;
    }

    result = cuDriverGetVersion(driver_version);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DRIVER_GET_VERSION) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/*****************************Device_Management_API****************************/

/**
 * \internal
 * \brief Returns the major and the minor revision numbers that define the
 *        compute capability for the device that is sent as the argument.
 *
 * \param major Pointer to an integer, that will be updated with the major revision.
 * \param minor Pointer to an integer, that will be updated with the minor revision.
 * \param dev  The device handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceComputeCapability(int *major, int *minor, CUdevice dev)
{
    CUresult result = 0;

    if (major == NULL || minor == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "major is NULL or minor is NULL");
        goto error;
    }

    result = cuDeviceComputeCapability(major, minor, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_COMPUTE_CAPABILITY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Returns a device handle given an ordinal in the range
 *        [0, cuDeviceGetCount() - 1].
 *
 * \param device  Pointer to a CUDevice instance that will be updated with the
 *                device handle.
 * \param ordinal An index in the range [0, cuDeviceGetCount() - 1].
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceGet(CUdevice *device, int ordinal)
{
    CUresult result = 0;

    if (device == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "device NULL");
        goto error;
    }

    result = cuDeviceGet(device, ordinal);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Returns the various attributes for the device that is sent as the arg.
 *
 *        The supported attributes are:
 *
 *        CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK: Maximum number of threads
 *            per block;
 *        CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X: Maximum x-dimension of a block;
 *        CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y: Maximum y-dimension of a block;
 *        CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z: Maximum z-dimension of a block;
 *        CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X: Maximum x-dimension of a grid;
 *        CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y: Maximum y-dimension of a grid;
 *        CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z: Maximum z-dimension of a grid;
 *        CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK: Maximum amount of
 *            shared mem-ory available to a thread block in bytes; this amount
 *            is shared by all thread blocks simultaneously resident on a
 *            multiprocessor;
 *        CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY: Memory available on device
 *            for __constant_-_ variables in a CUDA C kernel in bytes;
 *        CU_DEVICE_ATTRIBUTE_WARP_SIZE: Warp size in threads;
 *        CU_DEVICE_ATTRIBUTE_MAX_PITCH: Maximum pitch in bytes allowed by the
 *            memory copy functions that involve memory regions allocated
 *            through cuMemAllocPitch();
 *        CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK: Maximum number of 32-bit
 *            registers avail-able to a thread block; this number is shared by
 *            all thread blocks simultaneously resident on a multiprocessor;
 *        CU_DEVICE_ATTRIBUTE_CLOCK_RATE: Peak clock frequency in kilohertz;
 *        CU_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT: Alignment requirement; texture
 *            base addresses aligned to textureAlign bytes do not need an offset
 *            applied to texture fetches;
 *        CU_DEVICE_ATTRIBUTE_GPU_OVERLAP: 1 if the device can concurrently copy
 *            memory between host and device while executing a kernel, or 0 if not;
 *        CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT: Number of multiprocessors on
 *            the device;
 *        CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT: 1 if there is a run time limit
 *            for kernels executed on the device, or 0 if not;
 *        CU_DEVICE_ATTRIBUTE_INTEGRATED: 1 if the device is integrated with the
 *            memory subsystem, or 0 if not;
 *        CU_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY: 1 if the device can map host
 *            memory into the CUDA address space, or 0 if not;
 *        CU_DEVICE_ATTRIBUTE_COMPUTE_MODE: Compute mode that device is currently
 *            in. Available modes are as follows:
 *           - CU_COMPUTEMODE_DEFAULT: Default mode - Device is not restricted
 *                 and can have multiple CUDA contexts present at a single time.
 *           - CU_COMPUTEMODE_EXCLUSIVE: Compute-exclusive mode - Device can have
 *                 only one CUDA con-text present on it at a time.
 *           - CU_COMPUTEMODE_PROHIBITED: Compute-prohibited mode - Device is
 *                 prohibited from creating new CUDA contexts.
 *
 * \param pi     Pointer to an interger instance that will be updated with the
 *               attribute value.
 * \param attrib Device attribute to query.
 * \param dev  The device handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceGetAttribute(int *pi, CUdevice_attribute attrib,
                             CUdevice dev)
{
    CUresult result = 0;

    if (pi == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "prop is NULL");
        goto error;
    }

    result = cuDeviceGetAttribute(pi, attrib, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_ATTRIBUTE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Gets the total no of devices with compute capability greater than or
 *        equal to 1.0 that are available for execution.
 *
 * \param count Pointer to an integer that will be updated with the device count.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceGetCount(int *count)
{
    CUresult result = 0;

    if (count == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "count NULL");
        goto error;
    }

    result = cuDeviceGetCount(count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_COUNT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Returns the device name, given the device handle.
 *
 * \param name Pointer to a char buffer which will be updated with the device name.
 * \param len  Length of the above buffer.
 * \param dev  The device handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceGetName(char *name, int len, CUdevice dev)
{
    CUresult result = 0;

    if (name == NULL || len == 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "name is NULL or len is 0");
        goto error;
    }

    result = cuDeviceGetName(name, len, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_NAME) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Returns the properties of the device.  The CUdevprop structure is
 *        defined as
 *
 *        typedef struct CUdevprop_st {
 *            int maxThreadsPerBlock;
 *            int maxThreadsDim[3];
 *            int maxGridSize[3];
 *            int sharedMemPerBlock;
 *            int totalConstantMemory;
 *            int SIMDWidth;
 *            int memPitch;
 *            int regsPerBlock;
 *            int clockRate;
 *            int textureAlign
 *        } CUdevprop;
 *
 * \param prop Pointer to a CUdevprop instance that holds the device properties.
 * \param dev  The device handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceGetProperties(CUdevprop *prop, CUdevice dev)
{
    CUresult result = 0;

    if (prop == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "prop is NULL");
        goto error;
    }

    result = cuDeviceGetProperties(prop, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_PROPERTIES) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Returns the total amount of memory availabe on the device which
 *        is sent as the argument.
 *
 * \param bytes Pointer to an unsigned int instance, that will be updated with
 *              total memory for the device.
 * \param dev   The device handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaDeviceTotalMem(size_t *bytes, CUdevice dev)
{
    CUresult result = 0;

    if (bytes == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "bytes is NULL");
        goto error;
    }

    result = cuDeviceTotalMem(bytes, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_TOTAL_MEM) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \internal
 * \brief Creates and returns a new instance of SCCudaDevice.
 *
 * \retval device Pointer to the new instance of SCCudaDevice.
 */
static SCCudaDevice *SCCudaAllocSCCudaDevice(void)
{
    SCCudaDevice *device = SCMalloc(sizeof(SCCudaDevice));
    if (unlikely(device == NULL))
        return NULL;
    memset(device, 0 , sizeof(SCCudaDevice));

    return device;
}

/**
 * \internal
 * \brief Frees an instance of SCCudaDevice.
 *
 * \param device Pointer to the an instance of SCCudaDevice to be freed.
 */
static void SCCudaDeAllocSCCudaDevice(SCCudaDevice *device)
{
    SCFree(device);

    return;
}

/**
 * \internal
 * \brief Creates and returns a new instance of SCCudaDevices.
 *
 * \retval devices Pointer to the new instance of SCCudaDevices.
 */
static SCCudaDevices *SCCudaAllocSCCudaDevices(void)
{
    SCCudaDevices *devices = SCMalloc(sizeof(SCCudaDevices));
    if (unlikely(devices == NULL))
        return NULL;
    memset(devices, 0 , sizeof(SCCudaDevices));

    return devices;
}

/**
 * \internal
 * \brief Frees an instance of SCCudaDevices.
 *
 * \param device Pointer to the an instance of SCCudaDevices to be freed.
 */
static void SCCudaDeAllocSCCudaDevices(SCCudaDevices *devices)
{
    int i = 0;

    if (devices == NULL)
        return;

    if (devices->devices != NULL) {
        for (i = 0; i < devices->count; i++)
            SCCudaDeAllocSCCudaDevice(devices->devices[i]);

        SCFree(devices->devices);
    }

    SCFree(devices);

    return;
}

/**
 * \brief Retrieves all the devices and all the information corresponding to
 *        the devices on the CUDA device available on this system and returns
 *        a SCCudaDevices instances which holds all this information.
 *
 * \retval devices Pointer to a SCCudaDevices instance that holds information
 *                 for all the CUDA devices on the system.
 */
static SCCudaDevices *SCCudaGetDevices(void)
{
    SCCudaDevices *devices = SCCudaAllocSCCudaDevices();
    int i = 0;

    if (SCCudaDeviceGetCount(&devices->count) == -1)
        goto error;

    devices->devices = SCMalloc(devices->count * sizeof(SCCudaDevice *));
    if (devices->devices == NULL)
        goto error;

    /* update the device properties */
    for (i = 0; i < devices->count; i++) {
        devices->devices[i] = SCCudaAllocSCCudaDevice();

        if (SCCudaDeviceGet(&devices->devices[i]->device, i) == -1)
            goto error;

        if (SCCudaDeviceComputeCapability(&devices->devices[i]->major_rev,
                                          &devices->devices[i]->minor_rev,
                                          devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetName(devices->devices[i]->name,
                                SC_CUDA_DEVICE_NAME_MAX_LEN,
                                devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceTotalMem(&devices->devices[i]->bytes,
                                 devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetProperties(&devices->devices[i]->prop,
                                      devices->devices[i]->device) == -1) {
            goto error;
        }

        /* retrieve the attributes */
        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_threads_per_block,
                                     CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_block_dim_x,
                                     CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_block_dim_y,
                                     CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_block_dim_z,
                                     CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_grid_dim_x,
                                     CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_grid_dim_y,
                                     CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_grid_dim_z,
                                     CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_shared_memory_per_block,
                                     CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_total_constant_memory,
                                     CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_warp_size,
                                     CU_DEVICE_ATTRIBUTE_WARP_SIZE,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_pitch,
                                     CU_DEVICE_ATTRIBUTE_MAX_PITCH,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_max_registers_per_block,
                                     CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_clock_rate,
                                     CU_DEVICE_ATTRIBUTE_CLOCK_RATE,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_texture_alignment,
                                     CU_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_gpu_overlap,
                                     CU_DEVICE_ATTRIBUTE_GPU_OVERLAP,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_multiprocessor_count,
                                     CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_kernel_exec_timeout,
                                     CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_integrated,
                                     CU_DEVICE_ATTRIBUTE_INTEGRATED,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_can_map_host_memory,
                                     CU_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }

        if (SCCudaDeviceGetAttribute(&devices->devices[i]->attr_compute_mode,
                                     CU_DEVICE_ATTRIBUTE_COMPUTE_MODE,
                                     devices->devices[i]->device) == -1) {
            goto error;
        }
    }

#ifdef DEBUG
    SCCudaPrintDeviceList(devices);
#endif

    return devices;

 error:
    SCCudaDeAllocSCCudaDevices(devices);
    return NULL;
}

/**
 * \brief Prints the information for all the devices for this CUDA platform,
 *        supplied inside the argument.
 *
 * \param devices Pointer to a SCCudaDevices instance that holds information on
 *                the devices.
 */
void SCCudaPrintDeviceList(SCCudaDevices *devices)
{
    int i = 0;

    if (devices == NULL) {
        SCLogError(SC_ERR_CUDA_ERROR, "CUDA environment not initialized.  "
                   "Please initialized the CUDA environment by calling "
                   "SCCudaInitCudaEnvironment() before making any calls "
                   "to the CUDA API.");
        return;
    }

    SCLogDebug("Printing device info for this CUDA context");
    SCLogDebug("No of devices:  %d", devices->count);

    for (i = 0; i < devices->count; i++) {
        SCLogDebug("Device ID: %d", devices->devices[i]->device);
        SCLogDebug("Device Name: %s", devices->devices[i]->name);
        SCLogDebug("Device Major Revision: %d", devices->devices[i]->major_rev);
        SCLogDebug("Device Minor Revision: %d", devices->devices[i]->minor_rev);

        /* Cudevprop */
        SCLogDebug("Device Max Threads Per Block: %d",
                   devices->devices[i]->prop.maxThreadsPerBlock);
        SCLogDebug("Device Max Threads Dim: [%d, %d, %d]",
                   devices->devices[i]->prop.maxThreadsDim[0],
                   devices->devices[i]->prop.maxThreadsDim[1],
                   devices->devices[i]->prop.maxThreadsDim[2]);
        SCLogDebug("Device Max Grid Size: [%d, %d, %d]",
                   devices->devices[i]->prop.maxGridSize[0],
                   devices->devices[i]->prop.maxGridSize[1],
                   devices->devices[i]->prop.maxGridSize[2]);
        SCLogDebug("Device Shared Memory Per Block: %d",
                   devices->devices[i]->prop.sharedMemPerBlock);
        SCLogDebug("Device Total Constant Memory: %d",
                   devices->devices[i]->prop.totalConstantMemory);
        SCLogDebug("Device SIMD Width(Warp Size): %d",
                   devices->devices[i]->prop.SIMDWidth);
        SCLogDebug("Device Maximum Mem Pitch: %d", devices->devices[i]->prop.memPitch);
        SCLogDebug("Device Total Registers Available Per Block: %d",
                   devices->devices[i]->prop.regsPerBlock);
        SCLogDebug("Device Clock Frequency: %d", devices->devices[i]->prop.clockRate);
        SCLogDebug("Device Texture Alignment Requirement: %d",
                   devices->devices[i]->prop.textureAlign);


        /* device attributes */
        SCLogDebug("Device Max Threads Per Block: %d",
                   devices->devices[i]->attr_max_threads_per_block);
        SCLogDebug("Device Max Block Dim X: %d",
                   devices->devices[i]->attr_max_block_dim_x);
        SCLogDebug("Device Max Block Dim Y: %d",
                   devices->devices[i]->attr_max_block_dim_y);
        SCLogDebug("Device Max Block Dim Z: %d",
                   devices->devices[i]->attr_max_block_dim_z);
        SCLogDebug("Device Max Grid Dim X: %d",
                   devices->devices[i]->attr_max_grid_dim_x);
        SCLogDebug("Device Max Grid Dim Y: %d",
                   devices->devices[i]->attr_max_grid_dim_y);
        SCLogDebug("Device Max Grid Dim Z: %d",
                   devices->devices[i]->attr_max_grid_dim_z);
        SCLogDebug("Device Max Shared Memory Per Block: %d",
                   devices->devices[i]->attr_max_shared_memory_per_block);
        SCLogDebug("Device Total Constant Memory: %d",
                   devices->devices[i]->attr_total_constant_memory);
        SCLogDebug("Device Warp Size: %d", devices->devices[i]->attr_warp_size);
        SCLogDebug("Device Max Pitch: %d", devices->devices[i]->attr_max_pitch);
        SCLogDebug("Device Max Registers Per Block: %d",
                   devices->devices[i]->attr_max_registers_per_block);
        SCLogDebug("Device Clock Rate: %d", devices->devices[i]->attr_clock_rate);
        SCLogDebug("Device Texture Alignement: %d",
                   devices->devices[i]->attr_texture_alignment);
        SCLogDebug("Device GPU Overlap: %s",
                   (devices->devices[i]->attr_gpu_overlap == 1) ? "Yes": "No");
        SCLogDebug("Device Multiprocessor Count: %d",
                   devices->devices[i]->attr_multiprocessor_count);
        SCLogDebug("Device Kernel Exec Timeout: %s",
                   (devices->devices[i]->attr_kernel_exec_timeout) ? "Yes": "No");
        SCLogDebug("Device Integrated With Memory Subsystem: %s",
                   (devices->devices[i]->attr_integrated) ? "Yes": "No");
        SCLogDebug("Device Can Map Host Memory: %s",
                   (devices->devices[i]->attr_can_map_host_memory) ? "Yes": "No");
        if (devices->devices[i]->attr_compute_mode == CU_COMPUTEMODE_DEFAULT)
            SCLogDebug("Device Compute Mode: CU_COMPUTEMODE_DEFAULT");
        else if (devices->devices[i]->attr_compute_mode == CU_COMPUTEMODE_EXCLUSIVE)
            SCLogDebug("Device Compute Mode: CU_COMPUTEMODE_EXCLUSIVE");
        else if (devices->devices[i]->attr_compute_mode == CU_COMPUTEMODE_PROHIBITED)
            SCLogDebug("Device Compute Mode: CU_COMPUTEMODE_PROHIBITED");
    }

    return;
}

/**
 * \brief Prints some basic information for the default device(the first devie)
 *        we will be using on this cuda platform for use by our engine.  This
 *        function is basically to be used to print some minimal information to
 *        the user at engine startup.
 *
 * \param devices Pointer to a SCCudaDevices instance that holds information on
 *                the devices.
 */
void SCCudaPrintBasicDeviceInfo(SCCudaDevices *devices)
{
    int i = 0;

    if (devices == NULL) {
        SCLogError(SC_ERR_CUDA_ERROR, "CUDA environment not initialized.  "
                   "Please initialized the CUDA environment by calling "
                   "SCCudaInitCudaEnvironment() before making any calls "
                   "to the CUDA API.");
        return;
    }

    for (i = 0; i < devices->count; i++) {
        SCLogInfo("GPU Device %d: %s, %d Multiprocessors, %dMHz, CUDA Compute "
                  "Capability %d.%d", i + 1,
                  devices->devices[i]->name,
                  devices->devices[i]->attr_multiprocessor_count,
                  devices->devices[i]->attr_clock_rate/1000,
                  devices->devices[i]->major_rev,
                  devices->devices[i]->minor_rev);
    }

    return;
}

/**
 * \brief Gets the device list, for the CUDA platform environment initialized by
 *        the engine.
 *
 * \retval devices Pointer to the CUDA device list on success; NULL on failure.
 */
SCCudaDevices *SCCudaGetDeviceList(void)
{
    if (devices == NULL) {
        SCLogError(SC_ERR_CUDA_ERROR, "CUDA environment not initialized.  "
                   "Please initialized the CUDA environment by calling "
                   "SCCudaInitCudaEnvironment() before making any calls "
                   "to the CUDA API.");
        return NULL;
    }

    return devices;
}

/*****************************Context_Management_API***************************/

/**
 * \brief Creates a new CUDA context and associates it with the calling thread.
 *        The flags parameter is described below. The context is created with
 *        a usage count of 1 and the caller of cuCtxCreate() must call
 *        cuCtxDestroy() or cuCtxDetach() when done using the context. If a
 *        context is already current to the thread, it is supplanted by the
 *        newly created context and may be restored by a subsequent call to
 *        cuCtxPopCurrent(). The two LSBs of the flags parameter can be used
 *        to control how the OS thread, which owns the CUDA context at the
 *        time of an API call, interacts with the OS scheduler when waiting for
 *        results from the GPU.
 *
 *        - CU_CTX_SCHED_AUTO: The default value if the flags parameter is zero,
 *              uses a heuristic based on the number of active CUDA contexts in
 *              the process C and the number of logical processors in the system
 *              P. If C > P, then CUDA will yield to other OS threads when
 *              waiting for the GPU, otherwise CUDA will not yield while waiting
 *              for results and actively spin on the processor.
 *        - CU_CTX_SCHED_SPIN: Instruct CUDA to actively spin when waiting for
 *              results from the GPU. This can de-crease latency when waiting for
 *              the GPU, but may lower the performance of CPU threads if they are
 *              performing work in parallel with the CUDA thread.
 *        - CU_CTX_SCHED_YIELD: Instruct CUDA to yield its thread when waiting
 *              for results from the GPU. This can increase latency when waiting
 *              for the GPU, but can increase the performance of CPU threads
 *              performing work in parallel with the GPU.
 *        - CU_CTX_BLOCKING_SYNC: Instruct CUDA to block the CPU thread on a
 *              synchronization primitive when waiting for the GPU to finish work.
 *        - CU_CTX_MAP_HOST: Instruct CUDA to support mapped pinned allocations.
 *              This flag must be set in order to allocate pinned host memory
 *              that is accessible to the GPU.
 *
 *        Note to Linux users:
 *        Context creation will fail with CUDA_ERROR_UNKNOWN if the compute mode
 *        of the device is CU_COMPUTEMODE_PROHIBITED. Similarly, context creation
 *        will also fail with CUDA_ERROR_UNKNOWN if the compute mode for the
 *        device is set to CU_COMPUTEMODE_EXCLUSIVE and there is already an
 *        active context on the device. The function cuDeviceGetAttribute() can
 *        be used with CU_DEVICE_ATTRIBUTE_COMPUTE_MODE to determine the compute
 *        mode of the device. The nvidia-smi tool can be used to set the compute
 *        mode for devices. Documentation for nvidia-smi can be obtained by
 *        passing a -h option to it.
 *
 * \param pctx  Returned context handle of the current context.
 * \param flags Context creation flags.
 * \param dev   Device to create context on.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxCreate(CUcontext *pctx, unsigned int flags, CUdevice dev)
{
    CUresult result = 0;

    if (pctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pctx NULL");
        goto error;
    }

    result = cuCtxCreate(pctx, flags, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Destroys the CUDA context specified by ctx. If the context usage count
 *        is not equal to 1, or the context is current to any CPU thread other
 *        than the current one, this function fails. Floating contexts (detached
 *        from a CPU thread via cuCtxPopCurrent()) may be destroyed by this
 *        function.
 *
 * \param ctx Context to destroy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxDestroy(CUcontext ctx)
{
    CUresult result = 0;

    result = cuCtxDestroy(ctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_DESTROY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxGetApiVersion(CUcontext ctx, unsigned int *version)
{
    CUresult result = 0;

    if (version == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "version NULL");
        goto error;
    }

    result = cuCtxGetApiVersion(ctx, version);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_GET_API_VERSION) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxGetCacheConfig(CUfunc_cache *pconfig)
{
    CUresult result = 0;

    if (pconfig == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pconfig NULL");
        goto error;
    }

    result = cuCtxGetCacheConfig(pconfig);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_GET_CACHE_CONFIG) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxGetCurrent(CUcontext *pctx)
{
    CUresult result = 0;

    if (pctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pctx NULL");
        goto error;
    }

    result = cuCtxGetCurrent(pctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_GET_CURRENT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *device the ordinal of the current context's device.
 *
 * \param device Returned device id for the current context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxGetDevice(CUdevice *device)
{
    CUresult result = 0;

    if (device == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "device NULL");
        goto error;
    }

    result = cuCtxGetDevice(device);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_GET_DEVICE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxGetLimit(size_t *pvalue, CUlimit limit)
{
    CUresult result = 0;

    result = cuCtxGetLimit(pvalue, limit);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_GET_LIMIT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Pops the current CUDA context from the CPU thread. The CUDA context
 *        must have a usage count of 1. CUDA contexts have a usage count of 1
 *        upon creation; the usage count may be incremented with cuCtxAttach()
 *        and decremented with cuCtxDetach().
 *
 *        If successful, cuCtxPopCurrent() passes back the new context handle
 *        in *pctx. The old context may then be made current to a different CPU
 *        thread by calling cuCtxPushCurrent().
 *
 *        Floating contexts may be destroyed by calling cuCtxDestroy().
 *
 *        If a context was current to the CPU thread before cuCtxCreate() or
 *        cuCtxPushCurrent() was called, this function makes that context
 *        current to the CPU thread again.
 *
 * \param pctx Returned new context handle.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxPopCurrent(CUcontext *pctx)
{
    CUresult result = 0;

    result = cuCtxPopCurrent(pctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_POP_CURRENT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Pushes the given context ctx onto the CPU thread's stack of current
 *        contexts. The speci?ed context becomes the CPU thread's current
 *        context, so all CUDA functions that operate on the current context
 *        are affected.
 *
 *        The previous current context may be made current again by calling
 *        cuCtxDestroy() or cuCtxPopCurrent().
 *
 *        The context must be "floating," i.e. not attached to any thread.
 *        Contexts are made to float by calling cuCtxPopCurrent().
 *
 * \param ctx Floating context to attach.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxPushCurrent(CUcontext ctx)
{
    CUresult result = 0;

    result = cuCtxPushCurrent(ctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_PUSH_CURRENT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxSetCacheConfig(CUfunc_cache config)
{
    CUresult result = 0;

    result = cuCtxSetCacheConfig(config);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_SET_CACHE_CONFIG) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxSetCurrent(CUcontext ctx)
{
    CUresult result = 0;

    result = cuCtxSetCurrent(ctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_SET_CURRENT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaCtxSetLimit(CUlimit limit, size_t value)
{
    CUresult result = 0;

    result = cuCtxSetLimit(value, limit);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_SET_LIMIT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Blocks until the device has completed all preceding requested tasks.
 *        cuCtxSynchronize() returns an error if one of the preceding tasks failed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxSynchronize(void)
{
    CUresult result = 0;

    result = cuCtxSynchronize();
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_SYNCHRONIZE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Increments the usage count of the context and passes back a context
 *        handle in *pctx that must be passed to cuCtxDetach() when the
 *        application is done with the context. cuCtxAttach() fails if there is
 *        no context current to the thread.  Currently, the flags parameter must
 *        be 0.
 *
 * \param pctx  Returned context handle of the current context.
 * \param flags Context attach flags (must be 0).
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxAttach(CUcontext *pctx, unsigned int flags)
{
    CUresult result = 0;

    SCLogInfo("Cuda API - %s deprecated",
              SCMapEnumValueToName(SC_CUDA_CU_CTX_ATTACH,
                                   sc_cuda_api_names_string_map));

    if (pctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pctx NULL");
        goto error;
    }

    result = cuCtxAttach(pctx, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_ATTACH) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Decrements the usage count of the context ctx, and destroys the
 *        context if the usage count goes to 0. The context must be a handle
 *        that was passed back by cuCtxCreate() or cuCtxAttach(), and must be
 *        current to the calling thread.
 *
 * \param ctx Context to destroy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaCtxDetach(CUcontext ctx)
{
    CUresult result = 0;

    SCLogInfo("Cuda API - %s deprecated",
              SCMapEnumValueToName(SC_CUDA_CU_CTX_DETACH,
                                   sc_cuda_api_names_string_map));

    result = cuCtxDetach(ctx);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_CTX_DETACH) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/*****************************Module_Management_API****************************/

/**
 * \brief Returns in *hfunc the handle of the function of name \"name\" located
 *        in module hmod. If no function of that name exists,
 *        cuModuleGetFunction() returns CUDA_ERROR_NOT_FOUND.
 *
 * \param hfunc Returned function handle.
 * \param hmod  Module to return function from.
 * \param name  Name of function to retrieve.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleGetFunction(CUfunction *hfunc, CUmodule hmod, const char *name)
{
    CUresult result = 0;

    if (hfunc == NULL || name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "hfunc is NULL or name is NULL");
        goto error;
    }

    result = cuModuleGetFunction(hfunc, hmod, name);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_GET_FUNCTION) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *dptr and *bytes the base pointer and size of the global
 *        name \"name\" located in module hmod. If no variable of that name
 *        exists, cuModuleGetGlobal() returns CUDA_ERROR_NOT_FOUND. Both
 *        parameters dptr and bytes are optional. If one of them is NULL,
 *        it is ignored.
 *
 * \param dptr Returned global device pointer.
 * \param bytes Returned global size in bytes.
 * \param hmod  Module to return function from.
 * \param name  Name of global to retrieve.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleGetGlobal(CUdeviceptr *dptr, size_t *bytes, CUmodule hmod,
                          const char *name)
{
    CUresult result = 0;

    if (name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "name is NULL");
        goto error;
    }

    result = cuModuleGetGlobal(dptr, bytes, hmod, name);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_GET_GLOBAL) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaModuleGetSurfRef(CUsurfref *p_surf_ref, CUmodule hmod, const char *name)
{
    CUresult result = 0;

    if (p_surf_ref == NULL || name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_surf_ref is NULL or name is NULL");
        goto error;
    }

    result = cuModuleGetSurfRef(p_surf_ref, hmod, name);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_GET_SURF_REF) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *p_tex_ref the handle of the texture reference of name
 *        \"name\" in the module hmod. If no texture reference of that name
 *        exists, cuModuleGetTexRef() returns CUDA_ERROR_NOT_FOUND. This texture
 *        reference handle should not be destroyed, since it will be destroyed
 *        when the module is unloaded.
 *
 * \param p_tex_ref Returned global device pointer.
 * \param hmod      Module to retrieve texture reference from.
 * \param name      Name of the texture reference to retrieve.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleGetTexRef(CUtexref *p_tex_ref, CUmodule hmod, const char *name)
{
    CUresult result = 0;

    if (p_tex_ref == NULL || name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_tex_ref is NULL or name is NULL");
        goto error;
    }

    result = cuModuleGetTexRef(p_tex_ref, hmod, name);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_GET_TEX_REF) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Takes a filename fname and loads the corresponding module \"module\"
 *        into the current context. The CUDA driver API does not attempt to
 *        lazily allocate the resources needed by a module; if the memory for
 *        functions and data (constant and global) needed by the module cannot
 *        be allocated, cuModuleLoad() fails. The file should be a cubin file
 *        as output by nvcc or a PTX file, either as output by nvcc or handwrtten.
 *
 * \param module Returned module.
 * \param fname  Filename of module to load.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleLoad(CUmodule *module, const char *fname)
{
    CUresult result = 0;

    if (module == NULL || fname == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "module is NULL or fname is NULL");
        goto error;
    }

    result = cuModuleLoad(module, fname);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_LOAD) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Takes a pointer image and loads the corresponding module \"module\"
 *        into the current context. The pointer may be obtained by mapping a
 *        cubin or PTX file, passing a cubin or PTX ?le as a NULL-terminated
 *        text string, or incorporating a cubin object into the executable
 *        resources and using operating system calls such as Windows
 *        FindResource() to obtain the pointer.
 *
 * \param module Returned module.
 * \param image  Module data to load
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleLoadData(CUmodule *module, const void *image)
{
    CUresult result = 0;

    if (module == NULL || image == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "module is NULL or image is NULL");
        goto error;
    }

    result = cuModuleLoadData(module, image);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_LOAD_DATA) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Takes a pointer image and loads the corresponding module module into
 *        the current context. The pointer may be obtained by mapping a cubin or
 *        PTX file, passing a cubin or PTX file as a NULL-terminated text
 *        string, or incorporating a cubin object into the executable resources
 *        and using operating system calls such as Windows FindResource() to
 *        obtain the pointer. Options are passed as an array via options and any
 *        corresponding parameters are passed in optionValues. The number of
 *        total options is supplied via numOptions. Any outputs will be returned
 *        via optionValues. Supported options are:
 *
 *        - CU_JIT_MAX_REGISTERS: input specifies the maximum number of registers
 *              per thread;
 *        - CU_JIT_THREADS_PER_BLOCK: input specifies number of threads per block
 *              to target compilation for; output returns the number of threads
 *              the compiler actually targeted;
 *        - CU_JIT_WALL_TIME: output returns the float value of wall clock time,
 *              in milliseconds, spent compiling the PTX code;
 *        - CU_JIT_INFO_LOG_BUFFER: input is a pointer to a buffer in which to
 *              print any informational log messages from PTX assembly;
 *        - CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES: input is the size in bytes of the
 *              buffer; output is the number of bytes filled with messages;
 *        - CU_JIT_ERROR_LOG_BUFFER: input is a pointer to a buffer in which to
 *              print any error log messages from PTX assembly;
 *        - CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES: input is the size in bytes of the
 *              buffer; output is the number of bytes filled with messages;
 *        - CU_JIT_OPTIMIZATION_LEVEL: input is the level of optimization to apply
 *              to generated code (0 - 4), with 4 being the default and highest
 *              level;
 *        - CU_JIT_TARGET_FROM_CUCONTEXT: causes compilation target to be
 *              determined based on current attached context (default);
 *        - CU_JIT_TARGET: input is the compilation target based on supplied
 *              CUjit_target_enum; possible values are:
 *            -- CU_TARGET_COMPUTE_10
 *            -- CU_TARGET_COMPUTE_11
 *            -- CU_TARGET_COMPUTE_12
 *            -- CU_TARGET_COMPUTE_13
 *
 * \param module       Returned module.
 * \param image        Module data to load.
 * \param numOptions   Number of options.
 * \param options      Options for JIT.
 * \param optionValues Option values for JIT.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleLoadDataEx(CUmodule *module, const void *image,
                           unsigned int num_options, CUjit_option *options,
                           void **option_values)
{
    CUresult result = 0;

    if (module == NULL || image == NULL || options == NULL ||
        option_values == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "module is NULL or image is NULL or options is NULL or "
                   "option_values is NULL");
        goto error;
    }

    result = cuModuleLoadDataEx(module, image, num_options, options, option_values);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_LOAD_DATA_EX) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Takes a pointer fat_cubin and loads the corresponding module \"module\"
 *        into the current context. The pointer represents a fat binary object,
 *        which is a collection of different cubin files, all representing the
 *        same device code, but compiled and optimized for different
 *        architectures. There is currently no documented API for constructing
 *        and using fat binary objects by programmers, and therefore this
 *        function is an internal function in this version of CUDA. More
 *        information can be found in the nvcc document.
 *
 * \param module   Returned module.
 * \param fatCubin Fat binary to load.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleLoadFatBinary(CUmodule *module, const void *fat_cubin)
{
    CUresult result = 0;

    if (module == NULL || fat_cubin == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "module is NULL or fatCubin is NULL");
        goto error;
    }

    result = cuModuleLoadFatBinary(module, fat_cubin);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_LOAD_FAT_BINARY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Unloads a module hmod from the current context.
 *
 * \param module Module to unload
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaModuleUnload(CUmodule hmod)
{
    CUresult result = 0;

    result = cuModuleUnload(hmod);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MODULE_UNLOAD) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/****************************Memory_Management_API*****************************/

/**
 * \brief Creates a CUDA array according to the CUDA_ARRAY3D_DESCRIPTOR
 *        structure pAllocateArray and returns a handle to the new CUDA
 *        array in *p_handle. The CUDA_ARRAY3D_DESCRIPTOR is defined as:
 *
 *        typedef struct {
 *            unsigned int Width;
 *            unsigned int Height;
 *            unsigned int Depth;
 *            CUarray_format Format;
 *            unsigned int NumChannels;
 *            unsigned int Flags;
 *        } CUDA_ARRAY3D_DESCRIPTOR;
 *
 *        where:
 *
 *        - Width, Height, and Depth are the width, height, and depth of the
 *          CUDA array (in elements); the CUDA array is one-dimensional if
v *          height and depth are 0, two-dimensional if depth is 0, and
 *          three-dimensional otherwise;
 *        - Format speci?es the format of the elements; CUarray_format is
 *          defined as:
 *
 *          typedef enum CUarray_format_enum {
 *              CU_AD_FORMAT_UNSIGNED_INT8 = 0x01,
 *              CU_AD_FORMAT_UNSIGNED_INT16 = 0x02,
 *              CU_AD_FORMAT_UNSIGNED_INT32 = 0x03,
 *              CU_AD_FORMAT_SIGNED_INT8 = 0x08,
 *              CU_AD_FORMAT_SIGNED_INT16 = 0x09,
 *              CU_AD_FORMAT_SIGNED_INT32 = 0x0a,
 *              CU_AD_FORMAT_HALF = 0x10,
 *              CU_AD_FORMAT_FLOAT = 0x20
 *          } CUarray_format;
 *
 *        - NumChannels speci?es the number of packed components per CUDA array
 *          element; it may be 1, 2, or 4;
 *        - Flags provides for future features. For now, it must be set to 0.
 *
 *        Here are examples of CUDA array descriptions:
 *
 *        Description for a CUDA array of 2048 floats:
 *
 *        CUDA_ARRAY3D_DESCRIPTOR desc;
 *        desc.Format = CU_AD_FORMAT_FLOAT;
 *        desc.NumChannels = 1;
 *        desc.Width = 2048;
 *        desc.Height = 0;
 *        desc.Depth = 0;
 *
 *        Description for a 64 x 64 CUDA array of floats:
 *
 *        CUDA_ARRAY3D_DESCRIPTOR desc;
 *        desc.Format = CU_AD_FORMAT_FLOAT;
 *        desc.NumChannels = 1;
 *        desc.Width = 64;
 *        desc.Height = 64;
 *        desc.Depth = 0;
 *
 *        Description for a width x height x depth CUDA array of 64-bit,
 *        4x16-bit float16's:
 *
 *        CUDA_ARRAY3D_DESCRIPTOR desc;
 *        desc.FormatFlags = CU_AD_FORMAT_HALF;
 *        desc.NumChannels = 4;
 *        desc.Width = width;
 *        desc.Height = height;
 *        desc.Depth = depth;
 *
 * \param p_handle         Returned Handle.
 * \param p_allocate_array 3D array descriptor.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaArray3DCreate(CUarray *p_handle,
                        const CUDA_ARRAY3D_DESCRIPTOR *p_allocate_array)
{
    CUresult result = 0;

    if (p_handle == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_handle is NULL");
        goto error;
    }

    result = cuArray3DCreate(p_handle, p_allocate_array);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_ARRAY_3D_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *p_rray_descriptor a descriptor containing information on
 *        the format and dimensions of the CUDA array h_array. It is useful for
 *        subroutines that have been passed a CUDA array, but need to know the
 *        CUDA array parameters for validation or other purposes.
 *
 *        This function may be called on 1D and 2D arrays, in which case the
 *        Height and/or Depth members of the descriptor struct will be set to 0.
 *
 * \param p_array_descriptor Returned 3D array descriptor.
 * \param h_array            3D array to get descriptor of.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaArray3DGetDescriptor(CUDA_ARRAY3D_DESCRIPTOR *p_array_descriptor,
                               CUarray h_array)
{
    CUresult result = 0;

    if (p_array_descriptor == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_array_descriptor is NULL");
        goto error;
    }

    result = cuArray3DGetDescriptor(p_array_descriptor, h_array);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_ARRAY_3D_GET_DESCRIPTOR) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Creates a CUDA array according to the CUDA_ARRAY_DESCRIPTOR structure
 *        p_allocate_array and returns a handle to the new CUDA array in
 *        p_handle. The CUDA_ARRAY_DESCRIPTOR is defined as:
 *
 *        typedef struct {
 *            unsigned int Width;
 *            unsigned int Height;
 *            CUarray_format Format;
 *            unsigned int NumChannels;
 *        } CUDA_ARRAY_DESCRIPTOR;
 *
 *        where:
 *
 *        - Width, and Height are the width, and height of the CUDA array
 *          (in elements); the CUDA array is one-dimensional if height is 0,
 *          two-dimensional otherwise;
 *        - Format speci?es the format of the elements; CUarray_format is
 *          defined as:
 *
 *        typedef enum CUarray_format_enum {
 *            CU_AD_FORMAT_UNSIGNED_INT8 = 0x01,
 *            CU_AD_FORMAT_UNSIGNED_INT16 = 0x02,
 *            CU_AD_FORMAT_UNSIGNED_INT32 = 0x03,
 *            CU_AD_FORMAT_SIGNED_INT8 = 0x08,
 *            CU_AD_FORMAT_SIGNED_INT16 = 0x09,
 *            CU_AD_FORMAT_SIGNED_INT32 = 0x0a,
 *            CU_AD_FORMAT_HALF = 0x10,
 *            CU_AD_FORMAT_FLOAT = 0x20
 *        } CUarray_format;
 *
 *        - NumChannels specifies the number of packed components per CUDA
 *          array element; it may be 1, 2, or 4;
 *
 *        Here are examples of CUDA array descriptions:
 *
 *        Description for a CUDA array of 2048 floats:
 *
 *        CUDA_ARRAY_DESCRIPTOR desc;
 *        desc.Format = CU_AD_FORMAT_FLOAT;
 *        desc.NumChannels = 1;
 *        desc.Width = 2048;
 *        desc.Height = 1;
 *
 *        Description for a 64 x 64 CUDA array of floats:
 *
 *        CUDA_ARRAY_DESCRIPTOR desc;
 *        desc.Format = CU_AD_FORMAT_FLOAT;
 *        desc.NumChannels = 1;
 *        desc.Width = 64;
 *        desc.Height = 64;
 *
 *        Description for a width x height CUDA array of 64-bit, 4x16-bit
 *        float16's:
 *
 *        CUDA_ARRAY_DESCRIPTOR desc;
 *        desc.FormatFlags = CU_AD_FORMAT_HALF;
 *        desc.NumChannels = 4;
 *        desc.Width = width;
 *        desc.Height = height;
 *
 *        Description for a width x height CUDA array of 16-bit elements, each
 *        of which is two 8-bit unsigned chars:
 *
 *        CUDA_ARRAY_DESCRIPTOR arrayDesc;
 *        desc.FormatFlags = CU_AD_FORMAT_UNSIGNED_INT8;
 *        desc.NumChannels = 2;
 *        desc.Width = width;
 *        desc.Height = height;
 *
 * \param p_handle         Returned array.
 * \param p_allocate_array Array descriptor.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaArrayCreate(CUarray *p_handle,
                      const CUDA_ARRAY_DESCRIPTOR *p_allocate_array)
{
    CUresult result = 0;

    if (p_handle == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_handle is NULL");
        goto error;
    }

    result = cuArrayCreate(p_handle, p_allocate_array);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_ARRAY_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}


/**
 * \brief Destroys the CUDA array h_array.
 *
 * \param h_array Array to destroy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaArrayDestroy(CUarray h_array)
{
    int result = cuArrayDestroy(h_array);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_ARRAY_DESTROY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *p_array_descriptor a descriptor containing information on
 *        the format and dimensions of the CUDA array h_array. It is useful for
 *        subroutines that have been passed a CUDA array, but need to know the
 *        CUDA array parameters for validation or other purposes.
 *
 * \param p_array_descriptor Returned array descriptor.
 * \param h_array            Array to get descriptor of.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaArrayGetDescriptor(CUDA_ARRAY_DESCRIPTOR *p_array_descriptor,
                             CUarray h_array)
{
    CUresult result = 0;

    if (p_array_descriptor == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_array_descriptor is NULL");
        goto error;
    }

    result = cuArrayGetDescriptor(p_array_descriptor, h_array);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_ARRAY_GET_DESCRIPTOR) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaDeviceGetByPCIBusId(CUdevice *dev, char *pci_bus_id)
{
    CUresult result = 0;

    result = cuDeviceGetByPCIBusId(dev, pci_bus_id);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_BY_PCI_BUS_ID) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaDeviceGetPCIBusId(char *pci_bus_id, int len, CUdevice dev)
{
    CUresult result = 0;

    result = cuDeviceGetPCIBusId(pci_bus_id, len, dev);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_DEVICE_GET_PCI_BUS_ID) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaIpcCloseMemHandle(CUdeviceptr dptr)
{
    CUresult result = 0;

    result = cuIpcCloseMemHandle(dptr);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_IPC_CLOSE_MEM_HANDLE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaIpcGetEventHandle(CUipcEventHandle *p_handle, CUevent event)
{
    CUresult result = 0;

    result = cuIpcGetEventHandle(p_handle, event);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_IPC_GET_MEM_HANDLE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaIpcGetMemHandle(CUipcMemHandle *p_handle, CUdeviceptr dptr)
{
    CUresult result = 0;

    result = cuIpcGetMemHandle(p_handle, dptr);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_IPC_GET_MEM_HANDLE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaIpcOpenEventHandle(CUevent *ph_event, CUipcEventHandle handle)
{
    CUresult result = 0;

    result = cuIpcOpenEventHandle(ph_event, handle);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_IPC_GET_MEM_HANDLE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaIpcOpenMemHandle(CUdeviceptr *pdptr, CUipcMemHandle handle,
                           unsigned int flags)
{
    CUresult result = 0;

    result = cuIpcOpenMemHandle(pdptr, handle, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_IPC_OPEN_EVENT_HANDLE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Returns in *p_array_descriptor a descriptor containing information on
 *        the format and dimensions of the CUDA array h_array. It is useful for
 *        subroutines that have been passed a CUDA array, but need to know the
 *        CUDA array parameters for validation or other purposes.
 *
 * \param p_array_descriptor Returned array descriptor.
 * \param h_array            Array to get descriptor of.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemAlloc(CUdeviceptr *dptr, size_t byte_size)
{
    CUresult result = 0;

    if (dptr == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "dptr is NULL");
        goto error;
    }

    result = cuMemAlloc(dptr, byte_size);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_ALLOC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Allocates bytesize bytes of host memory that is page-locked and
 *        accessible to the device. The driver tracks the vir-tual memory
 *        ranges allocated with this function and automatically accelerates
 *        calls to functions such as cuMemcpy(). Since the memory can be
 *        accessed directly by the device, it can be read or written with
 *        much higher bandwidth than pageable memory obtained with functions
 *        such as SCMalloc(). Allocating excessive amounts of memory with
 *        cuMemAllocHost() may degrade system performance, since it reduces
 *        the amount of memory available to the system for paging. As a result,
 *        this function is best used sparingly to allocate staging areas for
 *        data exchange between host and device.
 *
 * \param pp        Returned host pointer to page-locked memory.
 * \param byte_size Requested allocation size in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemAllocHost(void **pp, size_t byte_size)
{
    CUresult result = 0;

    if (pp == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pp is NULL");
        goto error;
    }

    result = cuMemAllocHost(pp, byte_size);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_ALLOC_HOST) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Allocates at least width_in_bytes * height bytes of linear memory on the
 *        device and returns in *dptr a pointer to the allocated memory. The
 *        function may pad the allocation to ensure that corresponding pointers in
 *        any given row will continue to meet the alignment requirements for
 *        coalescing as the address is updated from row to row. ElementSizeBytes
 *        specifies the size of the largest reads and writes that will be
 *        performed on the memory range.
 *
 *        element_size_bytes may be 4, 8 or 16 (since coalesced memory
 *        transactions are not possible on other data sizes). If element_size_bytes
 *        is smaller than the actual read/write size of a kernel, the kernel will
 *        run correctly, but possibly at reduced speed. The pitch returned in
 *        *p_itch by cuMemAllocPitch() is the width in bytes of the allocation.
 *        The intended usage of pitch is as a separate parameter of the allocation,
 *        used to compute addresses within the 2D array. Given the row and column
 *        of an array element of type T, the address is computed as:
 *
 *        T * p_element = (T*)((char*)base_address + row * pitch) + column;
 *
 *        The pitch returned by cuMemAllocPitch() is guaranteed to work with
 *        cuMemcpy2D() under all circumstances. For allocations of 2D arrays, it
 *        is recommended that programmers consider performing pitch allocations
 *        using cuMemAllocPitch(). Due to alignment restrictions in the hardware,
 *        this is especially true if the application will be performing 2D memory
 *        copies between different regions of device memory (whether linear memory
 *        or CUDA arrays).
 *
 * \param dptr Returned device pointer.
 * \param p_pitch Returned pitch of allocation in bytes.
 * \param width_in_bytes Requested allocation width in bytes.
 * \param height Requested allocation width in rows.
 * \param element_size_bytes Size of largest reads/writes for range.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemAllocPitch(CUdeviceptr *dptr, size_t *p_pitch,
                        size_t width_in_bytes,
                        size_t height,
                        unsigned int element_size_bytes)
{
    CUresult result = 0;

    if (dptr == NULL || p_pitch == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "dptr is NULL or p_pitch is NULL");
        goto error;
    }

    result = cuMemAllocPitch(dptr, p_pitch, width_in_bytes, height,
                             element_size_bytes);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_ALLOC_PITCH) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemcpy(CUdeviceptr dst, CUdeviceptr src, size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpy(dst, src, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY) == -1)
        goto error;

    return 0;
 error:
    return -1;
}


/**
 * \brief Perform a 2D memory copy according to the parameters specified in
 *        p_copy. The CUDA_MEMCPY2D structure is defined as:
 *
 *        typedef struct CUDA_MEMCPY2D_st {
 *            unsigned int srcXInBytes, srcY;
 *            CUmemorytype srcMemoryType;
 *            const void *srcHost;
 *            CUdeviceptr srcDevice;
 *            CUarray srcArray;
 *            unsigned int srcPitch;
 *            unsigned int dstXInBytes, dstY;
 *            CUmemorytype dstMemoryType;
 *            void *dstHost;
 *            CUdeviceptr dstDevice;
 *            CUarray dstArray;
 *            unsigned int dstPitch;
 *            unsigned int WidthInBytes;
 *            unsigned int Height;
 *        } CUDA_MEMCPY2D;
 *
 *        where:
 *
 *        - srcMemoryType and dstMemoryType specify the type of memory of the
 *          source and destination, respectively;
 *
 *          CUmemorytype_enum is de?ned as:
 *
 *          typedef enum CUmemorytype_enum {
 *              CU_MEMORYTYPE_HOST = 0x01,
 *              CU_MEMORYTYPE_DEVICE = 0x02,
 *              CU_MEMORYTYPE_ARRAY = 0x03
 *          } CUmemorytype;
 *
 *        If srcMemoryType is CU_MEMORYTYPE_HOST, srcHost and srcPitch specify
 *        the (host) base address of the source data and the bytes per row to
 *        apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_DEVICE, srcDevice and srcPitch
 *        specify the (device) base address of the source data and the bytes per
 *        row to apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_ARRAY, srcArray speci?es the handle
 *        of the source data. srcHost, srcDevice and srcPitch are ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_HOST, dstHost and dstPitch specify
 *        the (host) base address of the destination data and the bytes per row
 *        to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_DEVICE, dstDevice and dstPitch
 *        specify the (device) base address of the destination data and the
 *        bytes per row to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_ARRAY, dstArray specifies the handle
 *        of the destination data dstHost, dstDevice and dstPitch are ignored.
 *
 *        - srcXInBytes and srcY specify the base address of the source data for
 *          the copy.
 *
 *        For host pointers, the starting address is
 *
 *            void* Start = (void*)((char*)srcHost+srcY*srcPitch + srcXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr Start = srcDevice+srcY*srcPitch+srcXInBytes;
 *
 *        For CUDA arrays, srcXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - dstXInBytes and dstY specify the base address of the destination data
 *          for the copy.
 *
 *        For host pointers, the base address is
 *
 *            void* dstStart = (void*)((char*)dstHost+dstY*dstPitch + dstXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr dstStart = dstDevice+dstY*dstPitch+dstXInBytes;
 *
 *        For CUDA arrays, dstXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - WidthInBytes and Height specify the width (in bytes) and height of
 *          the 2D copy being performed. Any pitches must be greater than or
 *          equal to WidthInBytes.
 *
 *        cuMemcpy2D() returns an error if any pitch is greater than the
 *        maximum allowed (CU_DEVICE_ATTRIBUTE_MAX_PITCH). cuMemAllocPitch()
 *        passes back pitches that always work with cuMemcpy2D(). On intra-device
 *        memory copies (device ? device, CUDA array ? device, CUDA array ?
 *        CUDA array), cuMemcpy2D() may fail for pitches not computed by
 *        cuMemAllocPitch(). cuMemcpy2DUnaligned() does not have this restriction,
 *        but may run signi?cantly slower in the cases where cuMemcpy2D() would
 *        have returned an error code.
 *
 * \param p_copy Parameters for the memory copy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpy2D(const CUDA_MEMCPY2D *p_copy)
{
    CUresult result = 0;

    if (p_copy == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_copy is NULL");
        goto error;
    }

    result = cuMemcpy2D(p_copy);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_2D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Perform a 2D memory copy according to the parameters specified in
 *        p_copy. The CUDA_MEMCPY2D structure is defined as:
 *
 *        typedef struct CUDA_MEMCPY2D_st {
 *            unsigned int srcXInBytes, srcY;
 *            CUmemorytype srcMemoryType;
 *            const void *srcHost;
 *            CUdeviceptr srcDevice;
 *            CUarray srcArray;
 *            unsigned int srcPitch;
 *            unsigned int dstXInBytes, dstY;
 *            CUmemorytype dstMemoryType;
 *            void *dstHost;
 *            CUdeviceptr dstDevice;
 *            CUarray dstArray;
 *            unsigned int dstPitch;
 *            unsigned int WidthInBytes;
 *            unsigned int Height;
 *        } CUDA_MEMCPY2D;
 *
 *        where:
 *
 *        - srcMemoryType and dstMemoryType specify the type of memory of the
 *          source and destination, respectively;
 *
 *          CUmemorytype_enum is de?ned as:
 *
 *          typedef enum CUmemorytype_enum {
 *              CU_MEMORYTYPE_HOST = 0x01,
 *              CU_MEMORYTYPE_DEVICE = 0x02,
 *              CU_MEMORYTYPE_ARRAY = 0x03
 *          } CUmemorytype;
 *
 *        If srcMemoryType is CU_MEMORYTYPE_HOST, srcHost and srcPitch specify
 *        the (host) base address of the source data and the bytes per row to
 *        apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_DEVICE, srcDevice and srcPitch
 *        specify the (device) base address of the source data and the bytes per
 *        row to apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_ARRAY, srcArray speci?es the handle
 *        of the source data. srcHost, srcDevice and srcPitch are ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_HOST, dstHost and dstPitch specify
 *        the (host) base address of the destination data and the bytes per row
 *        to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_DEVICE, dstDevice and dstPitch
 *        specify the (device) base address of the destination data and the
 *        bytes per row to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_ARRAY, dstArray specifies the handle
 *        of the destination data dstHost, dstDevice and dstPitch are ignored.
 *
 *        - srcXInBytes and srcY specify the base address of the source data for
 *          the copy.
 *
 *        For host pointers, the starting address is
 *
 *            void* Start = (void*)((char*)srcHost+srcY*srcPitch + srcXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr Start = srcDevice+srcY*srcPitch+srcXInBytes;
 *
 *        For CUDA arrays, srcXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - dstXInBytes and dstY specify the base address of the destination data
 *          for the copy.
 *
 *        For host pointers, the base address is
 *
 *            void* dstStart = (void*)((char*)dstHost+dstY*dstPitch + dstXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr dstStart = dstDevice+dstY*dstPitch+dstXInBytes;
 *
 *        For CUDA arrays, dstXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - WidthInBytes and Height specify the width (in bytes) and height of
 *          the 2D copy being performed. Any pitches must be greater than or
 *          equal to WidthInBytes.
 *
 *        cuMemcpy2D() returns an error if any pitch is greater than the
 *        maximum allowed (CU_DEVICE_ATTRIBUTE_MAX_PITCH). cuMemAllocPitch()
 *        passes back pitches that always work with cuMemcpy2D(). On intra-device
 *        memory copies (device ? device, CUDA array ? device, CUDA array ?
 *        CUDA array), cuMemcpy2D() may fail for pitches not computed by
 *        cuMemAllocPitch(). cuMemcpy2DUnaligned() does not have this restriction,
 *        but may run signi?cantly slower in the cases where cuMemcpy2D() would
 *        have returned an error code.
 *
 *        cuMemcpy2DAsync() is asynchronous and can optionally be associated to a
 *        stream by passing a non-zero hStream argument. It only works on
 *        page-locked host memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 * \param p_copy   Parameters for the memory copy.
 * \param h_stream Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpy2DAsync(const CUDA_MEMCPY2D *p_copy, CUstream h_stream)
{
    CUresult result = 0;

    if (p_copy == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_copy is NULL");
        goto error;
    }

    result = cuMemcpy2DAsync(p_copy, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_2D_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Perform a 2D memory copy according to the parameters specified in
 *        p_copy. The CUDA_MEMCPY2D structure is defined as:
 *
 *        typedef struct CUDA_MEMCPY2D_st {
 *            unsigned int srcXInBytes, srcY;
 *            CUmemorytype srcMemoryType;
 *            const void *srcHost;
 *            CUdeviceptr srcDevice;
 *            CUarray srcArray;
 *            unsigned int srcPitch;
 *            unsigned int dstXInBytes, dstY;
 *            CUmemorytype dstMemoryType;
 *            void *dstHost;
 *            CUdeviceptr dstDevice;
 *            CUarray dstArray;
 *            unsigned int dstPitch;
 *            unsigned int WidthInBytes;
 *            unsigned int Height;
 *        } CUDA_MEMCPY2D;
 *
 *        where:
 *
 *        - srcMemoryType and dstMemoryType specify the type of memory of the
 *          source and destination, respectively;
 *
 *          CUmemorytype_enum is de?ned as:
 *
 *          typedef enum CUmemorytype_enum {
 *              CU_MEMORYTYPE_HOST = 0x01,
 *              CU_MEMORYTYPE_DEVICE = 0x02,
 *              CU_MEMORYTYPE_ARRAY = 0x03
 *          } CUmemorytype;
 *
 *        If srcMemoryType is CU_MEMORYTYPE_HOST, srcHost and srcPitch specify
 *        the (host) base address of the source data and the bytes per row to
 *        apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_DEVICE, srcDevice and srcPitch
 *        specify the (device) base address of the source data and the bytes per
 *        row to apply. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_ARRAY, srcArray speci?es the handle
 *        of the source data. srcHost, srcDevice and srcPitch are ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_HOST, dstHost and dstPitch specify
 *        the (host) base address of the destination data and the bytes per row
 *        to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_DEVICE, dstDevice and dstPitch
 *        specify the (device) base address of the destination data and the
 *        bytes per row to apply. dstArray is ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_ARRAY, dstArray specifies the handle
 *        of the destination data dstHost, dstDevice and dstPitch are ignored.
 *
 *        - srcXInBytes and srcY specify the base address of the source data for
 *          the copy.
 *
 *        For host pointers, the starting address is
 *
 *            void* Start = (void*)((char*)srcHost+srcY*srcPitch + srcXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr Start = srcDevice+srcY*srcPitch+srcXInBytes;
 *
 *        For CUDA arrays, srcXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - dstXInBytes and dstY specify the base address of the destination data
 *          for the copy.
 *
 *        For host pointers, the base address is
 *
 *            void* dstStart = (void*)((char*)dstHost+dstY*dstPitch + dstXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *            CUdeviceptr dstStart = dstDevice+dstY*dstPitch+dstXInBytes;
 *
 *        For CUDA arrays, dstXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - WidthInBytes and Height specify the width (in bytes) and height of
 *          the 2D copy being performed. Any pitches must be greater than or
 *          equal to WidthInBytes.
 *
 *        cuMemcpy2D() returns an error if any pitch is greater than the
 *        maximum allowed (CU_DEVICE_ATTRIBUTE_MAX_PITCH). cuMemAllocPitch()
 *        passes back pitches that always work with cuMemcpy2D(). On intra-device
 *        memory copies (device ? device, CUDA array ? device, CUDA array ?
 *        CUDA array), cuMemcpy2D() may fail for pitches not computed by
 *        cuMemAllocPitch(). cuMemcpy2DUnaligned() does not have this restriction,
 *        but may run signi?cantly slower in the cases where cuMemcpy2D() would
 *        have returned an error code.
 *
 *        cuMemcpy2DAsync() is asynchronous and can optionally be associated to a
 *        stream by passing a non-zero hStream argument. It only works on
 *        page-locked host memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 * \param p_copy   Parameters for the memory copy.
 * \param h_stream Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpy2DUnaligned(const CUDA_MEMCPY2D *p_copy)
{
    CUresult result = 0;

    if (p_copy == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_copy is NULL");
        goto error;
    }

    result = cuMemcpy2DUnaligned(p_copy);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_2D_UNALIGNED) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Perform a 3D memory copy according to the parameters specified in
 *        p_copy. The CUDA_MEMCPY3D structure is defined as:
 *
 *        typedef struct CUDA_MEMCPY3D_st {
 *            unsigned int srcXInBytes, srcY, srcZ;
 *            unsigned int srcLOD;
 *            CUmemorytype srcMemoryType;
 *            const void *srcHost;
 *            CUdeviceptr srcDevice;
 *            CUarray srcArray;
 *            unsigned int srcPitch; // ignored when src is array
 *            unsigned int srcHeight; // ignored when src is array; may be 0 if Depth==1
 *            unsigned int dstXInBytes, dstY, dstZ;
 *            unsigned int dstLOD;
 *            CUmemorytype dstMemoryType;
 *            void *dstHost;
 *            CUdeviceptr dstDevice;
 *            CUarray dstArray;
 *            unsigned int dstPitch; // ignored when dst is array
 *            unsigned int dstHeight; // ignored when dst is array; may be 0 if Depth==1
 *            unsigned int WidthInBytes;
 *            unsigned int Height;
 *            unsigned int Depth;
 *        } CUDA_MEMCPY3D;
 *
 *        where:
 *
 *        - srcMemoryType and dstMemoryType specify the type of memory of the
 *          source and destination, respectively;
 *        CUmemorytype_enum is defined as:
 *
 *        typedef enum CUmemorytype_enum {
 *            CU_MEMORYTYPE_HOST = 0x01,
 *            CU_MEMORYTYPE_DEVICE = 0x02,
 *            CU_MEMORYTYPE_ARRAY = 0x03
 *        } CUmemorytype;
 *
 *        If srcMemoryType is CU_MEMORYTYPE_HOST, srcHost, srcPitch and srcHeight
 *        specify the (host) base address of the source data, the bytes per row,
 *        and the height of each 2D slice of the 3D array. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_DEVICE, srcDevice, srcPitch and
 *        srcHeight specify the (device) base address of the source data, the
 *        bytes per row, and the height of each 2D slice of the 3D array.
 *        srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_ARRAY, srcArray specifies the handle
 *        of the source data. srcHost, srcDevice, srcPitch and srcHeight are
 *        ignored. If dstMemoryType is CU_MEMORYTYPE_HOST, dstHost and dstPitch
 *        specify the (host) base address of the destination data, the bytes per
 *        row, and the height of each 2D slice of the 3D array. dstArray is
 *        ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_DEVICE, dstDevice and dstPitch
 *        specify the (device) base address of the destination data, the bytes
 *        per row, and the height of each 2D slice of the 3D array. dstArray is
 *        ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_ARRAY, dstArray specifies the
 *        handle of the destination data. dstHost, dstDevice, dstPitch and
 *        dstHeight are ignored.
 *
 *        - srcXInBytes, srcY and srcZ specify the base address of the source
 *          data for the copy.
 *
 *        For host pointers, the starting address is
 *
 *        void* Start = (void*)((char*)srcHost+(srcZ*srcHeight+srcY)*srcPitch + srcXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *        CUdeviceptr Start = srcDevice+(srcZ*srcHeight+srcY)*srcPitch+srcXInBytes;
 *
 *        For CUDA arrays, srcXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - dstXInBytes, dstY and dstZ specify the base address of the destination
 *          data for the copy.
 *
 *        For host pointers, the base address is
 *
 *        void* dstStart = (void*)((char*)dstHost+(dstZ*dstHeight+dstY)*dstPitch + dstXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *        CUdeviceptr dstStart = dstDevice+(dstZ*dstHeight+dstY)*dstPitch+dstXInBytes;
 *
 *        For CUDA arrays, dstXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - WidthInBytes, Height and Depth specify the width (in bytes), height
 *          and depth of the 3D copy being performed. Any pitches must be greater
 *          than or equal to WidthInBytes.
 *
 *        cuMemcpy3D() returns an error if any pitch is greater than the maximum
 *        allowed (CU_DEVICE_ATTRIBUTE_MAX_PITCH).
 *
 *        The srcLOD and dstLOD members of the CUDA_MEMCPY3D structure must be
 *        set to 0.
 *
 * \param p_copy Parameters for the memory copy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpy3D(const CUDA_MEMCPY3D *p_copy)
{
    CUresult result = 0;

    if (p_copy == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_copy is NULL");
        goto error;
    }

    result = cuMemcpy3D(p_copy);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_3D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Perform a 3D memory copy according to the parameters specified in
 *        p_copy. The CUDA_MEMCPY3D structure is defined as:
 *
 *        typedef struct CUDA_MEMCPY3D_st {
 *            unsigned int srcXInBytes, srcY, srcZ;
 *            unsigned int srcLOD;
 *            CUmemorytype srcMemoryType;
 *            const void *srcHost;
 *            CUdeviceptr srcDevice;
 *            CUarray srcArray;
 *            unsigned int srcPitch; // ignored when src is array
 *            unsigned int srcHeight; // ignored when src is array; may be 0 if Depth==1
 *            unsigned int dstXInBytes, dstY, dstZ;
 *            unsigned int dstLOD;
 *            CUmemorytype dstMemoryType;
 *            void *dstHost;
 *            CUdeviceptr dstDevice;
 *            CUarray dstArray;
 *            unsigned int dstPitch; // ignored when dst is array
 *            unsigned int dstHeight; // ignored when dst is array; may be 0 if Depth==1
 *            unsigned int WidthInBytes;
 *            unsigned int Height;
 *            unsigned int Depth;
 *        } CUDA_MEMCPY3D;
 *
 *        where:
 *
 *        - srcMemoryType and dstMemoryType specify the type of memory of the
 *          source and destination, respectively;
 *        CUmemorytype_enum is defined as:
 *
 *        typedef enum CUmemorytype_enum {
 *            CU_MEMORYTYPE_HOST = 0x01,
 *            CU_MEMORYTYPE_DEVICE = 0x02,
 *            CU_MEMORYTYPE_ARRAY = 0x03
 *        } CUmemorytype;
 *
 *        If srcMemoryType is CU_MEMORYTYPE_HOST, srcHost, srcPitch and srcHeight
 *        specify the (host) base address of the source data, the bytes per row,
 *        and the height of each 2D slice of the 3D array. srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_DEVICE, srcDevice, srcPitch and
 *        srcHeight specify the (device) base address of the source data, the
 *        bytes per row, and the height of each 2D slice of the 3D array.
 *        srcArray is ignored.
 *
 *        If srcMemoryType is CU_MEMORYTYPE_ARRAY, srcArray specifies the handle
 *        of the source data. srcHost, srcDevice, srcPitch and srcHeight are
 *        ignored. If dstMemoryType is CU_MEMORYTYPE_HOST, dstHost and dstPitch
 *        specify the (host) base address of the destination data, the bytes per
 *        row, and the height of each 2D slice of the 3D array. dstArray is
 *        ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_DEVICE, dstDevice and dstPitch
 *        specify the (device) base address of the destination data, the bytes
 *        per row, and the height of each 2D slice of the 3D array. dstArray is
 *        ignored.
 *
 *        If dstMemoryType is CU_MEMORYTYPE_ARRAY, dstArray specifies the
 *        handle of the destination data. dstHost, dstDevice, dstPitch and
 *        dstHeight are ignored.
 *
 *        - srcXInBytes, srcY and srcZ specify the base address of the source
 *          data for the copy.
 *
 *        For host pointers, the starting address is
 *
 *        void* Start = (void*)((char*)srcHost+(srcZ*srcHeight+srcY)*srcPitch + srcXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *        CUdeviceptr Start = srcDevice+(srcZ*srcHeight+srcY)*srcPitch+srcXInBytes;
 *
 *        For CUDA arrays, srcXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - dstXInBytes, dstY and dstZ specify the base address of the destination
 *          data for the copy.
 *
 *        For host pointers, the base address is
 *
 *        void* dstStart = (void*)((char*)dstHost+(dstZ*dstHeight+dstY)*dstPitch + dstXInBytes);
 *
 *        For device pointers, the starting address is
 *
 *        CUdeviceptr dstStart = dstDevice+(dstZ*dstHeight+dstY)*dstPitch+dstXInBytes;
 *
 *        For CUDA arrays, dstXInBytes must be evenly divisible by the array
 *        element size.
 *
 *        - WidthInBytes, Height and Depth specify the width (in bytes), height
 *          and depth of the 3D copy being performed. Any pitches must be greater
 *          than or equal to WidthInBytes.
 *
 *        cuMemcpy3D() returns an error if any pitch is greater than the maximum
 *        allowed (CU_DEVICE_ATTRIBUTE_MAX_PITCH).
 *
 *        cuMemcpy3DAsync() is asynchronous and can optionally be associated
 *        to a stream by passing a non-zero hStream argument. It only works on
 *        page-locked host memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 *        The srcLOD and dstLOD members of the CUDA_MEMCPY3D structure must be
 *        set to 0.
 *
 * \param p_copy Parameters for the memory copy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpy3DAsync(const CUDA_MEMCPY3D *p_copy, CUstream h_stream)
{
    CUresult result = 0;

    if (p_copy == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_copy is NULL");
        goto error;
    }

    result = cuMemcpy3DAsync(p_copy, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_3D_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemcpy3DPeer(const CUDA_MEMCPY3D_PEER *p_copy)
{
    CUresult result = 0;

    result = cuMemcpy3DPeer(p_copy);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_3D_PEER) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaMemcpy3DPeerAsync(const CUDA_MEMCPY3D_PEER *p_copy,
                            CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpy3DPeerAsync(p_copy, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_3D_PEER_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaMemcpyAsync(CUdeviceptr dst, CUdeviceptr src, size_t byte_count,
                      CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyAsync(dst, src, byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Copies from one 1D CUDA array to another. dstArray and srcArray
 *        specify the handles of the destination and source CUDA arrays for the
 *        copy, respectively. dstIndex and srcIndex specify the destination and
 *        source indices into the CUDA array. These values are in the range
 *        [0, Width-1] for the CUDA array; they are not byte offsets. ByteCount
 *        is the number of bytes to be copied. The size of the elements in the
 *        CUDA arrays need not be the same format, but the elements must be the
 *        same size; and count must be evenly divisible by that size.
 *
 * \param dst_array  Destination array.
 * \param dst_index  Offset of destination array.
 * \param src_array  Source array.
 * \param src_index  Offset of source array.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyAtoA(CUarray dst_array, size_t dst_offset,
                     CUarray src_array, size_t src_offset,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyAtoA(dst_array, dst_offset, src_array, src_offset,
                          byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_A_TO_A) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \param Copies from one 1D CUDA array to device memory. dstDevice specifies the
 *        base pointer of the destination and must be naturally aligned with the
 *        CUDA array elements. hSrc and SrcIndex specify the CUDA array handle and
 *        the index (in array elements) of the array element where the copy is
 *        to begin. ByteCount speci?es the number of bytes to copy and must be
 *        evenly divisible by the array element size.
 *
 * \param dst_device Destination device pointer.
 * \param h_src      Source array.
 * \param src_index  Offset of source array.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyAtoD(CUdeviceptr dst_device, CUarray src_array,
                     size_t src_offset, size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyAtoD(dst_device, src_array, src_offset, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_A_TO_D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \param Copies from one 1D CUDA array to host memory. dstHost specifies the
 *        base pointer of the destination. srcArray and srcIndex specify the
 *        CUDA array handle and starting index of the source data. ByteCount
 *        specifies the number of bytes to copy.
 *
 * \param dst_device Destination device pointer.
 * \param h_src      Source array.
 * \param src_index  Offset of source array.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyAtoH(void *dst_host, CUarray src_array, size_t src_offset,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyAtoH(dst_host, src_array, src_offset, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_A_TO_H) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \param Copies from one 1D CUDA array to host memory. dstHost specifies the
 *        base pointer of the destination. srcArray and srcIndex specify the
 *        CUDA array handle and starting index of the source data. ByteCount
 *        specifies the number of bytes to copy.
 *
 *        cuMemcpyAtoHAsync() is asynchronous and can optionally be associated
 *        to a stream by passing a non-zero stream argument. It only works on
 *        page-locked host memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 * \param dst_device Destination device pointer.
 * \param src_array  Source array.
 * \param src_index  Offset of source array.
 * \param byte_count Size of memory copy in bytes.
 * \param h_stream   Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyAtoHAsync(void *dst_host, CUarray src_array,
                          size_t src_offset, size_t byte_count,
                          CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyAtoHAsync(dst_host, src_array, src_offset, byte_count,
                               h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_A_TO_H_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from device memory to a 1D CUDA array. dstArray and dstIndex
 *        specify the CUDA array handle and starting index of the destination
 *        data. srcDevice speci?es the base pointer of the source. ByteCount
 *        specifies the number of bytes to copy.
 *
 * \param dst_array  Destination array.
 * \param dst_index  Offset of destination array.
 * \param src_device Source device pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyDtoA(CUarray dst_array, size_t dst_offset,
                     CUdeviceptr src_device, size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyDtoA(dst_array, dst_offset, src_device, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_D_TO_A) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from device memory to device memory. dstDevice and srcDevice are
 *        the base pointers of the destination and source, respectively.
 *        byte_count specifies the number of bytes to copy. Note that this
 *        function is asynchronous.
 *
 * \param dst_device Destination device pointer.
 * \param src_device Source device pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyDtoD(CUdeviceptr dst_device, CUdeviceptr src_device,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyDtoD(dst_device, src_device, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_D_TO_D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemcpyDtoDAsync(CUdeviceptr dst_device, CUdeviceptr src_device,
                          size_t byte_count, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyDtoDAsync(dst_device, src_device, byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_D_TO_D_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}


/**
 * \brief Copies from device to host memory. dst_host and src_device specify
 *        the base pointers of the destination and source, respectively.
 *        byte_count specifies the number of bytes to copy. Note that this
 *        function is synchronous.
 *
 * \param dst_host   Destination device pointer.
 * \param src_device Source device pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyDtoH(void *dst_host, CUdeviceptr src_device,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyDtoH(dst_host, src_device, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_D_TO_H) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from device to host memory. dst_host and src_device specify
 *        the base pointers of the destination and source, respectively.
 *        byte_count specifies the number of bytes to copy.
 *
 *        cuMemcpyDtoHAsync() is asynchronous and can optionally be associated
 *        to a stream by passing a non-zero h_stream argument. It only works
 *        on page-locked memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 * \param dst_host   Destination device pointer.
 * \param src_device Source device pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyDtoHAsync(void *dst_host, CUdeviceptr src_device,
                          size_t byte_count, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyDtoHAsync(dst_host, src_device, byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_D_TO_H_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from host memory to a 1D CUDA array. dst_array and dst_index
 *        specify the CUDA array handle and starting index of the destination
 *        data. p_src specifies the base address of the source. byte_count
 *        specifies the number of bytes to copy.
 *
 * \param dst_array  Destination array.
 * \param dst_index  Offset of destination array.
 * \param p_src      Source host pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyHtoA(CUarray dst_array, size_t dst_offset,
                     const void *src_host, size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyHtoA(dst_array, dst_offset, src_host, byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_H_TO_A) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from host memory to a 1D CUDA array. dst_array and dst_index
 *        specify the CUDA array handle and starting index of the destination
 *        data. p_src specifies the base address of the source. byte_count
 *        specfies the number of bytes to copy.
 *
 *        cuMemcpyHtoAAsync() is asynchronous and can optionally be associated
 *        to a stream by passing a non-zero h_stream argument. It only works on
 *        page-locked memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 * \param dst_array  Destination array.
 * \param dst_index  Offset of destination array.
 * \param p_src      Source host pointer.
 * \param byte_count Size of memory copy in bytes.
 * \param h_stream   Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyHtoAAsync(CUarray dst_array, size_t dst_offset,
                          const void *src_host, size_t byte_count,
                          CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyHtoAAsync(dst_array, dst_offset, src_host, byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_H_TO_A_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from host memory to device memory. dst_device and src_host
 *        are the base addresses of the destination and source, respectively.
 *        byte_count specifies the number of bytes to copy. Note that this
 *        function is synchronous.
 *
 * \param dst_device Destination device pointer.
 * \param src_host   Source host pointer.
 * \param byte_count Size of memory copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyHtoD(CUdeviceptr dst_device, const void *src_host,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyHtoD(dst_device, src_host,byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_H_TO_D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies from host memory to device memory. dst_device and src_host are
 *        the base addresses of the destination and source, respectively.
 *        byte_count specifies the number of bytes to copy.
 *
 *        cuMemcpyHtoDAsync() is asynchronous and can optionally be associated
 *        to a stream by passing a non-zero h_stream argument. It only works on
 *        page-locked memory and returns an error if a pointer to pageable
 *        memory is passed as input.
 *
 *
 * \param dst_device Destination device pointer.
 * \param src_host   Source host pointer.
 * \param byte_count Size of memory copy in bytes.
 * \param h_stream   Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemcpyHtoDAsync(CUdeviceptr dst_device, const void *src_host,
                          size_t byte_count, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyHtoDAsync(dst_device, src_host, byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_H_TO_D_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemcpyPeer(CUdeviceptr dst_device, CUcontext dst_context,
                     CUdeviceptr src_device, CUcontext src_context,
                     size_t byte_count)
{
    CUresult result = 0;

    result = cuMemcpyPeer(dst_device, dst_context, src_device, src_context,
                          byte_count);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_PEER) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaMemcpyPeerAsync(CUdeviceptr dst_device, CUcontext dst_context,
                          CUdeviceptr src_device, CUcontext src_context,
                          size_t byte_count, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemcpyPeerAsync(dst_device, dst_context, src_device, src_context,
                               byte_count, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMCPY_PEER_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Frees the memory space pointed to by dptr, which must have been
 *        returned by a previous call to cuMemAlloc() or cuMemAllocPitch().
 *
 * \param dptr Pointer to the memory to free.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemFree(CUdeviceptr dptr)
{
    CUresult result = 0;

    result = cuMemFree(dptr);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_FREE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Frees the memory space pointed to by p, which must have been returned
 *        by a previous call to cuMemAllocHost().
 *
 * \param p Pointer to the memory to free.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemFreeHost(void *p)
{
    CUresult result = 0;

    if (p == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p is NULL");
        goto error;
    }

    result = cuMemFreeHost(p);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_FREE_HOST) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns the base address in *pbase and size in *psize of the allocation
 *        by cuMemAlloc() or cuMemAllocPitch() that contains the input pointer
 *        dptr. Both parameters pbase and psize are optional. If one of them is
 *        NULL, it is ignored.
 *
 * \param pbase Returned base address.
 * \param psize Returned size of device memory allocation.
 * \param dptr  Device pointer to query
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemGetAddressRange(CUdeviceptr *pbase, size_t *psize,
                             CUdeviceptr dptr)
{
    CUresult result = 0;

    result = cuMemGetAddressRange(pbase, psize, dptr);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_GET_ADDRESS_RANGE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *free and *total respectively, the free and total amount
 *        of memory available for allocation by the CUDA context, in bytes.
 *
 * \param free  Returned free memory in bytes.
 * \param total Returned total memory in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemGetInfo(size_t *free, size_t *total)
{
    CUresult result = 0;

    if (free == NULL || total == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "free is NULL || total is NULL");
        goto error;
    }

    result = cuMemGetInfo(free, total);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_GET_INFO) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Allocates bytesize bytes of host memory that is page-locked and
 *        accessible to the device. The driver tracks the virtual memory ranges
 *        allocated with this function and automatically accelerates calls to
 *        functions such as cuMemcpyHtoD(). Since the memory can be accessed
 *        directly by the device, it can be read or written with much higher
 *        bandwidth than pageable memory obtained with functions such as
 *        SCMalloc(). Allocating excessive amounts of pinned memory may degrade
 *        system performance, since it reduces the amount of memory available
 *        to the system for paging. As a result, this function is best used
 *        sparingly to allocate staging areas for data exchange between host
 *        and device.
 *
 *        The Flags parameter enables different options to be specified that
 *        affect the allocation, as follows.
 *
 *        - CU_MEMHOSTALLOC_PORTABLE: The memory returned by this call will be
 *          considered as pinned memory by all CUDA contexts, not just the one
 *          that performed the allocation.
 *        - CU_MEMHOSTALLOC_DEVICEMAP: Maps the allocation into the CUDA
 *          address space. The device pointer to the memory may be obtained by
 *          calling cuMemHostGetDevicePointer(). This feature is available only
 *          on GPUs with compute capability greater than or equal to 1.1.
 *        - CU_MEMHOSTALLOC_WRITECOMBINED: Allocates the memory as write-combined
 *          (WC). WC memory can be transferred across the PCI Express bus more
 *          quickly on some system con?gurations, but cannot be read efficiently
 *          by most CPUs. WC memory is a good option for buffers that will be
 *          written by the CPU and read by the GPU via mapped pinned memory or
 *          host->device transfers.  All of these fags are orthogonal to one
 *          another: a developer may allocate memory that is portable, mapped
 *          and/or write-combined with no restrictions.
 *
 *        The CUDA context must have been created with the CU_CTX_MAP_HOST flag
 *        in order for the CU_MEMHOSTALLOC_MAPPED flag to have any effect.
 *
 *        The CU_MEMHOSTALLOC_MAPPED flag may be specified on CUDA contexts for
 *        devices that do not support mapped pinned memory. The failure is
 *        deferred to cuMemHostGetDevicePointer() because the memory may be
 *        mapped into other CUDA contexts via the CU_MEMHOSTALLOC_PORTABLE flag.
 *
 *        The memory allocated by this function must be freed with cuMemFreeHost().
 *
 * \param pp        Returned host pointer to page-locked memory.
 * \param byte_size Requested allocation size in bytes.
 * \param flags     Flags for allocation request.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemHostAlloc(void **pp, size_t byte_size, unsigned int flags)
{
    CUresult result = 0;

    result = cuMemHostAlloc(pp, byte_size, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_HOST_ALLOC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Passes back the device pointer pdptr corresponding to the mapped,
 *        pinned host buffer p allocated by cuMemHostAlloc.
 *
 *        cuMemHostGetDevicePointer() will fail if the CU_MEMALLOCHOST_DEVICEMAP
 *        flag was not speci?ed at the time the memory was allocated, or if the
 *        function is called on a GPU that does not support mapped pinned memory.
 *
 *        Flags provides for future releases. For now, it must be set to 0.
 *
 * \param pdptr Returned device pointer.
 * \param p     Host pointer.
 * \param flags Options(must be 0).
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemHostGetDevicePointer(CUdeviceptr *pdptr, void *p, unsigned int flags)
{
    CUresult result = 0;

    result = cuMemHostGetDevicePointer(pdptr, p, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_HOST_GET_DEVICE_POINTER) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Passes back the flags p_flags that were specified when allocating the
 *        pinned host buffer p allocated by cuMemHostAlloc.
 *
 *        cuMemHostGetFlags() will fail if the pointer does not reside in an
 *        allocation performed by cuMemAllocHost() or cuMemHostAlloc().
 *
 * \param p_flags Returned flags word.
 * \param p       Host pointer.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemHostGetFlags(unsigned int *p_flags, void *p)
{
    CUresult result = 0;

    result = cuMemHostGetFlags(p_flags, p);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_HOST_GET_FLAGS) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemHostRegister(void *p, size_t byte_size, unsigned int flags)
{
    CUresult result = 0;

    result = cuMemHostRegister(p, byte_size, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_HOST_REGISTER) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaMemHostUnregister(void *p)
{
    CUresult result = 0;

    result = cuMemHostUnregister(p);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEM_HOST_UNREGISTER) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the memory range of N 16-bit values to the speci?ed value us.
 *
 * \param dst_device Destination device pointer.
 * \param us         Value to set.
 * \param n          Number of elements.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD16(CUdeviceptr dst_device, unsigned short us, size_t n)
{
    CUresult result = 0;

    result = cuMemsetD16(dst_device, us, n);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D16) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD16Async(CUdeviceptr dst_device, unsigned short us,
                         size_t n, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD16Async(dst_device, us, n, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D16_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the 2D memory range of Width 16-bit values to the specified
 *        value us. Height specifies the number of rows to set, and dst_pitch
 *        specifies the number of bytes between each row. This function
 *        performs fastest when the pitch is one that has been passed back
 *        by cuMemAllocPitch().
 *
 * \param dst_device Destination device pointer.
 * \param dst_pitch  Pitch of destination device pointer.
 * \param us         Value to set
 * \param width      Width of row.
 * \param height     Number of rows
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD2D16(CUdeviceptr dst_device, size_t dst_pitch,
                      unsigned short us, size_t width,
                      size_t height)
{
    CUresult result = 0;

    result = cuMemsetD2D16(dst_device, dst_pitch, us, width, height);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D16) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD2D16Async(CUdeviceptr dst_device, size_t dst_pitch,
                           unsigned short us, size_t width,
                           size_t height, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD2D16Async(dst_device, dst_pitch, us, width, height,
                                h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D16_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the 2D memory range of Width 32-bit values to the specified value
 *        ui. Height speci?es the number of rows to set, and dstPitch specifies
 *        the number of bytes between each row. This function performs fastest
 *        when the pitch is one that has been passed back by cuMemAllocPitch().
 *
 * \param dst_device Destination device pointer.
 * \param dst_pitch  Pitch of destination device pointer.
 * \param ui         Value to set
 * \param width      Width of row.
 * \param height     Number of rows
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD2D32(CUdeviceptr dst_device, size_t dst_pitch,
                      unsigned int ui, size_t width, size_t height)
{
    CUresult result = 0;

    result = cuMemsetD2D32(dst_device, dst_pitch, ui, width, height);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D32) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD2D32Async(CUdeviceptr dst_device, size_t dst_pitch,
                           unsigned int ui, size_t width, size_t height,
                           CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD2D32Async(dst_device, dst_pitch, ui, width, height,
                                h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D32_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the 2D memory range of Width 8-bit values to the specified value
 *        uc. Height speci?es the number of rows to set, and dstPitch specifies
 *        the number of bytes between each row. This function performs fastest
 *        when the pitch is one that has been passed back by cuMemAllocPitch().
 *
 * \param dst_device Destination device pointer.
 * \param dst_pitch  Pitch of destination device pointer.
 * \param uc         Value to set
 * \param width      Width of row.
 * \param height     Number of rows
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD2D8(CUdeviceptr dst_device, size_t dst_pitch,
                     unsigned char uc, size_t width, size_t height)
{
    CUresult result = 0;

    result = cuMemsetD2D8(dst_device, dst_pitch, uc, width, height);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D8) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD2D8Async(CUdeviceptr dst_device, size_t dst_pitch,
                          unsigned char uc, size_t width, size_t height,
                          CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD2D8Async(dst_device, dst_pitch, uc, width, height,
                               h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D2_D8_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the memory range of N 32-bit values to the specified value ui.
 *
 * \param dst_device Destination device pointer.
 * \param ui         Value to set.
 * \param n          Number of elements.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD32(CUdeviceptr dst_device, unsigned int ui, size_t n)
{
    CUresult result = 0;

    result = cuMemsetD32(dst_device, ui, n);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D32) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD32Async(CUdeviceptr dst_device, unsigned int ui,
                         size_t n, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD32Async(dst_device, ui, n, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D32_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Sets the memory range of N 8-bit values to the specified value ui.
 *
 * \param dst_device Destination device pointer.
 * \param uc         Value to set.
 * \param n          Number of elements.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaMemsetD8(CUdeviceptr dst_device, unsigned char uc, size_t n)
{
    CUresult result = 0;

    result = cuMemsetD8(dst_device, uc, n);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D8) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaMemsetD8Async(CUdeviceptr dst_device, unsigned char uc,
                        size_t n, CUstream h_stream)
{
    CUresult result = 0;

    result = cuMemsetD8Async(dst_device, uc, n, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_MEMSET_D8_ASYNC) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/*****************************Unified_Addressing_API****************************/

int SCCudaPointerGetAttribute(void *data, CUpointer_attribute attribute,
                              CUdeviceptr ptr)
{
    CUresult result = 0;

    result = cuPointerGetAttribute(data, attribute, ptr);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_POINTER_GET_ATTRIBUTE) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/*****************************Stream_Management_API****************************/

/**
 * \brief Creates a stream and returns a handle in ph_stream. Flags is
 *        required to be 0.
 *
 * \param ph_stream Returned newly created stream.
 * \param flags    Parameters for stream creation(must be 0).
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaStreamCreate(CUstream *ph_stream, unsigned int flags)
{
    CUresult result = 0;

    if (ph_stream == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "phStream is NULL");
        goto error;
    }

    result = cuStreamCreate(ph_stream, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_STREAM_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Destroys the stream specified by h_stream.
 *
 * \param h_stream Stream to destroy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaStreamDestroy(CUstream h_stream)
{
    CUresult result = 0;

    result = cuStreamDestroy(h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_STREAM_DESTROY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns CUDA_SUCCESS if all operations in the stream specifed by
 *        h_stream have completed, or CUDA_ERROR_NOT_READY if not.
 *
 * \param h_stream Stream to query status of.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaStreamQuery(CUstream h_stream)
{
    CUresult result = 0;

    result = cuStreamQuery(h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_STREAM_QUERY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Waits until the device has completed all operations in the stream
 *        specified by h_stream.
 *
 * \param h_stream Stream to wait for.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaStreamSynchronize(CUstream h_stream)
{
    CUresult result = 0;

    result = cuStreamSynchronize(h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_STREAM_SYNCHRONIZE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaStreamWaitEvent(CUstream h_stream, CUevent h_event,
                          unsigned int flags)
{
    CUresult result = 0;

    result = cuStreamWaitEvent(h_stream, h_event, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_STREAM_WAIT_EVENT) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/*****************************Event_Management_API*****************************/

/**
 * \brief Creates an event *ph_event with the flags specified via flags.  Valid
 *        flags include:
 *
 *        CU_EVENT_DEFAULT: Default event creation flag.
 *        CU_EVENT_BLOCKING_SYNC: Specifies that event should use blocking
 *            synchronization.
 *
 * \param ph_event Returns newly created event.
 * \param flags   Event creation flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventCreate(CUevent *ph_event, unsigned int flags)
{
    CUresult result = 0;

    if (ph_event == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "ph_event is NULL");
        goto error;
    }

    result = cuEventCreate(ph_event, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Destroys the event specified by h_event.
 *
 * \param h_event Event to destroy.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventDestroy(CUevent h_event)
{
    CUresult result = 0;

    result = cuEventDestroy(h_event);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_DESTROY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Computes the elapsed time between two events (in milliseconds with
 *        a resolution of around 0.5 microseconds). If either event has not
 *        been recorded yet, this function returns CUDA_ERROR_NOT_READY. If
 *        either event has been recorded with a non-zero stream, the result
 *        is undefined.
 *
 * \param p_milli_seconds Returned elapsed time in milliseconds.
 * \param h_start         Starting event.
 * \param h_end           Ending event.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventElapsedTime(float *p_milli_seconds, CUevent h_start, CUevent h_end)
{
    CUresult result = 0;

    if (p_milli_seconds == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_milli_seconds is NULL");
        goto error;
    }

    result = cuEventElapsedTime(p_milli_seconds, h_start, h_end);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_ELAPSED_TIME) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns CUDA_SUCCESS if the event has actually been recorded, or
 *        CUDA_ERROR_NOT_READY if not. If cuEventRecord() has not been called
 *        on this event, the function returns CUDA_ERROR_INVALID_VALUE.
 *
 * \param h_event Event to query.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventQuery(CUevent h_event)
{
    CUresult result = 0;

    result = cuEventQuery(h_event);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_QUERY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Records an event. If stream is non-zero, the event is recorded after
 *        all preceding operations in the stream have been completed; otherwise,
 *        it is recorded after all preceding operations in the CUDA context have
 *        been completed. Since operation is asynchronous, cuEventQuery() and/or
 *        cuEventSynchronize() must be used to determine when the event has
 *        actually been recorded.
 *
 *        If cuEventRecord() has previously been called and the event has not
 *        been recorded yet, this function returns CUDA_ERROR_INVALID_VALUE.
 *
 * \param h_event  Event to record.
 * \param h_stream Stream to record event for.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventRecord(CUevent h_event, CUstream h_stream)
{
    CUresult result = 0;

    result = cuEventRecord(h_event, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_RECORD) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Waits until the event has actually been recorded. If cuEventRecord()
 *        has been called on this event, the function returns
 *        CUDA_ERROR_INVALID_VALUE.
 *
 *        If cuEventRecord() has previously been called and the event has not
 *        been recorded yet, this function returns CUDA_ERROR_INVALID_VALUE.
 *
 * \param h_event  Event to wait for.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaEventSynchronize(CUevent h_event)
{
    CUresult result = 0;

    result = cuEventSynchronize(h_event);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_EVENT_SYNCHRONIZE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/***********************Execution_Control_Management_API***********************/

/**
 * \brief Returns in *pi the integer value of the attribute attrib on the
 *        kernel given by hfunc. The supported attributes are:
 *
 *        - CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK: The number of threads
 *              beyond which a launch of the function would fail. This number
 *              depends on both the function and the device on which the
 *              function is currently loaded.
 *        - CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES: The size in bytes of
 *              statically-allocated shared memory required by this function.
 *              This does not include dynamically-allocated shared memory
 *              requested by the user at runtime.
 *        - CU_FUNC_ATTRIBUTE_CONST_SIZE_BYTES: The size in bytes of
 *              user-allocated constant memory required by this function.
 *        - CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES: The size in bytes of thread
 *              local memory used by this function.
 *        - CU_FUNC_ATTRIBUTE_NUM_REGS: The number of registers used by each
 *              thread of this function.
 *
 * \param pi     Pointer to an integer which would be updated with the returned
 *               attribute value.
 * \param attrib Attribute requested.
 * \param hfunc  Function to query attribute of.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaFuncGetAttribute(int *pi, CUfunction_attribute attrib, CUfunction hfunc)
{
    CUresult result = 0;

    if (pi == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pi is NULL");
        goto error;
    }

    result = cuFuncGetAttribute(pi, attrib, hfunc);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_FUNC_GET_ATTRIBUTE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

int SCCudaFuncSetCacheConfig(CUfunction hfunc, CUfunc_cache config)
{
    CUresult result = 0;

    result = cuFuncSetCacheConfig(hfunc, config);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_FUNC_SET_CACHE_CONFIG) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

int SCCudaLaunchKernel(CUfunction f, unsigned int grid_dim_x,
                       unsigned int grid_dim_y, unsigned int grid_dim_z,
                       unsigned int block_dim_x, unsigned int block_dim_y,
                       unsigned int block_dim_z, unsigned int shared_mem_bytes,
                       CUstream h_stream, void **kernel_params, void **extra)
{
    CUresult result = 0;

    result = cuLaunchKernel(f, grid_dim_x, grid_dim_y, grid_dim_z,
                            block_dim_x, block_dim_y, block_dim_z,
                            shared_mem_bytes, h_stream, kernel_params, extra);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_LAUNCH_KERNEL) == -1)
        goto error;

    return 0;
 error:
    return -1;
}

/**
 * \brief Specifies the x, y, and z dimensions of the thread blocks that are
 *        created when the kernel given by hfunc is launched.
 *
 * \param hfunc Kernel to specify dimensions of.
 * \param x X dimension.
 * \param y Y dimension.
 * \param z Z dimension.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaFuncSetBlockShape(CUfunction hfunc, int x, int y, int z)
{
    CUresult result = 0;

    result = cuFuncSetBlockShape(hfunc, x, y, z);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_FUNC_SET_BLOCK_SHAPE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Sets through bytes the amount of dynamic shared memory that will be
 *        available to each thread block when the kernel given by hfunc is
 *        launched.
 *
 * \param hfunc Kernel to specify dynamic shared memory for.
 * \param bytes Dynamic shared memory size per thread in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaFuncSetSharedSize(CUfunction hfunc, unsigned int bytes)
{
    CUresult result = 0;

    result = cuFuncSetSharedSize(hfunc, bytes);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_FUNC_SET_SHARED_SIZE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Invokes the kernel f on a 1 x 1 x 1 grid of blocks. The block contains
 *        the number of threads specified by a previous call to
 *        cuFuncSetBlockShape().
 *
 * \param f Kernel to launch.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaLaunch(CUfunction f)
{
    CUresult result = 0;

    result = cuLaunch(f);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_LAUNCH) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Invokes the kernel f on a grid_width x grid_height grid of blocks.
 *        Each block contains the number of threads specified by a previous call
 *        to cuFuncSetBlockShape().
 *
 * \param f           Kernel to launch.
 * \param grid_width  Width of grid in blocks.
 * \param grib_height Height of grid in blocks.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaLaunchGrid(CUfunction f, int grid_width, int grid_height)
{
    CUresult result = 0;

    result = cuLaunchGrid(f, grid_width, grid_height);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_LAUNCH_GRID) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Invokes the kernel f on a grid_width x grid_height grid of blocks.
 *        Each block contains the number of threads specified by a previous call
 *        to cuFuncSetBlockShape().  cuLaunchGridAsync() can optionally be
 *        associated to a stream by passing a non-zero hStream argument.
 *
 * \param f           Kernel to launch.
 * \param grid_width  Width of grid in blocks.
 * \param grib_height Height of grid in blocks.
 * \param h_stream    Stream identifier.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaLaunchGridAsync(CUfunction f, int grid_width, int grid_height,
                          CUstream h_stream)
{
    CUresult result = 0;

    result = cuLaunchGridAsync(f, grid_width, grid_height, h_stream);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_LAUNCH_GRID_ASYNC) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Sets a foating-point parameter that will be specified the next time
 *        the kernel corresponding to hfunc will be invoked. offset is a byte
 *        offset.
 *
 * \param h_func Kernel to add parameter to.
 * \param offset Offset to add parameter to argument list.
 * \param value  Value of parameter.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaParamSetf(CUfunction h_func, int offset, float value)
{
    CUresult result = 0;

    result = cuParamSetf(h_func, offset, value);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_PARAM_SETF) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Sets an integer parameter that will be specified the next time
 *        the kernel corresponding to hfunc will be invoked. offset is a byte
 *        offset.
 *
 * \param h_func Kernel to add parameter to.
 * \param offset Offset to add parameter to argument list.
 * \param value  Value of parameter.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaParamSeti(CUfunction h_func, int offset, unsigned int value)
{
    CUresult result = 0;

    result = cuParamSeti(h_func, offset, value);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_PARAM_SETI) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Sets through numbytes the total size in bytes needed by the function
 *        parameters of the kernel corresponding to hfunc.
 *
 * \param h_func    Kernel to set parameter size for.
 * \param num_bytes Size of paramter list in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaParamSetSize(CUfunction h_func, unsigned int num_bytes)
{
    CUresult result = 0;

    result = cuParamSetSize(h_func, num_bytes);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_PARAM_SET_SIZE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Makes the CUDA array or linear memory bound to the texture reference
 *        h_tex_ref available to a device program as a texture. In this version
 *        of CUDA, the texture-reference must be obtained via cuModuleGetTexRef()
 *        and the tex_unit parameter must be set to CU_PARAM_TR_DEFAULT.
 *
 * \param h_func    Kernel to add texture-reference to.
 * \param tex_unit  Texture unit (must be CU_PARAM_TR_DEFAULT).
 * \param h_tex_ref Texture-reference to add to argument list.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaParamSetTexRef(CUfunction h_func, int tex_unit, CUtexref h_tex_ref)
{
    CUresult result = 0;

    result = cuParamSetTexRef(h_func, tex_unit, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_PARAM_SET_TEX_REF) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Copies an arbitrary amount of data (specified in numbytes) from ptr
 *        into the parameter space of the kernel corresponding to hfunc.
 *        offset is a byte offset.
 *
 * \param h_func    Kernel to add data to.
 * \param offset    Offset to add data to argument list.
 * \param ptr       Pointer to arbitrary data.
 * \param num_bytes Size of data to copy in bytes.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaParamSetv(CUfunction h_func, int offset, void *ptr,
                    unsigned int num_bytes)
{
    CUresult result = 0;

    if (ptr == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "ptr is NULL");
        goto error;
    }

    result = cuParamSetv(h_func, offset, ptr, num_bytes);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_PARAM_SETV) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/***********************Texture_Reference_Management_API***********************/

/**
 * \brief Creates a texture reference and returns its handle in *pTexRef. Once
 *        created, the application must call cuTexRefSetArray() or cuTexRefSetAddress()
 *        to associate the reference with allocated memory. Other texture reference
 *        functions are used to specify the format and interpretation (addressing,
 *        filtering, etc.) to be used when the memory is read through this texture
 *        reference. To associate the texture reference with a texture ordinal for
 *        a given function, the application should call cuParamSetTexRef().
 *
 * \param p_tex_ref  Returned texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefCreate(CUtexref *p_tex_ref)
{
    CUresult result = 0;

    if (p_tex_ref == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_tex_ref is NULL");
        goto error;
    }

    result = cuTexRefCreate(p_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_CREATE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Destroys the texture reference specified by hTexRef.
 *
 * \param h_tex_ref  Texture reference to destroy
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefDestroy(CUtexref h_tex_ref)
{
    CUresult result = 0;

    result = cuTexRefDestroy(h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_DESTROY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *pdptr the base address bound to the texture reference
 *        hTexRef, or returns CUDA_ERROR_INVALID_VALUE if the texture reference
 *        is not bound to any device memory range.
 *
 * \param pdptr      Returned device address
 * \param h_tex_ref  Texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetAddress(CUdeviceptr *pdptr, CUtexref h_tex_ref)
{
    CUresult result = 0;

    if (pdptr == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pdptr is NULL");
        goto error;
    }

    result = cuTexRefGetAddress(pdptr, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_ADDRESS) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *pam the addressing mode corresponding to the dimension
 *        dim of the texture reference hTexRef. Currently, the only valid value
 *        for dim are 0 and 1.
 *
 * \param pam        Returned addressing mode
 * \param h_tex_ref  Texture reference
 * \param dim        Dimension
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetAddressMode(CUaddress_mode *pam, CUtexref h_tex_ref, int dim)
{
    CUresult result = 0;

    if (pam == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pam is NULL");
        goto error;
    }

    result = cuTexRefGetAddressMode(pam, h_tex_ref, dim);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_ADDRESS_MODE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *phArray the CUDA array bound to the texture reference
 *        hTexRef, or returns CUDA_ERROR_INVALID_VALUE if the texture reference
 *        is not bound to any CUDA array.
 *
 * \param ph_array   Returned array
 * \param h_tex_ref  Texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetArray(CUarray *ph_array, CUtexref h_tex_ref)
{
    CUresult result = 0;

    if (ph_array == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "ph_array is NULL");
        goto error;
    }

    result = cuTexRefGetArray(ph_array, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_ARRAY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *pfm the filtering mode of the texture reference hTexRef.
 *
 * \param pfm        Returned filtering mode
 * \param h_tex_ref  Texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetFilterMode(CUfilter_mode *pfm, CUtexref h_tex_ref)
{
    CUresult result = 0;

    if (pfm == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "pfm is NULL");
        goto error;
    }

    result = cuTexRefGetFilterMode(pfm, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_FILTER_MODE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *pFlags the flags of the texture reference hTexRef.
 *
 * \param p_flags    Returned flags
 * \param h_tex_ref  Texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetFlags(unsigned int *p_flags, CUtexref h_tex_ref)
{
    CUresult result = 0;

    if (p_flags == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_flags is NULL");
        goto error;
    }

    result = cuTexRefGetFlags(p_flags, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_FLAGS) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns in *pFormat and *pNumChannels the format and number of
 *        components of the CUDA array bound to the texture reference hTexRef.
 *        If pFormat or pNumChannels is NULL, it will be ignored.
 *
 * \param p_format        Returned format
 * \param p_num_channels  Returned number of components
 * \param h_tex_ref       Texture reference
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefGetFormat(CUarray_format *p_format, int *p_num_channels,
                          CUtexref h_tex_ref)
{
    CUresult result = 0;

    if (p_format == NULL || p_num_channels == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "p_format == NULL || p_num_channels == NULL");
        goto error;
    }

    result = cuTexRefGetFormat(p_format, p_num_channels, h_tex_ref);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_GET_FORMAT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Binds a linear address range to the texture reference hTexRef. Any
 *        previous address or CUDA array state associated with the texture
 *        reference is superseded by this function. Any memory previously
 *        bound to hTexRef is unbound.
 *
 *        Since the hardware enforces an alignment requirement on texture
 *        base addresses, cuTexRefSetAddress() passes back a byte offset in
 *        *ByteOffset that must be applied to texture fetches in order to read
 *        from the desired memory. This offset must be divided by the texel
 *        size and passed to kernels that read from the texture so they can be
 *        applied to the tex1Dfetch() function.
 *
 *        If the device memory pointer was returned from cuMemAlloc(), the
 *        offset is guaranteed to be 0 and NULL may be passed as the
 *        ByteOffset parameter.
 *
 * \param byte_offset  Returned byte offset
 * \param h_tex_ref    Texture reference to bind
 * \param dptr         Device pointer to bind
 * \param bytes        Size of memory to bind in bytes
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetAddress(size_t *byte_offset, CUtexref h_tex_ref,
                           CUdeviceptr dptr, unsigned int bytes)
{
    CUresult result = 0;

    if (byte_offset == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument supplied.  "
                   "byte_offset is NULL");
        goto error;
    }

    result = cuTexRefSetAddress(byte_offset, h_tex_ref, dptr, bytes);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_ADDRESS) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Binds a linear address range to the texture reference hTexRef. Any
 *        previous address or CUDA array state associated with the texture
 *        reference is superseded by this function. Any memory previously bound
 *        to hTexRef is unbound.
 *
 *        Using a tex2D() function inside a kernel requires a call to either
 *        cuTexRefSetArray() to bind the corresponding texture reference to an
 *        array, or cuTexRefSetAddress2D() to bind the texture reference to
 *        linear memory.
 *
 *        Function calls to cuTexRefSetFormat() cannot follow calls to
 *        cuTexRefSetAddress2D() for the same texture reference.
 *
 *        It is required that dptr be aligned to the appropriate hardware-
 *        specific texture alignment. You can query this value using the device
 *        attribute CU_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT. If an unaligned dptr
 *        is supplied, CUDA_ERROR_INVALID_VALUE is returned.
 *
 * \param h_tex_ref  Texture reference to bind
 * \param desc       Descriptor of CUDA array
 * \param dptr       Device pointer to bind
 * \param pitch      Line pitch in bytes
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetAddress2D(CUtexref h_tex_ref, const CUDA_ARRAY_DESCRIPTOR *desc,
                             CUdeviceptr dptr, unsigned int pitch)
{
    CUresult result = 0;

    result = cuTexRefSetAddress2D(h_tex_ref, desc, dptr, pitch);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_ADDRESS_2D) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Specifies the addressing mode am for the given dimension dim of the
 *        texture reference hTexRef. If dim is zero, the addressing mode is
 *        applied to the first parameter of the functions used to fetch from
 *        the texture; if dim is 1, the second, and so on. CUaddress_mode is
 *        defined as:
 *
 *        typedef enum CUaddress_mode_enum {
 *            CU_TR_ADDRESS_MODE_WRAP = 0,
 *            CU_TR_ADDRESS_MODE_CLAMP = 1,
 *            CU_TR_ADDRESS_MODE_MIRROR = 2,
 *        } CUaddress_mode;
 *
 * \param h_tex_ref  Texture reference
 * \param dim        Dimension
 * \param am         Addressing mode to set
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetAddressMode(CUtexref h_tex_ref, int dim, CUaddress_mode am)
{
    CUresult result = 0;

    result = cuTexRefSetAddressMode(h_tex_ref, dim, am);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_ADDRESS_MODE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Binds the CUDA array hArray to the texture reference hTexRef. Any
 *        previous address or CUDA array state associated with the texture
 *        reference is superseded by this function. Flags must be set to
 *        CU_TRSA_OVERRIDE_FORMAT. Any CUDA array previously bound to hTexRef
 *        is unbound.
 *
 * \param h_tex_ref  Texture reference to bind
 * \param h_array    Array to bind
 * \param flags      Options (must be CU_TRSA_OVERRIDE_FORMAT)
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetArray(CUtexref h_tex_ref, CUarray h_array, unsigned int flags)
{
    CUresult result = 0;

    result = cuTexRefSetArray(h_tex_ref, h_array, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_ARRAY) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Specifies the filtering mode fm to be used when reading memory through
 *        the texture reference hTexRef. CUfilter_mode_enum is defined as:
 *
 *        typedef enum CUfilter_mode_enum {
 *            CU_TR_FILTER_MODE_POINT = 0,
 *            CU_TR_FILTER_MODE_LINEAR = 1
 *        } CUfilter_mode;
 *
 * \param h_tex_ref  Texture reference
 * \param fm         Filtering mode to set
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetFilterMode(CUtexref h_tex_ref, CUfilter_mode fm)
{
    CUresult result = 0;

    result = cuTexRefSetFilterMode(h_tex_ref, fm);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_FILTER_MODE) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Specifies optional flags via Flags to specify the behavior of data
 *        returned through the texture reference hTexRef. The valid flags are:
 *
 *        * CU_TRSF_READ_AS_INTEGER, which suppresses the default behavior of
 *          having the texture promote integer data to floating point data in
 *          the range [0, 1];
 *        * CU_TRSF_NORMALIZED_COORDINATES, which suppresses the default
 *          behavior of having the texture coordinates range from [0, Dim) where
 *          Dim is the width or height of the CUDA array. Instead, the texture
 *          coordinates [0, 1.0) reference the entire breadth of the array
 *          dimension;
 *
 * \param h_tex_ref  Texture reference
 * \param flags      Optional flags to set
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetFlags(CUtexref h_tex_ref, unsigned int flags)
{
    CUresult result = 0;

    result = cuTexRefSetFlags(h_tex_ref, flags);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_FLAGS) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**
 * \brief Specifies the format of the data to be read by the texture reference
 *        hTexRef. fmt and NumPackedComponents are exactly analogous to the
 *        Format and NumChannels members of the CUDA_ARRAY_DESCRIPTOR structure:
 *        They specify the format of each component and the number of components
 *        per array element.
 *
 * \param h_tex_ref  Texture reference
 * \param fmt        Format to set
 * \param num_packed_components  Number of components per array element
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaTexRefSetFormat(CUtexref h_tex_ref, CUarray_format fmt,
                          int num_packed_components)
{
    CUresult result = 0;

    result = cuTexRefSetFormat(h_tex_ref, fmt, num_packed_components);
    if (SCCudaHandleRetValue(result, SC_CUDA_CU_TEX_REF_SET_FORMAT) == -1)
        goto error;

    return 0;

 error:
    return -1;
}

/**************************Cuda_Env_Initialization_API*************************/

/**
 * \brief Initialize the CUDA Environment for the engine.
 *
 * \retval  0 On successfully initializing the CUDA environment for the engine.
 * \retval -1 On failure.
 */
int SCCudaInitCudaEnvironment(void)
{
    if (devices != NULL) {
        SCLogWarning(SC_ERR_CUDA_ERROR, "CUDA engine already initalized!!!!");
        return 0;
    }

    if (SCCudaInit(0) == -1) {
        SCLogError(SC_ERR_CUDA_ERROR, "Error initializing CUDA API.  SCCudaInit() "
                   "returned -1");
        goto error;
    }

    if ( (devices = SCCudaGetDevices()) == NULL) {
        SCLogError(SC_ERR_CUDA_ERROR, "Error getting CUDA device list.  "
                   "SCCudaGetDevices() returned NULL");
        goto error;
    }

    SCCudaPrintBasicDeviceInfo(devices);

    return 0;

 error:
    SCCudaDeAllocSCCudaDevices(devices);
    return -1;
}

/**********************************Cuda_Utility********************************/

/**
 * \brief List the cuda cards on the system.
 *
 */
void SCCudaListCards(void)
{
    int i = 0;

    if (devices == NULL) {
        SCLogWarning(SC_ERR_CUDA_ERROR, "CUDA engine not initalized!  Please "
                     "initialize the cuda environment using "
                     "SCCudaInitCudaEnvironment().");
        return;
    }

    printf("CUDA Cards recognized by the suricata CUDA module - \n");
    printf("|-----------------------------------------------------------------------------|\n");
    printf("| %-10s | %-20s | %-10s | %-10s | %-13s |\n",
           "Device Id", "    Device Name", "  Multi-", "Clock Rate", "Cuda Compute");
    printf("| %-10s | %-20s | %-10s | %-10s | %-13s |\n",
           "", "", "Processors", "   (MHz)", "Capability");
    printf("|-----------------------------------------------------------------------------|\n");
    for (i = 0; i < devices->count; i++) {
        printf("| %-10d | %-20s | %-10d | %-10d | %d.%-11d |\n",
               i,
               devices->devices[i]->name,
               devices->devices[i]->attr_multiprocessor_count,
               devices->devices[i]->attr_clock_rate/1000,
               devices->devices[i]->major_rev,
               devices->devices[i]->minor_rev);
    }
    printf("|-----------------------------------------------------------------------------|\n");

    return;
}

int SCCudaIsCudaDeviceIdValid(int cuda_device_id)
{
    if (devices == NULL) {
        SCLogWarning(SC_ERR_CUDA_ERROR, "CUDA engine not initalized!  Please "
                     "initialize the cuda environment using "
                     "SCCudaInitCudaEnvironment().");
        return 0;
    }

    return (cuda_device_id < devices->count);
}

/**********************************Unittests***********************************/

int SCCudaTest01(void)
{
    SCCudaDevices *devices = SCCudaGetDeviceList();

    if (devices == NULL)
        return 0;

    return (devices->count != 0);
}

#if defined(__x86_64__) || defined(__ia64__)
/**
 * extern "C" __global__ void SCCudaSuricataTest(int *input, int *output)
 * {
 *   output[threadIdx.x] = input[threadIdx.x] * 2;
 * }
 */
static const char *sc_cuda_test_kernel_64_bit =
    "    .version 1.4\n"
    "    .target sm_10, map_f64_to_f32\n"
    "    .entry SCCudaSuricataTest (\n"
    "                               .param .u64 __cudaparm_SCCudaSuricataTest_input,\n"
    "                               .param .u64 __cudaparm_SCCudaSuricataTest_output)\n"
    "{\n"
    "    .reg .u32 %r<5>;\n"
    "    .reg .u64 %rd<8>;\n"
    "    .loc 15 1 0\n"
    "    $LBB1_SCCudaSuricataTest:\n"
    "    .loc 15 3 0\n"
    "    cvt.u32.u16 %r1, %tid.x;\n"
    "    cvt.u64.u32 %rd1, %r1;\n"
    "    mul.lo.u64 %rd2, %rd1, 4;\n"
    "    ld.param.u64 %rd3, [__cudaparm_SCCudaSuricataTest_input];\n"
    "    add.u64 %rd4, %rd3, %rd2;\n"
    "    ld.global.s32 %r2, [%rd4+0];\n"
    "    mul.lo.s32 %r3, %r2, 2;\n"
    "    ld.param.u64 %rd5, [__cudaparm_SCCudaSuricataTest_output];\n"
    "    add.u64 %rd6, %rd5, %rd2;\n"
    "    st.global.s32 [%rd6+0], %r3;\n"
    "    .loc 15 4 0\n"
    "    exit;\n"
    " $LDWend_SCCudaSuricataTest:\n"
    "} // SCCudaSuricataTest\n"
    "\n";
#else
/**
 * extern "C" __global__ void SCCudaSuricataTest(int *input, int *output)
 * {
 *   output[threadIdx.x] = input[threadIdx.x] * 2;
 * }
 */
static const char *sc_cuda_test_kernel_32_bit =
    "        .version 1.4\n"
    "        .target sm_10, map_f64_to_f32\n"
    "        .entry SCCudaSuricataTest (\n"
    "                .param .u32 __cudaparm_SCCudaSuricataTest_input,\n"
    "                .param .u32 __cudaparm_SCCudaSuricataTest_output)\n"
    "        {\n"
    "        .reg .u16 %rh<3>;\n"
    "        .reg .u32 %r<9>;\n"
    "        .loc    15      2       0\n"
    "$LBB1_SCCudaSuricataTest:\n"
    "        .loc    15      4       0\n"
    "        mov.u16         %rh1, %tid.x;\n"
    "        mul.wide.u16    %r1, %rh1, 4;\n"
    "        ld.param.u32    %r2, [__cudaparm_SCCudaSuricataTest_input];\n"
    "        add.u32         %r3, %r2, %r1;\n"
    "        ld.global.s32   %r4, [%r3+0];\n"
    "        mul.lo.s32      %r5, %r4, 2;\n"
    "        ld.param.u32    %r6, [__cudaparm_SCCudaSuricataTest_output];\n"
    "        add.u32         %r7, %r6, %r1;\n"
    "        st.global.s32   [%r7+0], %r5;\n"
    "        .loc    15      5       0\n"
    "        exit;\n"
    "$LDWend_SCCudaSuricataTest:\n"
    "        } // SCCudaSuricataTest\n"
    "";
#endif

int SCCudaTest02(void)
{
#define ALIGN_UP(offset, alignment) do { \
            (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1); \
        } while (0)
#define N 256
    CUcontext context;
    CUmodule module;
    CUfunction kernel;
    CUdeviceptr d_input, d_output;
    int h_input[N];
    int h_result[N];
    SCCudaDevices *devices = SCCudaGetDeviceList();
    int result = 0;
    int offset = 0;
    int i = 0;

    if (devices == NULL)
        goto end;

    if (devices->count == 0)
        goto end;

    if (SCCudaCtxCreate(&context, 0, devices->devices[0]->device) == -1)
        goto end;

#if defined(__x86_64__) || defined(__ia64__)
    if (SCCudaModuleLoadData(&module, (void *)sc_cuda_test_kernel_64_bit) == -1)
        goto end;
#else
    if (SCCudaModuleLoadData(&module, (void *)sc_cuda_test_kernel_32_bit) == -1)
        goto end;
#endif

    if (SCCudaModuleGetFunction(&kernel, module, "SCCudaSuricataTest") == -1)
        goto end;

    for (i = 0; i < N; i++)
        h_input[i] = i * 2;

    if (SCCudaMemAlloc(&d_input, N * sizeof(int)) == -1)
        goto end;

    if (SCCudaMemcpyHtoD(d_input, h_input, N * sizeof(int)) == -1)
        goto end;

    if (SCCudaMemAlloc(&d_output, N * sizeof(int)) == -1)
        goto end;

    offset = 0;
    ALIGN_UP(offset, __alignof(void *));
    if (SCCudaParamSetv(kernel, offset, (void *)&d_input, sizeof(void *)) == -1)
        goto end;
    offset += sizeof(void *);

    ALIGN_UP(offset, __alignof(void *));
    if (SCCudaParamSetv(kernel, offset, (void *)&d_output, sizeof(void *)) == -1)
        goto end;
    offset += sizeof(void *);

    if (SCCudaParamSetSize(kernel, offset) == -1)
        goto end;

    if (SCCudaFuncSetBlockShape(kernel, N, 1, 1) == -1)
        goto end;

    if (SCCudaLaunchGrid(kernel, 1, 1) == -1)
        goto end;

    if (SCCudaMemcpyDtoH(h_result, d_output, N * sizeof(int)) == -1)
        goto end;

    for (i = 0; i < N; i++)
        h_input[i] = i * 4;

    for (i = 0; i < N; i++) {
        if (h_result[i] != h_input[i])
            goto end;
    }

    if (SCCudaMemFree(d_input) == -1)
        goto end;

    if (SCCudaMemFree(d_output) == -1)
        goto end;

    if (SCCudaModuleUnload(module) == -1)
        goto end;

    if (SCCudaCtxDestroy(context) == -1)
        goto end;

    result = 1;

 end:
    return result;
}

void SCCudaRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCCudaTest01", SCCudaTest01);
    UtRegisterTest("SCCudaTest02", SCCudaTest02);
#endif

    return;
}

#endif /* __SC_CUDA_SUPPORT__ */
