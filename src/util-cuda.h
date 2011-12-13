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

#ifndef __UTIL_CUDA__H__
#define __UTIL_CUDA__H__

#ifdef __SC_CUDA_SUPPORT__

#include <cuda.h>

#define SC_CUDA_DEFAULT_DEVICE 0
#define SC_CUDA_DEVICE_NAME_MAX_LEN 128

typedef struct SCCudaDevice_ {
    /* device id */
    CUdevice device;

    /* device name */
    char name[SC_CUDA_DEVICE_NAME_MAX_LEN];

    /* device compute capability */
    int major_rev;
    int minor_rev;

    /* device properties */
    CUdevprop prop;

    /* device total memory */
    unsigned int bytes;

    /* device attributes.  We could have used a fixed int array table to hold
     * the attributes, but it is better we specify it exclusively this way,
     * since the usage would be less error prone */
    int attr_max_threads_per_block;
    int attr_max_block_dim_x;
    int attr_max_block_dim_y;
    int attr_max_block_dim_z;
    int attr_max_grid_dim_x;
    int attr_max_grid_dim_y;
    int attr_max_grid_dim_z;
    int attr_max_shared_memory_per_block;
    int attr_total_constant_memory;
    int attr_warp_size;
    int attr_max_pitch;
    int attr_max_registers_per_block;
    int attr_clock_rate;
    int attr_texture_alignment;
    int attr_gpu_overlap;
    int attr_multiprocessor_count;
    int attr_kernel_exec_timeout;
    int attr_integrated;
    int attr_can_map_host_memory;
    int attr_compute_mode;
} SCCudaDevice;


typedef struct SCCudaDevices_ {
    int count;
    SCCudaDevice **devices;
} SCCudaDevices;

int SCCudaArray3DCreate(CUarray *, const CUDA_ARRAY3D_DESCRIPTOR *);
int SCCudaArray3DGetDescriptor(CUDA_ARRAY3D_DESCRIPTOR *, CUarray);
int SCCudaArrayCreate(CUarray *, const CUDA_ARRAY_DESCRIPTOR *);
int SCCudaArrayDestroy(CUarray);
int SCCudaArrayGetDescriptor(CUDA_ARRAY_DESCRIPTOR *, CUarray);
int SCCudaMemAlloc(CUdeviceptr *dptr, unsigned int);
int SCCudaMemAllocHost(void **, unsigned int);
int SCCudaMemAllocPitch(CUdeviceptr *, unsigned int *, unsigned int,
                        unsigned int, unsigned int);
int SCCudaMemcpy2D(const CUDA_MEMCPY2D *);
int SCCudaMemcpy2DAsync(const CUDA_MEMCPY2D *, CUstream);
int SCCudaMemcpy2DUnaligned(const CUDA_MEMCPY2D *);
int SCCudaMemcpy3D(const CUDA_MEMCPY3D *);
int SCCudaMemcpy3DAsync(const CUDA_MEMCPY3D *, CUstream);
int SCCudaMemcpyAtoA(CUarray, unsigned int, CUarray, unsigned int, unsigned int);
int SCCudaMemcpyAtoD(CUdeviceptr, CUarray, unsigned int, unsigned int);
int SCCudaMemcpyAtoH(void *, CUarray, unsigned int, unsigned int);
int SCCudaMemcpyAtoHAsync(void *, CUarray, unsigned int, unsigned int,
                          CUstream);
int SCCudaMemcpyDtoA(CUarray, unsigned int, CUdeviceptr, unsigned int);
int SCCudaMemcpyDtoD(CUdeviceptr, CUdeviceptr, unsigned int byte_count);
int SCCudaMemcpyDtoH(void *, CUdeviceptr, unsigned int);
int SCCudaMemcpyDtoHAsync(void *, CUdeviceptr, unsigned int, CUstream);
int SCCudaMemcpyHtoA(CUarray, unsigned int, const void *, unsigned int);
int SCCudaMemcpyHtoAAsync(CUarray, unsigned int, const void *,
                          unsigned int, CUstream);
int SCCudaMemcpyHtoD(CUdeviceptr, const void *, unsigned int);
int SCCudaMemcpyHtoDAsync(CUdeviceptr, const void *, unsigned int,
                          CUstream);
int SCCudaMemFree(CUdeviceptr);
int SCCudaMemFreeHost(void *);
int SCCudaMemGetAddressRange(CUdeviceptr *, unsigned int *, CUdeviceptr);
int SCCudaMemGetInfo(unsigned int *, unsigned int *);
int SCCudaMemHostAlloc(void **, size_t, unsigned int);
int SCCudaMemHostGetDevicePointer(CUdeviceptr *, void *, unsigned int);
int SCCudaMemHostGetFlags(unsigned int *, void *);
int SCCudaMemsetD16(CUdeviceptr, unsigned short, unsigned int);
int SCCudaMemsetD2D16(CUdeviceptr, unsigned int, unsigned short,
                      unsigned int, unsigned int);
int SCCudaMemsetD2D32(CUdeviceptr, unsigned int, unsigned int, unsigned int,
                      unsigned int);
int SCCudaMemsetD2D8(CUdeviceptr, unsigned int, unsigned char, unsigned int,
                     unsigned int);
int SCCudaMemsetD32(CUdeviceptr, unsigned int, unsigned int);
int SCCudaMemsetD8(CUdeviceptr, unsigned char, unsigned int);

int SCCudaTexRefCreate(CUtexref *);
int SCCudaTexRefDestroy(CUtexref);
int SCCudaTexRefGetAddress(CUdeviceptr *, CUtexref);
int SCCudaTexRefGetAddressMode(CUaddress_mode *, CUtexref, int);
int SCCudaTexRefGetArray(CUarray *, CUtexref);
int SCCudaTexRefGetFilterMode(CUfilter_mode *, CUtexref);
int SCCudaTexRefGetFlags(unsigned int *, CUtexref);
int SCCudaTexRefGetFormat(CUarray_format *, int *, CUtexref);
int SCCudaTexRefSetAddress(unsigned int *, CUtexref, CUdeviceptr,
                           unsigned int);
int SCCudaTexRefSetAddress2D(CUtexref, const CUDA_ARRAY_DESCRIPTOR *,
                             CUdeviceptr, unsigned int);
int SCCudaTexRefSetAddressMode(CUtexref, int, CUaddress_mode);
int SCCudaTexRefSetArray(CUtexref, CUarray, unsigned int);
int SCCudaTexRefSetFilterMode(CUtexref, CUfilter_mode);
int SCCudaTexRefSetFlags(CUtexref, unsigned int);
int SCCudaTexRefSetFormat(CUtexref, CUarray_format, int);

int SCCudaFuncGetAttribute(int *, CUfunction_attribute, CUfunction);
int SCCudaFuncSetBlockShape(CUfunction, int, int, int);
int SCCudaFuncSetSharedSize(CUfunction, unsigned int);
int SCCudaLaunch(CUfunction);
int SCCudaLaunchGrid(CUfunction, int, int);
int SCCudaLaunchGridAsync(CUfunction, int, int, CUstream);
int SCCudaParamSetf(CUfunction, int, float);
int SCCudaParamSeti(CUfunction, int, unsigned int);
int SCCudaParamSetSize(CUfunction, unsigned int);
int SCCudaParamSetTexRef(CUfunction, int, CUtexref);
int SCCudaParamSetv(CUfunction, int, void *, unsigned int);

int SCCudaEventCreate(CUevent *, unsigned int);
int SCCudaEventDestroy(CUevent);
int SCCudaEventElapsedTime(float *, CUevent, CUevent);
int SCCudaEventQuery(CUevent);
int SCCudaEventRecord(CUevent, CUstream);
int SCCudaEventSynchronize(CUevent);

int SCCudaStreamCreate(CUstream *, unsigned int);
int SCCudaStreamDestroy(CUstream);
int SCCudaStreamQuery(CUstream);
int SCCudaStreamSynchronize(CUstream);

int SCCudaModuleGetFunction(CUfunction *, CUmodule, const char *);
int SCCudaModuleGetGlobal(CUdeviceptr *, unsigned int *, CUmodule, const char *);
int SCCudaModuleGetTexRef(CUtexref *, CUmodule, const char *);
int SCCudaModuleLoad(CUmodule *, const char *);
int SCCudaModuleLoadData(CUmodule *, const char *);
int SCCudaModuleLoadDataEx(CUmodule *, const char *, unsigned int,
                           CUjit_option *, void **);
int SCCudaModuleLoadFatBinary(CUmodule *, const void *);
int SCCudaModuleUnload(CUmodule);


int SCCudaCtxAttach(CUcontext *, unsigned int);
int SCCudaCtxCreate(CUcontext *, unsigned int, CUdevice);
int SCCudaCtxDestroy(CUcontext);
int SCCudaCtxDetach(CUcontext);
int SCCudaCtxGetDevice(CUdevice *);
int SCCudaCtxPopCurrent(CUcontext *);
int SCCudaCtxPushCurrent(CUcontext);
int SCCudaCtxSynchronize(void);

int SCCudaDriverGetVersion(int *);

void SCCudaPrintDeviceList(SCCudaDevices *);
void SCCudaPrintBasicDeviceInfo(SCCudaDevices *);
SCCudaDevices *SCCudaGetDeviceList(void);

int SCCudaInitCudaEnvironment(void);

void SCCudaListCards(void);
int SCCudaIsCudaDeviceIdValid(int);

void SCCudaRegisterTests(void);

#endif /* __SC_CUDA_SUPPORT__ */
#endif /* __UTIL_CUDA_H__ */
