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
    size_t bytes;

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


/**************************Cuda_Initialization_API**************************/
int SCCudaInit(unsigned int flags);

/***************************Version_Management_API***************************/
int SCCudaDriverGetVersion(int *driver_version);

/***************************Device_Management_API****************************/
int SCCudaDeviceComputeCapability(int *major, int *minor, CUdevice dev);
int SCCudaDeviceGet(CUdevice *device, int ordinal);
int SCCudaDeviceGetAttribute(int *pi, CUdevice_attribute attrib,
                             CUdevice dev);
int SCCudaDeviceGetCount(int *count);
int SCCudaDeviceGetName(char *name, int len, CUdevice dev);
int SCCudaDeviceGetProperties(CUdevprop *prop, CUdevice dev);
int SCCudaDeviceTotalMem(size_t *bytes, CUdevice dev);

void SCCudaPrintDeviceList(SCCudaDevices *);
void SCCudaPrintBasicDeviceInfo(SCCudaDevices *);
SCCudaDevices *SCCudaGetDeviceList(void);

/***************************Context_Management_API***************************/
int SCCudaCtxCreate(CUcontext *pctx, unsigned int flags, CUdevice dev);
int SCCudaCtxDestroy(CUcontext ctx);
int SCCudaCtxGetApiVersion(CUcontext ctx, unsigned int *version);
int SCCudaCtxGetCacheConfig(CUfunc_cache *pconfig);
int SCCudaCtxGetCurrent(CUcontext *pctx);
int SCCudaCtxGetDevice(CUdevice *device);
int SCCudaCtxGetLimit(size_t *pvalue, CUlimit limit);
int SCCudaCtxPopCurrent(CUcontext *pctx);
int SCCudaCtxPushCurrent(CUcontext ctx);
int SCCudaCtxSetCacheConfig(CUfunc_cache config);
int SCCudaCtxSetCurrent(CUcontext ctx);
int SCCudaCtxSetLimit(CUlimit limit, size_t value);
int SCCudaCtxSynchronize(void);
int SCCudaCtxAttach(CUcontext *pctx, unsigned int flags);
int SCCudaCtxDetach(CUcontext ctx);

/***************************Module_Management_API****************************/
int SCCudaModuleGetFunction(CUfunction *hfunc, CUmodule hmod,
                            const char *name);
int SCCudaModuleGetGlobal(CUdeviceptr *dptr, size_t *bytes, CUmodule hmod,
                          const char *name);
int SCCudaModuleGetSurfRef(CUsurfref *p_surf_ref, CUmodule hmod,
                           const char *name);
int SCCudaModuleGetTexRef(CUtexref *p_tex_ref, CUmodule hmod,
                          const char *name);
int SCCudaModuleLoad(CUmodule *module, const char *fname);
int SCCudaModuleLoadData(CUmodule *module, const void *image);
int SCCudaModuleLoadDataEx(CUmodule *module, const void *image,
                           unsigned int num_options, CUjit_option *options,
                           void **option_values);
int SCCudaModuleLoadFatBinary(CUmodule *module, const void *fat_cubin);
int SCCudaModuleUnload(CUmodule hmod);

/**************************Memory_Management_API*****************************/
int SCCudaArray3DCreate(CUarray *p_handle,
                        const CUDA_ARRAY3D_DESCRIPTOR *p_allocate_array);
int SCCudaArray3DGetDescriptor(CUDA_ARRAY3D_DESCRIPTOR *p_array_descriptor,
                               CUarray h_array);
int SCCudaArrayCreate(CUarray *p_handle,
                      const CUDA_ARRAY_DESCRIPTOR *p_allocate_array);
int SCCudaArrayDestroy(CUarray h_array);
int SCCudaArrayGetDescriptor(CUDA_ARRAY_DESCRIPTOR *p_array_descriptor,
                             CUarray h_array);
int SCCudaDeviceGetByPCIBusId(CUdevice *dev, char *pci_bus_id);
int SCCudaDeviceGetPCIBusId(char *pci_bus_id, int len, CUdevice dev);
int SCCudaIpcCloseMemHandle(CUdeviceptr dptr);
int SCCudaIpcGetEventHandle(CUipcEventHandle *p_handle, CUevent event);
int SCCudaIpcGetMemHandle(CUipcMemHandle *p_handle, CUdeviceptr dptr);
int SCCudaIpcOpenEventHandle(CUevent *ph_event, CUipcEventHandle handle);
int SCCudaIpcOpenMemHandle(CUdeviceptr *pdptr, CUipcMemHandle handle,
                           unsigned int flags);
int SCCudaMemAlloc(CUdeviceptr *dptr, size_t byte_size);
int SCCudaMemAllocHost(void **pp, size_t byte_size);
int SCCudaMemAllocPitch(CUdeviceptr *dptr, size_t *p_pitch,
                        size_t width_in_bytes,
                        size_t height,
                        unsigned int element_size_bytes);
int SCCudaMemcpy(CUdeviceptr dst, CUdeviceptr src, size_t byte_count);
int SCCudaMemcpy2D(const CUDA_MEMCPY2D *p_copy);
int SCCudaMemcpy2DAsync(const CUDA_MEMCPY2D *p_copy, CUstream h_stream);
int SCCudaMemcpy2DUnaligned(const CUDA_MEMCPY2D *p_copy);
int SCCudaMemcpy3D(const CUDA_MEMCPY3D *p_copy);
int SCCudaMemcpy3DAsync(const CUDA_MEMCPY3D *p_copy, CUstream h_stream);
int SCCudaMemcpy3DPeer(const CUDA_MEMCPY3D_PEER *p_copy);
int SCCudaMemcpy3DPeerAsync(const CUDA_MEMCPY3D_PEER *p_copy,
                            CUstream h_stream);
int SCCudaMemcpyAsync(CUdeviceptr dst, CUdeviceptr src, size_t byte_count,
                      CUstream h_stream);
int SCCudaMemcpyAtoA(CUarray dst_array, size_t dst_offset,
                     CUarray src_array, size_t src_offset,
                     size_t byte_count);
int SCCudaMemcpyAtoD(CUdeviceptr dst_device, CUarray src_array,
                     size_t src_offset, size_t byte_count);
int SCCudaMemcpyAtoH(void *dst_host, CUarray src_array, size_t src_offset,
                     size_t byte_count);
int SCCudaMemcpyAtoHAsync(void *dst_host, CUarray src_array,
                          size_t src_offset, size_t byte_count,
                          CUstream h_stream);
int SCCudaMemcpyDtoA(CUarray dst_array, size_t dst_offset,
                     CUdeviceptr src_device, size_t byte_count);
int SCCudaMemcpyDtoD(CUdeviceptr dst_device, CUdeviceptr src_device,
                     size_t byte_count);
int SCCudaMemcpyDtoDAsync(CUdeviceptr dst_device, CUdeviceptr src_device,
                          size_t byte_count, CUstream h_stream);
int SCCudaMemcpyDtoH(void *dst_host, CUdeviceptr src_device,
                     size_t byte_count);
int SCCudaMemcpyDtoHAsync(void *dst_host, CUdeviceptr src_device,
                          size_t byte_count, CUstream h_stream);
int SCCudaMemcpyHtoA(CUarray dst_array, size_t dst_offset,
                     const void *src_host, size_t byte_count);
int SCCudaMemcpyHtoAAsync(CUarray dst_array, size_t dst_offset,
                          const void *src_host, size_t byte_count,
                          CUstream h_stream);
int SCCudaMemcpyHtoD(CUdeviceptr dst_device, const void *src_host,
                     size_t byte_count);
int SCCudaMemcpyHtoDAsync(CUdeviceptr dst_device, const void *src_host,
                          size_t byte_count, CUstream h_stream);
int SCCudaMemcpyPeer(CUdeviceptr dst_device, CUcontext dst_context,
                     CUdeviceptr src_device, CUcontext src_context,
                     size_t byte_count);
int SCCudaMemcpyPeerAsync(CUdeviceptr dst_device, CUcontext dst_context,
                          CUdeviceptr src_device, CUcontext src_context,
                          size_t byte_count, CUstream h_stream);
int SCCudaMemFree(CUdeviceptr dptr);
int SCCudaMemFreeHost(void *p);
int SCCudaMemGetAddressRange(CUdeviceptr *pbase, size_t *psize,
                             CUdeviceptr dptr);
int SCCudaMemGetInfo(size_t *free, size_t *total);
int SCCudaMemHostAlloc(void **pp, size_t byte_size, unsigned int flags);
int SCCudaMemHostGetDevicePointer(CUdeviceptr *pdptr, void *p,
                                  unsigned int flags);
int SCCudaMemHostGetFlags(unsigned int *p_flags, void *p);
int SCCudaMemHostRegister(void *p, size_t byte_size, unsigned int flags);
int SCCudaMemHostUnregister(void *p);
int SCCudaMemsetD16(CUdeviceptr dst_device, unsigned short us, size_t n);
int SCCudaMemsetD16Async(CUdeviceptr dst_device, unsigned short us,
                         size_t n, CUstream h_stream);
int SCCudaMemsetD2D16(CUdeviceptr dst_device, size_t dst_pitch,
                      unsigned short us, size_t width,
                      size_t height);
int SCCudaMemsetD2D16Async(CUdeviceptr dst_device, size_t dst_pitch,
                           unsigned short us, size_t width,
                           size_t height, CUstream h_stream);
int SCCudaMemsetD2D32(CUdeviceptr dst_device, size_t dst_pitch,
                      unsigned int ui, size_t width, size_t height);
int SCCudaMemsetD2D32Async(CUdeviceptr dst_device, size_t dst_pitch,
                           unsigned int ui, size_t width, size_t height,
                           CUstream h_stream);
int SCCudaMemsetD2D8(CUdeviceptr dst_device, size_t dst_pitch,
                     unsigned char uc, size_t width, size_t height);
int SCCudaMemsetD2D8Async(CUdeviceptr dst_device, size_t dst_pitch,
                          unsigned char uc, size_t width, size_t height,
                          CUstream h_stream);
int SCCudaMemsetD32(CUdeviceptr dst_device, unsigned int ui, size_t n);
int SCCudaMemsetD32Async(CUdeviceptr dst_device, unsigned int ui,
                         size_t n, CUstream h_stream);
int SCCudaMemsetD8(CUdeviceptr dst_device, unsigned char uc, size_t n);
int SCCudaMemsetD8Async(CUdeviceptr dst_device, unsigned char uc,
                        size_t n, CUstream h_stream);

/***************************Unified_Addressing_API****************************/

int SCCudaPointerGetAttribute(void *data, CUpointer_attribute attribute,
                              CUdeviceptr ptr);

/***************************Stream_Management_API****************************/
int SCCudaStreamCreate(CUstream *ph_stream, unsigned int flags);
int SCCudaStreamDestroy(CUstream h_stream);
int SCCudaStreamQuery(CUstream h_stream);
int SCCudaStreamSynchronize(CUstream h_stream);
int SCCudaStreamWaitEvent(CUstream h_stream, CUevent h_event,
                          unsigned int flags);

/***************************Event_Management_API*****************************/
int SCCudaEventCreate(CUevent *ph_event, unsigned int flags);
int SCCudaEventDestroy(CUevent h_event);
int SCCudaEventElapsedTime(float *p_milli_seconds, CUevent h_start,
                           CUevent h_end);
int SCCudaEventQuery(CUevent h_event);
int SCCudaEventRecord(CUevent h_event, CUstream h_stream);
int SCCudaEventSynchronize(CUevent h_event);

/***********************Execution_Control_Management_API***********************/
int SCCudaFuncGetAttribute(int *pi, CUfunction_attribute attrib,
                           CUfunction hfunc);
int SCCudaFuncSetCacheConfig(CUfunction hfunc, CUfunc_cache config);
int SCCudaLaunchKernel(CUfunction f, unsigned int grid_dim_x,
                       unsigned int grid_dim_y, unsigned int grid_dim_z,
                       unsigned int block_dim_x, unsigned int block_dim_y,
                       unsigned int block_dim_z, unsigned int shared_mem_bytes,
                       CUstream h_stream, void **kernel_params, void **extra);
int SCCudaFuncSetBlockShape(CUfunction hfunc, int x, int y, int z);
int SCCudaFuncSetSharedSize(CUfunction hfunc, unsigned int bytes);
int SCCudaLaunch(CUfunction f);
int SCCudaLaunchGrid(CUfunction f, int grid_width, int grid_height);
int SCCudaLaunchGridAsync(CUfunction f, int grid_width, int grid_height,
                          CUstream h_stream);
int SCCudaParamSetf(CUfunction h_func, int offset, float value);
int SCCudaParamSeti(CUfunction h_func, int offset, unsigned int value);
int SCCudaParamSetSize(CUfunction h_func, unsigned int num_bytes);
int SCCudaParamSetTexRef(CUfunction h_func, int tex_unit, CUtexref h_tex_ref);
int SCCudaParamSetv(CUfunction h_func, int offset, void *ptr,
                    unsigned int num_bytes);

/*********************Texture_Reference_Management_API***********************/
int SCCudaTexRefCreate(CUtexref *p_tex_ref);
int SCCudaTexRefDestroy(CUtexref h_tex_ref);
int SCCudaTexRefGetAddress(CUdeviceptr *pdptr, CUtexref h_tex_ref);
int SCCudaTexRefGetAddressMode(CUaddress_mode *pam, CUtexref h_tex_ref,
                               int dim);
int SCCudaTexRefGetArray(CUarray *ph_array, CUtexref h_tex_ref);
int SCCudaTexRefGetFilterMode(CUfilter_mode *pfm, CUtexref h_tex_ref);
int SCCudaTexRefGetFlags(unsigned int *p_flags, CUtexref h_tex_ref);
int SCCudaTexRefGetFormat(CUarray_format *p_format, int *p_num_channels,
                          CUtexref h_tex_ref);
int SCCudaTexRefSetAddress(size_t *byte_offset, CUtexref h_tex_ref,
                           CUdeviceptr dptr, unsigned int bytes);
int SCCudaTexRefSetAddress2D(CUtexref h_tex_ref,
                             const CUDA_ARRAY_DESCRIPTOR *desc,
                             CUdeviceptr dptr, unsigned int pitch);
int SCCudaTexRefSetAddressMode(CUtexref h_tex_ref, int dim, CUaddress_mode am);
int SCCudaTexRefSetArray(CUtexref h_tex_ref, CUarray h_array,
                         unsigned int flags);
int SCCudaTexRefSetFilterMode(CUtexref h_tex_ref, CUfilter_mode fm);
int SCCudaTexRefSetFlags(CUtexref h_tex_ref, unsigned int flags);
int SCCudaTexRefSetFormat(CUtexref h_tex_ref, CUarray_format fmt,
                          int num_packed_components);

/************************Cuda_Env_Initialization_API*************************/
int SCCudaInitCudaEnvironment(void);

/********************************Cuda_Utility********************************/
void SCCudaListCards(void);
int SCCudaIsCudaDeviceIdValid(int cuda_device_id);

/********************************Unittests***********************************/
void SCCudaRegisterTests(void);

#endif /* __SC_CUDA_SUPPORT__ */
#endif /* __UTIL_CUDA_H__ */
