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
 * \file Provides cuda utility functions.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

#include <cuda.h>

#ifndef __UTIL_MPM_CUDA_HANDLERS_H__
#define __UTIL_MPM_CUDA_HANDLERS_H__

typedef enum {
    SC_CUDA_HL_MTYPE_RULE_NONE = -1,
    SC_CUDA_HL_MTYPE_RULE_CONTENTS = 0,
    SC_CUDA_HL_MTYPE_RULE_URICONTENTS,
    SC_CUDA_HL_MTYPE_APP_LAYER,
    SC_CUDA_HL_MTYPE_RULE_CUSTOM,
    SC_CUDA_HL_MTYPE_MAX,
} SCCudaHlModuleType;

typedef struct SCCudaHlModuleDevicePointer_ {
    /* device pointer name.  This is a primary key.  For the same module you
     * can't register different device pointers */
    char *name;
    CUdeviceptr d_ptr;

    struct SCCudaHlModuleDevicePointer_ *next;
} SCCudaHlModuleDevicePointer;

typedef struct SCCudaHlModuleCUmodule_ {
    /* Handle for this CUmodule.  This has to be first obtained from the
     * call to SCCudaHlGetCudaModule() or SCCudaHlGetCudaModuleFromFile() */
    int cuda_module_handle;

    CUmodule cuda_module;
    SCCudaHlModuleDevicePointer *device_ptrs;

    struct SCCudaHlModuleCUmodule_ *next;
} SCCudaHlModuleCUmodule;

typedef struct SCCudaHlModuleData_ {
    /* The unique module handle.  This has to be first obtained from the
     * call to SCCudaHlGetUniqueHandle() */
    const char *name;
    int handle;

    CUcontext cuda_context;
    SCCudaHlModuleCUmodule *cuda_modules;
    void *(*SCCudaHlDispFunc)(void *);

    struct SCCudaHlModuleData_ *next;
} SCCudaHlModuleData;

/**
 * \brief Used to hold the cuda configuration from our conf yaml file
 */
typedef struct SCCudaHlCudaProfile_ {
    /* profile name.  Should be unique */
    char *name;
    /* the data associated with this profile */
    void *data;

    struct SCCudaHlCudaProfile_ *next;
} SCCudaHlCudaProfile;

void SCCudaHlGetYamlConf(void);
void *SCCudaHlGetProfile(char *);
void SCCudaHlCleanProfiles(void);
void SCCudaHlBackupRegisteredProfiles(void);
void SCCudaHlRestoreBackupRegisteredProfiles(void);

int SCCudaHlGetCudaContext(CUcontext *, char *, int);
int SCCudaHlGetCudaModule(CUmodule *, const char *, int);
int SCCudaHlGetCudaModuleFromFile(CUmodule *, const char *, int);
int SCCudaHlGetCudaDevicePtr(CUdeviceptr *, const char *, size_t, void *, int, int);
int SCCudaHlFreeCudaDevicePtr(const char *, int, int);
int SCCudaHlRegisterDispatcherFunc(void *(*SCCudaHlDispFunc)(void *), int);

SCCudaHlModuleData *SCCudaHlGetModuleData(uint8_t);
const char *SCCudaHlGetModuleName(int);
int SCCudaHlGetModuleHandle(const char *);

int SCCudaHlRegisterModule(const char *);
int SCCudaHlDeRegisterModule(const char *);
void SCCudaHlDeRegisterAllRegisteredModules(void);

int SCCudaHlPushCudaContextFromModule(const char *);

int SCCudaHlTestEnvCudaContextInit(void);
int SCCudaHlTestEnvCudaContextDeInit(void);

void SCCudaHlProcessPacketWithDispatcher(Packet *, DetectEngineThreadCtx *,
                                         void *);
void SCCudaHlProcessUriWithDispatcher(uint8_t *, uint16_t, DetectEngineThreadCtx *,
                                      void *);

#endif /* __UTIL_CUDA_HANDLERS__ */

#endif /* __SC_CUDA_SUPPORT__ */
