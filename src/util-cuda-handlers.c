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
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

/* compile in, only if we have a CUDA enabled device on the machine, with the
 * toolkit and the driver installed */
#ifdef __SC_CUDA_SUPPORT__

#include "suricata-common.h"

#include "util-error.h"
#include "util-debug.h"
#include "conf.h"
#include "util-cuda.h"
#include "util-cuda-handlers.h"

/* file only exists if cuda is enabled */
#include "cuda-ptxdump.h"

static SCMutex mutex = PTHREAD_MUTEX_INITIALIZER;

/************************conf file profile section**********************/

typedef struct CudaHL_ConfProfile_ {
    char *name;
    void *ctx;
    void (*Free)(void *);

    struct CudaHL_ConfProfile_ *next;
} CudaHL_ConfProfile;

static CudaHL_ConfProfile *conf_profiles = NULL;

void CudaHL_AddCudaProfileFromConf(const char *name,
                                   void *(*Callback)(ConfNode *node),
                                   void (*Free)(void *))
{
    /* we don't do data validation */
    SCMutexLock(&mutex);

    CudaHL_ConfProfile *tmp_cp = conf_profiles;
    while (tmp_cp != NULL && strcasecmp(name, tmp_cp->name) != 0)
        tmp_cp = tmp_cp->next;

    if (tmp_cp != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "We already have a cuda conf "
                   "profile by the name \"%s\" registered.", name);
        exit(EXIT_FAILURE);
    }

    char tmp[200];
    int r = snprintf(tmp, sizeof(tmp), "%s%s", "cuda.", name);
    if (r < 0) {
        SCLogError(SC_ERR_FATAL, "snprintf failure.");
        exit(EXIT_FAILURE);
    } else if (r > (int)sizeof(tmp)) {
        SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
        exit(EXIT_FAILURE);
    }
    void *ctx = Callback(ConfGetNode(tmp));
    if (ctx == NULL) {
        SCMutexUnlock(&mutex);
        return;
    }

    CudaHL_ConfProfile *new_cp = SCMalloc(sizeof(CudaHL_ConfProfile));
    if (new_cp == NULL)
        exit(EXIT_FAILURE);
    memset(new_cp, 0, sizeof(CudaHL_ConfProfile));
    new_cp->name = SCStrdup(name);
    if (new_cp->name == NULL)
        exit(EXIT_FAILURE);
    new_cp->ctx = ctx;
    new_cp->Free = Free;

    if (conf_profiles == NULL) {
        conf_profiles = new_cp;
    } else {
        new_cp->next = conf_profiles;
        conf_profiles = new_cp;
    }

    SCMutexUnlock(&mutex);
    return;
}

void *CudaHL_GetCudaProfile(const char *name)
{
    SCMutexLock(&mutex);

    CudaHL_ConfProfile *tmp_cp = conf_profiles;
    while (tmp_cp != NULL && strcasecmp(name, tmp_cp->name) != 0)
        tmp_cp = tmp_cp->next;

    if (tmp_cp == NULL) {
        SCMutexUnlock(&mutex);
        return NULL;
    }

    SCMutexUnlock(&mutex);
    return tmp_cp->ctx;
}

void CudaHL_FreeProfiles(void)
{
    SCMutexLock(&mutex);

    CudaHL_ConfProfile *tmp = conf_profiles;
    while (tmp != NULL) {
        CudaHL_ConfProfile *curr = tmp;
        tmp = tmp->next;
        SCFree(curr->name);
        if (curr->Free != NULL)
            curr->Free(curr->ctx);
        SCFree(curr);
    }

    SCMutexUnlock(&mutex);
    return;
}

/*******************cuda context related data section*******************/

/* we use a concept where every device on the gpu has only 1 context.  If
 * a section in the engine wants to use a device and tries to open a context
 * on it, we first check if a context is already created for the device and if
 * so we return it.  If not we create a new one and update with the entry */

static CUcontext *cuda_contexts = NULL;
static int no_of_cuda_contexts = 0;

typedef struct CudaHL_ModuleData_ {
    char *name;
    void *data;

    struct CudaHL_ModuleData_ *next;
} CudaHL_ModuleData;

typedef struct CudaHL_Module_ {
    char *name;

    /* the context used by this module */
    CUcontext context;
    /* the device on which the above context was created */
    int device_id;
    CudaHL_ModuleData *module_data;

    struct CudaHL_Module_ *next;
} CudaHL_Module;

static CudaHL_Module *cudahl_modules = NULL;

CUcontext CudaHL_Module_GetContext(const char *name, int device_id)
{
    SCMutexLock(&mutex);

    CudaHL_Module *module = cudahl_modules;
    while (module != NULL && strcasecmp(module->name, name) != 0)
        module = module->next;
    if (module != NULL) {
        if (module->device_id != device_id) {
            SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Module already "
                       "registered, but the new device_id is different "
                       "from the already registered device_id.");
            exit(EXIT_FAILURE);
        }
        SCMutexUnlock(&mutex);
        return module->context;
    }

    CudaHL_Module *new_module = SCMalloc(sizeof(CudaHL_Module));
    if (new_module == NULL)
        exit(EXIT_FAILURE);
    memset(new_module, 0, sizeof(CudaHL_Module));
    new_module->device_id = device_id;
    new_module->name = SCStrdup(name);
    if (new_module->name == NULL)
        exit(EXIT_FAILURE);
    if (cudahl_modules == NULL) {
        cudahl_modules = new_module;
    } else {
        new_module->next = cudahl_modules;
        cudahl_modules = new_module;
    }

    if (no_of_cuda_contexts <= device_id) {
        cuda_contexts = SCRealloc(cuda_contexts, sizeof(CUcontext) * (device_id + 1));
        memset(cuda_contexts + no_of_cuda_contexts, 0,
               sizeof(CUcontext) * ((device_id + 1) - no_of_cuda_contexts));
        no_of_cuda_contexts = device_id + 1;
    }

    if (cuda_contexts[device_id] == 0) {
        SCCudaDevices *devices = SCCudaGetDeviceList();
        if (SCCudaCtxCreate(&cuda_contexts[device_id], CU_CTX_SCHED_BLOCKING_SYNC,
                            devices->devices[device_id]->device) == -1) {
            printf("ctxcreate failure\n");
            exit(EXIT_FAILURE);
        }
    }
    new_module->context = cuda_contexts[device_id];

    SCMutexUnlock(&mutex);
    return cuda_contexts[device_id];
}

void CudaHL_Module_StoreData(const char *module_name,
                             const char *data_name, void *data_ptr)
{
    SCMutexLock(&mutex);

    CudaHL_Module *module = cudahl_modules;
    while (module != NULL && strcasecmp(module->name, module_name) != 0)
        module = module->next;
    if (module == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Trying to retrieve data "
                   "\"%s\" from module \"%s\" that hasn't been registered "
                   "yet.",  module_name, data_name);
        exit(EXIT_FAILURE);
    }

    CudaHL_ModuleData *data = module->module_data;
    while (data != NULL && (strcasecmp(data_name, data->name) != 0)) {
        data = data->next;
    }
    if (data != NULL) {
        SCLogWarning(SC_ERR_CUDA_HANDLER_ERROR, "Data \"%s\" already "
                     "registered for this module \"%s\".", data_name,
                     module_name);
        SCMutexUnlock(&mutex);
        return;
    }

    CudaHL_ModuleData *new_data = SCMalloc(sizeof(CudaHL_ModuleData));
    if (new_data == NULL)
        exit(EXIT_FAILURE);
    memset(new_data, 0, sizeof(CudaHL_ModuleData));
    new_data->name = SCStrdup(data_name);
    if (new_data->name == NULL)
        exit(EXIT_FAILURE);
    new_data->data = data_ptr;

    if (module->module_data == NULL) {
        module->module_data = new_data;
    } else {
        new_data->next = module->module_data;
        module->module_data = new_data;
    }

    SCMutexUnlock(&mutex);
    return;
}

void *CudaHL_Module_GetData(const char *module_name, const char *data_name)
{
    SCMutexLock(&mutex);

    CudaHL_Module *module = cudahl_modules;
    while (module != NULL && strcasecmp(module->name, module_name) != 0)
        module = module->next;
    if (module == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Trying to retrieve data "
                   "\"%s\" from module \"%s\" that hasn't been registered "
                   "yet.",  module_name, data_name);
        SCMutexUnlock(&mutex);
        return NULL;
    }

    CudaHL_ModuleData *data = module->module_data;
    while (data != NULL && (strcasecmp(data_name, data->name) != 0)) {
        data = data->next;
    }
    if (data == NULL) {
        SCLogInfo("Data \"%s\" already registered for this module \"%s\".  "
                  "Returning it.", data_name, module_name);
        SCMutexUnlock(&mutex);
        return NULL;
    }

    SCMutexUnlock(&mutex);
    return data->data;
}

int CudaHL_GetCudaModule(CUmodule *p_module, const char *ptx_image)
{
#define CudaHL_GetCudaModule_BUFFER_EXTRA_SPACE 15

    /* select the ptx image based on the compute capability supported by all
     * devices (i.e. the lowest) */
    char *image = SCMalloc(strlen(ptx_image) + CudaHL_GetCudaModule_BUFFER_EXTRA_SPACE);
    if (unlikely(image == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(image, 0x00, strlen(ptx_image) + CudaHL_GetCudaModule_BUFFER_EXTRA_SPACE);

    int major = INT_MAX;
    int minor = INT_MAX;
    SCCudaDevices *devices = SCCudaGetDeviceList();
    for (int i = 0; i < devices->count; i++){
        if (devices->devices[i]->major_rev < major){
            major = devices->devices[i]->major_rev;
            minor = devices->devices[i]->minor_rev;
        }
        if (devices->devices[i]->major_rev == major &&
            devices->devices[i]->minor_rev < minor){
            minor = devices->devices[i]->minor_rev;
        }
    }
    snprintf(image,
             strlen(ptx_image) + CudaHL_GetCudaModule_BUFFER_EXTRA_SPACE,
             "%s_sm_%u%u",
             ptx_image, major, minor);

    /* we don't have a cuda module associated with this module.  Create a
     * cuda module, update the module with this cuda module reference and
     * then return the module refernce back to the calling function using
     * the argument */
    SCLogDebug("Loading kernel module: %s\n",image);
    if (SCCudaModuleLoadData(p_module, (void *)SCCudaPtxDumpGetModule(image)) == -1)
        goto error;
    SCFree(image);

    return 0;
 error:
    SCFree(image);
    return -1;
}


#endif /*  __SC_CUDA_SUPPORT__ */
