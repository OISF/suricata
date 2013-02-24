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
 *
 *       A module in the engine that wants to use the cuda engine, might need
 *       some utilities to handle contexts, modules and device_pointers.
 *
 *       Let us say we have a module that needs to share a context among various
 *       sections inside it.  To enable it share contexts within various
 *       sections the module first register itself using the function
 *       SCCudaHlRegisterModule() and receive a unique handle.  Once it has
 *       retrieved the unique handle, it can then call SCCudaHlGetCudaContext(),
 *       with the handle.  A new cuda context would be created and the internal
 *       data structures would be updated to associate this newly created
 *       context with this module handle.  Any future calls to
 *       SCCudaHlGetCudaContext() with the same handle will return the
 *       cuda_context, which has already been created and associated with the
 *       handle.  Any calls to SCCudaHlGetCudaContext() with a new handle,
 *       would result in the creation of a new cuda context.
 *
 *       Similarly if we want to create a new cuda_module against a particular
 *       context, we can call SCCudaHlGetCudaModule() with the handle and it
 *       should work as above.  Please do note that a cuda module can't be
 *       created against a handle using SCCudaHlGetCudaModule(), unless
 *       a cuda_context has been associated with the handle by a previous call
 *       to SCCudaHlGetCudaContext().  Also do note that, a cuda module is
 *       created against a cuda context that is associated with the current
 *       host thread.  So do takecare to associate your host thread with the
 *       cuda_context that is associated with the handle, against which you
 *       want to call SCCudaHlGetCudaModule().
 *
 * \todo Provide support for multiple cuda context storage, although it is
 *       highly unlikely we would need this feature.
 *
 *       We also need to use a mutex for module_data.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "decode.h"

#include "util-cuda.h"
#include "util-cuda-handlers.h"
#include "util-mpm-b2g-cuda.h"

#include "tmqh-simple.h"

#include "conf.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "packet-queue.h"
#include "util-mpm.h"

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

/* file only exists if cuda is enabled */
#include "cuda-ptxdump.h"

static SCCudaHlModuleData *module_data = NULL;

static uint8_t module_handle = 1;

/* holds the parsed cuda configuration from our yaml file */
static SCCudaHlCudaProfile *cuda_profiles = NULL;

/* used by unittests only */
static SCCudaHlCudaProfile *backup_cuda_profiles = NULL;

/**
 * \brief Needed by unittests.  Backup the existing cuda profile in handlers.
 */
void SCCudaHlBackupRegisteredProfiles(void)
{
    backup_cuda_profiles = cuda_profiles;
    cuda_profiles = NULL;

    return;
}

/**
 * \brief Needed by unittests.  Restore the previous backup of handlers'
 *        cuda profile.
 */
void SCCudaHlRestoreBackupRegisteredProfiles(void)
{
    cuda_profiles = backup_cuda_profiles;

    return;
}

/**
 * \brief Parse the "cuda" subsection config from our conf file.
 */
void SCCudaHlGetYamlConf(void)
{
    SCCudaHlCudaProfile *profile = NULL;

    /* "mpm" profile, found under "cuda.mpm" in the conf file */
    profile = SCMalloc(sizeof(SCCudaHlCudaProfile));
    if (unlikely(profile == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(profile, 0, sizeof(SCCudaHlCudaProfile));
    profile->name = "mpm";
    profile->data = MpmCudaConfParse();
    if (cuda_profiles == NULL) {
        cuda_profiles = profile;
    } else {
        profile->next = cuda_profiles;
        cuda_profiles = profile;
    }

    return;
}

/**
 * \brief Get a particular cuda profile specified as arg.
 *
 * \param profile_name Name of the the profile to retrieve.
 *
 * \retval Data associated with the profile.
 */
void *SCCudaHlGetProfile(char *profile_name)
{
    SCCudaHlCudaProfile *profile = cuda_profiles;

    if (cuda_profiles == NULL ) {
        SCLogInfo("No cuda profile registered");
        return NULL;
    }

    if (profile_name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "argument profile NULL");
        return NULL;
    }

    while (profile != NULL && strcasecmp(profile->name, profile_name) != 0) {
        profile = profile->next;
    }

    if (profile != NULL)
        return profile->data;
    else
        return NULL;
}

/**
 * \brief Clean the cuda profiles, held in cuda_profiles.
 */
void SCCudaHlCleanProfiles(void)
{
    SCCudaHlCudaProfile *profile = cuda_profiles;
    SCCudaHlCudaProfile *profile_next = NULL;

    while (profile != NULL) {
        profile_next = profile->next;
        if (profile->data != NULL) {
            if (strcasecmp(profile->name, "mpm") == 0) {
                MpmCudaConfCleanup(profile->data);
            }
        }
        SCFree(profile);
        profile = profile_next;
    }
    cuda_profiles = NULL;

    return;
}

/**
 * \internal
 * \brief Get a unique handle for a new module registration.  This new handle
 *        returned uniquely represents a module.  All future calls to functions
 *        requires suppling this handle.
 *
 * \param module_handle A unique module handle that needs to used to refer
 *                      to data(like cuda_contexts, cuda_modules, device pointers).
 */
static int SCCudaHlGetUniqueHandle(void)
{
    return module_handle++;
}

/**
 * \internal
 * \brief Returns a SCCudaHlModuleData instance from the global data store
 *        that matches the handle sent as arg.
 *
 * \param handle The handle for the SCCudaHlModuleData that has to be returned.
 *
 * \retval data The SCCudaHlModuleData instance that matches the handle.
 */
SCCudaHlModuleData *SCCudaHlGetModuleData(uint8_t handle)
{
    SCCudaHlModuleData *data = module_data;

    if (data == NULL)
        return NULL;

    while (data != NULL && data->handle != handle) {
        data = data->next;
    }

    return data;
}

/**
 * \internal
 * \brief Returns a SCCudaHlModuleCUmodule instance that matches the cumodule_handle
 *        from a SCCudaHlModuleData.
 *
 * \param data             The module data this CUmodule belongs to, obtained by a call to
 *                         SCCudaHlGetModuleData()
 * \param cumodule_handle  The handle for the SCCudaHlModuleCUmodule that has to be returned.
 *
 * \retval The SCCudaHlModuleCUmodule instance that matches the handle.
 */
static SCCudaHlModuleCUmodule *SCCudaHlGetModuleCUmodule(SCCudaHlModuleData *data, uint8_t cumodule_handle)
{
    SCCudaHlModuleCUmodule *cumodule = NULL;

    if (data == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Argument data cannot be NULL");
        return NULL;
    }

    cumodule = data->cuda_modules;
    if (cumodule == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR,
                   "No cumodule registered by the cumodule_handle %"PRIu8, cumodule_handle);
        return NULL;
    }

    while (cumodule != NULL && cumodule->cuda_module_handle != cumodule_handle) {
        cumodule = cumodule->next;
    }

    return cumodule;
}

/**
 * \brief Returns a cuda_module against the handle in the argument.
 *
 *        If a cuda_module is not present for a handle, it is created
 *        and associated with this handle and the cuda_module is returned
 *        in the argument.
 *
 * \param p_module  Pointer to a cuda module instance that should be updated
 *                  with a cuda module.
 * \param handle    A unique handle which identifies a module.  Obtained from
 *                  a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  A unique handle within the module that is associated with the
 *          loaded CUmodule. Needed for future API calls.
 * \retval  -1 on failure.
 */
int SCCudaHlGetCudaModuleFromFile(CUmodule *p_module, const char *filename, int handle)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaHlModuleCUmodule *new_module_cumodule = NULL;
    SCCudaHlModuleCUmodule *module_cumodules = NULL;

    if (p_module == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "p_module NULL");
        return -1;
    }

    /* check if the particular module that wants a CUDA module is already
     * registered or not.  If it is registered, check if a context has
     * been associated with the module.  If yes, then we can go ahead and
     * create a cuda module and associate it with the module referenced by
     * the handle in the functions arguments. If no, log warning and get
     * out of here */
    if ( ((data = SCCudaHlGetModuleData(handle)) == NULL) ||
         (data->cuda_context == 0)) {
        SCLogDebug("Module not registered or no cuda context associated with "
                   "this module.  You can't create a CUDA module without"
                   "associating a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        return -1;
    }

    /* Register new CUmodule in the module */
    new_module_cumodule = SCMalloc(sizeof(SCCudaHlModuleCUmodule));
    if (unlikely(new_module_cumodule == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(new_module_cumodule, 0, sizeof(SCCudaHlModuleCUmodule));

    /* Create a cuda module, update the module with this cuda module reference
     * and then return the module reference back to the calling function using
     * the argument */
    if (SCCudaModuleLoad(p_module, filename) == -1)
        goto error;

    new_module_cumodule->cuda_module = p_module[0];
    new_module_cumodule->cuda_module_handle = SCCudaHlGetUniqueHandle();

    /* insert it into the cuda_modules list for the module instance */
    if (data->cuda_modules == NULL) {
        data->cuda_modules = new_module_cumodule;
        return new_module_cumodule->cuda_module_handle;
    }

    module_cumodules = data->cuda_modules;
    while (module_cumodules->next != NULL)
        module_cumodules = module_cumodules->next;
    module_cumodules->next = new_module_cumodule;

    return new_module_cumodule->cuda_module_handle;

 error:
    return -1;
}

/**
 * \brief Returns a cuda context against the handle in the argument.
 *
 *        If a cuda_context is not present for a handle, it is created
 *        and associated with this handle and the context is returned
 *        in the argument.  If a cuda_context is already present for
 *        a handle, it is returned.
 *
 * \param p_context    Pointer to a cuda context instance that should be updated
 *                     with a cuda context.
 * \param cuda_profile The cuda profile, supplied as a string.
 * \param handle       A unique handle which identifies a module.  Obtained from
 *                     a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlGetCudaContext(CUcontext *p_context, char *cuda_profile, int handle)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaDevices *devices = NULL;

    if (p_context == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments.  "
                   "p_context NULL");
        return -1;
    }

    /* check if the particular module that wants a CUDA context
     * is already registered or not.  If it is not registered
     * log a warning and get out of here */
    if ( (data = SCCudaHlGetModuleData(handle)) == NULL) {
        SCLogDebug("Module not registered.  You can't create a CUDA context "
                   "without registering a module first.  To use this "
                   "registration facility, first register a module using "
                   "SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module hanle using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        return -1;
    }

    if (data->cuda_context != 0) {
        p_context[0] = data->cuda_context;
        return 0;
    }

    int device_id = SC_CUDA_DEFAULT_DEVICE;
    if (cuda_profile != NULL) {
        /* Get default log level and format. */
        MpmCudaConf *profile = SCCudaHlGetProfile(cuda_profile);
        if (profile != NULL) {
            if (SCCudaIsCudaDeviceIdValid(profile->device_id)) {
                device_id = profile->device_id;
            } else {
                SCLogError(SC_ERR_CUDA_ERROR, "Invalid device id \"%d\" supplied.  "
                           "Using the first device.", profile->device_id);
            }
        }
    }

    /* Get the device list for this CUDA platform and create a new cuda context */
    devices = SCCudaGetDeviceList();
    if (SCCudaCtxCreate(p_context, 0, devices->devices[device_id]->device) == -1)
        goto error;
    data->cuda_context = p_context[0];

    return 0;

 error:
    return -1;
}

/**
 * \brief Returns a cuda_module against the handle in the argument.
 *
 *        If a cuda_module is not present for a handle, it is created
 *        and associated with this handle and the cuda_module is returned
 *        in the argument.
 *
 * \param p_module The loaded CUmodule that is returned.
 * \param ptx_image Name of the module source file, w/o the .cu extension
 * \param handle    A unique handle which identifies a module.  Obtained from
 *                  a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  A unique handle within the module that is associated with the
 *          loaded CUmodule. Needed for future API calls.
 * \retval  -1 on failure.
 */
int SCCudaHlGetCudaModule(CUmodule *p_module, const char *ptx_image, int handle)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaHlModuleCUmodule *new_module_cumodule = NULL;
    SCCudaHlModuleCUmodule *module_cumodules = NULL;

    if (p_module == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "p_module NULL");
        return -1;
    }

    /* check if the particular module that wants a CUDA module is already
     * registered or not.  If it is registered, check if a context has
     * been associated with the module.  If yes, then we can go ahead and
     * create a cuda module and associate it with the module referenced by
     * the handle in the functions arguments. If no, log warning and get
     * out of here */
    if ( ((data = SCCudaHlGetModuleData(handle)) == NULL) ||
         (data->cuda_context == 0)) {
        SCLogDebug("Module not registered or no cuda context associated with "
                   "this module.  You can't create a CUDA module without"
                   "associating a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        return -1;
    }

    /* Register new CUmodule in the module */
    new_module_cumodule = SCMalloc(sizeof(SCCudaHlModuleCUmodule));
    if (unlikely(new_module_cumodule == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(new_module_cumodule, 0, sizeof(SCCudaHlModuleCUmodule));

    /* select the ptx image based on the compute capability supported by all
     * devices (i.e. the lowest) */
    char* image = SCMalloc(strlen(ptx_image)+15);
    if (unlikely(image == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(image, 0x0, strlen(ptx_image)+15);

    int major = INT_MAX;
    int minor = INT_MAX;
    SCCudaDevices *devices = SCCudaGetDeviceList();
    int i=0;
    for (; i<devices->count; i++){
        if (devices->devices[i]->major_rev < major){
            major = devices->devices[i]->major_rev;
            minor = devices->devices[i]->minor_rev;
        }
        if (devices->devices[i]->major_rev == major &&
            devices->devices[i]->minor_rev < minor){
            minor = devices->devices[i]->minor_rev;
        }
    }
    snprintf(image, strlen(ptx_image) + 15, "%s_sm_%u%u",
             ptx_image, major, minor);

    /* we don't have a cuda module associated with this module.  Create a
     * cuda module, update the module with this cuda module reference and
     * then return the module refernce back to the calling function using
     * the argument */
    SCLogDebug("Loading kernel module: %s\n",image);
    if (SCCudaModuleLoadData(p_module, (void *)SCCudaPtxDumpGetModule(image)) == -1)
        goto error;
    SCFree(image);

    new_module_cumodule->cuda_module = p_module[0];
    new_module_cumodule->cuda_module_handle = SCCudaHlGetUniqueHandle();

    /* insert it into the cuda_modules list for the module instance */
    if (data->cuda_modules == NULL) {
        data->cuda_modules = new_module_cumodule;
        return new_module_cumodule->cuda_module_handle;
    }

    module_cumodules = data->cuda_modules;
    while (module_cumodules->next != NULL)
        module_cumodules = module_cumodules->next;
    module_cumodules->next = new_module_cumodule;

    return new_module_cumodule->cuda_module_handle;

 error:
    SCFree(image);
    return -1;
}

/**
 * \brief Verify if a device pointer by a particular name is registered under
 *        a module.  If it is registered, return this device pointer instance
 *        back; else return NULL.
 *
 * \param data Pointer to the module SCCudaHlModuleData instance which has to
 *             checked for the registration of the device pointer.
 * \param name Name of the device pointer to search in the module.
 *
 * \retval module_device_ptr Pointer to the device pointer instance on finding
 *                           it; NULL otherwise.
 */
SCCudaHlModuleDevicePointer *SCCudaHlCudaDevicePtrAvailable(SCCudaHlModuleCUmodule *cumodule,
                                                            const char *name)
{
    SCCudaHlModuleDevicePointer *module_device_ptr = cumodule->device_ptrs;

    while (module_device_ptr != NULL &&
           strcmp(module_device_ptr->name, name) != 0) {
        module_device_ptr = module_device_ptr->next;
    }

    return module_device_ptr;
}

/**
 * \brief Returns a cuda_device_pointer against the handle in the argument.
 *
 *        If a device pointer by the name \"name\"  is not registered for the
 *        handle, it is created and associated with this handle and cuda mem is
 *        alloted and the cuda_device_pointer is returned in the argument.
 *        If a device pointer by the name \"name\" is already registered with
 *        the handle, the cuda_device_pointer is returned in the argument.
 *
 * \param device_ptr Pointer to the device pointer instance which should be
 *                   with the cuda_device_pointer that has to be returned back.
 * \param name       Name of the device pointer by which we have to search
 *                   module for its existance.
 * \param size       Size of the cuda device memory to be alloted.
 * \param host_ptr   If any host memory has to be transferred to the cuda device
 *                   memory, it can sent using this argument.  host_ptr should
 *                   hold atleast size bytes in memory.
 * \param handle     A unique handle which identifies a module.  Obtained from
 *                   a call to SCCudaHlGetUniqueHandle().
 * \param cumodule_handle   A handle that identifies the CUmodule within the above module.
 *                   Obtained from a call to SCCudaHlGetCudaModule() or
 *                   SCCudaHlGetCudaModuleFromFile().
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlGetCudaDevicePtr(CUdeviceptr *device_ptr, const char *name,
                             size_t size, void *host_ptr, int handle,
                             int cumodule_handle)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaHlModuleCUmodule *cumodule = NULL;
    SCCudaHlModuleDevicePointer *new_module_device_ptr = NULL;
    SCCudaHlModuleDevicePointer *module_device_ptr = NULL;

    if (device_ptr == NULL || name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "device_ptr is NULL or name is NULL");
        goto error;
    }

    /* check if the particular module that wants to allocate device memory is
     * already registered or not.  If it is registered, check if a context has
     * been associated with the module.  If yes, then we can go ahead and
     * create the device memory or return the reference to the device memory if
     * we already have the device memory associated with the module.  If no, "
     * log warning and get out of here */
    if ( ((data = SCCudaHlGetModuleData(handle)) == NULL) ||
         (data->cuda_context == 0)) {
        SCLogDebug("Module not registered or no cuda context associated with "
                   "this module.  You can't create a CUDA module without"
                   "associating a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        goto error;
    }

    if ( (cumodule = SCCudaHlGetModuleCUmodule(data, cumodule_handle)) == NULL ) {
        SCLogDebug("CUmodule not registered with the module. Before you can request"
                   "a device pointer for a module you need to load the CUmodule into"
                   "the engine module using SCCudaHlGetCudaModule() or"
                   "SCCudaHlGetCudaModuleFromFile().");
        goto error;
    }

    /* if we already have a device pointer registered by this name return the
     * cuda device pointer instance */
    if ( (module_device_ptr = SCCudaHlCudaDevicePtrAvailable(cumodule, name)) != NULL) {
        device_ptr[0] = module_device_ptr->d_ptr;
        return 0;
    }

    new_module_device_ptr = SCMalloc(sizeof(SCCudaHlModuleDevicePointer));
    if (unlikely(new_module_device_ptr == NULL))
        goto error;
    memset(new_module_device_ptr, 0, sizeof(SCCudaHlModuleDevicePointer));

    if ( (new_module_device_ptr->name = SCStrdup(name)) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in SCCudaHlGetCudaDevicePtr. Exiting...");
        exit(EXIT_FAILURE);
    }

    /* allocate the cuda memory */
    if (SCCudaMemAlloc(&new_module_device_ptr->d_ptr, size) == -1)
        goto error;

    /* if the user has supplied a host buffer, copy contents to the device mem */
    if (host_ptr != NULL) {
        if (SCCudaMemcpyHtoD(new_module_device_ptr->d_ptr, host_ptr,
                             size) == -1) {
            goto error;
        }
    }

    /* send the newly assigned device pointer back to the caller */
    device_ptr[0] = new_module_device_ptr->d_ptr;

    /* insert it into the device_ptr list for the module instance */
    if (cumodule->device_ptrs == NULL) {
        cumodule->device_ptrs = new_module_device_ptr;
        return 0;
    }

    module_device_ptr = cumodule->device_ptrs;
    while (module_device_ptr->next != NULL)
        module_device_ptr = module_device_ptr->next;
    module_device_ptr->next = new_module_device_ptr;

    return 0;

 error:
    if (new_module_device_ptr != NULL)
        SCFree(new_module_device_ptr);
    return -1;
}

/**
 * \brief Frees a Cuda Device Pointer.
 *
 *        If a device pointer by the name \"name\"  is registered for this
 *        handle, it is freed.
 *
 * \param name       Name of the device pointer by which we have to search
 *                   module for its existance.
 * \param handle     A unique handle which identifies a module.  Obtained from
 *                   a call to SCCudaHlGetUniqueHandle().
 * \param cumodule   A handle that identifies the CUmodule within the above module.
 *                   Obtained from a call to SCCudaHlGetCudaModule() or
 *                   SCCudaHlGetCudaModuleFromFile().
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlFreeCudaDevicePtr(const char *name, int handle, int cumodule_handle)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaHlModuleCUmodule *cumodule = NULL;
    SCCudaHlModuleDevicePointer *module_device_ptr = NULL;
    SCCudaHlModuleDevicePointer *temp_module_device_ptr = NULL;

    if (name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "device_ptr is NULL or name is NULL");
        goto error;
    }

    /* check if the particular module that wants to free device memory is
     * already registered or not.  If it is registered, check if a context has
     * been associated with the module.  If yes, then we can go ahead and
     * free the device memory.
     */
    if ( ((data = SCCudaHlGetModuleData(handle)) == NULL) ||
         (data->cuda_context == 0)) {
        SCLogDebug("Module not registered or no cuda context associated with "
                   "this module.  You can't create a CUDA module without"
                   "associating a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        goto error;
    }

    if ( (cumodule = SCCudaHlGetModuleCUmodule(data, cumodule_handle)) == NULL ) {
        SCLogDebug("CUmodule not registered with the module. Before you can request"
                   "a device pointer for a module you need to load the CUmodule into"
                   "the engine module using SCCudaHlGetCudaModule() or"
                   "SCCudaHlGetCudaModuleFromFile().");
        goto error;
    }

    /* if we do not have a device pointer registered by this name get out */
    if ( (module_device_ptr = SCCudaHlCudaDevicePtrAvailable(cumodule, name)) == NULL) {
        goto error;
    }

    SCCudaMemFree(module_device_ptr->d_ptr);
    module_device_ptr->d_ptr = 0;
    if (module_device_ptr == cumodule->device_ptrs) {
        cumodule->device_ptrs = cumodule->device_ptrs->next;
    } else {
        temp_module_device_ptr = cumodule->device_ptrs;
        while (strcmp(temp_module_device_ptr->next->name, name) != 0) {
            temp_module_device_ptr = temp_module_device_ptr->next;
        }
        temp_module_device_ptr->next = temp_module_device_ptr->next->next;
    }
    SCFree(module_device_ptr->name);
    SCFree(module_device_ptr);

    return 0;

 error:
    return -1;
}

/**
 * \brief Registers a Dispatcher function against this handle.
 *
 * \param SCCudaHlDispFunc Pointer to a dispatcher function to be registered
 *                         for this handle.
 * \param handle           A unique handle which identifies a module.  Obtained
 *                         from a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlRegisterDispatcherFunc(void *(*SCCudaHlDispFunc)(void *), int handle)
{
    SCCudaHlModuleData *data = NULL;

    if (SCCudaHlDispFunc == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "SCCudaHlDispFunc NULL");
        return -1;
    }

    if ( (data = SCCudaHlGetModuleData(handle)) == NULL) {
        SCLogDebug("Module not registered.  To avail the benefits of this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), after which you "
                   "can call this function");
        return -1;
    }

    data->SCCudaHlDispFunc = SCCudaHlDispFunc;

    return 0;
}

/**
 * \brief Get the name of the module associated with the module whose handle is
 *        sent as the arg.
 *
 * \param handle The handle of the module which has to be searched.
 *
 * \retval data->name The name of the module on finding a module that matches
 *                    the handle sent as argument; NULL on failure.
 */
const char *SCCudaHlGetModuleName(int handle)
{
    SCCudaHlModuleData *data = module_data;

    while (data != NULL && data->handle != handle) {
        data = data->next;
    }

    if (data == NULL)
        return NULL;

    return data->name;
}

/**
 * \brief Get the handle associated with this module who name is sent as the arg.
 *
 * \param name The name of the module which has to be searched.
 *
 * \retval data->handle The handle to the module on finding a module that
 *                      matches the name sent as argument; -1 on failure.
 */
int SCCudaHlGetModuleHandle(const char *name)
{
    SCCudaHlModuleData *data = module_data;

    while (data != NULL &&
           strcmp(data->name, name) != 0) {
        data = data->next;
    }

    if (data == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "A cuda module by the name \"%s\" "
                   "hasn't been registered", name);
        return -1;
    }

    return data->handle;
}

/**
 * \brief Register a new module.  To understand what exactly these utilities are
 *        needed for please look at the file comments.
 *
 * \param name A unique name to register the module with.  No module should have
 *             registered itself previously with this name.
 *
 * \retval handle A unique handle that is associated with this module and all
 *                future use of API would require supplying this handle.
 */
int SCCudaHlRegisterModule(const char *name)
{
    SCCudaHlModuleData *data = module_data;
    SCCudaHlModuleData *new_data = NULL;

    while (data != NULL &&
           strcmp(data->name, name) != 0) {
        data = data->next;
    }

    if (data != NULL) {
        SCLogInfo("Module \"%s\" already registered.  Returning the handle "
                  "for the already registered module", name);
        return data->handle;
    }

    /* the module is not already registered.  Register the module */
    new_data = SCMalloc(sizeof(SCCudaHlModuleData));
    if (unlikely(new_data == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(new_data, 0, sizeof(SCCudaHlModuleData));

    if ( (new_data->name = SCStrdup(name)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    new_data->handle = SCCudaHlGetUniqueHandle();

    /* first module to be registered */
    if (module_data == NULL) {
        module_data = new_data;
        return new_data->handle;
    }

    /* add this new module_data instance to the global module_data list */
    data = module_data;
    while (data->next != NULL)
        data = data->next;
    data->next = new_data;

    return new_data->handle;
}

/**
 * \brief DeRegister a registered module.
 *
 * \param name Name of the module to deregister.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlDeRegisterModule(const char *name)
{
    SCCudaHlModuleData *data = NULL;
    SCCudaHlModuleData *prev_data = NULL;
    SCCudaHlModuleCUmodule *cumodule = NULL;
    SCCudaHlModuleCUmodule *temp_cumodule = NULL;
    SCCudaHlModuleDevicePointer *device_ptr = NULL;
    SCCudaHlModuleDevicePointer *temp_device_ptr = NULL;
    int module_handle = SCCudaHlGetModuleHandle(name);

    /* get the module */
    data = (module_handle == -1) ? NULL : SCCudaHlGetModuleData(module_handle);

    /* a module by this name doesn't exist.  Log Error and return */
    if (data == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Module \"%s\" not "
                   "registered", name);
        return -1;
    }

    /* the application must take care to check that the following cuda context
     * which is being freed is floating(not attached to any host thread) */
    if (data->cuda_context != 0)
        SCCudaCtxPushCurrent(data->cuda_context);

    /* looks like we do have a module registered by this name.
     * Go through all CUmodules registered in this module and
     * free cuda device pointers and unload the module.
     */
    cumodule = data->cuda_modules;
    while (cumodule != NULL) {
        /* free all device pointers */
        device_ptr = cumodule->device_ptrs;
        while (device_ptr != NULL) {
            temp_device_ptr = device_ptr;
            device_ptr = device_ptr->next;
            if (SCCudaMemFree(temp_device_ptr->d_ptr) == -1)
                goto error;
            SCFree(temp_device_ptr->name);
            SCFree(temp_device_ptr);
        }
        cumodule->device_ptrs = NULL;

        /* unload the cuda module */
        temp_cumodule = cumodule;
        cumodule = cumodule->next;
        if (SCCudaModuleUnload(temp_cumodule->cuda_module) == -1)
            goto error;
        SCFree(temp_cumodule);
    }
    data->cuda_modules = NULL;

    if (data->name != NULL)
        SCFree((void *)data->name);

    /* clean the dispatcher function registered */
    data->SCCudaHlDispFunc = NULL;

    /* destroy the cuda context */
    if (data->cuda_context != 0) {
        if (SCCudaCtxDestroy(data->cuda_context) == -1)
            goto error;
    }

    /* find the previous module data instance */
    if (module_data == data) {
        module_data = module_data->next;
    } else {
        prev_data = module_data;
        while (prev_data->next != data)
            prev_data = prev_data->next;
        prev_data->next = data->next;
    }

    /* delete the module data instance */
    SCFree(data);

    /* mission accomplished.  let's go */
    return 0;
 error:
    return -1;
}

/**
 * \brief DeRegister all the modules registered under cuda handlers.
 */
void SCCudaHlDeRegisterAllRegisteredModules(void)
{
    SCCudaHlModuleData *data = module_data;
    SCCudaHlModuleData *next_data = NULL;

    next_data = data;
    while (data != NULL) {
        next_data = data->next;
        if (SCCudaHlDeRegisterModule(data->name) == -1) {
            SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Error de-registering module "
                       "\"%s\"", data->name);
        }
        data = next_data;
    }

    module_data = NULL;

    return;
}

/**
 * \brief Pushes a cuda context for the calling thread.
 *
 *        Before calling this function make sure that the cuda context belonging
 *        to the registered module, is floating(not attached to any host thread).
 *
 * \param name Name of the registered module whose cuda context has to be
 *             pushed for the calling thread.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlPushCudaContextFromModule(const char *name)
{
    SCCudaHlModuleData *data = SCCudaHlGetModuleData(SCCudaHlGetModuleHandle(name));

    if (data == NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "No module registered by the "
                   "name \"%s\"", name);
        return -1;
    }

    if (SCCudaCtxPushCurrent(data->cuda_context) == -1) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Error pushing cuda context from "
                   "module \"%s\" for this calling thread\n", name);
        return -1;
    }

    return 0;
}

/**
 * \brief Used for testing purposes.  Running tests with cuda enabled
 *        requires some hacks, which is what this function does.
 *
 * \retval 1 Always.
 */
int SCCudaHlTestEnvCudaContextInit(void)
{
    CUcontext context;
    int module_handle = SCCudaHlRegisterModule("SC_RULES_CONTENT_B2G_CUDA");
    if (SCCudaHlGetCudaContext(&context, NULL, module_handle) == -1) {
        printf("Error getting a cuda context");
    }
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
    }

    return 1;
}

/**
 * \brief Used for testing purposes.  Running tests with cuda enabled
 *        requires some hacks, which is what this function does.
 *
 * \retval 1 Always.
 */
int SCCudaHlTestEnvCudaContextDeInit(void)
{
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }

    return 1;
}

#endif /* __SC_CUDA_SUPPORT */
