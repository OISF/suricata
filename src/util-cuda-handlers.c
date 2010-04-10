/**
 * Copyright (c) 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * \file Provides cuda utility functions.
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
 * \todo Provide support for multiple cuda context storage and creating multiple
 *       cuda modules against a cuda_context, although it is highly unlikely we
 *       would need this feature.
 *
 *       We also need to use a mutex for module_datas.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "decode.h"

#include "util-cuda.h"
#include "util-cuda-handlers.h"
#include "util-mpm-b2g-cuda.h"

#include "tmqh-simple.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "packet-queue.h"

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

static SCCudaHlModuleData *module_datas = NULL;

static uint8_t module_handle = 1;

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
    SCCudaHlModuleData *data = module_datas;

    if (data == NULL)
        return NULL;

    while (data != NULL && data->handle != handle) {
        data = data->next;
    }

    return data;
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
 * \brief Returns a cuda context against the handle in the argument.
 *
 *        If a cuda_context is not present for a handle, it is created
 *        and associated with this handle and the context is returned
 *        in the argument.  If a cuda_context is already present for
 *        a handle, it is returned.
 *
 * \param p_context Pointer to a cuda context instance that should be updated
 *                  with a cuda context.
 * \param handle    A unique handle which identifies a module.  Obtained from
 *                  a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlGetCudaContext(CUcontext *p_context, int handle)
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

    /* Get the device list for this CUDA platform and create a new cuda context */
    devices = SCCudaGetDeviceList();
    if (SCCudaCtxCreate(p_context, 0, devices->devices[0]->device) == -1)
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
 *        in the argument.  If a cuda_module is already present for
 *        a handle, it is returned.
 *
 * \param p_context Pointer to a cuda context instance that should be updated
 *                  with a cuda context.
 * \param handle    A unique handle which identifies a module.  Obtained from
 *                  a call to SCCudaHlGetUniqueHandle().
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlGetCudaModule(CUmodule *p_module, const char *ptx_image, int handle)
{
    SCCudaHlModuleData *data = NULL;

    if (p_module == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments"
                   "p_module NULL");
        return -1;
    }

    /* check if the particular module that wants a CUDA module is already
     * registered or not.  If it is registered, check if a context has
     * been associated with the module.  If yes, then we can go ahead and
     * create a cuda module or return the reference to the cuda module if
     * we already have a cuda module associated with the module.  If no, "
     * log warning and get out of here */
    if ( ((data = SCCudaHlGetModuleData(handle)) == NULL) ||
         (data->cuda_context == 0)) {
        SCLogDebug("Module not registered or no cuda context associated with "
                   "this module.  You can't create a CUDA module without"
                   "associatin a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        return -1;
    }

    /* we already have a cuda module associated with this module.  Return the
     * cuda module */
    if (data->cuda_module != 0) {
        p_module[0] = data->cuda_module;
        return 0;
    }

    /* we don't have a cuda module associated with this module.  Create a
     * cuda module, update the module with this cuda module reference and
     * then return the module refernce back to the calling function using
     * the argument */
    if (SCCudaModuleLoadData(p_module, (void *)ptx_image) == -1)
        goto error;
    data->cuda_module = p_module[0];

    return 0;

 error:
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
SCCudaHlModuleDevicePointer *SCCudaHlCudaDevicePtrAvailable(SCCudaHlModuleData *data,
                                                            const char *name)
{
    SCCudaHlModuleDevicePointer *module_device_ptr = data->device_ptrs;

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
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCCudaHlGetCudaDevicePtr(CUdeviceptr *device_ptr, const char *name,
                             size_t size, void *host_ptr, int handle)
{
    SCCudaHlModuleData *data = NULL;
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
                   "associatin a context with a module first. To use this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), and then register "
                   "a cuda context with that module using "
                   "SCCudaHlGetCudaContext(), after which you can call this "
                   "function ");
        goto error;
    }

    /* if we already have a device pointer registered by this name return the
     * cuda device pointer instance */
    if ( (module_device_ptr = SCCudaHlCudaDevicePtrAvailable(data, name)) != NULL) {
        device_ptr[0] = module_device_ptr->d_ptr;
        return 0;
    }

    new_module_device_ptr = SCMalloc(sizeof(SCCudaHlModuleDevicePointer));
    if (new_module_device_ptr == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(new_module_device_ptr, 0, sizeof(SCCudaHlModuleDevicePointer));

    if ( (new_module_device_ptr->name = SCStrdup(name)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
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

    /* insert it into the device_ptr list for the module instance */
    if (data->device_ptrs == NULL) {
        data->device_ptrs = new_module_device_ptr;
        device_ptr[0] = new_module_device_ptr->d_ptr;
        return 0;
    }

    module_device_ptr = data->device_ptrs;
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
    SCCudaHlModuleData *data = module_datas;

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
    SCCudaHlModuleData *data = module_datas;

    while (data != NULL &&
           strcmp(data->name, name) != 0) {
        data = data->next;
    }

    if (data == NULL)
        return -1;

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
    SCCudaHlModuleData *data = module_datas;
    SCCudaHlModuleData *new_data = NULL;

    while (data != NULL &&
           strcmp(data->name, name) != 0) {
        data = data->next;
    }

    if (data != NULL) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Module \"%s\" already "
                   "registered.  Returning the handle for the already "
                   "registered module", name);
        return data->handle;
    }

    /* the module is not already registered.  Register the module */
    new_data = SCMalloc(sizeof(SCCudaHlModuleData));
    if (new_data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(new_data, 0, sizeof(SCCudaHlModuleData));

    if ( (new_data->name = SCStrdup(name)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    new_data->handle = SCCudaHlGetUniqueHandle();

    /* first module to be registered */
    if (module_datas == NULL) {
        module_datas = new_data;
        return new_data->handle;
    }

    /* add this new module_data instance to the global module_data list */
    data = module_datas;
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

    /* the applicationg must take care to check that the following cuda context
     * which is being freed is floating(not attached to any host thread) */
    if (data->cuda_context != 0)
        SCCudaCtxPushCurrent(data->cuda_context);

    /* looks like we do have a module registered by this name */
    /* first clean the cuda device pointers */
    device_ptr = data->device_ptrs;
    while (device_ptr != NULL) {
        temp_device_ptr = device_ptr;
        device_ptr = device_ptr->next;
        if (SCCudaMemFree(temp_device_ptr->d_ptr) == -1)
            goto error;
        SCFree(temp_device_ptr->name);
        SCFree(temp_device_ptr);
    }
    data->device_ptrs = NULL;

    if (data->name != NULL)
        SCFree((void *)data->name);

    /* clean the dispatcher function registered */
    data->SCCudaHlDispFunc = NULL;

    /* unload the cuda module */
    if (data->cuda_module != 0) {
        if (SCCudaModuleUnload(data->cuda_module) == -1)
            goto error;
    }

    /* destroy the cuda context */
    if (data->cuda_context != 0) {
        if (SCCudaCtxDestroy(data->cuda_context) == -1)
            goto error;
    }

    /* find the previous module data instance */
    if (module_datas == data) {
        module_datas = module_datas->next;
    } else {
        prev_data = module_datas;
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
    SCCudaHlModuleData *data = module_datas;
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

    module_datas = NULL;

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
    if (SCCudaHlGetCudaContext(&context, module_handle) == -1) {
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

void SCCudaHlProcessPacketWithDispatcher(Packet *p, DetectEngineThreadCtx *det_ctx,
                                         void *result)
{
    Packet *out_p = NULL;

    p->cuda_mpm_ctx = det_ctx->sgh->mpm_ctx;
    p->cuda_mtc = &det_ctx->mtc;
    p->cuda_pmq = &det_ctx->pmq;
    /* this outq is unique to this detection thread instance.  The dispatcher thread
     * would use this queue to pump the packets back to this detection thread once
     * it has processed the packet */
    p->cuda_outq = &trans_q[det_ctx->cuda_mpm_rc_disp_outq->id];
    /* for now it is hardcoded.  \todo Make the access to the right queue or the
     * ThreadVars generic */

    /* Push the packet into the dispatcher's input queue */
    B2gCudaPushPacketTo_tv_CMB2_RC(p);

    /* wait for the dispatcher to process and return the packet we pushed */
    out_p = TmqhInputSimpleOnQ(&trans_q[det_ctx->cuda_mpm_rc_disp_outq->id]);

    /* todo make this generic, so that if we have more than 2 modules using the
     * cuda interface, we can call update function for the module that has
     * queued the packet and retrieve the results */
    *((uint32_t *)result) = p->cuda_matches;

    return;
}

void SCCudaHlProcessUriWithDispatcher(uint8_t *uri, uint16_t uri_len,
                                      DetectEngineThreadCtx *det_ctx,
                                      void *result)
{
    Packet *out_p = NULL;

    Packet *p = SCMalloc(sizeof(Packet));
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(Packet));

    p->cuda_mpm_ctx = det_ctx->sgh->mpm_uri_ctx;
    p->cuda_mtc = &det_ctx->mtcu;
    p->cuda_pmq = &det_ctx->pmq;
    p->payload = uri;
    p->payload_len = uri_len;
    /* this outq is unique to this detection thread instance.  The dispatcher thread
     * would use this queue to pump the packets back to this detection thread once
     * it has processed the packet */
    p->cuda_outq = &trans_q[det_ctx->cuda_mpm_rc_disp_outq->id];

    /* Push the packet into the dispatcher's input queue */
    B2gCudaPushPacketTo_tv_CMB2_RC(p);

    /* wait for the dispatcher to process and return the packet we pushed */
    out_p = TmqhInputSimpleOnQ(&trans_q[det_ctx->cuda_mpm_rc_disp_outq->id]);

    /* todo make this generic, so that if we have more than 2 modules using the
     * cuda interface, we can call update function for the module that has
     * queued the packet and retrieve the results */
    *((uint32_t *)result) = p->cuda_matches;

    SCFree(p);

    return;
}

#endif /* __SC_CUDA_SUPPORT */
