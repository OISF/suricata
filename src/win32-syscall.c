/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 * Isolation for WMI/COM functionality
 *
 * References:
 * https://msdn.microsoft.com/en-us/library/aa390421(v=vs.85).aspx
 * https://blogs.msdn.microsoft.com/ndis/2015/03/21/mapping-from-ndis-oids-to-wmi-classes/
 * https://stackoverflow.com/questions/1431103/how-to-obtain-data-from-wmi-using-a-c-application
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-parameters
 * https://wutils.com/wmi/root/wmi/ms_409/msndis_tcpoffloadcurrentconfig/
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-current-config
 * https://wutils.com/wmi/root/wmi/msndis_tcpoffloadparameters/
 */

#ifdef OS_WIN32

#include <inttypes.h>
#include <stdbool.h>

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <wbemidl.h>
#include <strsafe.h>
#include <ntddndis.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
// clang-format on

/* Windows strsafe.h defines _snprintf as an undefined warning type */
#undef _snprintf
#define _snprintf StringCbPrintfA

#include "util-debug.h"
#include "util-device.h"
#include "util-mem.h"
#include "util-unittest.h"

#include "suricata.h"

#include "win32-syscall.h"

/**
 * \brief return only the GUID portion of the name
 */
static const char *StripPcapPrefix(const char *pcap_dev)
{
    return strchr(pcap_dev, '{');
}

/**
 * \brief get the adapter address list, which includes IP status/details
 *
 * Clients MUST FREE the returned list to avoid memory leaks.
 */
uint32_t Win32GetAdaptersAddresses(IP_ADAPTER_ADDRESSES **pif_info_list)
{
    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list;

    ULONG size = 0;
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (err != ERROR_BUFFER_OVERFLOW) {
        return err;
    }
    if_info_list = SCMalloc((size_t)size);
    if (if_info_list == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, if_info_list, &size);
    if (err != NO_ERROR) {
        SCFree(if_info_list);
        return err;
    }

    *pif_info_list = if_info_list;
    return NO_ERROR;
}

uint32_t Win32FindAdapterAddresses(IP_ADAPTER_ADDRESSES *if_info_list,
                                   const char *adapter_name,
                                   IP_ADAPTER_ADDRESSES **pif_info)
{
    DWORD ret = NO_ERROR;
    adapter_name = StripPcapPrefix(adapter_name);
    *pif_info = NULL;

    for (IP_ADAPTER_ADDRESSES *current = if_info_list; current != NULL;
         current = current->Next) {

        /* if we find the adapter, return that data */
        if (strncmp(adapter_name, current->AdapterName, strlen(adapter_name)) ==
            0) {

            *pif_info = current;
            break;
        }
    }

    if (*pif_info == NULL) {
        ret = ERROR_NOT_FOUND;
    }

    return ret;
}

#if NTDDI_VERSION < NTDDI_VISTA

int GetIfaceMTUWin32(const char *pcap_dev) { return 0; }
int GetGlobalMTUWin32(void) { return 0; }

int GetIfaceOffloadingWin32(const char *ifname, int csum, int other)
{
    SCLogWarning(SC_ERR_SYSCALL, "Suricata not targeted for Windows Vista or "
                                 "higher. Network offload interrogation not "
                                 "available.");
    return -1;
}
int DisableIfaceOffloadingWin32(LiveDevice *ldev, int csum, int other)
{
    SCLogWarning(SC_ERR_SYSCALL, "Suricata not targeted for Windows Vista or "
                                 "higher. Network offload interrogation not "
                                 "available.");
    return -1;
}
int RestoreIfaceOffloadingWin32(LiveDevice *ldev)
{
    SCLogWarning(SC_ERR_SYSCALL, "Suricata not targeted for Windows Vista or "
                                 "higher. Network offload interrogation not "
                                 "available.");
    return -1;
}

#else /* NTDDI_VERSION >= NTDDI_VISTA */

static HMODULE wmiutils_dll = NULL;

/**
 * \brief obtain the WMI utilities DLL
 */
static HMODULE WmiUtils(void)
{
    if (wmiutils_dll == NULL) {
        wmiutils_dll =
                LoadLibraryA("C:\\Windows\\System32\\wbem\\wmiutils.dll");
    }

    return wmiutils_dll;
}

/**
 * \brief allocate a BSTR from a converted unsigned integer
 */
static BSTR utob(uint64_t ui)
{
    wchar_t buf[20];
    _ui64tow(ui, buf, 10);
    return SysAllocString(buf);
}

/**
 * \brief Get the win32/wmi error string
 */
static const char *GetErrorString(DWORD error_code)
{
    char *error_string = NULL;
    FormatMessageA(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            WmiUtils(), error_code, 0, (LPTSTR)&error_string, 0, NULL);

    error_string[strlen(error_string) - 2] = 0; // remove line breaks

    return error_string;
}

/**
 * \brief log an HRESULT in-place
 */
#ifdef DEBUG
#define Win32LogDebug(hr)                                                      \
    do {                                                                       \
        const char *error_string = GetErrorString(hr);                         \
        SCLogDebug("HRESULT: %s (0x%" PRIx32 ")", error_string,                \
                   (uint32_t)(hr));                                            \
        LocalFree((LPVOID)error_string);                                       \
    } while (0);

/**
 * \brief log a WBEM error in-place
 */
#define WbemLogDebug(hr)                                                       \
    do {                                                                       \
        Win32LogDebug(hr);                                                     \
        IErrorInfo *err_info;                                                  \
        BSTR err_description;                                                  \
        char *err_description_mb = NULL;                                       \
        GetErrorInfo(0, &err_info);                                            \
        err_info->lpVtbl->GetDescription(err_info, &err_description);          \
        err_description_mb = SCMalloc(SysStringLen(err_description) + 1);      \
        err_description_mb[SysStringLen(err_description)] = 0;                 \
        wcstombs(err_description_mb, err_description,                          \
                 SysStringLen(err_description));                               \
        SCLogDebug("WBEM error: %s", err_description_mb);                      \
        SCFree(err_description_mb);                                            \
        SysFreeString(err_description);                                        \
    } while (0);
#else
#define Win32LogDebug(hr)
#define WbemLogDebug(hr)
#endif /* DEBUG */

/**
 * \brief get the maximum transmissible unit for the specified pcap device name
 */
int GetIfaceMTUWin32(const char *pcap_dev)
{
    DWORD err = NO_ERROR;

    int mtu = 0;

    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        mtu = -1;
        goto fail;
    }
    err = Win32FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (err != NO_ERROR) {
        mtu = -1;
        goto fail;
    }

    mtu = if_info->Mtu;

fail:
    SCFree(if_info_list);

    if (err != S_OK) {
        const char *errbuf = GetErrorString(err);
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get MTU via syscall for '%s': %s "
                     "(%" PRId32 ")",
                     pcap_dev, errbuf, (uint32_t)err);
        LocalFree((LPVOID)errbuf);
    } else {
        SCLogInfo("Found an MTU of %d for '%s'", mtu, pcap_dev);
    }

    return mtu;
}

/**
 * \brief get the maximum transmissible unit for all devices on the system
 */
int GetGlobalMTUWin32()
{
    uint32_t mtu = 0;

    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list = NULL;

    /* get a list of all adapters' data */
    err = Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        goto fail;
    }

    /* now search for the right adapter in the list */
    IP_ADAPTER_ADDRESSES *if_info = NULL;
    for (if_info = if_info_list; if_info != NULL; if_info = if_info->Next) {
        /* -1 (uint) is an invalid value */
        if (if_info->Mtu == (uint32_t)-1) {
            continue;
        }

        /* we want to return the largest MTU value so we allocate enough */
        mtu = max(mtu, if_info->Mtu);
    }

    SCFree(if_info_list);

    SCLogInfo("Found a global MTU of %" PRIu32, mtu);
    return (int)mtu;

fail:
    SCFree(if_info_list);

    const char *errbuf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, (LPTSTR)&errbuf, 0, NULL);

    SCLogWarning(
            SC_ERR_SYSCALL,
            "Failure when trying to get global MTU via syscall: %s (%" PRId32
            ")",
            errbuf, (uint32_t)err);

    return -1;
}

#define ReleaseObject(objptr)                                                  \
    do {                                                                       \
        if ((objptr) != NULL) {                                                \
            (objptr)->lpVtbl->Release(objptr);                                 \
            (objptr) = NULL;                                                   \
        }                                                                      \
    } while (0);

#ifdef DEBUG
#define DebugPrintWmiObject(object)                                            \
    do {                                                                       \
        if ((object) == NULL) {                                                \
            SCLogDebug("NULL");                                                \
            break;                                                             \
        }                                                                      \
        BSTR str = NULL;                                                       \
        (object)->lpVtbl->GetObjectText((object), 0, &str);                    \
        char *strA = SCMalloc(SysStringLen(str) + 1);                          \
        strA[SysStringLen(str)] = 0;                                           \
        wcstombs(strA, str, SysStringLen(str));                                \
        SCLogDebug("\n%s", strA);                                              \
        SCFree(strA);                                                          \
        SysFreeString(str);                                                    \
    } while (0);
#else
#define DebugPrintWmiObject(object)
#endif

typedef enum Win32TcpOffloadFlags_ {
    WIN32_TCP_OFFLOAD_FLAG_NONE = 0,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX = 1,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX = 1 << 1,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX = 1 << 2,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX = 1 << 3,
    WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4 = 1 << 4,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4 = 1 << 5,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6 = 1 << 6,

    /* aggregates */
    WIN32_TCP_OFFLOAD_FLAG_CSUM = WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4 = WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX |
                                      WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6 = WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX |
                                      WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX,
    WIN32_TCP_OFFLOAD_FLAG_LSO = WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4 |
                                 WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4 |
                                 WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6,
} Win32TcpOffloadFlags;

typedef struct ComInstance_ {
    IWbemLocator *locator;
    IWbemServices *services;
} ComInstance;

/**
 * \brief Creates a COM instance connected to the specified resource
 */
static HRESULT ComInstanceInit(ComInstance *instance, LPCWSTR resource)
{
    HRESULT hr = S_OK;

    instance->locator = NULL;
    instance->services = NULL;

    BSTR resource_bstr = SysAllocString(resource);
    if (resource_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* connect to COM */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == S_FALSE) {
        /* already initialized */
        hr = S_OK;
    } else {
        if (hr != S_OK) {
            SCLogWarning(SC_ERR_SYSCALL,
                         "COM CoInitializeEx failed: 0x%" PRIx32, (uint32_t)hr);
            goto fail;
        }
        hr = CoInitializeSecurity(
                NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (hr != S_OK) {
            SCLogWarning(SC_ERR_SYSCALL,
                         "COM CoInitializeSecurity failed: 0x%" PRIx32,
                         (uint32_t)hr);
            goto fail;
        }
    }

    /* connect to WMI */
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&instance->locator);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM CoCreateInstance failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    hr = instance->locator->lpVtbl->ConnectServer(
            instance->locator, resource_bstr, NULL, NULL, NULL, 0, NULL, NULL,
            &instance->services);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM ConnectServer failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    SysFreeString(resource_bstr);

    return hr;
}

/**
 * \brief Releases resources for a COM instance.
 */
static void ComInstanceRelease(ComInstance *instance)
{
    if (instance == NULL) {
        return;
    }
    ReleaseObject(instance->services);
    ReleaseObject(instance->locator);
}

/**
 * \brief obtains a class definition from COM services
 */
static HRESULT GetWbemClass(ComInstance *instance, LPCWSTR name,
                            IWbemClassObject **p_class)
{
    HRESULT hr = WBEM_S_NO_ERROR;
    BSTR name_bstr = NULL;

    if (instance == NULL || name == NULL || p_class == NULL ||
        *p_class != NULL) {
        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* allocate name string */
    name_bstr = SysAllocString(name);
    if (name_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* obtain object */
    hr = instance->services->lpVtbl->GetObject(instance->services, name_bstr,
                                               WBEM_FLAG_RETURN_WBEM_COMPLETE,
                                               NULL, p_class, NULL);
    if (hr != S_OK) {
        WbemLogDebug(hr);
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    SysFreeString(name_bstr);

    return hr;
}

/**
 * \brief spawns an empty class instance of the specified type
 */
static HRESULT GetWbemClassInstance(ComInstance *instance, LPCWSTR name,
                                    IWbemClassObject **p_instance)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    IWbemClassObject *class = NULL;

    hr = GetWbemClass(instance, name, &class);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    hr = class->lpVtbl->SpawnInstance(class, 0, p_instance);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        SCLogWarning(SC_ERR_SYSCALL, "WMI SpawnInstance failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

typedef struct WbemMethod_ {
    ComInstance *com_instance;

    BSTR method_name;

    IWbemClassObject *in_params, *out_params;
} WbemMethod;

/**
 * \brief initializes resources for a WMI method handle
 */
static HRESULT GetWbemMethod(ComInstance *com_instance, LPCWSTR class_name,
                             LPCWSTR method_name, WbemMethod *method)
{
    HRESULT hr = S_OK;
    IWbemClassObject *class = NULL;

    method->com_instance = com_instance;

    BSTR class_name_bstr = SysAllocString(class_name);
    if (class_name_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }
    method->method_name = SysAllocString(method_name);
    if (method->method_name == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* find our class definition to retrieve parameters */
    hr = GetWbemClass(com_instance, class_name, &class);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* find the method on the retrieved class */
    hr = class->lpVtbl->GetMethod(class, method_name, 0, &method->in_params,
                                  &method->out_params);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    ReleaseObject(class);

    SysFreeString(class_name_bstr);

    return hr;
}

/**
 * \brief Releases resources for a WMI method handle
 */
static void WbemMethodRelease(WbemMethod *method)
{
    if (method == NULL) {
        return;
    }
    ReleaseObject(method->in_params);
    ReleaseObject(method->out_params);

    SysFreeString(method->method_name);
}

typedef struct WbemMethodCall_ {
    WbemMethod *method;

    BSTR instance_path;

    IWbemClassObject *in_params;
} WbemMethodCall;

/**
 * \brief generates a single-use WMI method call
 */
static HRESULT GetWbemMethodCall(WbemMethod *method, LPCWSTR instance_path,
                                 WbemMethodCall *call)
{
    HRESULT hr = S_OK;

    call->method = method;
    call->instance_path = SysAllocString(instance_path);
    if (call->instance_path == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* make an instance of the in/out params */
    hr = method->in_params->lpVtbl->SpawnInstance(method->in_params, 0,
                                                  &call->in_params);
    if (hr != S_OK) {
        WbemLogDebug(hr);
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI SpawnInstance failed on in_params: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

/**
 *  \brief releases the WMI method call resources
 */
static void WbemMethodCallRelease(WbemMethodCall *call)
{
    if (call == NULL) {
        return;
    }
    ReleaseObject(call->in_params);

    SysFreeString(call->instance_path);
}

/**
 * \brief executes the method after the client has set applicable parameters.
 */
static HRESULT WbemMethodCallExec(WbemMethodCall *call,
                                  IWbemClassObject **p_out_params)
{
    HRESULT hr = S_OK;

    hr = call->method->com_instance->services->lpVtbl->ExecMethod(
            call->method->com_instance->services, call->instance_path,
            call->method->method_name, 0, NULL, call->in_params, p_out_params,
            NULL);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        SCLogInfo("WMI ExecMethod failed: 0x%" PRIx32, (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

/**
 * Obtains an IWbemClassObject named property of a parent IWbemClassObject
 */
static HRESULT WbemGetSubObject(IWbemClassObject *object, LPCWSTR property_name,
                                IWbemClassObject **sub_object)
{
    HRESULT hr = S_OK;

    VARIANT out_var;
    VariantInit(&out_var);
    hr = object->lpVtbl->Get(object, property_name, 0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    IUnknown *unknown = V_UNKNOWN(&out_var);
    hr = unknown->lpVtbl->QueryInterface(unknown, &IID_IWbemClassObject,
                                         (void **)sub_object);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IWbemClassObject) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    VariantClear(&out_var);
    return hr;
}

/**
 * Obtains an Encapsulation value from an MSNdis_WmiOffload property
 */
static HRESULT GetEncapsulation(IWbemClassObject *object, LPCWSTR category,
                                LPCWSTR subcategory, ULONG *encapsulation)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    IWbemClassObject *category_object = NULL;
    IWbemClassObject *subcategory_object = NULL;

    VARIANT out_var;
    VariantInit(&out_var);

    /* get category object */
    hr = WbemGetSubObject(object, category, &category_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* get sub-category object */
    hr = WbemGetSubObject(category_object, subcategory, &subcategory_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = subcategory_object->lpVtbl->Get(subcategory_object, L"Encapsulation",
                                         0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    *encapsulation = V_UI4(&out_var);

fail:
    VariantClear(&out_var);
    ReleaseObject(subcategory_object);
    ReleaseObject(category_object);
    return hr;
}

static HRESULT GetIUnknown(IWbemClassObject *object, IUnknown **p_unknown)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    if (object == NULL || p_unknown == NULL || *p_unknown != NULL) {
        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    hr = object->lpVtbl->QueryInterface(object, &IID_IUnknown,
                                        (void **)p_unknown);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IUnknown) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

static HRESULT BuildNdisObjectHeader(ComInstance *instance, uint8_t type,
                                     uint8_t revision, uint16_t size,
                                     IWbemClassObject **p_ndis_object_header)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    if (instance == NULL || p_ndis_object_header == NULL ||
        *p_ndis_object_header != NULL) {

        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* obtain object */
    hr = GetWbemClassInstance(instance, L"MSNdis_ObjectHeader",
                              p_ndis_object_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);
    IWbemClassObject *ndis_object_header = *p_ndis_object_header;

    /* set parameters */
    V_VT(&param_variant) = VT_UI1;
    V_UI1(&param_variant) = type;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Type", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_UI1;
    V_UI1(&param_variant) = revision;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Revision", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    /* https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-object-version-issues-for-wmi
     */
    V_VT(&param_variant) = VT_I4;
    V_I4(&param_variant) = size;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Size", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

fail:
    return hr;
}

static HRESULT BuildNdisWmiMethodHeader(ComInstance *instance,
                                        uint64_t net_luid, uint32_t port_number,
                                        uint64_t request_id, uint32_t timeout,
                                        IWbemClassObject **p_ndis_method_header)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    IWbemClassObject *ndis_object_header = NULL;

    if (instance == NULL || p_ndis_method_header == NULL ||
        *p_ndis_method_header != NULL) {

        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* obtain object */
    hr = GetWbemClassInstance(instance, L"MSNdis_WmiMethodHeader",
                              p_ndis_method_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);

    /* get embedded MSNdis_ObjectHeader */
    hr = BuildNdisObjectHeader(instance, NDIS_WMI_OBJECT_TYPE_METHOD,
                               NDIS_WMI_METHOD_HEADER_REVISION_1, 0xFFFF,
                               &ndis_object_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = NULL;
    hr = GetIUnknown(ndis_object_header, &V_UNKNOWN(&param_variant));
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    IWbemClassObject *ndis_method_header = *p_ndis_method_header;

    /* set parameters */
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Header", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(net_luid);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"NetLuid", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)port_number);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"PortNumber", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(request_id);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"RequestId", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)timeout);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Timeout", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)0);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Padding", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

fail:
    ReleaseObject(ndis_object_header);

    return hr;
}

/**
 * \brief polls the NDIS TCP offloading status, namely LSOv1/v2
 */
static HRESULT GetNdisOffload(LPCWSTR if_description, uint32_t *offload_flags)
{
    HRESULT hr = S_OK;

    ComInstance instance = {};
    WbemMethod method = {};
    WbemMethodCall call = {};

    IWbemClassObject *ndis_method_header = NULL;
    IWbemClassObject *out_params = NULL;
    IWbemClassObject *ndis_offload = NULL;

    if (if_description == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "No description specified for device");
        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        goto fail;
    }

    LPCWSTR class_name = L"MSNdis_TcpOffloadCurrentConfig";
    LPCWSTR instance_name_fmt = L"%s=\"%s\"";
    size_t n_chars = wcslen(class_name) + wcslen(if_description) +
                     wcslen(instance_name_fmt);
    LPWSTR instance_name = SCMalloc((n_chars + 1) * sizeof(wchar_t));
    instance_name[n_chars] = 0; /* defensively null-terminate */
    hr = StringCchPrintfW(instance_name, n_chars, instance_name_fmt, class_name,
                          if_description);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failed to format WMI class instance name: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    /* method name */
    LPCWSTR method_name = L"WmiQueryCurrentOffloadConfig";

    /* connect to COM/WMI */
    hr = ComInstanceInit(&instance, L"ROOT\\WMI");
    if (hr != S_OK) {
        goto fail;
    }

    /* obtain method */
    hr = GetWbemMethod(&instance, class_name, method_name, &method);
    if (hr != S_OK) {
        goto fail;
    }

    /* make parameter instances */
    hr = GetWbemMethodCall(&method, instance_name, &call);
    if (hr != S_OK) {
        goto fail;
    }

    /* build parameters */

    VARIANT param_variant;
    VariantInit(&param_variant);

    /* Make MSNdis_WmiMethodHeader */
    hr = BuildNdisWmiMethodHeader(&instance, 0, 0, 0, 5, &ndis_method_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = NULL;
    hr = GetIUnknown(ndis_method_header, &V_UNKNOWN(&param_variant));
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* Set in_params */
    hr = call.in_params->lpVtbl->Put(call.in_params, L"Header", 0,
                                     &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }

    /* execute the method */
    hr = WbemMethodCallExec(&call, &out_params);
    if (hr != S_OK) {
        size_t if_description_len = wcslen(if_description);
        char *if_description_ansi = SCMalloc(if_description_len + 1);
        if_description_ansi[if_description_len] = 0;
        wcstombs(if_description_ansi, if_description, if_description_len);
        SCLogWarning(SC_ERR_SYSCALL,
                     "Obtaining offload state failed, device \"%s\" may not "
                     "support offload. Error: 0x%" PRIx32,
                     if_description_ansi, (uint32_t)hr);
        SCFree(if_description_ansi);
        Win32LogDebug(hr);
        goto fail;
    }

    /* inspect the result */
    hr = WbemGetSubObject(out_params, L"Offload", &ndis_offload);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    ULONG encapsulation = 0;

    /* Checksum */
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv4Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv4Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv6Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv6Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX;
    }

    /* LsoV1 */
    hr = GetEncapsulation(ndis_offload, L"LsoV1", L"WmiIPv4", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4;
    }

    /* LsoV2 */
    hr = GetEncapsulation(ndis_offload, L"LsoV2", L"WmiIPv4", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4;
    }
    hr = GetEncapsulation(ndis_offload, L"LsoV2", L"WmiIPv6", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6;
    }

fail:
    ReleaseObject(ndis_method_header);
    ReleaseObject(ndis_offload);
    ReleaseObject(out_params);

    WbemMethodCallRelease(&call);
    WbemMethodRelease(&method);
    ComInstanceRelease(&instance);

    return hr;
}

int GetIfaceOffloadingWin32(const char *pcap_dev, int csum, int other)
{
    SCLogDebug("Querying offloading for device %s", pcap_dev);

    DWORD err = NO_ERROR;
    int ret = 0;
    uint32_t offload_flags = 0;

    /* WMI uses the description as an identifier... */
    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    err = Win32FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    LPWSTR if_description = if_info->Description;

    /* now query WMI for the offload info */
    err = GetNdisOffload(if_description, &offload_flags);
    if (err != S_OK) {
        ret = -1;
        goto fail;
    } else if (offload_flags != 0) {
        if (csum == 1) {
            if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM) != 0) {
                ret = 1;
            }
        }
        if (other == 1) {
            if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSO) != 0) {
                ret = 1;
            }
        }
    }

    if (ret == 0) {
        SCLogPerf("NIC offloading on %s: Checksum IPv4 Rx: %d Tx: %d IPv6 "
                  "Rx: %d Tx: %d LSOv1 IPv4: %d LSOv2 IPv4: %d IPv6: %d",
                  pcap_dev,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6) != 0);
    } else {
        SCLogWarning(SC_ERR_NIC_OFFLOADING,
                     "NIC offloading on %s: Checksum IPv4 Rx: %d Tx: %d IPv6 "
                     "Rx: %d Tx: %d LSOv1 IPv4: %d LSOv2 IPv4: %d IPv6: %d",
                     pcap_dev,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6) != 0);
    }

fail:
    if (ret == -1) {
        const char *errstr = GetErrorString(err);
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get feature via syscall for '%s': "
                     "%s (0x%" PRIx32 ")",
                     pcap_dev, errstr, (uint32_t)err);
        LocalFree((LPVOID)errstr);
    }

    SCFree(if_info_list);

    return ret;
}

static HRESULT
BuildNdisTcpOffloadParameters(ComInstance *instance, uint32_t offload_flags,
                              bool enable,
                              IWbemClassObject **p_ndis_tcp_offload_parameters)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    IWbemClassObject *ndis_object_header = NULL;

    if (instance == NULL || p_ndis_tcp_offload_parameters == NULL ||
        *p_ndis_tcp_offload_parameters != NULL) {

        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* obtain object */
    hr = GetWbemClassInstance(instance, L"MSNdis_TcpOffloadParameters",
                              p_ndis_tcp_offload_parameters);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);

    /* get embedded MSNdis_ObjectHeader */
    hr = BuildNdisObjectHeader(instance, NDIS_OBJECT_TYPE_DEFAULT,
                               NDIS_OFFLOAD_PARAMETERS_REVISION_1,
                               NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1,
                               &ndis_object_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = NULL;
    hr = GetIUnknown(ndis_object_header, &V_UNKNOWN(&param_variant));
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    IWbemClassObject *ndis_tcp_offload_parameters =
            *p_ndis_tcp_offload_parameters;

    /* set parameters */
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"Header", 0, &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    /* IPv4 csum */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    if (!enable && (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4) != 0) {
        /* this is basically all disabled cases */
        V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4) ==
               WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4) {
        /* implied enable */
        V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX) != 0) {
        /* implied enable */
        V_BSTR(&param_variant) =
                utob(NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX) != 0) {
        /* implied enable */
        V_BSTR(&param_variant) =
                utob(NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED);
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"IPv4Checksum", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"TCPIPv4Checksum", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"UDPIPv4Checksum", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    VariantClear(&param_variant);

    /* IPv6 csum */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    if (!enable && (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6) != 0) {
        /* this is basically all disabled cases */
        V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6) ==
               WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6) {
        /* implied enable */
        V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX) != 0) {
        /* implied enable */
        V_BSTR(&param_variant) =
                utob(NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED);
    } else if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX) != 0) {
        /* implied enable */
        V_BSTR(&param_variant) =
                utob(NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED);
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"TCPIPv6Checksum", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"UDPIPv6Checksum", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    VariantClear(&param_variant);

    /* LSOv1 */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4) != 0) {
        if (enable) {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED);
        } else {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV1_DISABLED);
        }
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"LsoV1", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    VariantClear(&param_variant);

    /* LSOv2 IPv4 */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4) != 0) {
        if (enable) {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED);
        } else {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED);
        }
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"LsoV2IPv4", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    VariantClear(&param_variant);

    /* LSOv2 IPv4 */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6) != 0) {
        if (enable) {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED);
        } else {
            V_BSTR(&param_variant) =
                    utob(NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED);
        }
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"LsoV2IPv6", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    VariantClear(&param_variant);

    /* currently unused fields */
    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(NDIS_OFFLOAD_PARAMETERS_NO_CHANGE);
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"IPSec", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"TcpConnectionIPv4", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(ndis_tcp_offload_parameters,
                                                  L"TcpConnectionIPv6", 0,
                                                  &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    hr = ndis_tcp_offload_parameters->lpVtbl->Put(
            ndis_tcp_offload_parameters, L"Flags", 0, &param_variant, 0);
    if (hr != WBEM_S_NO_ERROR) {
        WbemLogDebug(hr);
        goto fail;
    }
    /* further fields are for NDIS 6.1+ */

fail:
    VariantClear(&param_variant);

    return hr;
}

static HRESULT SetNdisOffload(LPCWSTR if_description, uint32_t offload_flags,
                              bool enable)
{
    HRESULT hr = S_OK;

    ComInstance instance = {};
    WbemMethod method = {};
    WbemMethodCall call = {};

    /* param 0 */
    IWbemClassObject *ndis_method_header = NULL;
    /* param 1 */
    IWbemClassObject *ndis_tcp_offload_parameters = NULL;

    if (if_description == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "No description specified for device");
        return E_INVALIDARG;
    }

    LPCWSTR class_name = L"MSNdis_SetTcpOffloadParameters";
    LPCWSTR instance_name_fmt = L"%s=\"%s\"";
    size_t n_chars = wcslen(class_name) + wcslen(if_description) +
                     wcslen(instance_name_fmt);
    LPWSTR instance_name = SCMalloc((n_chars + 1) * sizeof(wchar_t));
    instance_name[n_chars] = 0; /* defensively null-terminate */
    hr = StringCchPrintfW(instance_name, n_chars, instance_name_fmt, class_name,
                          if_description);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failed to format WMI class instance name: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* method name */
    LPCWSTR method_name = L"WmiSetTcpOffloadParameters";

    /* connect to COM/WMI */
    hr = ComInstanceInit(&instance, L"ROOT\\WMI");
    if (hr != S_OK) {
        goto fail;
    }

    /* obtain method */
    hr = GetWbemMethod(&instance, class_name, method_name, &method);
    if (hr != S_OK) {
        goto fail;
    }

    /* make parameter instances */
    hr = GetWbemMethodCall(&method, instance_name, &call);
    if (hr != S_OK) {
        goto fail;
    }

    /* build parameters */

    VARIANT param_variant;
    VariantInit(&param_variant);

    /* Make MSNdis_WmiMethodHeader */
    hr = BuildNdisWmiMethodHeader(&instance, 0, 0, 0, 5, &ndis_method_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = NULL;
    hr = GetIUnknown(ndis_method_header, &V_UNKNOWN(&param_variant));
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = call.in_params->lpVtbl->Put(call.in_params, L"MethodHeader", 0,
                                     &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    /* Make MSNdis_TcpOffloadParameters */
    hr = BuildNdisTcpOffloadParameters(&instance, offload_flags, enable,
                                       &ndis_tcp_offload_parameters);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = NULL;
    hr = GetIUnknown(ndis_tcp_offload_parameters, &V_UNKNOWN(&param_variant));
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = call.in_params->lpVtbl->Put(call.in_params, L"TcpOffloadParameters", 0,
                                     &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    /* execute the method */
    hr = WbemMethodCallExec(&call, NULL);
    if (hr != S_OK) {
        Win32LogDebug(hr);
        goto fail;
    }

fail:
    ReleaseObject(ndis_tcp_offload_parameters);
    ReleaseObject(ndis_method_header);

    WbemMethodCallRelease(&call);
    WbemMethodRelease(&method);
    ComInstanceRelease(&instance);

    return hr;
}

int DisableIfaceOffloadingWin32(LiveDevice *ldev, int csum, int other)
{
    SCLogDebug("Disabling offloading for device %s", ldev->dev);

    int ret = 0;
    DWORD err = NO_ERROR;
    uint32_t offload_flags = 0;

    if (ldev == NULL) {
        return -1;
    }

    /* WMI uses the description as an identifier... */
    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    err = Win32FindAdapterAddresses(if_info_list, ldev->dev, &if_info);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    LPWSTR if_description = if_info->Description;

    err = GetNdisOffload(if_description, &offload_flags);
    if (err != S_OK) {
        ret = -1;
        goto fail;
    }

    if (!csum) {
        offload_flags &= ~WIN32_TCP_OFFLOAD_FLAG_CSUM;
    }
    if (!other) {
        offload_flags &= ~WIN32_TCP_OFFLOAD_FLAG_LSO;
    }

    err = SetNdisOffload(if_description, offload_flags, 0);
    if (err != S_OK) {
        ret = -1;
        goto fail;
    }

fail:
    SCFree(if_info_list);

    return ret;
}

int RestoreIfaceOffloadingWin32(LiveDevice *ldev)
{
    SCLogDebug("Enabling offloading for device %s", ldev->dev);

    int ret = 0;
    DWORD err = NO_ERROR;

    if (ldev == NULL) {
        return -1;
    }

    /* WMI uses the description as an identifier... */
    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    err = Win32FindAdapterAddresses(if_info_list, ldev->dev, &if_info);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    LPWSTR if_description = if_info->Description;

    err = SetNdisOffload(if_description, ldev->offload_orig, 1);
    if (err != S_OK) {
        ret = -1;
        goto fail;
    }

fail:
    SCFree(if_info_list);

    return ret;
}

#endif /* NTDDI_VERSION >= NTDDI_VISTA */

#ifdef UNITTESTS
static int Win32TestStripPcapPrefix(void)
{
    int result = 1;

    const char *name1 = "\\Device\\NPF_{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";
    const char *expect_name1 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";

    const char *name2 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";
    const char *expect_name2 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";

    result &= (strncmp(expect_name1, StripPcapPrefix(name1),
                       strlen(expect_name1)) == 0);

    result &= (strncmp(expect_name2, StripPcapPrefix(name2),
                       strlen(expect_name2)) == 0);

    return result;
}
#endif /* UNITTESTS */

void Win32SyscallRegisterTests()
{
#ifdef UNITTESTS
    UtRegisterTest("Win32TestStripPcapPrefix", Win32TestStripPcapPrefix);
#endif
}

#endif /* OS_WIN32 */