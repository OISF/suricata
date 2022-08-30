/* Copyright (C) 2022 Open Information Security Foundation
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
 * WinDivert emulation of netfilter_queue functionality to hook into Suricata's
 * IPS mode. Supported solely on Windows.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "tm-threads.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-error.h"
#include "util-ioctl.h"
#include "util-privs.h"
#include "util-unittest.h"

#include "runmodes.h"

#include "queue.h"

#include "source-windivert-prototypes.h"
#include "source-windivert.h"

#ifdef WINDIVERT
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <iptypes.h>
#include <winerror.h>
// clang-format on
#endif

#ifndef WINDIVERT
/* Gracefully handle the case where no WinDivert support is compiled in */

TmEcode NoWinDivertSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveWinDivertRegister(void)
{
    tmm_modules[TMM_RECEIVEWINDIVERT].name = "ReceiveWinDivert";
    tmm_modules[TMM_RECEIVEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_RECEIVEWINDIVERT].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictWinDivertRegister(void)
{
    tmm_modules[TMM_VERDICTWINDIVERT].name = "VerdictWinDivert";
    tmm_modules[TMM_VERDICTWINDIVERT].ThreadInit = NoWinDivertSupportExit;
}

void TmModuleDecodeWinDivertRegister(void)
{
    tmm_modules[TMM_DECODEWINDIVERT].name = "DecodeWinDivert";
    tmm_modules[TMM_DECODEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_DECODEWINDIVERT].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoWinDivertSupportExit(ThreadVars *tv, const void *initdata,
                               void **data)
{
    SCLogError(
            SC_ERR_WINDIVERT_NOSUPPORT,
            "Error creating thread %s: you do not have support for WinDivert "
            "enabled; please recompile with --enable-windivert",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have WinDivert support */

typedef struct WinDivertThreadVars_ {
    WinDivertHandle filter_handle;

    int thread_num;
    CaptureStats stats;
    int64_t qpc_start_time;
    int64_t qpc_start_count;
    int64_t qpc_freq_usec;

    TmSlot *slot;

    bool offload_enabled;

    TAILQ_HEAD(, LiveDevice_) live_devices;
} WinDivertThreadVars;

#define WINDIVERT_MAX_QUEUE 16
static WinDivertThreadVars g_wd_tv[WINDIVERT_MAX_QUEUE];
static WinDivertQueueVars g_wd_qv[WINDIVERT_MAX_QUEUE];
static uint16_t g_wd_num = 0;
static SCMutex g_wd_init_lock = SCMUTEX_INITIALIZER;

void *WinDivertGetThread(int n)
{
    if (n >= g_wd_num) {
        return NULL;
    }
    return (void *)&g_wd_tv[n];
}

void *WinDivertGetQueue(int n)
{
    if (n >= g_wd_num) {
        return NULL;
    }
    return (void *)&g_wd_qv[n];
}

// not defined in MinGW winerror.h
#define ERROR_INVALID_IMAGE_HASH 577L
#define ERROR_DATA_NOT_ACCEPTED 592L

/**
 * \brief return an error description for Win32 error values commonly returned
 * by WinDivert
 */
static const char *WinDivertGetErrorString(DWORD error_code)
{
    switch (error_code) {
        // WinDivertOpen errors
        case ERROR_FILE_NOT_FOUND:
            return "The driver files WinDivert32.sys or WinDivert64.sys were "
                   "not found.";
        case ERROR_ACCESS_DENIED:
            return "Suricata must be run with Administrator privileges.";
        case ERROR_INVALID_PARAMETER:
            return "The WinDivert packet filter string is invalid.";
        case ERROR_INVALID_IMAGE_HASH:
            return "The WinDivert32.sys or WinDivert64.sys driver does not "
                   "have a valid digital signature, or your copy of Windows is "
                   "not up-to-date. Windows 7 and Server 2008 users need to "
                   "run Windows Update or install the following patch from "
                   "Microsoft: http://support.microsoft.com/kb/2949927";
        case ERROR_DRIVER_BLOCKED:
            return "This error occurs for various reasons, including: "
                   "attempting to load the 32-bit WinDivert.sys driver on a "
                   "64-bit system (or vice versa); the WinDivert.sys driver is "
                   "blocked by security software; or you are using a "
                   "virtualization environment that does not support "
                   "drivers.";
        case EPT_S_NOT_REGISTERED:
            return "This error occurs when the Base Filtering Engine service "
                   "has been disabled.";
        case ERROR_PROC_NOT_FOUND:
            return "The error may occur for Windows Vista users. The "
                   "solution is to install the following patch from Microsoft: "
                   "http://support.microsoft.com/kb/2761494.";

        // WinDivertSend errors
        case ERROR_HOST_UNREACHABLE:
            return "This error occurs when an impostor packet (with "
                   "pAddr->Impostor set to 1) is injected and the ip.TTL or "
                   "ipv6.HopLimit field goes to zero. This is a defense of "
                   "last resort against infinite loops caused by impostor "
                   "packets.";
        case ERROR_DATA_NOT_ACCEPTED:
            return "This error is returned when the user application attempts "
                   "to inject a malformed packet. It may also be returned for "
                   "valid inbound packets, and the Windows TCP/IP stack "
                   "rejects the packet for some reason.";
        case ERROR_RETRY:
            return "The underlying cause of this error is unknown. However, "
                   "this error usually occurs when certain kinds of "
                   "anti-virus/firewall/security software is installed, and "
                   "the error message usually resolves once the offending "
                   "program is uninstalled. This suggests a software "
                   "compatibility problem.";
        default:
            return "";
    }
}

/**
 * \brief logs a WinDivert error at Error level.
 */
#define WinDivertLogError(err_code)                                            \
    do {                                                                       \
        const char *win_err_str = Win32GetErrorString((err_code), NULL);       \
        SCLogError(SC_ERR_WINDIVERT_GENERIC,                                   \
                   "WinDivertOpen failed, error %" PRId32 " (0x%08" PRIx32     \
                   "): %s %s",                                                 \
                   (uint32_t)(err_code), (uint32_t)(err_code), win_err_str,    \
                   WinDivertGetErrorString(err_code));                         \
        LocalFree((LPVOID)win_err_str);                                        \
    } while (0);

/**
 * \brief initializes QueryPerformanceCounter values so we can get
 * absolute time from WinDivert timestamps.
 */
static void WinDivertInitQPCValues(WinDivertThreadVars *wd_tv)
{
    struct timeval now;

    TimeGet(&now);
    (void)QueryPerformanceCounter((LARGE_INTEGER *)&wd_tv->qpc_start_count);

    wd_tv->qpc_start_time =
            (uint64_t)now.tv_sec * (1000 * 1000) + (uint64_t)now.tv_usec;

    (void)QueryPerformanceFrequency((LARGE_INTEGER *)&wd_tv->qpc_freq_usec);
    /* \bug: clock drift? */
    wd_tv->qpc_freq_usec /= 1000 * 1000;
}

/**
 * \brief gets a timeval from a WinDivert timestamp
 */
static struct timeval WinDivertTimestampToTimeval(WinDivertThreadVars *wd_tv,
                                                  INT64 timestamp_count)
{
    struct timeval ts;

    int64_t qpc_delta = (int64_t)timestamp_count - wd_tv->qpc_start_count;
    int64_t unix_usec =
            wd_tv->qpc_start_time + (qpc_delta / wd_tv->qpc_freq_usec);

    ts.tv_sec = (long)(unix_usec / (1000 * 1000));
    ts.tv_usec = (long)(unix_usec - (int64_t)ts.tv_sec * (1000 * 1000));

    return ts;
}

/**
 * \brief initialize a WinDivert filter
 *
 * \param filter a WinDivert filter string as defined at
 * https://www.reqrypt.org/windivert-doc.html#filter_language
 *
 * \retval 0 on success
 * \retval -1 on failure
 */
int WinDivertRegisterQueue(bool forward, char *filter_str)
{
    SCEnter();
    int ret = 0;

    WINDIVERT_LAYER layer =
            forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;

    /* validate the filter string */
    const char *error_str;
    uint32_t error_pos;
    bool valid = WinDivertHelperCheckFilter(filter_str, layer, &error_str,
                                            &error_pos);
    if (!valid) {
        SCLogWarning(
                SC_ERR_WINDIVERT_INVALID_FILTER,
                "Invalid filter \"%s\" supplied to WinDivert: %s at position "
                "%" PRId32 "",
                filter_str, error_str, error_pos);
        SCReturnInt(SC_ERR_WINDIVERT_INVALID_FILTER);
    }

    /* initialize the queue */
    SCMutexLock(&g_wd_init_lock);

    if (g_wd_num >= WINDIVERT_MAX_QUEUE) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Too many WinDivert queues specified %" PRId32 "", g_wd_num);
        ret = -1;
        goto unlock;
    }
    if (g_wd_num == 0) {
        /* on first registration, zero-initialize all array structs */
        memset(&g_wd_tv, 0, sizeof(g_wd_tv));
        memset(&g_wd_qv, 0, sizeof(g_wd_qv));
    }

    /* init thread vars */
    WinDivertThreadVars *wd_tv = &g_wd_tv[g_wd_num];
    wd_tv->thread_num = g_wd_num;

    /* init queue vars */
    WinDivertQueueVars *wd_qv = &g_wd_qv[g_wd_num];
    wd_qv->queue_num = g_wd_num;

    WinDivertInitQPCValues(wd_tv);

    /* copy filter to persistent storage */
    size_t filter_len = strlen(filter_str);
    size_t copy_len =
            strlcpy(wd_qv->filter_str, filter_str, sizeof(wd_qv->filter_str));
    if (filter_len > copy_len) {
        SCLogWarning(SC_ERR_WINDIVERT_TOOLONG_FILTER,
                     "Queue length exceeds storage by %" PRId32 " bytes",
                     (int32_t)(filter_len - copy_len));
        ret = -1;
        goto unlock;
    }

    wd_qv->layer = layer;
    wd_qv->priority =
            g_wd_num; /* priority set in the order filters are defined */
    wd_qv->flags = 0; /* normal inline function */

    SCMutexInit(&wd_qv->filter_init_mutex, NULL);
    SCMutexInit(&wd_qv->counters_mutex, NULL);

    g_wd_num++;

unlock:
    SCMutexUnlock(&g_wd_init_lock);

    if (ret == 0) {
        // stringify queue index to use as thread name descriptor
        char wd_num_str[6];
        wd_num_str[sizeof(wd_num_str) - 1] = 0;
        snprintf(wd_num_str, sizeof(wd_num_str), "%" PRId16 "", g_wd_num);

        LiveRegisterDevice(wd_num_str);

        SCLogDebug("Queue %" PRId16 " registered", wd_qv->queue_num);
    }

    return ret;
}

/* forward declarations of internal functions */
/* Receive functions */
TmEcode ReceiveWinDivertLoop(ThreadVars *, void *, void *);
TmEcode ReceiveWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveWinDivertThreadDeinit(ThreadVars *, void *);
void ReceiveWinDivertThreadExitStats(ThreadVars *, void *);

/* Verdict functions */
TmEcode VerdictWinDivert(ThreadVars *, Packet *, void *);
TmEcode VerdictWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *, void *);

/* Decode functions */
TmEcode DecodeWinDivert(ThreadVars *, Packet *, void *);
TmEcode DecodeWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeWinDivertThreadDeinit(ThreadVars *, void *);

/* internal helper functions */
static TmEcode WinDivertRecvHelper(ThreadVars *tv, WinDivertThreadVars *);
static TmEcode WinDivertVerdictHelper(ThreadVars *tv, Packet *p);
static TmEcode WinDivertCloseHelper(WinDivertThreadVars *);

static TmEcode WinDivertCollectFilterDevices(WinDivertThreadVars *,
                                             WinDivertQueueVars *);
static bool WinDivertIfaceMatchFilter(const char *filter_string, int if_index);
static void WinDivertDisableOffloading(WinDivertThreadVars *);
static void WinDivertRestoreOffloading(WinDivertThreadVars *);

void TmModuleReceiveWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_RECEIVEWINDIVERT];

    tm_ptr->name = "ReceiveWinDivert";
    tm_ptr->ThreadInit = ReceiveWinDivertThreadInit;
    tm_ptr->PktAcqLoop = ReceiveWinDivertLoop;
    tm_ptr->ThreadExitPrintStats = ReceiveWinDivertThreadExitStats;
    tm_ptr->ThreadDeinit = ReceiveWinDivertThreadDeinit;
    tm_ptr->flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_VERDICTWINDIVERT];

    tm_ptr->name = "VerdictWinDivert";
    tm_ptr->ThreadInit = VerdictWinDivertThreadInit;
    tm_ptr->Func = VerdictWinDivert;
    tm_ptr->ThreadDeinit = VerdictWinDivertThreadDeinit;
}

void TmModuleDecodeWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_DECODEWINDIVERT];

    tm_ptr->name = "DecodeWinDivert";
    tm_ptr->ThreadInit = DecodeWinDivertThreadInit;
    tm_ptr->Func = DecodeWinDivert;
    tm_ptr->ThreadDeinit = DecodeWinDivertThreadDeinit;
    tm_ptr->flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief Main WinDivert packet receive pump
 */
TmEcode ReceiveWinDivertLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)data;
    wd_tv->slot = ((TmSlot *)slot)->slot_next;

    while (true) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        if (unlikely(WinDivertRecvHelper(tv, wd_tv) != TM_ECODE_OK)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode WinDivertRecvHelper(ThreadVars *tv, WinDivertThreadVars *wd_tv)
{
    SCEnter();

#ifdef COUNTERS
    WinDivertQueueVars *wd_qv = WinDivertGetQueue(wd_tv->thread_num);
#endif /* COUNTERS */

    /* make sure we have at least one packet in the packet pool, to prevent us
     * from alloc'ing packets at line rate
     */
    PacketPoolWait();

    /* obtain a packet buffer */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCLogDebug(
                "PacketGetFromQueueOrAlloc() - failed to obtain Packet buffer");
        SCReturnInt(TM_ECODE_FAILED);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* receive packet, depending on offload status. MTU is used as an estimator
     * for direct data alloc size, and this is meaningless if large segments are
     * coalesced before they reach WinDivert */
    bool success = false;
    uint32_t pktlen = 0;
    if (wd_tv->offload_enabled) {
        /* allocate external, if not already */
        PacketCallocExtPkt(p, MAX_PAYLOAD_SIZE);

        success =
                WinDivertRecv(wd_tv->filter_handle, p->ext_pkt,
                              MAX_PAYLOAD_SIZE, &p->windivert_v.addr, &pktlen);
    } else {
        success = WinDivertRecv(wd_tv->filter_handle, GET_PKT_DIRECT_DATA(p),
                                GET_PKT_DIRECT_MAX_SIZE(p),
                                &p->windivert_v.addr, &pktlen);
    }
    SET_PKT_LEN(p, pktlen);

    if (!success) {
#ifdef COUNTERS
        SCMutexLock(&wd_qv->counters_mutex);
        wd_qv->errs++;
        SCMutexUnlock(&wd_qv->counters_mutex);
#endif /* COUNTERS */

        /* ensure packet length is zero to trigger an error in packet decoding
         */
        SET_PKT_LEN(p, 0);

        SCLogInfo("WinDivertRecv failed: error %" PRIu32 "",
                  (uint32_t)(GetLastError()));
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogDebug("Packet received, length %" PRId32 "", GET_PKT_LEN(p));

    p->ts = WinDivertTimestampToTimeval(wd_tv, p->windivert_v.addr.Timestamp);
    p->windivert_v.thread_num = wd_tv->thread_num;

#ifdef COUNTERS
    SCMutexLock(&wd_qv->counters_mutex);
    wd_qv->pkts++;
    wd_qv->bytes += GET_PKT_LEN(p);
    SCMutexUnlock(&wd_qv->counters_mutex);
#endif /* COUNTERS */

    /* Do the packet processing by calling TmThreadsSlotProcessPkt, this will,
     * depending on the running mode, pass the packet to the treatment functions
     * or push it to a packet pool. So processing time can vary.
     */
    if (TmThreadsSlotProcessPkt(tv, wd_tv->slot, p) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceiveWinDivert
 *
 * ReceiveWinDivertThreadInit sets up receiving packets via WinDivert.
 *
 * \param tv pointer to generic thread vars
 * \param initdata pointer to the interface passed from the user
 * \param data out-pointer to the WinDivert-specific thread vars
 */
TmEcode ReceiveWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                   void **data)
{
    SCEnter();
    TmEcode ret = TM_ECODE_OK;

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)initdata;

    if (wd_tv == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    WinDivertQueueVars *wd_qv = WinDivertGetQueue(wd_tv->thread_num);

    if (wd_qv == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "queue == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCMutexLock(&wd_qv->filter_init_mutex);
    /* does the queue already have an active handle? */
    if (wd_qv->filter_handle != NULL &&
        wd_qv->filter_handle != INVALID_HANDLE_VALUE) {
        goto unlock;
    }

    TAILQ_INIT(&wd_tv->live_devices);

    if (WinDivertCollectFilterDevices(wd_tv, wd_qv) == TM_ECODE_OK) {
        WinDivertDisableOffloading(wd_tv);
    } else {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failed to obtain network devices for WinDivert filter");
    }

    /* we open now so that we can immediately start handling packets,
     * instead of losing however many would occur between registering the
     * queue and starting a receive thread. */
    wd_qv->filter_handle = WinDivertOpen(wd_qv->filter_str, wd_qv->layer,
                                         wd_qv->priority, wd_qv->flags);
    if (wd_qv->filter_handle == INVALID_HANDLE_VALUE) {
        WinDivertLogError(GetLastError());
        ret = TM_ECODE_FAILED;
        goto unlock;
    }

unlock:
    if (ret == 0) { /* success */
        wd_tv->filter_handle = wd_qv->filter_handle;

        /* set our return context */
        *data = wd_tv;
    }

    SCMutexUnlock(&wd_qv->filter_init_mutex);
    SCReturnInt(ret);
}

/**
 * \brief collect all devices covered by this filter in the thread vars'
 * live devices list
 *
 * \param wd_tv pointer to WinDivert thread vars
 * \param wd_qv pointer to WinDivert queue vars
 */
static TmEcode WinDivertCollectFilterDevices(WinDivertThreadVars *wd_tv,
                                             WinDivertQueueVars *wd_qv)
{
    SCEnter();
    TmEcode ret = TM_ECODE_OK;

    IP_ADAPTER_ADDRESSES *if_info_list;
    DWORD err = (DWORD)Win32GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        ret = TM_ECODE_FAILED;
        goto release;
    }

    for (IP_ADAPTER_ADDRESSES *if_info = if_info_list; if_info != NULL;
         if_info = if_info->Next) {

        if (WinDivertIfaceMatchFilter(wd_qv->filter_str, if_info->IfIndex)) {
            SCLogConfig("Found adapter %s matching WinDivert filter %s",
                      if_info->AdapterName, wd_qv->filter_str);

            LiveDevice *new_ldev = SCCalloc(1, sizeof(LiveDevice));
            if (new_ldev == NULL) {
                ret = TM_ECODE_FAILED;
                goto release;
            }
            new_ldev->dev = SCStrdup(if_info->AdapterName);
            if (new_ldev->dev == NULL) {
                ret = TM_ECODE_FAILED;
                goto release;
            }
            TAILQ_INSERT_TAIL(&wd_tv->live_devices, new_ldev, next);
        } else {
            SCLogDebug("Adapter %s does not match WinDivert filter %s",
                       if_info->AdapterName, wd_qv->filter_str);
        }
    }

release:
    SCFree(if_info_list);

    SCReturnInt(ret);
}

/**
 * \brief test if the specified interface index matches the filter
 */
static bool WinDivertIfaceMatchFilter(const char *filter_string, int if_index)
{
    bool match = false;

    WINDIVERT_ADDRESS if_addr = {};
    if_addr.IfIdx = if_index;

    uint8_t dummy[4] = {4, 4, 4, 4};

    match = WinDivertHelperEvalFilter(filter_string, WINDIVERT_LAYER_NETWORK,
                                      dummy, sizeof(dummy), &if_addr);
    if (!match) {
        int err = GetLastError();
        if (err != 0) {
            SCLogWarning(SC_ERR_WINDIVERT_GENERIC,
                         "Failed to evaluate filter: 0x%" PRIx32, err);
        }
    }

    return match;
}

/**
 * \brief disable offload status on devices for this filter
 *
 * \param wd_tv pointer to WinDivert thread vars
 */
static void WinDivertDisableOffloading(WinDivertThreadVars *wd_tv)
{
    for (LiveDevice *ldev = TAILQ_FIRST(&wd_tv->live_devices); ldev != NULL;
         ldev = TAILQ_NEXT(ldev, next)) {

        if (LiveGetOffload() == 0) {
            if (GetIfaceOffloading(ldev->dev, 1, 1) == 1) {
                wd_tv->offload_enabled = true;
            }
        } else {
            if (DisableIfaceOffloading(ldev, 1, 1) != 1) {
                wd_tv->offload_enabled = true;
            }
        }
    }
}

/**
 * \brief enable offload status on devices for this filter
 *
 * \param wd_tv pointer to WinDivert thread vars
 */
static void WinDivertRestoreOffloading(WinDivertThreadVars *wd_tv)
{
    for (LiveDevice *ldev = TAILQ_FIRST(&wd_tv->live_devices); ldev != NULL;
         ldev = TAILQ_NEXT(ldev, next)) {

        RestoreIfaceOffloading(ldev);
    }
}

/**
 * \brief Deinit function releases resources at exit.
 *
 * \param tv pointer to generic thread vars
 * \param data pointer to WinDivert-specific thread vars
 */
TmEcode ReceiveWinDivertThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)data;

    SCReturnCT(WinDivertCloseHelper(wd_tv), "TmEcode");
}

/**
 * \brief ExitStats prints stats to stdout at exit
 *
 *
 * \param tv pointer to generic thread vars
 * \param data pointer to WinDivert-specific thread vars
 */
void ReceiveWinDivertThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)data;
    WinDivertQueueVars *wd_qv = WinDivertGetQueue(wd_tv->thread_num);
    if (wd_qv == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "queue == NULL");
        SCReturn;
    }

    SCMutexLock(&wd_qv->counters_mutex);

    SCLogInfo("(%s) Packets %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
              tv->name, wd_qv->pkts, wd_qv->bytes, wd_qv->errs);
    SCLogInfo("(%s) Verdict: Accepted %" PRIu32 ", Dropped %" PRIu32
              ", Replaced %" PRIu32 "",
              tv->name, wd_qv->accepted, wd_qv->dropped, wd_qv->replaced);

    SCMutexUnlock(&wd_qv->counters_mutex);
    SCReturn;
}

/**
 * \brief WinDivert verdict module packet entry function
 */
TmEcode VerdictWinDivert(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    TmEcode ret = TM_ECODE_OK;

    ret = WinDivertVerdictHelper(tv, p);
    if (ret != TM_ECODE_OK) {
        SCReturnInt(ret);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief internal helper function to do the bulk of verdict work
 */
static TmEcode WinDivertVerdictHelper(ThreadVars *tv, Packet *p)
{
    SCEnter();
    WinDivertThreadVars *wd_tv = WinDivertGetThread(p->windivert_v.thread_num);

    /* update counters */
    CaptureStatsUpdate(tv, &wd_tv->stats, p);

#ifdef COUNTERS
    WinDivertQueueVars *wd_qv = WinDivertGetQueue(wd_tv->thread_num);
#endif /* COUNTERS */

    p->windivert_v.verdicted = true;

    /* can't verdict a "fake" packet */
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* the handle has been closed and we can no longer use it */
    if (wd_tv->filter_handle == INVALID_HANDLE_VALUE ||
        wd_tv->filter_handle == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* we can't verdict tunnel packets without ensuring all encapsulated
     * packets are verdicted */
    if (IS_TUNNEL_PKT(p)) {
        bool finalVerdict = VerdictTunnelPacket(p);
        if (!finalVerdict) {
            SCReturnInt(TM_ECODE_OK);
        }

        // the action needs to occur on the root packet.
        if (p->root != NULL) {
            p = p->root;
        }
    }

    /* DROP simply means we do nothing; the WinDivert driver does the rest.
     */
    if (PacketTestAction(p, ACTION_DROP)) {
#ifdef COUNTERS
        SCMutexLock(&wd_qv->counters_mutex);
        wd_qv->dropped++;
        SCMutexUnlock(&wd_qv->counters_mutex);
#endif /* counters */

        SCReturnInt(TM_ECODE_OK);
    }

    bool success = WinDivertSend(wd_tv->filter_handle, GET_PKT_DATA(p),
                                 GET_PKT_LEN(p), &p->windivert_v.addr, NULL);

    if (unlikely(!success)) {
        WinDivertLogError(GetLastError());
        SCReturnInt(TM_ECODE_FAILED);
    }

#ifdef COUNTERS
    SCMutexLock(&wd_qv->counters_mutex);
    wd_qv->accepted++;
    SCMutexUnlock(&wd_qv->counters_mutex);
#endif /* counters */

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief init the verdict thread, which is piggybacked off the receive
 * thread
 */
TmEcode VerdictWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                   void **data)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)initdata;

    CaptureStatsSetup(tv, &wd_tv->stats);

    *data = wd_tv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief deinit the verdict thread and shut down the WinDivert driver if
 * it's still up.
 */
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)data;

    SCReturnCT(WinDivertCloseHelper(wd_tv), "TmEcode");
}

/**
 * \brief decode a raw packet submitted to suricata from the WinDivert
 * driver
 *
 * All WinDivert packets are IPv4/v6, but do not include the network layer
 * to differentiate the two, so instead we must check the version and go
 * from there.
 */
TmEcode DecodeWinDivert(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *d_tv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    DecodeUpdatePacketCounters(tv, d_tv, p);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, d_tv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else if (IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, d_tv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else {
        SCLogDebug("packet unsupported by WinDivert, first byte: %02x",
                   *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, d_tv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                  void **data)
{
    SCEnter();

    DecodeThreadVars *d_tv = DecodeThreadVarsAlloc(tv);
    if (d_tv == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    DecodeRegisterPerfCounters(d_tv, tv);

    *data = d_tv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeWinDivertThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief helper function for use with ThreadDeinit functions
 */
static TmEcode WinDivertCloseHelper(WinDivertThreadVars *wd_tv)
{
    SCEnter();
    TmEcode ret = TM_ECODE_OK;

    WinDivertQueueVars *wd_qv = WinDivertGetQueue(wd_tv->thread_num);
    if (wd_qv == NULL) {
        SCLogDebug("No queue could be found for thread num %" PRId32 "",
                   wd_tv->thread_num);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCMutexLock(&wd_qv->filter_init_mutex);

    /* check if there's nothing to close */
    if (wd_qv->filter_handle == INVALID_HANDLE_VALUE ||
        wd_qv->filter_handle == NULL) {
        goto unlock;
    }

    if (!WinDivertClose(wd_qv->filter_handle)) {
        SCLogError(SC_ERR_FATAL, "WinDivertClose failed: error %" PRIu32 "",
                   (uint32_t)(GetLastError()));
        ret = TM_ECODE_FAILED;
        goto unlock;
    }

    (void)WinDivertRestoreOffloading(wd_tv);

    wd_qv->filter_handle = NULL;

unlock:
    SCMutexUnlock(&wd_qv->filter_init_mutex);

    if (ret == TM_ECODE_OK) {
        SCMutexDestroy(&wd_qv->filter_init_mutex);
        SCMutexDestroy(&wd_qv->counters_mutex);
    }

    SCReturnInt(ret);
}

#ifdef UNITTESTS
static int SourceWinDivertTestIfaceMatchFilter(void)
{
    struct testdata {
        const char *filter;
        int if_index;
        bool expected;
    };

    struct testdata tests[] = {
            {"true", 11, true},
            {"ifIdx=11", 11, true},
            {"ifIdx==11", 11, true},
            {"ifIdx!=11", 1, true},
            {"ifIdx!=11", 11, false},
            {"ifIdx=3", 4, false},
            {"ifIdx=11 || ifIdx=5", 5, true},
            {"ifIdx=11 || ifIdx=4", 5, false},
            {"ifIdx<3 || ifIdx>7", 8, true},
            {"ifIdx<3 || ifIdx>7", 5, false},
            {"ifIdx>3 or ifIdx<7", 5, true},
            {"ifIdx>3 && ifIdx<7", 5, true},
            {"ifIdx>3 && ifIdx<7", 1, false},
            {"(ifIdx > 3 && ifIdx < 7) or ifIdx == 11", 11, true}};

    size_t count = (sizeof(tests) / sizeof(tests[0]));

    for (size_t i = 0; i < count; i++) {
        struct testdata test = tests[i];

        bool actual = WinDivertIfaceMatchFilter(test.filter, test.if_index);
        if (actual != test.expected) {
            printf("WinDivertIfaceMatchFilter(\"%s\", %d) == %d, expected %d\n",
                   test.filter, test.if_index, actual, test.expected);
            FAIL;
        }
    }
    PASS;
}
#endif

/**
 * \brief this function registers unit tests for the WinDivert Source
 */
void SourceWinDivertRegisterTests()
{
#ifdef UNITTESTS
    UtRegisterTest("SourceWinDivertTestIfaceMatchFilter",
                   SourceWinDivertTestIfaceMatchFilter);
#endif
}

#endif /* WINDIVERT */
