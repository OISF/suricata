/* Copyright (C) 2011-2022 Open Information Security Foundation
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
 *  \defgroup afxdppacket AF_XDP running mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Richard McConnell <richard_mcconnell@rapid7.com>
 *
 * AF_XDP socket acquisition support
 *
 */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H  1
#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "conf.h"
#include "util-cpu.h"
#include "util-datalink.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-ebpf.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "util-host-info.h"
#include "tmqh-packetpool.h"
#include "source-af-xdp.h"
#include "runmodes.h"
#include "flow-storage.h"
#include "util-validate.h"

#ifdef HAVE_AF_XDP
#include <xdp/xsk.h>
#include <net/if.h>
#endif

#ifndef HAVE_AF_XDP

TmEcode NoAFXDPSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveAFXDPRegister(void)
{
    tmm_modules[TMM_RECEIVEAFXDP].name = "ReceiveAFXDP";
    tmm_modules[TMM_RECEIVEAFXDP].ThreadInit = NoAFXDPSupportExit;
    tmm_modules[TMM_RECEIVEAFXDP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].cap_flags = 0;
    tmm_modules[TMM_RECEIVEAFXDP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeAFXDP.
 */
void TmModuleDecodeAFXDPRegister(void)
{
    tmm_modules[TMM_DECODEAFXDP].name = "DecodeAFXDP";
    tmm_modules[TMM_DECODEAFXDP].ThreadInit = NoAFXDPSupportExit;
    tmm_modules[TMM_DECODEAFXDP].Func = NULL;
    tmm_modules[TMM_DECODEAFXDP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFXDP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEAFXDP].cap_flags = 0;
    tmm_modules[TMM_DECODEAFXDP].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoAFXDPSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_AF_XDP,
            "Error creating thread %s: you do not have "
            "support for AF_XDP enabled, on Linux host please recompile "
            "with --enable-af-xdp",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have AF_XDP support */

#define POLL_TIMEOUT 100
#define NUM_FRAMES   XSK_RING_PROD__DEFAULT_NUM_DESCS
#define FRAME_SIZE   XSK_UMEM__DEFAULT_FRAME_SIZE
#define MEM_BYTES    (NUM_FRAMES * FRAME_SIZE * 2)

#define DEFAULT_FILENAME_SIZE 50

struct xsk_init_protect {
    SCMutex queue_protect;
    SC_ATOMIC_DECLARE(uint8_t, queue_num);
} xsk_protect;

struct xsk_sock_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *buf;
    uint32_t prog_id;
    uint32_t queue_num;

    /* Configuration items */
    struct xsk_socket_config cfg;
    bool enable_busy_poll;
    uint32_t busy_poll_time;
    uint32_t busy_poll_budget;

    struct pollfd fd;
} xsk_info;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct AFXDPThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;
    LiveDevice *livedev;

    /* thread specific socket */
    int promisc;
    int threads;

    char iface[AFXDP_IFACE_NAME_LENGTH];
    uint32_t ifindex;

    /* AF_XDP stucture */
    struct xsk_sock_info xsk;
    struct xsk_umem_config mem_cfg;
    int mmap_alignment_flag;
    uint32_t gro_flush_timeout;
    uint32_t napi_defer_hard_irqs;

    /* Stats parameters */
    uint64_t pkts;
    uint64_t bytes;
    uint16_t capture_afxdp_packets;
    uint16_t capture_kernel_drops;
    uint16_t capture_afxdp_poll;
    uint16_t capture_afxdp_poll_timeout;
    uint16_t capture_afxdp_poll_failed;
    uint16_t capture_afxdp_empty_reads;
    uint16_t capture_afxdp_failed_reads;
} AFXDPThreadVars;

static TmEcode ReceiveAFXDPThreadInit(ThreadVars *, const void *, void **);
static void ReceiveAFXDPThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveAFXDPThreadDeinit(ThreadVars *, void *);
static TmEcode ReceiveAFXDPLoop(ThreadVars *tv, void *data, void *slot);

static TmEcode DecodeAFXDPThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeAFXDPThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeAFXDP(ThreadVars *, Packet *, void *);

/**
 * \brief Registration Function for RecieveAFXDP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveAFXDPRegister(void)
{
    tmm_modules[TMM_RECEIVEAFXDP].name = "ReceiveAFXDP";
    tmm_modules[TMM_RECEIVEAFXDP].ThreadInit = ReceiveAFXDPThreadInit;
    tmm_modules[TMM_RECEIVEAFXDP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].PktAcqLoop = ReceiveAFXDPLoop;
    tmm_modules[TMM_RECEIVEAFXDP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadExitPrintStats = ReceiveAFXDPThreadExitStats;
    tmm_modules[TMM_RECEIVEAFXDP].ThreadDeinit = ReceiveAFXDPThreadDeinit;
    tmm_modules[TMM_RECEIVEAFXDP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEAFXDP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeAFXDP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeAFXDPRegister(void)
{
    tmm_modules[TMM_DECODEAFXDP].name = "DecodeAFXDP";
    tmm_modules[TMM_DECODEAFXDP].ThreadInit = DecodeAFXDPThreadInit;
    tmm_modules[TMM_DECODEAFXDP].Func = DecodeAFXDP;
    tmm_modules[TMM_DECODEAFXDP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFXDP].ThreadDeinit = DecodeAFXDPThreadDeinit;
    tmm_modules[TMM_DECODEAFXDP].cap_flags = 0;
    tmm_modules[TMM_DECODEAFXDP].flags = TM_FLAG_DECODE_TM;
}

static inline void AFXDPDumpCounters(AFXDPThreadVars *ptv)
{
    struct xdp_statistics stats;
    socklen_t len = sizeof(struct xdp_statistics);
    int fd = xsk_socket__fd(ptv->xsk.xsk);

    if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &len) >= 0) {
        uint64_t rx_dropped = stats.rx_dropped + stats.rx_invalid_descs + stats.rx_ring_full;

        StatsAddUI64(ptv->tv, ptv->capture_kernel_drops,
                rx_dropped - StatsGetLocalCounterValue(ptv->tv, ptv->capture_kernel_drops));
        StatsAddUI64(ptv->tv, ptv->capture_afxdp_packets, ptv->pkts);

        (void)SC_ATOMIC_SET(ptv->livedev->drop, rx_dropped);
        (void)SC_ATOMIC_ADD(ptv->livedev->pkts, ptv->pkts);

        SCLogDebug("(%s) Kernel: Packets %" PRIu64 ", bytes %" PRIu64 ", dropped %" PRIu64 "",
                ptv->tv->name, StatsGetLocalCounterValue(ptv->tv, ptv->capture_afxdp_packets),
                ptv->bytes, StatsGetLocalCounterValue(ptv->tv, ptv->capture_kernel_drops));

        ptv->pkts = 0;
    }
}

/**
 * \brief Init function for socket creation.
 *
 * Mutex used to synchonise initialisation - each socket opens a
 * different queue. The specific order in which each queue is
 * opened is not important, but it is vital the queue_num's
 * are different.
 *
 * \param tv pointer to ThreadVars
 */
TmEcode AFXDPQueueProtectionInit(void)
{
    SCEnter();

    SCMutexInit(&xsk_protect.queue_protect, NULL);
    SC_ATOMIC_SET(xsk_protect.queue_num, 0);
    SCReturnInt(TM_ECODE_OK);
}

void AFXDPMutexClean(void)
{
    SCMutexDestroy(&xsk_protect.queue_protect);
}

static TmEcode AFXDPAssignQueueID(AFXDPThreadVars *ptv)
{
    ptv->xsk.queue_num = SC_ATOMIC_GET(xsk_protect.queue_num);
    SC_ATOMIC_ADD(xsk_protect.queue_num, 1);
    SCReturnInt(TM_ECODE_OK);
}

static void AFXDPAllThreadsRunning(AFXDPThreadVars *ptv)
{
    SCMutexLock(&xsk_protect.queue_protect);
    if ((ptv->threads - 1) == (int)ptv->xsk.queue_num) {
        SCLogInfo("All AF_XDP capture threads are running.");
    }
    SCMutexUnlock(&xsk_protect.queue_protect);
}

/**
 * \brief Init function for ReceiveAFXDP.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with AFPThreadVars
 *
 * \todo Create a general AFP setup function.
 */
static TmEcode ReceiveAFXDPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    AFXDPIfaceConfig *afxdpconfig = (AFXDPIfaceConfig *)initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFXDPThreadVars *ptv = SCMalloc(sizeof(AFXDPThreadVars));
    if (unlikely(ptv == NULL)) {
        afxdpconfig->DerefFunc(afxdpconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(AFXDPThreadVars));

    ptv->tv = tv;

    strlcpy(ptv->iface, afxdpconfig->iface, AFXDP_IFACE_NAME_LENGTH);
    ptv->iface[AFXDP_IFACE_NAME_LENGTH - 1] = '\0';
    ptv->ifindex = if_nametoindex(ptv->iface);

    ptv->livedev = LiveGetDevice(ptv->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->promisc = afxdpconfig->promisc;
    if (ptv->promisc != 0) {
        /* Force promiscuous mode */
        if (SetIfaceFlags(ptv->iface, IFF_PROMISC | IFF_UP) != 0) {
            SCLogError(SC_ERR_AFXDP_CREATE,
                    "Failed to switch interface (%s) to promiscuous, error %s", ptv->iface,
                    strerror(errno));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    ptv->threads = afxdpconfig->threads;

    /* Socket configuration */
    ptv->xsk.cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ptv->xsk.cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    ptv->xsk.cfg.xdp_flags = afxdpconfig->mode;
    ptv->xsk.cfg.bind_flags = afxdpconfig->bind_flags;

    /* UMEM configuration */
    ptv->mem_cfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
    ptv->mem_cfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ptv->mem_cfg.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    ptv->mem_cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
    ptv->mem_cfg.flags = afxdpconfig->mem_alignment;

    /* Use hugepages if unaligned chunk mode */
    if (ptv->mem_cfg.flags == XDP_UMEM_UNALIGNED_CHUNK_FLAG) {
        ptv->mmap_alignment_flag = MAP_HUGETLB;
    }

    /* Busy polling configuration */
    ptv->xsk.enable_busy_poll = afxdpconfig->enable_busy_poll;
    ptv->xsk.busy_poll_budget = afxdpconfig->busy_poll_budget;
    ptv->xsk.busy_poll_time = afxdpconfig->busy_poll_time;
    ptv->gro_flush_timeout = afxdpconfig->gro_flush_timeout;
    ptv->napi_defer_hard_irqs = afxdpconfig->napi_defer_hard_irqs;

    /* Stats registration */
    ptv->capture_afxdp_packets = StatsRegisterCounter("capture.afxdp_packets", ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops", ptv->tv);
    ptv->capture_afxdp_poll = StatsRegisterCounter("capture.afxdp.poll", ptv->tv);
    ptv->capture_afxdp_poll_timeout = StatsRegisterCounter("capture.afxdp.poll_timeout", ptv->tv);
    ptv->capture_afxdp_poll_failed = StatsRegisterCounter("capture.afxdp.poll_failed", ptv->tv);
    ptv->capture_afxdp_empty_reads = StatsRegisterCounter("capture.afxdp.empty_reads", ptv->tv);
    ptv->capture_afxdp_failed_reads = StatsRegisterCounter("capture.afxdp.failed_reads", ptv->tv);

    *data = (void *)ptv;
    afxdpconfig->DerefFunc(afxdpconfig);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ConfigureXSKUmem(AFXDPThreadVars *ptv)
{
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | ptv->mmap_alignment_flag;

    ptv->xsk.buf = mmap(NULL, MEM_BYTES, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);

    if (ptv->xsk.buf == MAP_FAILED) {
        SCLogError(SC_ERR_MEM_ALLOC, "mmap: failed to acquire memory");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (xsk_umem__create(&ptv->xsk.umem, ptv->xsk.buf, MEM_BYTES, &ptv->xsk.fq, &ptv->xsk.cq,
                &ptv->mem_cfg)) {
        SCLogError(SC_ERR_AFXDP_CREATE, "failed to create umem");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Linux knobs are tuned to enable a NAPI polling context
 *
 * \param tv pointer to AFXDPThreadVars
 */
static TmEcode WriteLinuxTunables(AFXDPThreadVars *ptv)
{
    char fname[DEFAULT_FILENAME_SIZE];

    if (snprintf(fname, DEFAULT_FILENAME_SIZE, "/sys/class/net/%s/gro_flush_timeout", ptv->iface) <
            0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    FILE *fp = fopen(fname, "w");
    if (fp == NULL) {
        SCLogWarning(SC_ERR_FOPEN, "Could not open file: %s", fname);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (fprintf(fp, "%d", ptv->gro_flush_timeout) < 0) {
        SCLogWarning(SC_ERR_FOPEN, "Could not write to file: %s", fname);
        fclose(fp);
        SCReturnInt(TM_ECODE_FAILED);
    }
    fclose(fp);

    if (snprintf(fname, DEFAULT_FILENAME_SIZE, "/sys/class/net/%s/napi_defer_hard_irqs",
                ptv->iface) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    fp = fopen(fname, "w");
    if (fp == NULL) {
        SCLogWarning(SC_ERR_FOPEN, "Could not open file: %s", fname);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (fprintf(fp, "%d", ptv->napi_defer_hard_irqs) < 0) {
        SCLogWarning(SC_ERR_FOPEN, "Could not write to file: %s", fname);
        fclose(fp);
        SCReturnInt(TM_ECODE_FAILED);
    }
    fclose(fp);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ConfigureBusyPolling(AFXDPThreadVars *ptv)
{
    const int fd = xsk_socket__fd(ptv->xsk.xsk);
    int sock_opt = 1;

    if (!ptv->xsk.enable_busy_poll) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* Kernel version must be >= 5.11 to avail of SO_PREFER_BUSY_POLL
     * see linux commit: 7fd3253a7de6a317a0683f83739479fb880bffc8
     */
    if (!SCKernelVersionIsAtLeast(5, 11)) {
        SCLogWarning(SC_WARN_AFXDP_CONF, "Kernel version older than required: v5.11,"
                                         " upgrade kernel version to use this option.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (WriteLinuxTunables(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    sock_opt = ptv->xsk.busy_poll_time;
    if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    sock_opt = ptv->xsk.busy_poll_budget;
    if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

static inline void WakeupSocket(void *data)
{
    AFXDPThreadVars *ptv = (AFXDPThreadVars *)data;

    /* Assuming kernel >= 5.11 in use if xdp_busy_poll is enabled */
    if (ptv->xsk.enable_busy_poll || xsk_ring_prod__needs_wakeup(&ptv->xsk.fq)) {
        recvfrom(xsk_socket__fd(ptv->xsk.xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }
}

static TmEcode InitFillRing(AFXDPThreadVars *ptv, const uint32_t cnt)
{
    uint32_t idx_fq = 0;

    uint32_t ret = xsk_ring_prod__reserve(&ptv->xsk.fq, cnt, &idx_fq);
    while (ret != cnt) {
        WakeupSocket(ptv);
        ret = xsk_ring_prod__reserve(&ptv->xsk.fq, cnt, &idx_fq);
    }

    for (uint32_t i = 0; i < cnt; i++) {
        *xsk_ring_prod__fill_addr(&ptv->xsk.fq, idx_fq++) = i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(&ptv->xsk.fq, cnt);
    SCReturnInt(TM_ECODE_OK);
}

static void AFXDPReleasePacket(Packet *p)
{
    *xsk_ring_prod__fill_addr((struct xsk_ring_prod *)p->afxdp_v.fq, p->afxdp_v.fq_idx) =
            p->afxdp_v.orig;

    PacketFreeOrRelease(p);
}

static TmEcode OpenXSKSocket(AFXDPThreadVars *ptv)
{
    int ret;

    SCMutexLock(&xsk_protect.queue_protect);

    if (AFXDPAssignQueueID(ptv) != TM_ECODE_OK) {
        SCLogError(SC_ERR_SOCKET, "Failed to assign queue ID");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if ((ret = xsk_socket__create(&ptv->xsk.xsk, ptv->livedev->dev, ptv->xsk.queue_num,
                 ptv->xsk.umem, &ptv->xsk.rx, &ptv->xsk.tx, &ptv->xsk.cfg))) {
        SCLogError(SC_ERR_SOCKET, "Failed to create socket: %s", strerror(-ret));
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogDebug("bind to %s on queue %u", ptv->iface, ptv->xsk.queue_num);

    /* For polling and socket options */
    ptv->xsk.fd.fd = xsk_socket__fd(ptv->xsk.xsk);
    ptv->xsk.fd.events = POLLIN;

    SCMutexUnlock(&xsk_protect.queue_protect);

    SCReturnInt(TM_ECODE_OK);
}

static inline int DumpStatsEverySecond(AFXDPThreadVars *ptv, time_t *last_dump)
{
    int stats_dumped = 0;
    time_t current_time = time(NULL);

    if (current_time != *last_dump) {
        AFXDPDumpCounters(ptv);
        *last_dump = current_time;
        stats_dumped = 1;
    }

    StatsSyncCountersIfSignalled(ptv->tv);

    return stats_dumped;
}

/**
 *  \brief Main AF_XDP reading Loop function
 */
static TmEcode ReceiveAFXDPLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    Packet *p;
    time_t last_dump = 0;
    uint32_t idx_rx = 0, idx_fq = 0, rcvd;
    AFXDPThreadVars *ptv = (AFXDPThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;

    /* Reserve memory for umem  */
    if (ConfigureXSKUmem(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Open AF_XDP socket */
    if (OpenXSKSocket(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (ConfigureBusyPolling(ptv) != TM_ECODE_OK) {
        SCLogWarning(SC_WARN_AFXDP_CONF, "Failed to configure busy polling"
                                         " performance may be reduced.");
    }

    /* Attach eBPF program to interface */
    if (bpf_get_link_xdp_id(ptv->ifindex, &ptv->xsk.prog_id, ptv->xsk.cfg.xdp_flags)) {
        SCLogError(SC_ERR_BPF, "Failed to attach eBPF program to interface: %s", ptv->livedev->dev);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (InitFillRing(ptv, NUM_FRAMES * 2) != TM_ECODE_OK) {
        SCLogError(SC_ERR_AFXDP_INIT, "Failed to initialise the fill ring.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFXDPAllThreadsRunning(ptv);

    PacketPoolWait();
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogDebug("Stopping Suricata!");
            AFXDPDumpCounters(ptv);
            break;
        }

        /* Busy polling is not set, using poll() to maintain (relatively) decent
         * performance. xdp_busy_poll must be disabled for kernels < 5.11
         */
        if (!ptv->xsk.enable_busy_poll) {
            StatsIncr(ptv->tv, ptv->capture_afxdp_poll);

            int ret = poll(&ptv->xsk.fd, 1, POLL_TIMEOUT);

            /* Report poll results */
            if (ret <= 0) {
                if (ret == 0) {
                    StatsIncr(ptv->tv, ptv->capture_afxdp_poll_timeout);
                } else if (ret < 0) {
                    StatsIncr(ptv->tv, ptv->capture_afxdp_poll_failed);
                    SCLogWarning(SC_ERR_AFXDP_READ, "poll failed with retval %d", ret);
                }

                DumpStatsEverySecond(ptv, &last_dump);
                continue;
            }
        }

        rcvd = xsk_ring_cons__peek(&ptv->xsk.rx, ptv->xsk.busy_poll_budget, &idx_rx);
        if (!rcvd) {
            StatsIncr(ptv->tv, ptv->capture_afxdp_empty_reads);
            WakeupSocket(ptv);
            DumpStatsEverySecond(ptv, &last_dump);
            continue;
        }

        uint32_t res = xsk_ring_prod__reserve(&ptv->xsk.fq, rcvd, &idx_fq);
        while (res != rcvd) {
            StatsIncr(ptv->tv, ptv->capture_afxdp_failed_reads);
            WakeupSocket(ptv);
            res = xsk_ring_prod__reserve(&ptv->xsk.fq, rcvd, &idx_fq);
        }

        ptv->pkts += rcvd;
        for (uint32_t i = 0; i < rcvd; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                continue;
            }

            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            p->livedev = ptv->livedev;
            p->ReleasePacket = AFXDPReleasePacket;
            p->flags |= PKT_IGNORE_CHECKSUM;

            gettimeofday(&p->ts, NULL);

            uint64_t addr = xsk_ring_cons__rx_desc(&ptv->xsk.rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&ptv->xsk.rx, idx_rx++)->len;
            uint64_t orig = xsk_umem__extract_addr(addr);
            addr = xsk_umem__add_offset_to_addr(addr);

            uint8_t *pkt_data = xsk_umem__get_data(ptv->xsk.buf, addr);

            ptv->bytes += len;

            p->afxdp_v.fq_idx = idx_fq++;
            p->afxdp_v.orig = orig;
            p->afxdp_v.fq = &ptv->xsk.fq;

            PacketSetData(p, pkt_data, len);

            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        xsk_ring_prod__submit(&ptv->xsk.fq, rcvd);
        xsk_ring_cons__release(&ptv->xsk.rx, rcvd);

        /* Trigger one dump of stats every second */
        DumpStatsEverySecond(ptv, &last_dump);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief DeInit function closes af-xdp socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFXDPPThreadVars for ptv
 */
static TmEcode ReceiveAFXDPThreadDeinit(ThreadVars *tv, void *data)
{
    AFXDPThreadVars *ptv = (AFXDPThreadVars *)data;

    xsk_socket__delete(ptv->xsk.xsk);
    xsk_umem__delete(ptv->xsk.umem);
    munmap(ptv->xsk.buf, MEM_BYTES);

    SCFree(ptv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFXDPThreadVars for ptv
 */
static void ReceiveAFXDPThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    AFXDPThreadVars *ptv = (AFXDPThreadVars *)data;

    AFXDPDumpCounters(ptv);

    SCLogPerf("(%s) Kernel: Packets %" PRIu64 ", bytes %" PRIu64 ", dropped %" PRIu64 "", tv->name,
            StatsGetLocalCounterValue(tv, ptv->capture_afxdp_packets), ptv->bytes,
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_drops));
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeAFXDP decodes packets from AF_XDP and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into AFXDPThreadVars for ptv
 */
static TmEcode DecodeAFXDP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    /* call the decoder */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeAFXDPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeAFXDPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_AF_XDP */
/* eof */
/**
 * @}
 */
