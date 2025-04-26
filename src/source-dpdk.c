/* Copyright (C) 2021-2025 Open Information Security Foundation
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
 *  \defgroup dpdk DPDK running mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK capture interface
 *
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "decode.h"
#include "packet.h"
#include "source-dpdk.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-privs.h"
#include "util-device-private.h"
#include "action-globals.h"

#ifndef HAVE_DPDK

TmEcode NoDPDKSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveDPDKRegister(void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = 0;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDPDK.
 */
void TmModuleDecodeDPDKRegister(void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_DECODEDPDK].Func = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoDPDKSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    FatalError("Error creating thread %s: you do not have "
               "support for DPDK enabled, on Linux host please recompile "
               "with --enable-dpdk",
            tv->name);
}

#else /* We have DPDK support */

#include "util-affinity.h"
#include "util-dpdk.h"
#include "util-dpdk-i40e.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-ixgbe.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-bonding.h"
#include <numa.h>

#define BURST_SIZE 32
// interrupt mode constants
#define MIN_ZERO_POLL_COUNT          10U
#define MIN_ZERO_POLL_COUNT_TO_SLEEP 10U
#define MINIMUM_SLEEP_TIME_US        1U
#define STANDARD_SLEEP_TIME_US       100U
#define MAX_EPOLL_TIMEOUT_MS         500U
static rte_spinlock_t intr_lock[RTE_MAX_ETHPORTS];

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct DPDKThreadVars_ {
    /* counters */
    uint64_t pkts;
    ThreadVars *tv;
    TmSlot *slot;
    LiveDevice *livedev;
    ChecksumValidationMode checksum_mode;
    bool intr_enabled;
    /* references to packet and drop counters */
    uint16_t capture_dpdk_packets;
    uint16_t capture_dpdk_rx_errs;
    uint16_t capture_dpdk_imissed;
    uint16_t capture_dpdk_rx_no_mbufs;
    uint16_t capture_dpdk_ierrors;
    uint16_t capture_dpdk_tx_errs;
    unsigned int flags;
    uint16_t threads;
    /* for IPS */
    DpdkCopyModeEnum copy_mode;
    uint16_t out_port_id;
    /* Entry in the peers_list */

    uint64_t bytes;
    uint64_t accepted;
    uint64_t dropped;
    uint16_t port_id;
    uint16_t queue_id;
    int32_t port_socket_id;
    struct rte_mbuf *received_mbufs[BURST_SIZE];
    DPDKWorkerSync *workers_sync;
} DPDKThreadVars;

static TmEcode ReceiveDPDKThreadInit(ThreadVars *, const void *, void **);
static void ReceiveDPDKThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *, void *);
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot);

static TmEcode DecodeDPDKThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeDPDK(ThreadVars *, Packet *, void *);

static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset);
static bool InterruptsRXEnable(uint16_t port_id, uint16_t queue_id)
{
    uint32_t event_data = (uint32_t)port_id << UINT16_WIDTH | queue_id;
    int32_t ret = rte_eth_dev_rx_intr_ctl_q(port_id, queue_id, RTE_EPOLL_PER_THREAD,
            RTE_INTR_EVENT_ADD, (void *)((uintptr_t)event_data));

    if (ret != 0) {
        SCLogError("%s-Q%d: failed to enable interrupt mode: %s", DPDKGetPortNameByPortID(port_id),
                queue_id, rte_strerror(-ret));
        return false;
    }
    return true;
}

static inline uint32_t InterruptsSleepHeuristic(uint32_t no_pkt_polls_count)
{
    if (no_pkt_polls_count < MIN_ZERO_POLL_COUNT_TO_SLEEP)
        return MINIMUM_SLEEP_TIME_US;

    return STANDARD_SLEEP_TIME_US;
}

static inline void InterruptsTurnOnOff(uint16_t port_id, uint16_t queue_id, bool on)
{
    rte_spinlock_lock(&(intr_lock[port_id]));

    if (on)
        rte_eth_dev_rx_intr_enable(port_id, queue_id);
    else
        rte_eth_dev_rx_intr_disable(port_id, queue_id);

    rte_spinlock_unlock(&(intr_lock[port_id]));
}

static inline void DPDKFreeMbufArray(
        struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset)
{
    for (int i = offset; i < mbuf_cnt; i++) {
        rte_pktmbuf_free(mbuf_array[i]);
    }
}

static void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0)
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSS(ptv->port_id, ptv->threads, ptv->livedev->dev);
    else if (strcmp(driver_name, "net_ixgbe") == 0)
        ixgbeDeviceSetRSS(ptv->port_id, ptv->threads, ptv->livedev->dev);
    else if (strcmp(driver_name, "net_ice") == 0)
        iceDeviceSetRSS(ptv->port_id, ptv->threads, ptv->livedev->dev);
    else if (strcmp(driver_name, "mlx5_pci") == 0)
        mlx5DeviceSetRSS(ptv->port_id, ptv->threads, ptv->livedev->dev);
}

static void DevicePreClosePMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    if (
#if RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0)
            strcmp(driver_name, "net_i40e") == 0 ||
#endif /* RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0) */
            strcmp(driver_name, "net_ixgbe") == 0 || strcmp(driver_name, "net_ice") == 0 ||
            strcmp(driver_name, "mlx5_pci") == 0) {
        // Flush the RSS rules that have been inserted in the post start section
        struct rte_flow_error flush_error = { 0 };
        int32_t retval = rte_flow_flush(ptv->port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s",
                    ptv->livedev->dev, rte_strerror(-retval), flush_error.message);
        }
    }
}

/**
 * Attempts to retrieve NUMA node id on which the caller runs
 * @return NUMA id on success, -1 otherwise
 */
static int GetNumaNode(void)
{
    int cpu = 0;
    int node = -1;

#if defined(__linux__)
    cpu = sched_getcpu();
    node = numa_node_of_cpu(cpu);
#else
    SCLogWarning("NUMA node retrieval is not supported on this OS.");
#endif

    return node;
}

/**
 * \brief Registration Function for ReceiveDPDK.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveDPDKRegister(void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDPDKThreadInit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDPDKLoop;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDPDKThreadExitStats;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDPDKThreadDeinit;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDPDK.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeDPDKRegister(void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDPDKThreadInit;
    tmm_modules[TMM_DECODEDPDK].Func = DecodeDPDK;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDPDKThreadDeinit;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

static inline void DPDKDumpCounters(DPDKThreadVars *ptv)
{
    /* Some NICs (e.g. Intel) do not support queue statistics and the drops can be fetched only on
     * the port level. Therefore setting it to the first worker to have at least continuous update
     * on the dropped packets. */
    if (ptv->queue_id == 0) {
        struct rte_eth_stats eth_stats;
        int retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
        if (unlikely(retval != 0)) {
            SCLogError("%s: failed to get stats: %s", ptv->livedev->dev, rte_strerror(-retval));
            return;
        }

        StatsSetUI64(ptv->tv, ptv->capture_dpdk_packets,
                ptv->pkts + eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        SC_ATOMIC_SET(ptv->livedev->pkts,
                eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_rx_errs,
                eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_imissed, eth_stats.imissed);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_rx_no_mbufs, eth_stats.rx_nombuf);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_ierrors, eth_stats.ierrors);
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_tx_errs, eth_stats.oerrors);
        SC_ATOMIC_SET(
                ptv->livedev->drop, eth_stats.imissed + eth_stats.ierrors + eth_stats.rx_nombuf);
    } else {
        StatsSetUI64(ptv->tv, ptv->capture_dpdk_packets, ptv->pkts);
    }
}

static void DPDKReleasePacket(Packet *p)
{
    int retval;
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet)
       When enabling promiscuous mode on Intel cards, 2 ICMPv6 packets are generated.
       These get into the infinite cycle between the NIC and the switch in some cases */
    if ((p->dpdk_v.copy_mode == DPDK_COPY_MODE_TAP ||
                (p->dpdk_v.copy_mode == DPDK_COPY_MODE_IPS && !PacketCheckAction(p, ACTION_DROP)))
#if defined(RTE_LIBRTE_I40E_PMD) || defined(RTE_LIBRTE_IXGBE_PMD) || defined(RTE_LIBRTE_ICE_PMD)
            && !(PacketIsICMPv6(p) && PacketGetICMPv6(p)->type == 143)
#endif
    ) {
        BUG_ON(PKT_IS_PSEUDOPKT(p));
        retval =
                rte_eth_tx_burst(p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id, &p->dpdk_v.mbuf, 1);
        // rte_eth_tx_burst can return only 0 (failure) or 1 (success) because we are only
        // transmitting burst of size 1 and the function rte_eth_tx_burst returns number of
        // successfully sent packets.
        if (unlikely(retval < 1)) {
            // sometimes a repeated transmit can help to send out the packet
            rte_delay_us(DPDK_BURST_TX_WAIT_US);
            retval = rte_eth_tx_burst(
                    p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id, &p->dpdk_v.mbuf, 1);
            if (unlikely(retval < 1)) {
                SCLogDebug("Unable to transmit the packet on port %u queue %u",
                        p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id);
                rte_pktmbuf_free(p->dpdk_v.mbuf);
                p->dpdk_v.mbuf = NULL;
            }
        }
    } else {
        rte_pktmbuf_free(p->dpdk_v.mbuf);
        p->dpdk_v.mbuf = NULL;
    }

    PacketFreeOrRelease(p);
}

static TmEcode ReceiveDPDKLoopInit(ThreadVars *tv, DPDKThreadVars *ptv)
{
    SCEnter();
    // Indicate that the thread is actually running its application level
    // code (i.e., it can poll packets)
    TmThreadsSetFlag(tv, THV_RUNNING);
    PacketPoolWait();

    rte_eth_stats_reset(ptv->port_id);
    rte_eth_xstats_reset(ptv->port_id);

    if (ptv->intr_enabled && !InterruptsRXEnable(ptv->port_id, ptv->queue_id))
        SCReturnInt(TM_ECODE_FAILED);

    SCReturnInt(TM_ECODE_OK);
}

static inline void LoopHandleTimeoutOnIdle(ThreadVars *tv)
{
    static thread_local uint64_t last_timeout_msec = 0;
    SCTime_t t = TimeGet();
    uint64_t msecs = SCTIME_MSECS(t);
    if (msecs > last_timeout_msec + 100) {
        TmThreadsCaptureHandleTimeout(tv, NULL);
        last_timeout_msec = msecs;
    }
}

/**
 * \brief Decides if it should retry the packet poll or continue with the packet processing
 * \return true if the poll should be retried, false otherwise
 */
static inline bool RXPacketCountHeuristic(ThreadVars *tv, DPDKThreadVars *ptv, uint16_t nb_rx)
{
    static thread_local uint32_t zero_pkt_polls_cnt = 0;

    if (nb_rx > 0) {
        zero_pkt_polls_cnt = 0;
        return false;
    }

    LoopHandleTimeoutOnIdle(tv);
    if (!ptv->intr_enabled)
        return true;

    zero_pkt_polls_cnt++;
    if (zero_pkt_polls_cnt <= MIN_ZERO_POLL_COUNT)
        return true;

    uint32_t pwd_idle_hint = InterruptsSleepHeuristic(zero_pkt_polls_cnt);
    if (pwd_idle_hint < STANDARD_SLEEP_TIME_US) {
        rte_delay_us(pwd_idle_hint);
    } else {
        InterruptsTurnOnOff(ptv->port_id, ptv->queue_id, true);
        struct rte_epoll_event event;
        rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1, MAX_EPOLL_TIMEOUT_MS);
        InterruptsTurnOnOff(ptv->port_id, ptv->queue_id, false);
        return true;
    }

    return false;
}

/**
 * \brief Initializes a packet from an mbuf
 * \return true if the packet was initialized successfully, false otherwise
 */
static inline Packet *PacketInitFromMbuf(DPDKThreadVars *ptv, struct rte_mbuf *mbuf)
{
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        return NULL;
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->datalink = LINKTYPE_ETHERNET;
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    }

    p->ts = TimeGet();
    p->dpdk_v.mbuf = mbuf;
    p->ReleasePacket = DPDKReleasePacket;
    p->dpdk_v.copy_mode = ptv->copy_mode;
    p->dpdk_v.out_port_id = ptv->out_port_id;
    p->dpdk_v.out_queue_id = ptv->queue_id;
    p->livedev = ptv->livedev;

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_OFFLOAD) {
        uint64_t ol_flags = p->dpdk_v.mbuf->ol_flags;
        if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_GOOD &&
                (ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
            SCLogDebug("HW detected GOOD IP and L4 chsum, ignoring validation");
            p->flags |= PKT_IGNORE_CHECKSUM;
        } else {
            if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD) {
                SCLogDebug("HW detected BAD IP checksum");
                // chsum recalc will not be triggered but rule keyword check will be
                p->l3.csum_set = true;
                p->l3.csum = 0;
            }
            if ((ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_BAD) {
                SCLogDebug("HW detected BAD L4 chsum");
                p->l4.csum_set = true;
                p->l4.csum = 0;
            }
        }
    }

    return p;
}

static inline void DPDKSegmentedMbufWarning(struct rte_mbuf *mbuf)
{
    static thread_local bool segmented_mbufs_warned = false;
    if (!segmented_mbufs_warned && !rte_pktmbuf_is_contiguous(mbuf)) {
        char warn_s[] = "Segmented mbufs detected! Redmine Ticket #6012 "
                        "Check your configuration or report the issue";
        enum rte_proc_type_t eal_t = rte_eal_process_type();
        if (eal_t == RTE_PROC_SECONDARY) {
            SCLogWarning("%s. To avoid segmented mbufs, "
                         "try to increase mbuf size in your primary application",
                    warn_s);
        } else if (eal_t == RTE_PROC_PRIMARY) {
            SCLogWarning("%s. To avoid segmented mbufs, "
                         "try to increase MTU in your suricata.yaml",
                    warn_s);
        }

        segmented_mbufs_warned = true;
    }
}

static void HandleShutdown(DPDKThreadVars *ptv)
{
    SCLogDebug("Stopping Suricata!");
    SC_ATOMIC_ADD(ptv->workers_sync->worker_checked_in, 1);
    while (SC_ATOMIC_GET(ptv->workers_sync->worker_checked_in) < ptv->workers_sync->worker_cnt) {
        rte_delay_us(10);
    }
    if (ptv->queue_id == 0) {
        rte_delay_us(20); // wait for all threads to get out of the sync loop
        SC_ATOMIC_SET(ptv->workers_sync->worker_checked_in, 0);
        // If Suricata runs in peered mode, the peer threads might still want to send
        // packets to our port. Instead, we know, that we are done with the peered port, so
        // we stop it. The peered threads will stop our port.
        if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS) {
            rte_eth_dev_stop(ptv->out_port_id);
        } else {
            // in IDS we stop our port - no peer threads are running
            rte_eth_dev_stop(ptv->port_id);
        }
    }
    DPDKDumpCounters(ptv);
}

static void PeriodicDPDKDumpCounters(DPDKThreadVars *ptv)
{
    static thread_local SCTime_t last_dump = { 0 };
    SCTime_t current_time = TimeGet();
    /* Trigger one dump of stats every second */
    if (current_time.secs != last_dump.secs) {
        DPDKDumpCounters(ptv);
        last_dump = current_time;
    }
}

/**
 *  \brief Main DPDK reading Loop function
 */
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;
    ptv->slot = ((TmSlot *)slot)->slot_next;
    TmEcode ret = ReceiveDPDKLoopInit(tv, ptv);
    if (ret != TM_ECODE_OK) {
        SCReturnInt(ret);
    }
    while (true) {
        if (unlikely(suricata_ctl_flags != 0)) {
            HandleShutdown(ptv);
            break;
        }

        uint16_t nb_rx =
                rte_eth_rx_burst(ptv->port_id, ptv->queue_id, ptv->received_mbufs, BURST_SIZE);
        if (RXPacketCountHeuristic(tv, ptv, nb_rx)) {
            continue;
        }

        ptv->pkts += (uint64_t)nb_rx;
        for (uint16_t i = 0; i < nb_rx; i++) {
            Packet *p = PacketInitFromMbuf(ptv, ptv->received_mbufs[i]);
            if (p == NULL) {
                rte_pktmbuf_free(ptv->received_mbufs[i]);
                continue;
            }
            DPDKSegmentedMbufWarning(ptv->received_mbufs[i]);
            PacketSetData(p, rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *),
                    rte_pktmbuf_pkt_len(p->dpdk_v.mbuf));
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i - 1, i + 1);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        PeriodicDPDKDumpCounters(ptv);
        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceiveDPDK.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with DPDKThreadVars
 *
 */
static TmEcode ReceiveDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    int retval, thread_numa;
    DPDKThreadVars *ptv = NULL;
    DPDKIfaceConfig *dpdk_config = (DPDKIfaceConfig *)initdata;

    if (initdata == NULL) {
        SCLogError("DPDK configuration is NULL in thread initialization");
        goto fail;
    }

    ptv = SCCalloc(1, sizeof(DPDKThreadVars));
    if (unlikely(ptv == NULL)) {
        SCLogError("Unable to allocate memory");
        goto fail;
    }

    ptv->tv = tv;
    ptv->pkts = 0;
    ptv->bytes = 0;
    ptv->livedev = LiveGetDevice(dpdk_config->iface);

    ptv->capture_dpdk_packets = StatsRegisterCounter("capture.packets", ptv->tv);
    ptv->capture_dpdk_rx_errs = StatsRegisterCounter("capture.rx_errors", ptv->tv);
    ptv->capture_dpdk_tx_errs = StatsRegisterCounter("capture.tx_errors", ptv->tv);
    ptv->capture_dpdk_imissed = StatsRegisterCounter("capture.dpdk.imissed", ptv->tv);
    ptv->capture_dpdk_rx_no_mbufs = StatsRegisterCounter("capture.dpdk.no_mbufs", ptv->tv);
    ptv->capture_dpdk_ierrors = StatsRegisterCounter("capture.dpdk.ierrors", ptv->tv);

    ptv->copy_mode = dpdk_config->copy_mode;
    ptv->checksum_mode = dpdk_config->checksum_mode;

    ptv->threads = dpdk_config->threads;
    ptv->intr_enabled = (dpdk_config->flags & DPDK_IRQ_MODE) ? true : false;
    ptv->port_id = dpdk_config->port_id;
    ptv->out_port_id = dpdk_config->out_port_id;
    ptv->port_socket_id = dpdk_config->socket_id;

    thread_numa = GetNumaNode();
    if (thread_numa >= 0 && ptv->port_socket_id != SOCKET_ID_ANY &&
            thread_numa != ptv->port_socket_id) {
        SC_ATOMIC_ADD(dpdk_config->inconsistent_numa_cnt, 1);
        SCLogPerf("%s: NIC is on NUMA %d, thread on NUMA %d", dpdk_config->iface,
                ptv->port_socket_id, thread_numa);
    }

    ptv->workers_sync = dpdk_config->workers_sync;
    uint16_t queue_id = SC_ATOMIC_ADD(dpdk_config->queue_id, 1);
    ptv->queue_id = queue_id;

    // the last thread starts the device
    if (queue_id == dpdk_config->threads - 1) {
        retval = rte_eth_dev_start(ptv->port_id);
        if (retval < 0) {
            SCLogError("%s: error (%s) during device startup", dpdk_config->iface,
                    rte_strerror(-retval));
            goto fail;
        }

        struct rte_eth_dev_info dev_info;
        retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError("%s: error (%s) when getting device info", dpdk_config->iface,
                    rte_strerror(-retval));
            goto fail;
        }

        uint32_t timeout = dpdk_config->linkup_timeout * 10;
        while (timeout > 0) {
            struct rte_eth_link link = { 0 };
            retval = rte_eth_link_get_nowait(ptv->port_id, &link);
            if (retval != 0) {
                if (retval == -ENOTSUP) {
                    SCLogInfo("%s: link status not supported, skipping", dpdk_config->iface);
                } else {
                    SCLogInfo("%s: error (%s) when getting link status, skipping",
                            dpdk_config->iface, rte_strerror(-retval));
                }
                break;
            }
            if (link.link_status) {
                char link_status_str[RTE_ETH_LINK_MAX_STR_LEN];
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                rte_eth_link_to_str(link_status_str, sizeof(link_status_str), &link);
#pragma GCC diagnostic pop
#else
                snprintf(link_status_str, sizeof(link_status_str),
                        "Link Up, speed %u Mbps, %s", // 22 chars + 10 for digits + 11 for duplex
                        link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex");
#endif

                SCLogInfo("%s: %s", dpdk_config->iface, link_status_str);
                break;
            }

            rte_delay_ms(100);
            timeout--;
        }

        if (dpdk_config->linkup_timeout && timeout == 0) {
            SCLogWarning("%s: link is down, trying to continue anyway", dpdk_config->iface);
        }

        // some PMDs requires additional actions only after the device has started
        DevicePostStartPMDSpecificActions(ptv, dev_info.driver_name);

        uint16_t inconsistent_numa_cnt = SC_ATOMIC_GET(dpdk_config->inconsistent_numa_cnt);
        if (inconsistent_numa_cnt > 0 && ptv->port_socket_id != SOCKET_ID_ANY) {
            SCLogWarning("%s: NIC is on NUMA %d, %u threads on different NUMA node(s)",
                    dpdk_config->iface, ptv->port_socket_id, inconsistent_numa_cnt);
        } else if (ptv->port_socket_id == SOCKET_ID_ANY && rte_socket_count() > 1) {
            SCLogNotice(
                    "%s: unable to determine NIC's NUMA node, degraded performance can be expected",
                    dpdk_config->iface);
        }
        if (ptv->intr_enabled) {
            rte_spinlock_init(&intr_lock[ptv->port_id]);
        }
    }

    *data = (void *)ptv;
    dpdk_config->DerefFunc(dpdk_config);
    SCReturnInt(TM_ECODE_OK);

fail:
    if (dpdk_config != NULL)
        dpdk_config->DerefFunc(dpdk_config);
    if (ptv != NULL)
        SCFree(ptv);
    SCReturnInt(TM_ECODE_FAILED);
}

static void PrintDPDKPortXstats(uint16_t port_id, const char *port_name)
{
    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;

    int32_t ret = rte_eth_xstats_get(port_id, NULL, 0);
    if (ret < 0) {
        FatalError("Error (%s) getting count of rte_eth_xstats failed on port %s",
                rte_strerror(-ret), port_name);
    }
    uint16_t len = (uint16_t)ret;

    xstats = SCCalloc(len, sizeof(*xstats));
    if (xstats == NULL)
        FatalError("Failed to allocate memory for the rte_eth_xstat structure");

    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        SCFree(xstats);
        FatalError("Error (%s) getting rte_eth_xstats failed on port %s", rte_strerror(-ret),
                port_name);
    }
    xstats_names = SCCalloc(len, sizeof(*xstats_names));
    if (xstats_names == NULL) {
        SCFree(xstats);
        FatalError("Failed to allocate memory for the rte_eth_xstat_name array");
    }
    ret = rte_eth_xstats_get_names(port_id, xstats_names, len);
    if (ret < 0 || ret > len) {
        SCFree(xstats);
        SCFree(xstats_names);
        FatalError("Error (%s) getting names of rte_eth_xstats failed on port %s",
                rte_strerror(-ret), port_name);
    }
    for (int32_t i = 0; i < len; i++) {
        if (xstats[i].value > 0)
            SCLogPerf("Port %u (%s) - %s: %" PRIu64, port_id, port_name, xstats_names[i].name,
                    xstats[i].value);
    }

    SCFree(xstats);
    SCFree(xstats_names);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static void ReceiveDPDKThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    int retval;
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;

    if (ptv->queue_id == 0) {
        struct rte_eth_stats eth_stats;
        PrintDPDKPortXstats(ptv->port_id, ptv->livedev->dev);
        retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
        if (unlikely(retval != 0)) {
            SCLogError("%s: failed to get stats (%s)", ptv->livedev->dev, strerror(-retval));
            SCReturn;
        }
        SCLogPerf("%s: total RX stats: packets %" PRIu64 " bytes: %" PRIu64 " missed: %" PRIu64
                  " errors: %" PRIu64 " nombufs: %" PRIu64,
                ptv->livedev->dev, eth_stats.ipackets, eth_stats.ibytes, eth_stats.imissed,
                eth_stats.ierrors, eth_stats.rx_nombuf);
        if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS)
            SCLogPerf("%s: total TX stats: packets %" PRIu64 " bytes: %" PRIu64 " errors: %" PRIu64,
                    ptv->livedev->dev, eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors);
    }

    DPDKDumpCounters(ptv);
    SCLogPerf("(%s) received packets %" PRIu64, tv->name, ptv->pkts);
}

/**
 * \brief DeInit function closes dpdk at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;

    if (ptv->queue_id == 0) {
        struct rte_eth_dev_info dev_info;
        int retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError("%s: error (%s) when getting device info", ptv->livedev->dev,
                    rte_strerror(-retval));
            SCReturnInt(TM_ECODE_FAILED);
        }

        DevicePreClosePMDSpecificActions(ptv, dev_info.driver_name);

        if (ptv->workers_sync) {
            SCFree(ptv->workers_sync);
        }
    }

    SCFree(ptv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeDPDK decodes packets from DPDK and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
static TmEcode DecodeDPDK(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

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

static TmEcode DecodeDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_DPDK */
/* eof */
/**
 * @}
 */
