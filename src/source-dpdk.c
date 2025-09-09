/* Copyright (C) 2021 Open Information Security Foundation
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
#include "util-dpdk-bonding.h"
#include <numa.h>

#define BURST_SIZE                   32
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
    int threads;
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
    struct rte_mempool *pkt_mempool;
    struct rte_mbuf *received_mbufs[BURST_SIZE];
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
    uint32_t event_data = port_id << UINT16_WIDTH | queue_id;
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

static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset)
{
    for (int i = offset; i < mbuf_cnt; i++) {
        rte_pktmbuf_free(mbuf_array[i]);
    }
}

static void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    // The PMD Driver i40e has a special way to set the RSS, it can be set via rte_flow rules
    // and only after the start of the port
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSS(ptv->port_id, ptv->threads);
}

static void DevicePreClosePMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    if (strcmp(driver_name, "net_bonding") == 0) {
        driver_name = BondingDeviceDriverGet(ptv->port_id);
    }

    if (strcmp(driver_name, "net_i40e") == 0) {
#if RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0)
        // Flush the RSS rules that have been inserted in the post start section
        struct rte_flow_error flush_error = { 0 };
        int32_t retval = rte_flow_flush(ptv->port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s",
                    ptv->livedev->dev, rte_strerror(-retval), flush_error.message);
        }
#endif /* RTE_VERSION > RTE_VERSION_NUM(20, 0, 0, 0) */
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
            && !(PKT_IS_ICMPV6(p) && p->icmpv6h->type == 143)
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

/**
 *  \brief Main DPDK reading Loop function
 */
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    Packet *p;
    uint16_t nb_rx;
    SCTime_t last_dump = { 0 };
    SCTime_t current_time;
    bool segmented_mbufs_warned = 0;
    SCTime_t t = TimeGet();
    uint64_t last_timeout_msec = SCTIME_MSECS(t);

    DPDKThreadVars *ptv = (DPDKThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);
    PacketPoolWait();

    rte_eth_stats_reset(ptv->port_id);
    rte_eth_xstats_reset(ptv->port_id);

    uint32_t pwd_zero_rx_packet_polls_count = 0;
    if (ptv->intr_enabled && !InterruptsRXEnable(ptv->port_id, ptv->queue_id))
        SCReturnInt(TM_ECODE_FAILED);

    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogDebug("Stopping Suricata!");
            if (ptv->queue_id == 0) {
                rte_eth_dev_stop(ptv->port_id);
                if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS) {
                    rte_eth_dev_stop(ptv->out_port_id);
                }
            }
            DPDKDumpCounters(ptv);
            break;
        }

        nb_rx = rte_eth_rx_burst(ptv->port_id, ptv->queue_id, ptv->received_mbufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) {
            t = TimeGet();
            uint64_t msecs = SCTIME_MSECS(t);
            if (msecs > last_timeout_msec + 100) {
                TmThreadsCaptureHandleTimeout(tv, NULL);
                last_timeout_msec = msecs;
            }

            if (!ptv->intr_enabled)
                continue;

            pwd_zero_rx_packet_polls_count++;
            if (pwd_zero_rx_packet_polls_count <= MIN_ZERO_POLL_COUNT)
                continue;

            uint32_t pwd_idle_hint = InterruptsSleepHeuristic(pwd_zero_rx_packet_polls_count);

            if (pwd_idle_hint < STANDARD_SLEEP_TIME_US) {
                rte_delay_us(pwd_idle_hint);
            } else {
                InterruptsTurnOnOff(ptv->port_id, ptv->queue_id, true);
                struct rte_epoll_event event;
                rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1, MAX_EPOLL_TIMEOUT_MS);
                InterruptsTurnOnOff(ptv->port_id, ptv->queue_id, false);
                continue;
            }
        } else if (ptv->intr_enabled && pwd_zero_rx_packet_polls_count) {
            pwd_zero_rx_packet_polls_count = 0;
        }

        ptv->pkts += (uint64_t)nb_rx;
        for (uint16_t i = 0; i < nb_rx; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                rte_pktmbuf_free(ptv->received_mbufs[i]);
                continue;
            }
            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }

            p->ts = TimeGet();
            p->dpdk_v.mbuf = ptv->received_mbufs[i];
            p->ReleasePacket = DPDKReleasePacket;
            p->dpdk_v.copy_mode = ptv->copy_mode;
            p->dpdk_v.out_port_id = ptv->out_port_id;
            p->dpdk_v.out_queue_id = ptv->queue_id;
            p->livedev = ptv->livedev;

            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_OFFLOAD) {
                uint64_t ol_flags = ptv->received_mbufs[i]->ol_flags;
                if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_GOOD &&
                        (ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
                    SCLogDebug("HW detected GOOD IP and L4 chsum, ignoring validation");
                    p->flags |= PKT_IGNORE_CHECKSUM;
                } else {
                    if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD) {
                        SCLogDebug("HW detected BAD IP checksum");
                        // chsum recalc will not be triggered but rule keyword check will be
                        p->level3_comp_csum = 0;
                    }
                    if ((ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_BAD) {
                        SCLogDebug("HW detected BAD L4 chsum");
                        p->level4_comp_csum = 0;
                    }
                }
            }

            if (!rte_pktmbuf_is_contiguous(p->dpdk_v.mbuf) && !segmented_mbufs_warned) {
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

                segmented_mbufs_warned = 1;
            }

            PacketSetData(p, rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *),
                    rte_pktmbuf_pkt_len(p->dpdk_v.mbuf));
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i - 1, i + 1);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        /* Trigger one dump of stats every second */
        current_time = TimeGet();
        if (current_time.secs != last_dump.secs) {
            DPDKDumpCounters(ptv);
            last_dump = current_time;
        }
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
    // pass the pointer to the mempool and then forget about it. Mempool is freed in thread deinit.
    ptv->pkt_mempool = dpdk_config->pkt_mempool;
    dpdk_config->pkt_mempool = NULL;

    thread_numa = GetNumaNode();
    if (thread_numa >= 0 && ptv->port_socket_id != SOCKET_ID_ANY &&
            thread_numa != ptv->port_socket_id) {
        SC_ATOMIC_ADD(dpdk_config->inconsitent_numa_cnt, 1);
        SCLogPerf("%s: NIC is on NUMA %d, thread on NUMA %d", dpdk_config->iface,
                ptv->port_socket_id, thread_numa);
    }

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

        // some PMDs requires additional actions only after the device has started
        DevicePostStartPMDSpecificActions(ptv, dev_info.driver_name);

        uint16_t inconsistent_numa_cnt = SC_ATOMIC_GET(dpdk_config->inconsitent_numa_cnt);
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

static void PrintDPDKPortXstats(uint32_t port_id, const char *port_name)
{
    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;

    int32_t len = rte_eth_xstats_get(port_id, NULL, 0);
    if (len < 0)
        FatalError("Error (%s) getting count of rte_eth_xstats failed on port %s",
                rte_strerror(-len), port_name);

    xstats = SCCalloc(len, sizeof(*xstats));
    if (xstats == NULL)
        FatalError("Failed to allocate memory for the rte_eth_xstat structure");

    int32_t ret = rte_eth_xstats_get(port_id, xstats, len);
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
    }

    ptv->pkt_mempool = NULL; // MP is released when device is closed

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
