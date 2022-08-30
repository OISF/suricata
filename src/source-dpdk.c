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
#include "source-dpdk.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-privs.h"

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
    FatalError(SC_ERR_NO_DPDK,
            "Error creating thread %s: you do not have "
            "support for DPDK enabled, on Linux host please recompile "
            "with --enable-dpdk",
            tv->name);
}

#else /* We have DPDK support */

#include "util-dpdk.h"
#include "util-dpdk-i40e.h"
#include <numa.h>

#define BURST_SIZE 32

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
    struct rte_mempool *pkt_mempool;
    struct rte_mbuf *received_mbufs[BURST_SIZE];
    struct timeval machine_start_time;
} DPDKThreadVars;

static TmEcode ReceiveDPDKThreadInit(ThreadVars *, const void *, void **);
static void ReceiveDPDKThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *, void *);
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot);

static TmEcode DecodeDPDKThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeDPDK(ThreadVars *, Packet *, void *);

static uint64_t CyclesToMicroseconds(uint64_t cycles);
static uint64_t CyclesToSeconds(uint64_t cycles);
static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset);
static uint64_t DPDKGetSeconds(void);

static void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset)
{
    for (int i = offset; i < mbuf_cnt; i++) {
        rte_pktmbuf_free(mbuf_array[i]);
    }
}

static uint64_t CyclesToMicroseconds(const uint64_t cycles)
{
    const uint64_t ticks_per_us = rte_get_tsc_hz() / 1000000;
    return cycles / ticks_per_us;
}

static uint64_t CyclesToSeconds(const uint64_t cycles)
{
    const uint64_t ticks_per_s = rte_get_tsc_hz();
    return cycles / ticks_per_s;
}

static void CyclesAddToTimeval(
        const uint64_t cycles, struct timeval *orig_tv, struct timeval *new_tv)
{
    uint64_t usec = CyclesToMicroseconds(cycles) + orig_tv->tv_usec;
    new_tv->tv_sec = orig_tv->tv_sec + usec / 1000000;
    new_tv->tv_usec = (usec % 1000000);
}

static void DPDKSetTimevalOfMachineStart(struct timeval *tv)
{
    gettimeofday(tv, NULL);
    tv->tv_sec -= DPDKGetSeconds();
}

/**
 * Initializes real_tv to the correct real time. Adds TSC counter value to the timeval of
 * the machine start
 * @param machine_start_tv - timestamp when the machine was started
 * @param real_tv
 */
static void DPDKSetTimevalReal(struct timeval *machine_start_tv, struct timeval *real_tv)
{
    CyclesAddToTimeval(rte_get_tsc_cycles(), machine_start_tv, real_tv);
}

/* get number of seconds from the reset of TSC counter (typically from the machine start) */
static uint64_t DPDKGetSeconds()
{
    return CyclesToSeconds(rte_get_tsc_cycles());
}

static void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    // The PMD Driver i40e has a special way to set the RSS, it can be set via rte_flow rules
    // and only after the start of the port
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSS(ptv->port_id, ptv->threads);
}

static void DevicePreStopPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name)
{
    int retval;

    if (strcmp(driver_name, "net_i40e") == 0) {
        // Flush the RSS rules that have been inserted in the post start section
        struct rte_flow_error flush_error = { 0 };
        retval = rte_flow_flush(ptv->port_id, &flush_error);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_CONF, "Unable to flush rte_flow rules: %s Flush error msg: %s",
                    rte_strerror(-retval), flush_error.message);
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
    SCLogWarning(SC_ERR_TM_THREADS_ERROR, "NUMA node retrieval is not supported on this OS.");
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
    struct rte_eth_stats eth_stats;
    int retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
    if (unlikely(retval != 0)) {
        SCLogError(SC_ERR_STAT, "Failed to get stats for port id %d: %s", ptv->port_id,
                rte_strerror(-retval));
        return;
    }

    /* Some NICs (e.g. Intel) do not support queue statistics and the drops can be fetched only on
     * the port level. Therefore setting it to the first worker to have at least continuous update
     * on the dropped packets. */
    if (ptv->queue_id == 0) {
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
                (p->dpdk_v.copy_mode == DPDK_COPY_MODE_IPS && !PacketTestAction(p, ACTION_DROP)))
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
    time_t last_dump = 0;
    time_t current_time;

    DPDKThreadVars *ptv = (DPDKThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;

    PacketPoolWait();
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogDebug("Stopping Suricata!");
            DPDKDumpCounters(ptv);
            break;
        }

        nb_rx = rte_eth_rx_burst(ptv->port_id, ptv->queue_id, ptv->received_mbufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) {
            continue;
        }

        ptv->pkts += (uint64_t)nb_rx;
        for (uint16_t i = 0; i < nb_rx; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                continue;
            }
            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }

            DPDKSetTimevalReal(&ptv->machine_start_time, &p->ts);
            p->dpdk_v.mbuf = ptv->received_mbufs[i];
            p->ReleasePacket = DPDKReleasePacket;
            p->dpdk_v.copy_mode = ptv->copy_mode;
            p->dpdk_v.out_port_id = ptv->out_port_id;
            p->dpdk_v.out_queue_id = ptv->queue_id;

            PacketSetData(p, rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *),
                    rte_pktmbuf_pkt_len(p->dpdk_v.mbuf));
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i - 1, i + 1);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        /* Trigger one dump of stats every second */
        current_time = DPDKGetSeconds();
        if (current_time != last_dump) {
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
        SCLogError(SC_ERR_INVALID_ARGUMENT, "DPDK configuration is NULL in thread initialization");
        goto fail;
    }

    ptv = SCCalloc(1, sizeof(DPDKThreadVars));
    if (unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate memory");
        goto fail;
    }

    ptv->tv = tv;
    ptv->pkts = 0;
    ptv->bytes = 0;
    ptv->livedev = LiveGetDevice(dpdk_config->iface);
    DPDKSetTimevalOfMachineStart(&ptv->machine_start_time);

    ptv->capture_dpdk_packets = StatsRegisterCounter("capture.packets", ptv->tv);
    ptv->capture_dpdk_rx_errs = StatsRegisterCounter("capture.rx_errors", ptv->tv);
    ptv->capture_dpdk_tx_errs = StatsRegisterCounter("capture.tx_errors", ptv->tv);
    ptv->capture_dpdk_imissed = StatsRegisterCounter("capture.dpdk.imissed", ptv->tv);
    ptv->capture_dpdk_rx_no_mbufs = StatsRegisterCounter("capture.dpdk.no_mbufs", ptv->tv);
    ptv->capture_dpdk_ierrors = StatsRegisterCounter("capture.dpdk.ierrors", ptv->tv);

    ptv->copy_mode = dpdk_config->copy_mode;
    ptv->checksum_mode = dpdk_config->checksum_mode;

    ptv->threads = dpdk_config->threads;
    ptv->port_id = dpdk_config->port_id;
    ptv->out_port_id = dpdk_config->out_port_id;
    uint16_t queue_id = SC_ATOMIC_ADD(dpdk_config->queue_id, 1);
    ptv->queue_id = queue_id;
    // pass the pointer to the mempool and then forget about it. Mempool is freed in thread deinit.
    ptv->pkt_mempool = dpdk_config->pkt_mempool;
    dpdk_config->pkt_mempool = NULL;

    // the last thread starts the device
    if (queue_id == dpdk_config->threads - 1) {
        retval = rte_eth_dev_start(ptv->port_id);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (%s) during device startup of %s",
                    rte_strerror(-retval), dpdk_config->iface);
            goto fail;
        }

        struct rte_eth_dev_info dev_info;
        retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (%s) when getting device info of %s",
                    rte_strerror(-retval), dpdk_config->iface);
            goto fail;
        }

        // some PMDs requires additional actions only after the device has started
        DevicePostStartPMDSpecificActions(ptv, dev_info.driver_name);
    }

    thread_numa = GetNumaNode();
    if (thread_numa >= 0 && thread_numa != rte_eth_dev_socket_id(ptv->port_id)) {
        SCLogWarning(SC_WARN_DPDK_CONF,
                "NIC on NUMA %d but thread on NUMA %d. Decreased performance expected",
                rte_eth_dev_socket_id(ptv->port_id), thread_numa);
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
        char port_name[RTE_ETH_NAME_MAX_LEN];

        retval = rte_eth_dev_get_name_by_port(ptv->port_id, port_name);
        if (unlikely(retval != 0)) {
            SCLogError(SC_ERR_STAT, "Failed to convert port id %d to the interface name: %s",
                    ptv->port_id, strerror(-retval));
            SCReturn;
        }
        retval = rte_eth_stats_get(ptv->port_id, &eth_stats);
        if (unlikely(retval != 0)) {
            SCLogError(SC_ERR_STAT, "Failed to get stats for interface %s: %s", port_name,
                    strerror(-retval));
            SCReturn;
        }
        SCLogPerf("Total RX stats of %s: packets %" PRIu64 " bytes: %" PRIu64 " missed: %" PRIu64
                  " errors: %" PRIu64 " nombufs: %" PRIu64,
                port_name, eth_stats.ipackets, eth_stats.ibytes, eth_stats.imissed,
                eth_stats.ierrors, eth_stats.rx_nombuf);
        if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS)
            SCLogPerf("Total TX stats of %s: packets %" PRIu64 " bytes: %" PRIu64
                      " errors: %" PRIu64,
                    port_name, eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors);
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

    int retval;
    if (ptv->queue_id == 0) {
        struct rte_eth_dev_info dev_info;
        char iface[RTE_ETH_NAME_MAX_LEN];
        retval = rte_eth_dev_get_name_by_port(ptv->port_id, iface);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when getting device name (port %d)",
                    retval, ptv->port_id);
            SCReturnInt(TM_ECODE_FAILED);
        }
        retval = rte_eth_dev_info_get(ptv->port_id, &dev_info);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during getting device info (port %s)",
                    retval, iface);
            SCReturnInt(TM_ECODE_FAILED);
        }

        DevicePreStopPMDSpecificActions(ptv, dev_info.driver_name);
    }

    rte_eth_dev_stop(ptv->port_id);
    if (ptv->copy_mode == DPDK_COPY_MODE_TAP || ptv->copy_mode == DPDK_COPY_MODE_IPS) {
        rte_eth_dev_stop(ptv->out_port_id);
    }

    if (ptv->queue_id == 0 && ptv->pkt_mempool != NULL) {
        rte_mempool_free(ptv->pkt_mempool);
        ptv->pkt_mempool = NULL;
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
