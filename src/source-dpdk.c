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
#include "source-dpdk.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-privs.h"
#include "util-dpdk.h"

#define BURST_SIZE 32

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
    SCLogError(SC_ERR_NO_DPDK,
            "Error creating thread %s: you do not have "
            "support for DPDK enabled, on Linux host please recompile "
            "with --enable-dpdk",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have DPDK support */

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
    uint16_t capture_dpdk_drops;
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
static void CyclesToTimeval(uint64_t cycles, struct timeval *tv);
void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset);
static uint64_t DPDKGetSeconds(void);
static void DPDKSetTimeval(struct timeval *tv);

void DPDKFreeMbufArray(struct rte_mbuf **mbuf_array, uint16_t mbuf_cnt, uint16_t offset)
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

static void CyclesToTimeval(const uint64_t cycles, struct timeval *tv)
{
    uint64_t usec = CyclesToMicroseconds(cycles);
    tv->tv_sec = usec / 1000000;
    tv->tv_usec = (usec % 1000000);
}

/* Set timeval to time that passed from the reset of TSC counter
 * (typically from the machine start)*/
static void DPDKSetTimeval(struct timeval *tv)
{
    CyclesToTimeval(rte_get_tsc_cycles(), tv);
}

/* get number of seconds from the reset of TSC counter (typically from the machine start) */
static uint64_t DPDKGetSeconds()
{
    return CyclesToSeconds(rte_get_tsc_cycles());
}

/**
 * \brief Registration Function for RecieveDPDK.
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
#ifdef PACKET_STATISTICS
    // Prevents access to other fields of stats structure
    if (unlikely(ptv->queue_id >= RTE_ETHDEV_QUEUE_STAT_CNTRS))
        return;

    struct rte_eth_stats eth_stats;
    rte_eth_stats_get(ptv->port_id, &eth_stats);

    uint64_t th_pkts = StatsGetLocalCounterValue(ptv->tv, ptv->capture_dpdk_packets);
    uint64_t th_drops = StatsGetLocalCounterValue(ptv->tv, ptv->capture_dpdk_drops);

    StatsAddUI64(ptv->tv, ptv->capture_dpdk_packets, eth_stats.q_ipackets[ptv->queue_id] - th_pkts);
    StatsAddUI64(ptv->tv, ptv->capture_dpdk_drops, eth_stats.q_errors[ptv->queue_id] - th_drops);
    SC_ATOMIC_ADD(ptv->livedev->pkts, eth_stats.q_ipackets[ptv->queue_id] - th_pkts);
    SC_ATOMIC_ADD(ptv->livedev->drop, eth_stats.q_errors[ptv->queue_id] - th_drops);
#endif
}

static void DPDKReleasePacket(Packet *p)
{
    int retval;
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->dpdk_v.copy_mode != DPDK_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p) &&
            p->dpdk_v.copy_mode == DPDK_COPY_MODE_IPS && !PACKET_TEST_ACTION(p, ACTION_DROP)) {
        retval =
                rte_eth_tx_burst(p->dpdk_v.out_port_id, p->dpdk_v.out_queue_id, &p->dpdk_v.mbuf, 1);
        if (unlikely(retval < 1)) {
            rte_pktmbuf_free(p->dpdk_v.mbuf);
            p->dpdk_v.mbuf = NULL;
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
TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot)
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
            SCLogInfo("Stopping Suricata!");
            DPDKDumpCounters(ptv);
            break;
        }

        nb_rx = rte_eth_rx_burst(ptv->port_id, ptv->queue_id, ptv->received_mbufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) {
            continue;
        }

        ptv->pkts += (uint64_t)nb_rx;
        for (int i = 0; i < nb_rx; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to get Packet Buffer for DPDK mbuf!");
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i, i);
                SCReturnInt(EXIT_FAILURE);
            }
            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }

            DPDKSetTimeval(&p->ts);
            p->dpdk_v.mbuf = ptv->received_mbufs[i];
            p->ReleasePacket = DPDKReleasePacket;
            p->dpdk_v.copy_mode = ptv->copy_mode;
            p->dpdk_v.out_port_id = ptv->out_port_id;
            p->dpdk_v.out_queue_id = ptv->queue_id;

            if (PacketSetData(p, rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *),
                        rte_pktmbuf_pkt_len(p->dpdk_v.mbuf)) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                DPDKFreeMbufArray(ptv->received_mbufs, nb_rx - i - 1, i + 1);
                SCReturnInt(EXIT_FAILURE);
            }

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
TmEcode ReceiveDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    int retval;
    DPDKIfaceConfig *dpdk_config = (DPDKIfaceConfig *)initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "DPDK Configuration failed");
        dpdk_config->DerefFunc(dpdk_config);
        SCReturnInt(TM_ECODE_FAILED);
    }

    DPDKThreadVars *ptv = SCCalloc(1, sizeof(DPDKThreadVars));
    if (unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate memory");
        dpdk_config->DerefFunc(dpdk_config);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->tv = tv;
    ptv->pkts = 0;
    ptv->bytes = 0;
    ptv->livedev = LiveGetDevice(dpdk_config->iface);

#ifdef PACKET_STATISTICS
    ptv->capture_dpdk_packets = StatsRegisterCounter("capture.packets", ptv->tv);
    ptv->capture_dpdk_drops = StatsRegisterCounter("capture.drops", ptv->tv);
#endif

    ptv->copy_mode = dpdk_config->copy_mode;
    ptv->checksum_mode = dpdk_config->checksum_mode;

    ptv->threads = dpdk_config->threads;
    ptv->port_id = dpdk_config->port_id;
    ptv->out_port_id = dpdk_config->out_port_id;
    uint16_t queue_id = SC_ATOMIC_ADD(dpdk_config->queue_id, 1);
    ptv->queue_id = queue_id;
    // pass the pointer to the mempool and then forget about it. Mempool is freed in thread deinit.
    ptv->pkt_mempool = dpdk_config->pkt_mempool_array[queue_id];
    dpdk_config->pkt_mempool_array[queue_id] = NULL;

    // the last thread starts the device
    if (queue_id == dpdk_config->threads - 1) {
        retval = rte_eth_dev_start(ptv->port_id);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) during device startup of port %u", retval,
                    ptv->port_id);
            dpdk_config->DerefFunc(dpdk_config);
            SCReturnInt(TM_ECODE_FAILED);
        }

        retval = dpdk_config->flags & DPDK_PROMISC ? rte_eth_promiscuous_enable(ptv->port_id)
                                                   : rte_eth_promiscuous_disable(ptv->port_id);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_INIT, "Error (err=%d) when enabling promiscuous mode on port %u",
                    retval, ptv->port_id);
            dpdk_config->DerefFunc(dpdk_config);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    if (rte_eth_dev_socket_id(ptv->port_id) != (int)rte_socket_id()) {
        SCLogWarning(SC_WARN_DPDK_CONF,
                "NIC on a different NUMA node as lcore %u is initialized on", rte_socket_id());
    }

    *data = (void *)ptv;
    dpdk_config->DerefFunc(dpdk_config);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
void ReceiveDPDKThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;

#ifdef PACKET_STATISTICS
    DPDKDumpCounters(ptv);
    SCLogPerf("(%s) DPDK: Packets %" PRIu64 " dropped: %" PRIu64 "", tv->name,
            StatsGetLocalCounterValue(ptv->tv, ptv->capture_dpdk_packets),
            StatsGetLocalCounterValue(ptv->tv, ptv->capture_dpdk_drops));
#endif
}

/**
 * \brief DeInit function closes dpdk at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ptv
 */
TmEcode ReceiveDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    DPDKThreadVars *ptv = (DPDKThreadVars *)data;
    if (ptv->pkt_mempool != NULL)
        rte_mempool_free(ptv->pkt_mempool);
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
TmEcode DecodeDPDK(ThreadVars *tv, Packet *p, void *data)
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

TmEcode DecodeDPDKThreadInit(ThreadVars *tv, const void *initdata, void **data)
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

TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_DPDK */
/* eof */
/**
 * @}
 */
