/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author William Metcalf <william.metcalf@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * PF_RING packet acquisition support
 *
 * \todo remove requirement for setting cluster so old 3.x versions are supported
 * \todo implement DNA support
 * \todo Allow ring options such as snaplen etc, to be user configurable.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-pfring.h"
#include "util-debug.h"
#include "util-checksum.h"
#include "util-privs.h"
#include "util-datalink.h"
#include "util-device.h"
#include "util-host-info.h"
#include "runmodes.h"
#include "util-profiling.h"

TmEcode ReceivePfringLoop(ThreadVars *tv, void *data, void *slot);
TmEcode PfringBreakLoop(ThreadVars *tv, void *data);
TmEcode ReceivePfringThreadInit(ThreadVars *, const void *, void **);
void ReceivePfringThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePfringThreadDeinit(ThreadVars *, void *);

TmEcode DecodePfringThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodePfring(ThreadVars *, Packet *, void *);
TmEcode DecodePfringThreadDeinit(ThreadVars *tv, void *data);

extern int max_pending_packets;

#ifndef HAVE_PFRING

/*Handle cases where we don't have PF_RING support built-in*/
TmEcode NoPfringSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceivePfringRegister (void)
{
    tmm_modules[TMM_RECEIVEPFRING].name = "ReceivePfring";
    tmm_modules[TMM_RECEIVEPFRING].ThreadInit = NoPfringSupportExit;
    tmm_modules[TMM_RECEIVEPFRING].Func = NULL;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPFRING].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
        SC_CAP_NET_BIND_SERVICE | SC_CAP_NET_BROADCAST;
    tmm_modules[TMM_RECEIVEPFRING].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePfringRegister (void)
{
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = NoPfringSupportExit;
    tmm_modules[TMM_DECODEPFRING].Func = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPFRING].cap_flags = 0;
    tmm_modules[TMM_DECODEPFRING].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PfringThreadVars
 */
TmEcode NoPfringSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_PF_RING,"Error creating thread %s: you do not have support for pfring "
               "enabled please recompile with --enable-pfring", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have PF_RING support */

#include <pfring.h>

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex pfring_bpf_set_filter_lock = SCMUTEX_INITIALIZER;

/* XXX replace with user configurable options */
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1

/* PfringThreadVars flags */
#define PFRING_FLAGS_ZERO_COPY (1 << 0)
#define PFRING_FLAGS_BYPASS    (1 << 1)

/**
 * \brief Structure to hold thread specific variables.
 */
struct PfringThreadVars_
{
    /* thread specific handle */
    pfring *pd;

    /* counters */
    uint64_t bytes;
    uint64_t pkts;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
    uint16_t capture_bypassed;

    uint32_t flags;

    ThreadVars *tv;
    TmSlot *slot;

    int vlan_in_ext_header;

    /* threads count */
    int threads;

    cluster_type ctype;

    uint8_t cluster_id;
    char *interface;
    LiveDevice *livedev;

    char *bpf_filter;

     ChecksumValidationMode checksum_mode;

    bool vlan_hdr_warned;
};

/**
 * \brief Registration Function for RecievePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePfringRegister (void)
{
    tmm_modules[TMM_RECEIVEPFRING].name = "ReceivePfring";
    tmm_modules[TMM_RECEIVEPFRING].ThreadInit = ReceivePfringThreadInit;
    tmm_modules[TMM_RECEIVEPFRING].Func = NULL;
    tmm_modules[TMM_RECEIVEPFRING].PktAcqLoop = ReceivePfringLoop;
    tmm_modules[TMM_RECEIVEPFRING].PktAcqBreakLoop = PfringBreakLoop;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = ReceivePfringThreadExitStats;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = ReceivePfringThreadDeinit;
    tmm_modules[TMM_RECEIVEPFRING].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePfringRegister (void)
{
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = DecodePfringThreadInit;
    tmm_modules[TMM_DECODEPFRING].Func = DecodePfring;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = DecodePfringThreadDeinit;
    tmm_modules[TMM_DECODEPFRING].flags = TM_FLAG_DECODE_TM;
}

static inline void PfringDumpCounters(PfringThreadVars *ptv)
{
    pfring_stat pfring_s;
    if (likely((pfring_stats(ptv->pd, &pfring_s) >= 0))) {
        /* pfring counter is per socket and is not cleared after read.
         * So to get the number of packet on the interface we can add
         * the newly seen packets and drops for this thread and add it
         * to the interface counter */
        uint64_t th_pkts = StatsGetLocalCounterValue(ptv->tv, ptv->capture_kernel_packets);
        uint64_t th_drops = StatsGetLocalCounterValue(ptv->tv, ptv->capture_kernel_drops);
        SC_ATOMIC_ADD(ptv->livedev->pkts, pfring_s.recv - th_pkts);
        SC_ATOMIC_ADD(ptv->livedev->drop, pfring_s.drop - th_drops);
        StatsSetUI64(ptv->tv, ptv->capture_kernel_packets, pfring_s.recv);
        StatsSetUI64(ptv->tv, ptv->capture_kernel_drops, pfring_s.drop);

#ifdef HAVE_PF_RING_FLOW_OFFLOAD
        if (ptv->flags & PFRING_FLAGS_BYPASS) {
            uint64_t th_bypassed = StatsGetLocalCounterValue(ptv->tv, ptv->capture_bypassed);
            SC_ATOMIC_ADD(ptv->livedev->bypassed, pfring_s.shunt - th_bypassed);
            StatsSetUI64(ptv->tv, ptv->capture_bypassed, pfring_s.shunt);
        }
#endif
    }
}

/**
 * \brief Pfring Packet Process function.
 *
 * This function fills in our packet structure from libpfring.
 * From here the packets are picked up by the DecodePfring thread.
 *
 * \param user pointer to PfringThreadVars
 * \param h pointer to pfring packet header
 * \param p pointer to the current packet
 */
static inline void PfringProcessPacket(void *user, struct pfring_pkthdr *h, Packet *p)
{
    PfringThreadVars *ptv = (PfringThreadVars *)user;

    ptv->bytes += h->caplen;
    ptv->pkts++;
    p->livedev = ptv->livedev;

    /* PF_RING may fail to set timestamp */
    if (h->ts.tv_sec == 0) {
        gettimeofday((struct timeval *)&h->ts, NULL);
    }

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;

    /* PF_RING all packets are marked as a link type of ethernet
     * so that is what we do here. */
    p->datalink = LINKTYPE_ETHERNET;

    /* In the past, we needed this vlan handling in cases
     * where the vlan header was stripped from the raw packet.
     * With modern (at least >= 6) versions of PF_RING, the
     * 'copy_data_to_ring' function (kernel/pf_ring.c) makes
     * sure that if the hardware stripped the vlan header,
     * it is put back by PF_RING.
     *
     * PF_RING should put it back in all cases, but as a extra
     * precaution keep the check here. If the vlan header is
     * part of the raw packet, the vlan_offset will be set.
     * So if it is not set, use the parsed info from PF_RING's
     * extended header.
     */
    if (ptv->vlan_in_ext_header &&
        h->extended_hdr.parsed_pkt.offset.vlan_offset == 0 &&
        h->extended_hdr.parsed_pkt.vlan_id)
    {
        p->vlan_id[0] = h->extended_hdr.parsed_pkt.vlan_id & 0x0fff;
        p->vlan_idx = 1;

        if (!ptv->vlan_hdr_warned) {
            SCLogWarning(SC_ERR_PF_RING_VLAN, "no VLAN header in the raw "
                    "packet. See #2355.");
            ptv->vlan_hdr_warned = true;
        }
    }

    switch (ptv->checksum_mode) {
        case CHECKSUM_VALIDATION_RXONLY:
            if (h->extended_hdr.rx_direction == 0) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        case CHECKSUM_VALIDATION_DISABLE:
            p->flags |= PKT_IGNORE_CHECKSUM;
            break;
        case CHECKSUM_VALIDATION_AUTO:
            if (ChecksumAutoModeCheck(ptv->pkts,
                        SC_ATOMIC_GET(ptv->livedev->pkts),
                        SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        default:
            break;
    }

    SET_PKT_LEN(p, h->caplen);
}

#ifdef HAVE_PF_RING_FLOW_OFFLOAD
/**
 * \brief Pfring bypass callback function
 *
 * \param p a Packet to use information from to trigger bypass
 * \return 1 if bypass is successful, 0 if not
 */
static int PfringBypassCallback(Packet *p)
{
    hw_filtering_rule r;

    /* Only bypass TCP and UDP */
    if (!(PKT_IS_TCP(p) || PKT_IS_UDP(p))) {
        return 0;
    }

    /* Bypassing tunneled packets is currently not supported */
    if (IS_TUNNEL_PKT(p)) {
        return 0;
    }

    r.rule_family_type = generic_flow_id_rule;
    r.rule_family.flow_id_rule.action = flow_drop_rule;
    r.rule_family.flow_id_rule.thread = 0;
    r.rule_family.flow_id_rule.flow_id = p->pfring_v.flow_id;

    SCLogDebug("Bypass set for flow ID = %u", p->pfring_v.flow_id);

    if (pfring_add_hw_rule(p->pfring_v.ptv->pd, &r) < 0) {
        return 0;
    }

    return 1;
}
#endif

/**
 * \brief Recieves packets from an interface via libpfring.
 *
 *  This function recieves packets from an interface and passes
 *  the packet on to the pfring callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptv
 * \param slot slot containing task information
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode ReceivePfringLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    PfringThreadVars *ptv = (PfringThreadVars *)data;
    Packet *p = NULL;
    struct pfring_pkthdr hdr;
    TmSlot *s = (TmSlot *)slot;
    time_t last_dump = 0;
    u_int buffer_size;
    u_char *pkt_buffer;

    ptv->slot = s->slot_next;

    /* we have to enable the ring here as we need to do it after all
     * the threads have called pfring_set_cluster(). */
    int rc = pfring_enable_ring(ptv->pd);
    if (rc != 0) {
        SCLogError(SC_ERR_PF_RING_OPEN, "pfring_enable_ring failed returned %d ", rc);
        SCReturnInt(TM_ECODE_FAILED);
    }

    while(1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        /* Some flavours of PF_RING may fail to set timestamp - see PF-RING-enabled libpcap code*/
        hdr.ts.tv_sec = hdr.ts.tv_usec = 0;

        /* Check for Zero-copy mode */
        if (ptv->flags & PFRING_FLAGS_ZERO_COPY) {
            buffer_size = 0;
            pkt_buffer = NULL;
        } else {
            buffer_size = GET_PKT_DIRECT_MAX_SIZE(p);
            pkt_buffer = GET_PKT_DIRECT_DATA(p);
        }

        int r = pfring_recv(ptv->pd, &pkt_buffer,
                buffer_size,
                &hdr,
                LIBPFRING_WAIT_FOR_INCOMING);
        if (likely(r == 1)) {
            /* profiling started before blocking pfring_recv call, so
             * reset it here */
            PACKET_PROFILING_RESTART(p);

#ifdef HAVE_PF_RING_FLOW_OFFLOAD
            if (ptv->flags & PFRING_FLAGS_BYPASS) {
                /* pkt hash contains the flow id in this configuration */
                p->pfring_v.flow_id = hdr.extended_hdr.pkt_hash;
                p->pfring_v.ptv = ptv;
                p->BypassPacketsFlow = PfringBypassCallback;
            }
#endif

            /* Check for Zero-copy mode */
            if (ptv->flags & PFRING_FLAGS_ZERO_COPY) {
                PacketSetData(p, pkt_buffer, hdr.caplen);
            }

            PfringProcessPacket(ptv, &hdr, p);

            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                SCReturnInt(TM_ECODE_FAILED);
            }

            /* Trigger one dump of stats every second */
            if (p->ts.tv_sec != last_dump) {
                PfringDumpCounters(ptv);
                last_dump = p->ts.tv_sec;
            }
        } else if (unlikely(r == 0)) {
            if (suricata_ctl_flags & SURICATA_STOP) {
                SCReturnInt(TM_ECODE_OK);
            }

            /* pfring didn't use the packet yet */
            TmThreadsCaptureHandleTimeout(tv, p);

        } else {
            SCLogError(SC_ERR_PF_RING_RECV,"pfring_recv error  %" PRId32 "", r);
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }
        StatsSyncCountersIfSignalled(tv);
    }

    return TM_ECODE_OK;
}

/**
 * \brief Stop function for ReceivePfringLoop.
 *
 * This function forces ReceivePfringLoop to stop the
 * execution, exiting the packet capture loop.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptv
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode PfringBreakLoop(ThreadVars *tv, void *data)
{
    PfringThreadVars *ptv = (PfringThreadVars *)data;

    /* Safety check */
    if (ptv->pd == NULL) {
        return TM_ECODE_FAILED;
    }

    pfring_breakloop(ptv->pd);

    return TM_ECODE_OK;
}

/**
 * \brief Init function for RecievePfring.
 *
 * This is a setup function for recieving packets
 * via libpfring.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PfringThreadVars
 * \todo add a config option for setting cluster id
 * \todo Create a general pfring setup function.
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on error
 */
TmEcode ReceivePfringThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    int rc;
    u_int32_t version = 0;
    PfringIfaceConfig *pfconf = (PfringIfaceConfig *) initdata;
    unsigned int opflag;
    char const *active_runmode = RunmodeGetActive();

    if (pfconf == NULL)
        return TM_ECODE_FAILED;

    PfringThreadVars *ptv = SCMalloc(sizeof(PfringThreadVars));
    if (unlikely(ptv == NULL)) {
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PfringThreadVars));

    ptv->tv = tv;
    ptv->threads = 1;

    ptv->interface = SCStrdup(pfconf->iface);
    if (unlikely(ptv->interface == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate device string");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->livedev = LiveGetDevice(pfconf->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* enable zero-copy mode for workers runmode */
    if (active_runmode && strcmp("workers", active_runmode) == 0) {
        ptv->flags |= PFRING_FLAGS_ZERO_COPY;
        SCLogPerf("Enabling zero-copy for %s", ptv->interface);
    }

    ptv->checksum_mode = pfconf->checksum_mode;

    opflag = PF_RING_PROMISC;

    /* if we have a recent kernel, we need to use parsed_pkt to get VLAN info */
    if (ptv->vlan_in_ext_header) {
        opflag |= PF_RING_LONG_HEADER;
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_RXONLY) {
        if (strncmp(ptv->interface, "dna", 3) == 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                         "Can't use rxonly checksum-checks on DNA interface,"
                         " resetting to auto");
            ptv->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else {
            opflag |= PF_RING_LONG_HEADER;
        }
    }

#ifdef HAVE_PF_RING_FLOW_OFFLOAD
    if (pfconf->flags & PFRING_CONF_FLAGS_BYPASS) {
        opflag |= PF_RING_FLOW_OFFLOAD | PF_RING_FLOW_OFFLOAD_NOUPDATES;
        ptv->flags |= PFRING_FLAGS_BYPASS;
    }
#endif

    ptv->pd = pfring_open(ptv->interface, (uint32_t)default_packet_size, opflag);
    if (ptv->pd == NULL) {
        SCLogError(SC_ERR_PF_RING_OPEN,"Failed to open %s: pfring_open error."
                " Check if %s exists and pf_ring module is loaded.",
                ptv->interface,
                ptv->interface);
        pfconf->DerefFunc(pfconf);
        SCFree(ptv);
        return TM_ECODE_FAILED;
    }

    pfring_set_application_name(ptv->pd, (char *)PROG_NAME);
    pfring_version(ptv->pd, &version);

    /* We only set cluster info if the number of pfring threads is greater than 1 */
    ptv->threads = pfconf->threads;

    ptv->cluster_id = pfconf->cluster_id;

    if ((ptv->threads == 1) && (strncmp(ptv->interface, "dna", 3) == 0)) {
        SCLogInfo("DNA interface detected, not adding thread to cluster");
    } else if (strncmp(ptv->interface, "zc", 2) == 0) {
        SCLogInfo("ZC interface detected, not adding thread to cluster");
    } else {
        ptv->ctype = (cluster_type)pfconf->ctype;
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, ptv->ctype);

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            if (rc != PF_RING_ERROR_NOT_SUPPORTED || (pfconf->flags & PFRING_CONF_FLAGS_CLUSTER)) {
                /* cluster is mandatory as explicitly specified in the configuration */
                pfconf->DerefFunc(pfconf);
                return TM_ECODE_FAILED;
            }
        }
    }

    if (ptv->threads > 1) {
        SCLogPerf("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface, ptv->cluster_id);
    } else {
        SCLogPerf("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d, single-pfring-thread",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface, ptv->cluster_id);
    }

    if (pfconf->bpf_filter) {
        ptv->bpf_filter = SCStrdup(pfconf->bpf_filter);
        if (unlikely(ptv->bpf_filter == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Set PF_RING bpf filter failed.");
        } else {
            SCMutexLock(&pfring_bpf_set_filter_lock);
            rc = pfring_set_bpf_filter(ptv->pd, ptv->bpf_filter);
            SCMutexUnlock(&pfring_bpf_set_filter_lock);

            if (rc < 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "Failed to compile BPF \"%s\"",
                           ptv->bpf_filter);
                return TM_ECODE_FAILED;
            }
        }
    }

    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
#ifdef HAVE_PF_RING_FLOW_OFFLOAD
    ptv->capture_bypassed = StatsRegisterCounter("capture.bypassed",
            ptv->tv);
#endif

    /* If kernel is older than 3.0, VLAN is not stripped so we don't
     * get the info from packt extended header but we will use a standard
     * parsing */
    ptv->vlan_in_ext_header = 1;
    if (! SCKernelVersionIsAtLeast(3, 0)) {
        ptv->vlan_in_ext_header = 0;
    }

    /* If VLAN tags are not in the extended header, set cluster type to 5-tuple
     * or in case of a ZC interface, do nothing */
    if ((! ptv->vlan_in_ext_header) && ptv->ctype == CLUSTER_FLOW &&
            strncmp(ptv->interface, "zc", 2) != 0) {
        SCLogPerf("VLAN not in extended header, setting cluster type to CLUSTER_FLOW_5_TUPLE");
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, CLUSTER_FLOW_5_TUPLE);

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            pfconf->DerefFunc(pfconf);
            return TM_ECODE_FAILED;
        }
    }

    DatalinkSetGlobalType(LINKTYPE_ETHERNET);

    *data = (void *)ptv;
    pfconf->DerefFunc(pfconf);

    return TM_ECODE_OK;
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptv
 */
void ReceivePfringThreadExitStats(ThreadVars *tv, void *data)
{
    PfringThreadVars *ptv = (PfringThreadVars *)data;

    PfringDumpCounters(ptv);
    SCLogPerf("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_packets),
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_drops));
    SCLogPerf("(%s) Packets %" PRIu64 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
#ifdef HAVE_PF_RING_FLOW_OFFLOAD
    if (ptv->flags & PFRING_FLAGS_BYPASS) {
        SCLogPerf("(%s) Bypass: Packets %" PRIu64 "",
                tv->name,
                StatsGetLocalCounterValue(tv, ptv->capture_bypassed));
    }
#endif
}

/**
 * \brief DeInit function closes pd at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptvi
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceivePfringThreadDeinit(ThreadVars *tv, void *data)
{
    PfringThreadVars *ptv = (PfringThreadVars *)data;
    if (ptv->interface)
        SCFree(ptv->interface);
    pfring_remove_from_cluster(ptv->pd);

    if (ptv->bpf_filter) {
        pfring_remove_bpf_filter(ptv->pd);
        SCFree(ptv->bpf_filter);
    }

    pfring_close(ptv->pd);
    return TM_ECODE_OK;
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodePfring decodes raw packets from PF_RING. Inside of libpcap version of
 * PF_RING all packets are marked as a link type of ethernet so that is what we do here.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PfringThreadVars for ptv
 *
 * \todo Verify that PF_RING only deals with ethernet traffic
 *
 * \warning This function bypasses the pkt buf and len macro's
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodePfring(ThreadVars *tv, Packet *p, void *data)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}

/**
 * \brief This an Init function for DecodePfring
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to initialization data.
 * \param data pointer that gets cast into PfringThreadVars for ptv
 * \retval TM_ECODE_OK is returned on success
 * \retval TM_ECODE_FAILED is returned on error
 */
TmEcode DecodePfringThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}

TmEcode DecodePfringThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_PFRING */
/* eof */
