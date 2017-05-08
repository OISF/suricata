/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifdef HAVE_PFRING
#include <pfring.h>
#endif /* HAVE_PFRING */

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
#include "util-device.h"
#include "util-host-info.h"
#include "runmodes.h"
#include "util-profiling.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

TmEcode ReceivePfringLoop(ThreadVars *tv, void *data, void *slot);
TmEcode PfringBreakLoop(ThreadVars *tv, void *data);
TmEcode ReceivePfringThreadInit(ThreadVars *, const void *, void **);
void ReceivePfringThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePfringThreadDeinit(ThreadVars *, void *);

TmEcode DecodePfringThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodePfring(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
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
    tmm_modules[TMM_RECEIVEPFRING].RegisterTests = NULL;
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
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPFRING].cap_flags = 0;
    tmm_modules[TMM_DECODEPFRING].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this funciton prints an error message and exits.
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

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex pfring_bpf_set_filter_lock = SCMUTEX_INITIALIZER;

/* XXX replace with user configurable options */
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1

typedef enum {
    PFRING_FLAGS_ZERO_COPY = 0x1
} PfringThreadVarsFlags;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PfringThreadVars_
{
    /* thread specific handle */
    pfring *pd;

    /* counters */
    uint64_t bytes;
    uint64_t pkts;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;

    uint32_t flags;

    ThreadVars *tv;
    TmSlot *slot;

    int vlan_disabled;

    /* threads count */
    int threads;

    cluster_type ctype;

    uint8_t cluster_id;
    char *interface;
    LiveDevice *livedev;

    char *bpf_filter;

     ChecksumValidationMode checksum_mode;
} PfringThreadVars;

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
    tmm_modules[TMM_RECEIVEPFRING].RegisterTests = NULL;
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
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
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
    }
}

/**
 * \brief Pfring Packet Process function.
 *
 * This function fills in our packet structure from libpfring.
 * From here the packets are picked up by the  DecodePfring thread.
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

    /* get vlan id from header. Check on vlan_id not null even if comment in
     * header announce NO_VLAN is used when there is no VLAN. But NO_VLAN
     * is not defined nor used in PF_RING code. And vlan_id is set to 0
     * in PF_RING kernel code when there is no VLAN. */
    if ((!ptv->vlan_disabled) && h->extended_hdr.parsed_pkt.vlan_id) {
        p->vlan_id[0] = h->extended_hdr.parsed_pkt.vlan_id & 0x0fff;
        p->vlan_idx = 1;
        p->vlanh[0] = NULL;
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
            if (ptv->livedev->ignore_checksum) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ChecksumAutoModeCheck(ptv->pkts,
                        SC_ATOMIC_GET(ptv->livedev->pkts),
                        SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                ptv->livedev->ignore_checksum = 1;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        default:
            break;
    }

    SET_PKT_LEN(p, h->caplen);
}

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

            /* Check for Zero-copy mode */
            if (ptv->flags & PFRING_FLAGS_ZERO_COPY) {
                PacketSetData(p, pkt_buffer, hdr.caplen);
            }

            //printf("RecievePfring src %" PRIu32 " sport %" PRIu32 " dst %" PRIu32 " dstport %" PRIu32 "\n",
            //        hdr.parsed_pkt.ipv4_src,hdr.parsed_pkt.l4_src_port, hdr.parsed_pkt.ipv4_dst,hdr.parsed_pkt.l4_dst_port);

            PfringProcessPacket(ptv, &hdr, p);

            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
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
            TmThreadsCaptureInjectPacket(tv, ptv->slot, p);

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

    /* if suri uses VLAN and if we have a recent kernel, we need
     * to use parsed_pkt to get VLAN info */
    if ((! ptv->vlan_disabled) && SCKernelVersionIsAtLeast(3, 0)) {
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
        ptv->ctype = pfconf->ctype;
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
                SCLogInfo("Set PF_RING bpf filter \"%s\" failed.",
                          ptv->bpf_filter);
            }
        }
    }

    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);

    /* A bit strange to have this here but we only have vlan information
     * during reading so we need to know if we want to keep vlan during
     * the capture phase */
    int vlanbool = 0;
    if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
        ptv->vlan_disabled = 1;
    }

    /* If kernel is older than 3.8, VLAN is not stripped so we don't
     * get the info from packt extended header but we will use a standard
     * parsing */
    if (! SCKernelVersionIsAtLeast(3, 0)) {
        ptv->vlan_disabled = 1;
    }

    /* If VLAN tracking is disabled, set cluster type to 5-tuple or in case of a
     * ZC interface, do nothing */
    if (ptv->vlan_disabled && ptv->ctype == CLUSTER_FLOW &&
            strncmp(ptv->interface, "zc", 2) != 0) {
        SCLogPerf("VLAN disabled, setting cluster type to CLUSTER_FLOW_5_TUPLE");
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, CLUSTER_FLOW_5_TUPLE);

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            pfconf->DerefFunc(pfconf);
            return TM_ECODE_FAILED;
        }
    }

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
 * DecodePfring reads packets from the PacketQueue. Inside of libpcap version of
 * PF_RING all packets are marked as a link type of ethernet so that is what we do here.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PfringThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 *
 * \todo Verify that PF_RING only deals with ethernet traffic
 *
 * \warning This function bypasses the pkt buf and len macro's
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodePfring(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}

/**
 * \brief This an Init function for DecodePfring
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to initilization data.
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

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

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
