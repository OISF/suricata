/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "util-privs.h"

TmEcode ReceivePfringLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceivePfringThreadInit(ThreadVars *, void *, void **);
void ReceivePfringThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePfringThreadDeinit(ThreadVars *, void *);

TmEcode DecodePfringThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePfring(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

extern int max_pending_packets;
extern uint8_t suricata_ctl_flags;

#ifndef HAVE_PFRING

/*Handle cases where we don't have PF_RING support built-in*/
TmEcode NoPfringSupportExit(ThreadVars *, void *, void **);

void TmModuleReceivePfringRegister (void) {
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

void TmModuleDecodePfringRegister (void) {
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = NoPfringSupportExit;
    tmm_modules[TMM_DECODEPFRING].Func = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPFRING].cap_flags = 0;
}

/**
 * \brief this funciton prints an error message and exits.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PfringThreadVars
 */
TmEcode NoPfringSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_PF_RING,"Error creating thread %s: you do not have support for pfring "
               "enabled please recompile with --enable-pfring", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have PF_RING support */

/* XXX replace with user configurable options */
#define LIBPFRING_SNAPLEN     1518
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PfringThreadVars_
{
    /* thread specific handle */
    pfring *pd;

    /* counters */
    uint64_t bytes;
    uint32_t pkts;

    ThreadVars *tv;
    TmSlot *slot;
    
    /* threads count */
    int threads;

#ifdef HAVE_PFRING_CLUSTER_TYPE
    cluster_type ctype;
#endif /* HAVE_PFRING_CLUSTER_TYPE */
    uint8_t cluster_id;
    char *interface;
} PfringThreadVars;

/**
 * \brief Registration Function for RecievePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePfringRegister (void) {
    tmm_modules[TMM_RECEIVEPFRING].name = "ReceivePfring";
    tmm_modules[TMM_RECEIVEPFRING].ThreadInit = ReceivePfringThreadInit;
    tmm_modules[TMM_RECEIVEPFRING].Func = NULL;
    tmm_modules[TMM_RECEIVEPFRING].PktAcqLoop = ReceivePfringLoop;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = ReceivePfringThreadExitStats;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = ReceivePfringThreadDeinit;
    tmm_modules[TMM_RECEIVEPFRING].RegisterTests = NULL;
}

/**
 * \brief Registration Function for DecodePfring.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePfringRegister (void) {
    tmm_modules[TMM_DECODEPFRING].name = "DecodePfring";
    tmm_modules[TMM_DECODEPFRING].ThreadInit = DecodePfringThreadInit;
    tmm_modules[TMM_DECODEPFRING].Func = DecodePfring;
    tmm_modules[TMM_DECODEPFRING].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPFRING].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPFRING].RegisterTests = NULL;
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
static inline void PfringProcessPacket(void *user, struct pfring_pkthdr *h, Packet *p) {

    PfringThreadVars *ptv = (PfringThreadVars *)user;

    ptv->bytes += h->caplen;
    ptv->pkts++;

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;

    /* PF_RING all packets are marked as a link type of ethernet
     * so that is what we do here. */
    p->datalink = LINKTYPE_ETHERNET;

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
    uint16_t packet_q_len = 0;
    PfringThreadVars *ptv = (PfringThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;

    struct pfring_pkthdr hdr;

    SCEnter();

    while(1) {
        if (suricata_ctl_flags & SURICATA_STOP ||
                suricata_ctl_flags & SURICATA_KILL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        /* Depending on what compile time options are used for pfring we either return 0 or -1 on error and always 1 for success */
#ifdef HAVE_PFRING_RECV_UCHAR
        int r = pfring_recv(ptv->pd, (u_char**)&GET_PKT_DIRECT_DATA(p),
                (u_int)GET_PKT_DIRECT_MAX_SIZE(p),
                &hdr,
                LIBPFRING_WAIT_FOR_INCOMING);
#else
        int r = pfring_recv(ptv->pd, (char *)GET_PKT_DIRECT_DATA(p),
                (u_int)GET_PKT_DIRECT_MAX_SIZE(p),
                &hdr,
                LIBPFRING_WAIT_FOR_INCOMING);
#endif /* HAVE_PFRING_RECV_UCHAR */

        if (r == 1) {
            //printf("RecievePfring src %" PRIu32 " sport %" PRIu32 " dst %" PRIu32 " dstport %" PRIu32 "\n",
            //        hdr.parsed_pkt.ipv4_src,hdr.parsed_pkt.l4_src_port, hdr.parsed_pkt.ipv4_dst,hdr.parsed_pkt.l4_dst_port);
            PfringProcessPacket(ptv, &hdr, p);
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            SCLogError(SC_ERR_PF_RING_RECV,"pfring_recv error  %" PRId32 "", r);
            TmqhOutputPacketpool(ptv->tv, p);
            return TM_ECODE_FAILED;
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

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
TmEcode ReceivePfringThreadInit(ThreadVars *tv, void *initdata, void **data) {
    int rc;
    u_int32_t version = 0;
    char *tmpclusterid;
    PfringIfaceConfig *pfconf = (PfringIfaceConfig *) initdata;


    if (pfconf == NULL)
        return TM_ECODE_FAILED;

    PfringThreadVars *ptv = SCMalloc(sizeof(PfringThreadVars));
    if (ptv == NULL) {
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PfringThreadVars));

    ptv->tv = tv;
    ptv->threads = 1;

    ptv->interface = SCStrdup(pfconf->iface);

    ptv->pd = pfring_open(ptv->interface, LIBPFRING_PROMISC, (uint32_t)default_packet_size, LIBPFRING_REENTRANT);
    if (ptv->pd == NULL) {
        SCLogError(SC_ERR_PF_RING_OPEN,"opening %s failed: pfring_open error",
                ptv->interface);
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    } else {
        pfring_set_application_name(ptv->pd, PROG_NAME);
        pfring_version(ptv->pd, &version);
    }

    /* We only set cluster info if the number of pfring threads is greater than 1 */
    ptv->threads = pfconf->threads;

    if (ptv->threads > 1) {
        ptv->cluster_id = pfconf->cluster_id;

#ifdef HAVE_PFRING_CLUSTER_TYPE
        ptv->ctype = pfconf->ctype;
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, ptv->ctype);
#else
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id);
#endif /* HAVE_PFRING_CLUSTER_TYPE */

        if (rc != 0) {
            SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                    "returned %d for cluster-id: %d", rc, ptv->cluster_id);
            pfconf->DerefFunc(pfconf);
            return TM_ECODE_FAILED;
        }
        SCLogInfo("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface, ptv->cluster_id);

    } else {
        SCLogInfo("(%s) Using PF_RING v.%d.%d.%d, interface %s, single-pfring-thread",
                tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
                version & 0x000000FF, ptv->interface);
    }

/* It seems that as of 4.7.1 this is required */
#ifdef HAVE_PFRING_ENABLE
    rc = pfring_enable_ring(ptv->pd);

    if (rc != 0) {
        SCLogError(SC_ERR_PF_RING_OPEN, "pfring_enable failed returned %d ", rc);
        pfconf->DerefFunc(pfconf);
        return TM_ECODE_FAILED;
    }
#endif /* HAVE_PFRING_ENABLE */


    *data = (void *)ptv;
    pfconf->DerefFunc(pfconf);
    return TM_ECODE_OK;
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptv
 */
void ReceivePfringThreadExitStats(ThreadVars *tv, void *data) {
    PfringThreadVars *ptv = (PfringThreadVars *)data;
    pfring_stat pfring_s;

    if(pfring_stats(ptv->pd, &pfring_s) < 0) {
        SCLogError(SC_ERR_STAT,"(%s) Failed to get pfring stats", tv->name);
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
    } else {
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

        SCLogInfo("(%s) Pfring Total:%" PRIu64 " Recv:%" PRIu64 " Drop:%" PRIu64 " (%02.1f%%).", tv->name,
        (uint64_t)pfring_s.recv + (uint64_t)pfring_s.drop, (uint64_t)pfring_s.recv,
        (uint64_t)pfring_s.drop, ((float)pfring_s.drop/(float)(pfring_s.drop + pfring_s.recv))*100);
    }
}

/**
 * \brief DeInit function closes pd at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptvi
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceivePfringThreadDeinit(ThreadVars *tv, void *data) {
    PfringThreadVars *ptv = (PfringThreadVars *)data;
    if (ptv->interface)
        SCFree(ptv->interface);
    pfring_remove_from_cluster(ptv->pd);
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

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0 );
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

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
TmEcode DecodePfringThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}
#endif /* HAVE_PFRING */
/* eof */
