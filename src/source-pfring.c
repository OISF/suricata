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
#include "tm-modules.h"
#include "tm-threads.h"
#include "source-pfring.h"
#include "util-debug.h"
#include "util-privs.h"

TmEcode ReceivePfring(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
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


int g_pfring_threads;

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
    tmm_modules[TMM_RECEIVEPFRING].Func = ReceivePfring;
    tmm_modules[TMM_RECEIVEPFRING].ThreadExitPrintStats = ReceivePfringThreadExitStats;
    tmm_modules[TMM_RECEIVEPFRING].ThreadDeinit = NULL;
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

int PfringConfGetThreads(void) {
    return g_pfring_threads;
}

void PfringLoadConfig(void) {
    char *threadsstr = NULL;

    if (ConfGet("pfring.threads", &threadsstr) != 1) {
        g_pfring_threads = 1;
    } else {
        if (threadsstr != NULL) {
            g_pfring_threads = (uint8_t)atoi(threadsstr);
            SCLogInfo("Going to use %" PRId32 " PF_RING receive thread(s)",
                    g_pfring_threads);
        }
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
static inline void PfringProcessPacket(void *user, struct pfring_pkthdr *h, Packet *p) {

    PfringThreadVars *ptv = (PfringThreadVars *)user;

    ptv->bytes += h->caplen;
    ptv->pkts++;

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;

    /* PF_RING all packets are marked as a link type of ethernet
     * so that is what we do here. */
    p->datalink = LINKTYPE_ETHERNET;

    p->pktlen = h->caplen;
}

/**
 * \brief Recieves packets from an interface via libpfring.
 *
 *  This function recieves packets from an interface and passes
 *  the packet on to the pfring callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PfringThreadVars for ptv
 * \param pq pointer to the PacketQueue (not used here but part of the api)
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode ReceivePfring(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    PfringThreadVars *ptv = (PfringThreadVars *)data;

    struct pfring_pkthdr hdr;

    if (suricata_ctl_flags & SURICATA_STOP ||
            suricata_ctl_flags & SURICATA_KILL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Depending on what compile time options are used for pfring we either return 0 or -1 on error and always 1 for success */
    int r = pfring_recv(ptv->pd, (char *)p->pkt , (u_int)(default_packet_size - 1), &hdr, LIBPFRING_WAIT_FOR_INCOMING);
    if (r == 1) {
        //printf("RecievePfring src %" PRIu32 " sport %" PRIu32 " dst %" PRIu32 " dstport %" PRIu32 "\n",
        //        hdr.parsed_pkt.ipv4_src,hdr.parsed_pkt.l4_src_port, hdr.parsed_pkt.ipv4_dst,hdr.parsed_pkt.l4_dst_port);
        PfringProcessPacket(ptv, &hdr, p);
    } else {
        SCLogError(SC_ERR_PF_RING_RECV,"pfring_recv error  %" PRId32 "", r);
        return TM_ECODE_FAILED;
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
    char *tmpctype;

    PfringThreadVars *ptv = SCMalloc(sizeof(PfringThreadVars));
    if (ptv == NULL)
        return TM_ECODE_FAILED;
    memset(ptv, 0, sizeof(PfringThreadVars));

    if (ConfGet("pfring.cluster-id", &tmpclusterid) != 1) {
        SCLogError(SC_ERR_PF_RING_GET_CLUSTERID_FAILED,"could not get pfring.cluster-id");
        return TM_ECODE_FAILED;
    } else {
        ptv->cluster_id = (uint8_t)atoi(tmpclusterid);
        SCLogDebug("Going to use cluster-id %" PRId32, ptv->cluster_id);
    }

    if (ConfGet("pfring.interface", &ptv->interface) != 1) {
        SCLogError(SC_ERR_PF_RING_GET_INTERFACE_FAILED,"Could not get pfring.interface");
        return TM_ECODE_FAILED;
    } else {
        SCLogDebug("going to use interface %s",ptv->interface);
    }

    ptv->pd = pfring_open(ptv->interface, LIBPFRING_PROMISC, (uint32_t)default_packet_size, LIBPFRING_REENTRANT);
    if (ptv->pd == NULL) {
        SCLogError(SC_ERR_PF_RING_OPEN,"opening %s failed: pfring_open error",
                ptv->interface);
        return TM_ECODE_FAILED;
    } else {
        pfring_set_application_name(ptv->pd, PROG_NAME);
        pfring_version(ptv->pd, &version);

    }

#ifdef HAVE_PFRING_CLUSTER_TYPE
    if (ConfGet("pfring.cluster-type", &tmpctype) != 1) {
        SCLogError(SC_ERR_GET_CLUSTER_TYPE_FAILED,"Could not get pfring.cluster-type");
        return TM_ECODE_FAILED;
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0 || strcmp(tmpctype, "cluster_flow") == 0) {
        ptv->ctype = (cluster_type)tmpctype;
        rc = pfring_set_cluster(ptv->pd, ptv->cluster_id, ptv->ctype);
    } else {
        SCLogError(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
        return TM_ECODE_FAILED;
    }
#else
    rc = pfring_set_cluster(ptv->pd, ptv->cluster_id);
#endif /* HAVE_PFRING_CLUSTER_TYPE */

    if (rc != 0) {
        SCLogError(SC_ERR_PF_RING_SET_CLUSTER_FAILED, "pfring_set_cluster "
                "returned %d for cluster-id: %d", rc, ptv->cluster_id);
        return TM_ECODE_FAILED;
    }

    SCLogInfo("(%s) Using PF_RING v.%d.%d.%d, interface %s, cluster-id %d",
            tv->name, (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
            version & 0x000000FF, ptv->interface, ptv->cluster_id);

    *data = (void *)ptv;
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

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0 );
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* Bypassing the pkt buffer and size macro's as we know the size of
     * our packet never to be bigger than default_packet_size */
    DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);

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
