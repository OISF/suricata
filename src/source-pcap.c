/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#if LIBPCAP_VERSION_MAJOR == 1
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "source-pcap.h"
#include "util-debug.h"

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PcapThreadVars_
{
    /* thread specific handle */
    pcap_t *pcap_handle;

    /* data link type for the thread */
    int datalink;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
} PcapThreadVars;

TmEcode ReceivePcap(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode ReceivePcapThreadInit(ThreadVars *, void *, void **);
void ReceivePcapThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePcap(ThreadVars *, Packet *, void *, PacketQueue *);

/**
 * \brief Registration Function for RecievePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePcapRegister (void) {
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceivePcap";
    tmm_modules[TMM_RECEIVEPCAP].ThreadInit = ReceivePcapThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].Func = ReceivePcap;
    tmm_modules[TMM_RECEIVEPCAP].ThreadExitPrintStats = ReceivePcapThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = NULL;
}

/**
 * \brief Registration Function for DecodePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePcapRegister (void) {
    tmm_modules[TMM_DECODEPCAP].name = "DecodePcap";
    tmm_modules[TMM_DECODEPCAP].ThreadInit = DecodePcapThreadInit;
    tmm_modules[TMM_DECODEPCAP].Func = DecodePcap;
    tmm_modules[TMM_DECODEPCAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPCAP].RegisterTests = NULL;
}

/**
 * \brief Pcap callback function.
 *
 * This function fills in our packet structure from libpcap.
 * From here the packets are picked up by the  DecodePcap thread.
 *
 * \param user pointer to PcapThreadVars passed from pcap_dispatch
 * \param h pointer to pcap packet header
 * \param pkt pointer to raw packet data
 */
void PcapCallback(char *user, struct pcap_pkthdr *h, u_char *pkt) {
    //printf("PcapCallback: user %p, h %p, pkt %p\n", user, h, pkt);
    PcapThreadVars *ptv = (PcapThreadVars *)user;
    ThreadVars *tv = ptv->tv;

    SCMutexLock(&mutex_pending);
    if (pending > MAX_PENDING) {
        SCondWait(&cond_pending, &mutex_pending);
    }
    SCMutexUnlock(&mutex_pending);

    Packet *p = tv->tmqh_in(tv);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;

    ptv->pkts++;
    ptv->bytes += h->caplen;

    p->datalink = ptv->datalink;
    p->pktlen = h->caplen;
    memcpy(p->pkt, pkt, p->pktlen);
    //printf("PcapCallback: p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)\n", p->pktlen, *pkt, *p->pkt);

    /* pass on... */
    tv->tmqh_out(tv, p);
}

/**
 * \brief Recieves packets from an interface via libpcap.
 *
 *  This function recieves packets from an interface and passes
 *  the packet on to the pcap callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the PacketQueue (not used here but part of the api)
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
TmEcode ReceivePcap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    /// Just read one packet at a time for now.
    int r = 0;
    while (r == 0) {
        //printf("ReceivePcap: call pcap_dispatch %" PRIu32 "\n", tv->flags);

        r = pcap_dispatch(ptv->pcap_handle, 1, (pcap_handler)PcapCallback, (u_char *)ptv);
        if (r < 0) {
            printf("ReceivePcap: error %s\n", pcap_geterr(ptv->pcap_handle));
            break;
        }

        if (TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
            SCLogInfo("pcap packet reading interrupted");
            return TM_ECODE_OK;
        }
    }

    return TM_ECODE_OK;
}

/**
 * \brief Init function for RecievePcap.
 *
 * This is a setup function for recieving packets
 * via libpcap. There are two versions of this function
 * depending on the major version of libpcap used.
 * For versions prior to 1.x we use open_pcap_live,
 * for versions 1.x and greater we use pcap_create + pcap_activate.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PcapThreadVars
 *
 * \todo Create a general pcap setup function.
 */
#if LIBPCAP_VERSION_MAJOR == 1
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    if (initdata == NULL) {
        printf("ReceivePcapThreadInit error: initdata == NULL\n");
        return TM_ECODE_FAILED;
    }

    PcapThreadVars *ptv = malloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    SCLogInfo("using interface %s", (char *)initdata);

    /* XXX create a general pcap setup function */
    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create((char *)initdata, errbuf);
    if (ptv->pcap_handle == NULL) {
        printf("error %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    /* set Snaplen, Promisc, and Timeout. Must be called before pcap_activate */
    int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle,LIBPCAP_SNAPLEN);
    //printf("ReceivePcapThreadInit: pcap_set_snaplen(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_snaplen_r);
    if (pcap_set_snaplen_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle,LIBPCAP_PROMISC);
    //printf("ReceivePcapThreadInit: pcap_set_promisc(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_promisc_r);
    if (pcap_set_promisc_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle,LIBPCAP_COPYWAIT);
    //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_timeout_r);
    if (pcap_set_timeout_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    //printf("ReceivePcapThreadInit: pcap_activate(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_activate_r);
    if (pcap_activate_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    return TM_ECODE_OK;
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    if (initdata == NULL) {
        printf("ReceivePcapThreadInit error: initdata == NULL\n");
        return TM_ECODE_FAILED;
    }

    PcapThreadVars *ptv = malloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    SCLogInfo("using interface %s", (char *)initdata);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ptv->pcap_handle = pcap_open_live((char *)initdata, LIBPCAP_SNAPLEN,
                                        LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        printf("error %s\n", errbuf);
        exit(1);
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    return TM_ECODE_OK;
}
#endif /* LIBPCAP_VERSION_MAJOR */

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
void ReceivePcapThreadExitStats(ThreadVars *tv, void *data) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
    return;
}

/**
 * \brief DeInit function closes pcap_handle at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode ReceivePcapThreadDeinit(ThreadVars *tv, void *data) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    pcap_close(ptv->pcap_handle);
    return TM_ECODE_OK;
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodePcap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodePcap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, p->pkt, p->pktlen, pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,p->pkt, p->pktlen, pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, p->pkt, p->pktlen, pq);
            break;
        default:
            printf("Error: datalink type %" PRId32 " not yet supported in module DecodePcap.\n", p->datalink);
            break;
    }

    return TM_ECODE_OK;
}

TmEcode DecodePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = malloc(sizeof(DecodeThreadVars))) == NULL) {
        printf("Error Allocating memory\n");
        return TM_ECODE_FAILED;
    }
    memset(dtv, 0, sizeof(DecodeThreadVars));

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}

/* eof */

