/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include <pthread.h>
#include <sys/signal.h>

#if LIBPCAP_VERSION_MAJOR == 1
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif

#include "eidps.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "source-pcap.h"

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
    u_int32_t pkts;
    u_int64_t bytes;
    u_int32_t errs;

    ThreadVars *tv;
} PcapThreadVars;

int ReceivePcap(ThreadVars *, Packet *, void *, PacketQueue *);
int ReceivePcapThreadInit(ThreadVars *, void *, void **);
void ReceivePcapThreadExitStats(ThreadVars *, void *);
int ReceivePcapThreadDeinit(ThreadVars *, void *);

int DecodePcapThreadInit(ThreadVars *, void *, void **);
int DecodePcap(ThreadVars *, Packet *, void *, PacketQueue *);

/**
 * \brief Registration Function for RecievePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePcapRegister (void) {
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceivePcap";
    tmm_modules[TMM_RECEIVEPCAP].Init = ReceivePcapThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].Func = ReceivePcap;
    tmm_modules[TMM_RECEIVEPCAP].ExitPrintStats = ReceivePcapThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAP].Deinit = NULL;
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = NULL;
}

/**
 * \brief Registration Function for DecodePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePcapRegister (void) {
    tmm_modules[TMM_DECODEPCAP].name = "DecodePcap";
    tmm_modules[TMM_DECODEPCAP].Init = DecodePcapThreadInit;
    tmm_modules[TMM_DECODEPCAP].Func = DecodePcap;
    tmm_modules[TMM_DECODEPCAP].ExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAP].Deinit = NULL;
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

    mutex_lock(&mutex_pending);
    if (pending > MAX_PENDING) {
        pthread_cond_wait(&cond_pending, &mutex_pending);
    }
    mutex_unlock(&mutex_pending);

    Packet *p = tv->tmqh_in(tv);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;

    ptv->pkts++;
    ptv->bytes += h->caplen;

    p->pcap_v.datalink = ptv->datalink;
    p->pktlen = h->caplen;
    memcpy(p->pkt, pkt, p->pktlen);
    //printf("PcapCallback: p->pktlen: %u (pkt %02x, p->pkt %02x)\n", p->pktlen, *pkt, *p->pkt);

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
 */
int ReceivePcap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    /// Just read one packet at a time for now.
    int r = 0;
    while (r == 0) {
        //printf("ReceivePcap: call pcap_dispatch %u\n", tv->flags);

        r = pcap_dispatch(ptv->pcap_handle, 1, (pcap_handler)PcapCallback, (u_char *)ptv);
        if (r < 0) {
            printf("ReceivePcap: error %s\n", pcap_geterr(ptv->pcap_handle));
            break;
        }

        if (tv->flags & THV_KILL || tv->flags & THV_PAUSE) {
            printf("ReceivePcap: interrupted.\n");
            return 0;
        }
    }

    return 0;
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
int ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    if (initdata == NULL) {
        printf("ReceivePcapThreadInit error: initdata == NULL\n");
        return -1;
    }

    PcapThreadVars *ptv = malloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        return -1;
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    printf("ReceivePcapThreadInit: using interface %s\n", (char *)initdata);

    /* XXX create a general pcap setup function */
    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create((char *)initdata, errbuf);
    if (ptv->pcap_handle == NULL) {
        printf("error %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    /* set Snaplen, Promisc, and Timeout. Must be called before pcap_activate */
    int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle,LIBPCAP_SNAPLEN);
    //printf("ReceivePcapThreadInit: pcap_set_snaplen(%p) returned %d\n", ptv->pcap_handle, pcap_set_snaplen_r);
    if (pcap_set_snaplen_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle,LIBPCAP_PROMISC);
    //printf("ReceivePcapThreadInit: pcap_set_promisc(%p) returned %d\n", ptv->pcap_handle, pcap_set_promisc_r);
    if (pcap_set_promisc_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle,LIBPCAP_COPYWAIT);
    //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %d\n", ptv->pcap_handle, pcap_set_timeout_r);
    if (pcap_set_timeout_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    //printf("ReceivePcapThreadInit: pcap_activate(%p) returned %d\n", ptv->pcap_handle, pcap_activate_r);
    if (pcap_activate_r != 0) {
        printf("ReceivePcapThreadInit: error is %s\n", pcap_geterr(ptv->pcap_handle));
        exit(1);
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    return 0;
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
int ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    if (initdata == NULL) {
        printf("ReceivePcapThreadInit error: initdata == NULL\n");
        return -1;
    }

    PcapThreadVars *ptv = malloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        return -1;
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    printf("ReceivePcapThreadInit: using interface %s\n", (char *)initdata);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ptv->pcap_handle = pcap_open_live((char *)initdata, LIBPCAP_SNAPLEN,
                                        LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        printf("error %s\n", errbuf);
        exit(1);
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    return 0;
}
#endif /* LIBPCAP_VERSION_MAJOR */

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
void ReceivePcapThreadExitStats(ThreadVars *tv, void *data) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    printf(" - (%s) Packets %u, bytes %llu.\n", tv->name, ptv->pkts, ptv->bytes);
    return;
}

/**
 * \brief DeInit function closes pcap_handle at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
int ReceivePcapThreadDeinit(ThreadVars *tv, void *data) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    pcap_close(ptv->pcap_handle);
    return 0;
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
int DecodePcap(ThreadVars *t, Packet *p, void *data, PacketQueue *pq)
{
    PerfCounterIncr(COUNTER_DECODER_PKTS, t->pca);
    PerfCounterAddUI64(COUNTER_DECODER_BYTES, t->pca, p->pktlen);
    PerfCounterAddUI64(COUNTER_DECODER_AVG_PKT_SIZE, t->pca, p->pktlen);
    PerfCounterSetUI64(COUNTER_DECODER_MAX_PKT_SIZE, t->pca, p->pktlen);

    /* call the decoder */
    switch(p->pcap_v.datalink)    {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(t,p,p->pkt,p->pktlen,pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(t,p,p->pkt,p->pktlen,pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(t,p,p->pkt,p->pktlen,pq);
            break;
        default:
            printf("Error: datalink type %d not yet supported in module DecodePcap.\n", p->pcap_v.datalink);
            break;
    }

    return 0;
}

int DecodePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    PerfRegisterCounter("decoder.pkts", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.bytes", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.ipv4", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.ipv6", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.ethernet", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.sll", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.tcp", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.udp", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.icmpv4", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.icmpv6", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.ppp", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_NONE, 1);
    PerfRegisterCounter("decoder.avg_pkt_size", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_AVERAGE, 1);
    PerfRegisterCounter("decoder.max_pkt_size", "DecodePcap", TYPE_UINT64, "NULL",
                        &tv->pctx, TYPE_Q_MAXIMUM, 1);

    tv->pca = PerfGetAllCountersArray(&tv->pctx);

    PerfAddToClubbedTMTable("DecodePcap", &tv->pctx);

    return 0;
}


/* eof */

