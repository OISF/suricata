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
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"

extern int max_pending_packets;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PcapThreadVars_
{
    /* thread specific handle */
    pcap_t *pcap_handle;

    /* thread specific bpf */
    struct bpf_program filter;

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
    SCLogDebug("user %p, h %p, pkt %p", user, h, pkt);
    PcapThreadVars *ptv = (PcapThreadVars *)user;
    ThreadVars *tv = ptv->tv;

    SCMutexLock(&mutex_pending);
    if (pending > max_pending_packets) {
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
    SCLogDebug("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);

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
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    /* Just read one packet at a time for now. */
    int r = 0;
    while (r == 0) {
        r = pcap_dispatch(ptv->pcap_handle, 1, (pcap_handler)PcapCallback, (u_char *)ptv);
        if (r < 0) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %"PRId32" %s",
                r, pcap_geterr(ptv->pcap_handle));
            break;
        }

        if (TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
            SCLogInfo("pcap packet reading interrupted");
            SCReturnInt(TM_ECODE_OK);
        }
    }

    SCReturnInt(TM_ECODE_OK);
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
    SCEnter();
    char *tmpbpfstring;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Couldn't allocate PcapThreadVars");
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    SCLogInfo("using interface %s", (char *)initdata);

    /* XXX create a general pcap setup function */
    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create((char *)initdata, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_CREATE, "Coudn't create a new pcap handler, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set Snaplen, Promisc, and Timeout. Must be called before pcap_activate */
    int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle,LIBPCAP_SNAPLEN);
    //printf("ReceivePcapThreadInit: pcap_set_snaplen(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_snaplen_r);
    if (pcap_set_snaplen_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_SNAPLEN, "Couldn't set snaplen, error: %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle,LIBPCAP_PROMISC);
    //printf("ReceivePcapThreadInit: pcap_set_promisc(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_promisc_r);
    if (pcap_set_promisc_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_PROMISC, "Couldn't set promisc mode, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle,LIBPCAP_COPYWAIT);
    //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_timeout_r);
    if (pcap_set_timeout_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_TIMEOUT, "Problems setting timeout, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    //printf("ReceivePcapThreadInit: pcap_activate(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_activate_r);
    if (pcap_activate_r != 0) {
        SCLogError(SC_ERR_PCAP_ACTIVATE_HANDLE, "Couldn't activate the pcap handler, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set bpf filter if we have one */
    if (ConfGet("bpf-filter", &tmpbpfstring) != 1) {
        SCLogDebug("could not get bpf or none specified");
    } else {
        SCLogInfo("using bpf-filter \"%s\"", tmpbpfstring);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter,tmpbpfstring,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            return TM_ECODE_FAILED;
        }
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();

    char *tmpbpfstring;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Couldn't allocate PcapThreadVars");
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    SCLogInfo("using interface %s", (char *)initdata);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ptv->pcap_handle = pcap_open_live((char *)initdata, LIBPCAP_SNAPLEN,
                                        LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_LIVE, "Problem creating pcap handler for live mode, error %s", errbuf);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set bpf filter if we have one */
    if (ConfGet("bpf-filter", &tmpbpfstring) != 1) {
        SCLogDebug("could not get bpf or none specified");
    } else {
        SCLogInfo("using bpf-filter \"%s\"", tmpbpfstring);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter,tmpbpfstring,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            return TM_ECODE_FAILED;
        }
    }


    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}
#endif /* LIBPCAP_VERSION_MAJOR */

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
void ReceivePcapThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    struct pcap_stat pcap_s;

    if (pcap_stats(ptv->pcap_handle, &pcap_s) < 0) {
        SCLogError(SC_ERR_STAT,"(%s) Failed to get pcap_stats: %s", tv->name, pcap_geterr(ptv->pcap_handle));
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

        return;
    } else {
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

        /* these numbers are not entirely accurate as ps_recv contains packets that are still waiting to be processed at exit.
         * ps_drop only contains packets dropped by the driver and not any packets dropped by the interface.
         * Additionally see http://tracker.icir.org/bro/ticket/18 */

        SCLogInfo("(%s) Pcap Total:%" PRIu64 " Recv:%" PRIu64 " Drop:%" PRIu64 " (%02.1f%%).", tv->name,
        (uint64_t)pcap_s.ps_recv + (uint64_t)pcap_s.ps_drop, (uint64_t)pcap_s.ps_recv,
        (uint64_t)pcap_s.ps_drop, ((float)pcap_s.ps_drop/(float)(pcap_s.ps_drop + pcap_s.ps_recv))*100);

        return;
    }
}

/**
 * \brief DeInit function closes pcap_handle at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode ReceivePcapThreadDeinit(ThreadVars *tv, void *data) {
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    pcap_close(ptv->pcap_handle);
    SCReturnInt(TM_ECODE_OK);
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
    SCEnter();
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
        case LINKTYPE_RAW:
            DecodeRaw(tv, dtv, p, p->pkt, p->pktlen, pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodePcap", p->datalink);
            break;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error Allocating memory");
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(dtv, 0, sizeof(DecodeThreadVars));

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/* eof */

