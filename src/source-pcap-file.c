/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

/* TODO
 *
 *
 *
 */

#if LIBPCAP_VERSION_MAJOR == 1
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif

#include "eidps-common.h"
#include "eidps.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "source-pcap-file.h"
#include "util-time.h"

typedef struct PcapFileGlobalVars_ {
    pcap_t *pcap_handle;
    void (*Decoder)(ThreadVars *, DecodeThreadVars *, Packet *, u_int8_t *, u_int16_t, PacketQueue *);
    int datalink;
} PcapFileGlobalVars;

typedef struct PcapFileThreadVars_
{
    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;

    Packet *in_p;
} PcapFileThreadVars;

static PcapFileGlobalVars pcap_g = { NULL, NULL, };

TmEcode ReceivePcapFile(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode ReceivePcapFileThreadInit(ThreadVars *, void *, void **);
void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapFile(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode DecodePcapFileThreadInit(ThreadVars *, void *, void **);

void TmModuleReceivePcapFileRegister (void) {
    tmm_modules[TMM_RECEIVEPCAPFILE].name = "ReceivePcapFile";
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadInit = ReceivePcapFileThreadInit;
    tmm_modules[TMM_RECEIVEPCAPFILE].Func = ReceivePcapFile;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadExitPrintStats = ReceivePcapFileThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].RegisterTests = NULL;
}

void TmModuleDecodePcapFileRegister (void) {
    tmm_modules[TMM_DECODEPCAPFILE].name = "DecodePcapFile";
    tmm_modules[TMM_DECODEPCAPFILE].ThreadInit = DecodePcapFileThreadInit;
    tmm_modules[TMM_DECODEPCAPFILE].Func = DecodePcapFile;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].RegisterTests = NULL;
}

void PcapFileCallback(char *user, struct pcap_pkthdr *h, u_char *pkt) {
    //printf("PcapFileCallback: user %p, h %p, pkt %p\n", user, h, pkt);
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)user;
    //ThreadVars *tv = ptv->tv;

    mutex_lock(&mutex_pending);
    if (pending > MAX_PENDING) {
        pthread_cond_wait(&cond_pending, &mutex_pending);
    }
    mutex_unlock(&mutex_pending);

    Packet *p = ptv->in_p;

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    TimeSet(&p->ts);
    p->datalink = pcap_g.datalink;

    ptv->pkts++;
    ptv->bytes += h->caplen;

    p->pktlen = h->caplen;
    memcpy(p->pkt, pkt, p->pktlen);
    //printf("PcapFileCallback: p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)\n", p->pktlen, *pkt, *p->pkt);
}

TmEcode ReceivePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    ptv->in_p = p;

    /// Right now we just support reading packets one at a time.
    int r = pcap_dispatch(pcap_g.pcap_handle, 1, (pcap_handler)PcapFileCallback, (u_char *)ptv);
    if (r <= 0) {
        printf("ReceivePcap: code %" PRId32 " error %s\n", r, pcap_geterr(pcap_g.pcap_handle));
        EngineStop();
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

TmEcode ReceivePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data) {
    if (initdata == NULL) {
        printf("ReceivePcapFileThreadInit error: initdata == NULL\n");
        return TM_ECODE_FAILED;
    }

    PcapFileThreadVars *ptv = malloc(sizeof(PcapFileThreadVars));
    if (ptv == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(ptv, 0, sizeof(PcapFileThreadVars));

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_g.pcap_handle = pcap_open_offline((char *)initdata, errbuf);
    if (pcap_g.pcap_handle == NULL) {
        printf("error %s\n", errbuf);
        exit(1);
    }

    pcap_g.datalink = pcap_datalink(pcap_g.pcap_handle);
    printf("TmModuleReceivePcapFileRegister: datalink %" PRId32 "\n", pcap_g.datalink);
    switch(pcap_g.datalink)	{
        case LINKTYPE_LINUX_SLL:
            pcap_g.Decoder = DecodeSll;
            break;
        case LINKTYPE_ETHERNET:
            pcap_g.Decoder = DecodeEthernet;
            break;
        case LINKTYPE_PPP:
            pcap_g.Decoder = DecodePPP;
            break;
        default:
            printf("Error: datalink type %" PRId32 " not yet supported in module PcapFile.\n", pcap_g.datalink);
            return -1;
    }

    ptv->tv = tv;
    *data = (void *)ptv;
    return TM_ECODE_OK;
}

void ReceivePcapFileThreadExitStats(ThreadVars *tv, void *data) {
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    printf(" - (%s) Packets %" PRIu32 ", bytes %" PRIu64 ".\n", tv->name, ptv->pkts, ptv->bytes);
    return;
}

TmEcode ReceivePcapFileThreadDeinit(ThreadVars *tv, void *data) {
    return TM_ECODE_OK;
}

TmEcode DecodePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    PerfCounterIncr(dtv->counter_pkts, tv->pca);
    PerfCounterAddUI64(dtv->counter_bytes, tv->pca, p->pktlen);
    PerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->pca, p->pktlen);
    PerfCounterSetUI64(dtv->counter_max_pkt_size, tv->pca, p->pktlen);

    /* call the decoder */
    pcap_g.Decoder(tv, dtv, p, p->pkt, p->pktlen, pq);

    return TM_ECODE_OK;
}

TmEcode DecodePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = malloc(sizeof(DecodeThreadVars))) == NULL) {
        printf("Error Allocating memory\n");
        return TM_ECODE_FAILED;
    }
    memset(dtv, 0, sizeof(DecodeThreadVars));

    /* register counters */
    dtv->counter_pkts = PerfTVRegisterCounter("decoder.pkts", tv, TYPE_UINT64, "NULL");
    dtv->counter_bytes = PerfTVRegisterCounter("decoder.bytes", tv, TYPE_UINT64, "NULL");
    dtv->counter_ipv4 = PerfTVRegisterCounter("decoder.ipv4", tv, TYPE_UINT64, "NULL");
    dtv->counter_ipv6 = PerfTVRegisterCounter("decoder.ipv6", tv, TYPE_UINT64, "NULL");
    dtv->counter_eth = PerfTVRegisterCounter("decoder.ethernet", tv, TYPE_UINT64, "NULL");
    dtv->counter_sll = PerfTVRegisterCounter("decoder.sll", tv, TYPE_UINT64, "NULL");
    dtv->counter_tcp = PerfTVRegisterCounter("decoder.tcp", tv, TYPE_UINT64, "NULL");
    dtv->counter_udp = PerfTVRegisterCounter("decoder.udp", tv, TYPE_UINT64, "NULL");
    dtv->counter_icmpv4 = PerfTVRegisterCounter("decoder.icmpv4", tv, TYPE_UINT64, "NULL");
    dtv->counter_icmpv6 = PerfTVRegisterCounter("decoder.icmpv6", tv, TYPE_UINT64, "NULL");
    dtv->counter_ppp = PerfTVRegisterCounter("decoder.ppp", tv, TYPE_UINT64, "NULL");
    dtv->counter_pppoe = PerfTVRegisterCounter("decoder.pppoe", tv, TYPE_UINT64, "NULL");
    dtv->counter_gre = PerfTVRegisterCounter("decoder.gre", tv, TYPE_UINT64, "NULL");
    dtv->counter_avg_pkt_size = PerfTVRegisterAvgCounter("decoder.avg_pkt_size", tv,
                                                         TYPE_DOUBLE, "NULL");
    dtv->counter_max_pkt_size = PerfTVRegisterMaxCounter("decoder.max_pkt_size", tv,
                                                         TYPE_UINT64, "NULL");

    tv->pca = PerfGetAllCountersArray(&tv->pctx);
    PerfAddToClubbedTMTable(tv->name, &tv->pctx);

    *data = (void *)dtv;
    return TM_ECODE_OK;
}

/* eof */

