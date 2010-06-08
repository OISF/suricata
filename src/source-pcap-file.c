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
 * \author Victor Julien <victor@inliniac.net>
 *
 * File based pcap packet acquisition support
 */

#if LIBPCAP_VERSION_MAJOR == 1
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif /* LIBPCAP_VERSION_MAJOR */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "source-pcap-file.h"
#include "util-time.h"
#include "util-debug.h"
#include "conf.h"
#include "util-error.h"
#include "util-privs.h"

extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

static int pcap_max_read_packets = 0;

typedef struct PcapFileGlobalVars_ {
    pcap_t *pcap_handle;
    void (*Decoder)(ThreadVars *, DecodeThreadVars *, Packet *, u_int8_t *, u_int16_t, PacketQueue *);
    int datalink;
    struct bpf_program filter;
    uint64_t cnt; /** packet counter */
} PcapFileGlobalVars;

/** max packets < 65536 */
#define PCAP_FILE_MAX_PKTS 256

typedef struct PcapFileThreadVars_
{
    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;

    Packet *in_p;

    Packet *array[PCAP_FILE_MAX_PKTS];
    uint16_t array_idx;

    uint8_t done;
} PcapFileThreadVars;

static PcapFileGlobalVars pcap_g;

TmEcode ReceivePcapFile(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceivePcapFileThreadInit(ThreadVars *, void *, void **);
void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapFile(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodePcapFileThreadInit(ThreadVars *, void *, void **);

void TmModuleReceivePcapFileRegister (void) {
    memset(&pcap_g, 0x00, sizeof(pcap_g));

    tmm_modules[TMM_RECEIVEPCAPFILE].name = "ReceivePcapFile";
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadInit = ReceivePcapFileThreadInit;
    tmm_modules[TMM_RECEIVEPCAPFILE].Func = ReceivePcapFile;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadExitPrintStats = ReceivePcapFileThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].cap_flags = 0;
}

void TmModuleDecodePcapFileRegister (void) {
    tmm_modules[TMM_DECODEPCAPFILE].name = "DecodePcapFile";
    tmm_modules[TMM_DECODEPCAPFILE].ThreadInit = DecodePcapFileThreadInit;
    tmm_modules[TMM_DECODEPCAPFILE].Func = DecodePcapFile;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].cap_flags = 0;
}

void PcapFileCallback(char *user, struct pcap_pkthdr *h, u_char *pkt) {
    SCEnter();

    PcapFileThreadVars *ptv = (PcapFileThreadVars *)user;

    Packet *p = NULL;
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
    }

    if (p == NULL) {
        SCReturn;
    }

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    TimeSet(&p->ts);
    p->datalink = pcap_g.datalink;

    ptv->pkts++;
    ptv->bytes += h->caplen;

    p->pktlen = h->caplen;
    memcpy(p->pkt, pkt, p->pktlen);
    //printf("PcapFileCallback: p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)\n", p->pktlen, *pkt, *p->pkt);

    /* store the packet in our array */
    ptv->array[ptv->array_idx] = p;
    ptv->array_idx++;

    SCReturn;
}

/**
 *  \brief Main PCAP file reading function
 */
TmEcode ReceivePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    SCEnter();
    uint16_t packet_q_len = 0;

    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    if (ptv->done == 1 || suricata_ctl_flags & SURICATA_STOP ||
            suricata_ctl_flags & SURICATA_KILL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* make sure we have at least one packet in the packet pool, to prevent
     * us from alloc'ing packets at line rate */
    while (packet_q_len == 0) {
        SCMutexLock(&packet_q.mutex_q);
        packet_q_len = packet_q.len;
        if (packet_q.len == 0) {
            SCondWait(&packet_q.cond_q, &packet_q.mutex_q);
        }
        packet_q_len = packet_q.len;
        SCMutexUnlock(&packet_q.mutex_q);
    }

    if (postpq == NULL)
        pcap_max_read_packets = 1;

    ptv->array_idx = 0;
    ptv->in_p = p;

    /* Right now we just support reading packets one at a time. */
    int r = pcap_dispatch(pcap_g.pcap_handle, (pcap_max_read_packets < packet_q_len) ? pcap_max_read_packets : packet_q_len,
            (pcap_handler)PcapFileCallback, (u_char *)ptv);

    uint16_t cnt = 0;
    for (cnt = 0; cnt < ptv->array_idx; cnt++) {
        Packet *pp = ptv->array[cnt];

        pcap_g.cnt++;

        if (cnt > 0) {
            pp->pcap_cnt = pcap_g.cnt;
            PacketEnqueue(postpq, pp);
        } else {
            pp->pcap_cnt = pcap_g.cnt;
        }
    }

    if (r < 0) {
        SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                r, pcap_geterr(pcap_g.pcap_handle));

        EngineStop();
        SCReturnInt(TM_ECODE_FAILED);
    } else if (r == 0) {
        SCLogInfo("pcap file end of file reached (pcap err code %" PRId32 ")", r);

        EngineStop();
        ptv->done = 1;
        SCReturnInt(TM_ECODE_OK);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceivePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();
    char *tmpbpfstring = NULL;
    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* use max_pending_packets as pcap read size unless it's bigger than
     * our size limit */
    pcap_max_read_packets = (PCAP_FILE_MAX_PKTS < max_pending_packets) ?
        PCAP_FILE_MAX_PKTS : max_pending_packets;

    SCLogInfo("reading pcap file %s", (char *)initdata);

    PcapFileThreadVars *ptv = SCMalloc(sizeof(PcapFileThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PcapFileThreadVars));

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_g.pcap_handle = pcap_open_offline((char *)initdata, errbuf);
    if (pcap_g.pcap_handle == NULL) {
        SCLogError(SC_ERR_FOPEN, "%s\n", errbuf);
        SCFree(ptv);
        exit(EXIT_FAILURE);
    }

    if (ConfGet("bpf-filter", &tmpbpfstring) != 1) {
        SCLogDebug("could not get bpf or none specified");
    } else {
        SCLogInfo("using bpf-filter \"%s\"", tmpbpfstring);

        if(pcap_compile(pcap_g.pcap_handle,&pcap_g.filter,tmpbpfstring,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(pcap_g.pcap_handle));
            SCFree(ptv);
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(pcap_g.pcap_handle,&pcap_g.filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(pcap_g.pcap_handle));
            SCFree(ptv);
            return TM_ECODE_FAILED;
        }
    }

    pcap_g.datalink = pcap_datalink(pcap_g.pcap_handle);
    SCLogDebug("datalink %" PRId32 "", pcap_g.datalink);

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
        case LINKTYPE_RAW:
            pcap_g.Decoder = DecodeRaw;
            break;

        default:
            SCLogError(SC_ERR_UNIMPLEMENTED, "datalink type %" PRId32 " not "
                      "(yet) supported in module PcapFile.\n", pcap_g.datalink);
            SCFree(ptv);
            SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->tv = tv;
    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

void ReceivePcapFileThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    SCLogInfo(" - (%s) Packets %" PRIu32 ", bytes %" PRIu64 ".", tv->name, ptv->pkts, ptv->bytes);
    return;
}

TmEcode ReceivePcapFileThreadDeinit(ThreadVars *tv, void *data) {
    SCEnter();
    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0 );

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    pcap_g.Decoder(tv, dtv, p, p->pkt, p->pktlen, pq);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/* eof */

