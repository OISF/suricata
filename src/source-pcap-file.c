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
 * \author Victor Julien <victor@inliniac.net>
 *
 * File based pcap packet acquisition support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "source-pcap-file.h"
#include "util-time.h"
#include "util-debug.h"
#include "conf.h"
#include "util-error.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "tm-threads.h"
#include "util-optimize.h"
#include "flow-manager.h"
#include "util-profiling.h"
#include "runmode-unix-socket.h"
#include "util-checksum.h"
#include "util-atomic.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

extern int max_pending_packets;

//static int pcap_max_read_packets = 0;

typedef struct PcapFileGlobalVars_ {
    pcap_t *pcap_handle;
    int (*Decoder)(ThreadVars *, DecodeThreadVars *, Packet *, u_int8_t *, u_int16_t, PacketQueue *);
    int datalink;
    struct bpf_program filter;
    uint64_t cnt; /** packet counter */
    ChecksumValidationMode conf_checksum_mode;
    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, invalid_checksums);

} PcapFileGlobalVars;

/** max packets < 65536 */
//#define PCAP_FILE_MAX_PKTS 256

typedef struct PcapFileThreadVars_
{
    uint32_t tenant_id;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;

    ThreadVars *tv;
    TmSlot *slot;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    uint8_t done;
    uint32_t errs;
} PcapFileThreadVars;

static PcapFileGlobalVars pcap_g;

TmEcode ReceivePcapFileLoop(ThreadVars *, void *, void *);

TmEcode ReceivePcapFileThreadInit(ThreadVars *, void *, void **);
void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapFile(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodePcapFileThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data);

void TmModuleReceivePcapFileRegister (void)
{
    memset(&pcap_g, 0x00, sizeof(pcap_g));

    tmm_modules[TMM_RECEIVEPCAPFILE].name = "ReceivePcapFile";
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadInit = ReceivePcapFileThreadInit;
    tmm_modules[TMM_RECEIVEPCAPFILE].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].PktAcqLoop = ReceivePcapFileLoop;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadExitPrintStats = ReceivePcapFileThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadDeinit = ReceivePcapFileThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].cap_flags = 0;
    tmm_modules[TMM_RECEIVEPCAPFILE].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePcapFileRegister (void)
{
    tmm_modules[TMM_DECODEPCAPFILE].name = "DecodePcapFile";
    tmm_modules[TMM_DECODEPCAPFILE].ThreadInit = DecodePcapFileThreadInit;
    tmm_modules[TMM_DECODEPCAPFILE].Func = DecodePcapFile;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadDeinit = DecodePcapFileThreadDeinit;
    tmm_modules[TMM_DECODEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAPFILE].flags = TM_FLAG_DECODE_TM;
}

void PcapFileGlobalInit()
{
    SC_ATOMIC_INIT(pcap_g.invalid_checksums);
}

void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();

    PcapFileThreadVars *ptv = (PcapFileThreadVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }
    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFILE);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = pcap_g.datalink;
    p->pcap_cnt = ++pcap_g.cnt;

    p->pcap_v.tenant_id = ptv->tenant_id;
    ptv->pkts++;
    ptv->bytes += h->caplen;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->tv, p);
        PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);
        SCReturn;
    }

    /* We only check for checksum disable */
    if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->pkts, p->pcap_cnt,
                                  SC_ATOMIC_GET(pcap_g.invalid_checksums))) {
            pcap_g.checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(pcap_g.pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
    }

    SCReturn;
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode ReceivePcapFileLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int packet_q_len = 64;
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;
    int r;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    while (1) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Right now we just support reading packets one at a time. */
        r = pcap_dispatch(pcap_g.pcap_handle, packet_q_len,
                          (pcap_handler)PcapFileCallbackLoop, (u_char *)ptv);
        if (unlikely(r == -1)) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                       r, pcap_geterr(pcap_g.pcap_handle));
            if (! RunModeUnixSocketIsActive()) {
                /* in the error state we just kill the engine */
                EngineKill();
                SCReturnInt(TM_ECODE_FAILED);
            } else {
                pcap_close(pcap_g.pcap_handle);
                pcap_g.pcap_handle = NULL;
                UnixSocketPcapFile(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        } else if (unlikely(r == 0)) {
            SCLogInfo("pcap file end of file reached (pcap err code %" PRId32 ")", r);
            if (! RunModeUnixSocketIsActive()) {
                EngineStop();
            } else {
                pcap_close(pcap_g.pcap_handle);
                pcap_g.pcap_handle = NULL;
                UnixSocketPcapFile(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
            break;
        } else if (ptv->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "Pcap callback PcapFileCallbackLoop failed");
            if (! RunModeUnixSocketIsActive()) {
                EngineKill();
                SCReturnInt(TM_ECODE_FAILED);
            } else {
                pcap_close(pcap_g.pcap_handle);
                pcap_g.pcap_handle = NULL;
                UnixSocketPcapFile(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        }
        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceivePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    char *tmpbpfstring = NULL;
    char *tmpstring = NULL;
    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("reading pcap file %s", (char *)initdata);

    PcapFileThreadVars *ptv = SCMalloc(sizeof(PcapFileThreadVars));
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PcapFileThreadVars));

    intmax_t tenant = 0;
    if (ConfGetInt("pcap-file.tenant-id", &tenant) == 1) {
        if (tenant > 0 && tenant < UINT_MAX) {
            ptv->tenant_id = (uint32_t)tenant;
            SCLogInfo("tenant %u", ptv->tenant_id);
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant out of range");
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_g.pcap_handle = pcap_open_offline((char *)initdata, errbuf);
    if (pcap_g.pcap_handle == NULL) {
        SCLogError(SC_ERR_FOPEN, "%s\n", errbuf);
        SCFree(ptv);
        if (! RunModeUnixSocketIsActive()) {
            return TM_ECODE_FAILED;
        } else {
            UnixSocketPcapFile(TM_ECODE_FAILED);
            SCReturnInt(TM_ECODE_DONE);
        }
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

    switch(pcap_g.datalink) {
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
        case LINKTYPE_NULL:
            pcap_g.Decoder = DecodeNull;
            break;

        default:
            SCLogError(SC_ERR_UNIMPLEMENTED, "datalink type %" PRId32 " not "
                      "(yet) supported in module PcapFile.\n", pcap_g.datalink);
            SCFree(ptv);
            if (! RunModeUnixSocketIsActive()) {
                SCReturnInt(TM_ECODE_FAILED);
            } else {
                pcap_close(pcap_g.pcap_handle);
                pcap_g.pcap_handle = NULL;
                UnixSocketPcapFile(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
    }

    if (ConfGet("pcap-file.checksum-checks", &tmpstring) != 1) {
        pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_AUTO;
    } else {
        if (strcmp(tmpstring, "auto") == 0) {
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (strcmp(tmpstring, "yes") == 0) {
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(tmpstring, "no") == 0) {
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        }
    }
    pcap_g.checksum_mode = pcap_g.conf_checksum_mode;

    ptv->tv = tv;
    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

void ReceivePcapFileThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    if (pcap_g.conf_checksum_mode == CHECKSUM_VALIDATION_AUTO &&
            pcap_g.cnt < CHECKSUM_SAMPLE_COUNT &&
            SC_ATOMIC_GET(pcap_g.invalid_checksums)) {
        uint64_t chrate = pcap_g.cnt / SC_ATOMIC_GET(pcap_g.invalid_checksums);
        if (chrate < CHECKSUM_INVALID_RATIO)
            SCLogWarning(SC_ERR_INVALID_CHECKSUM,
                         "1/%" PRIu64 "th of packets have an invalid checksum,"
                         " consider setting pcap-file.checksum-checks variable to no"
                         " or use '-k none' option on command line.",
                         chrate);
        else
            SCLogInfo("1/%" PRIu64 "th of packets have an invalid checksum",
                      chrate);
    }
    SCLogNotice("Pcap-file module read %" PRIu32 " packets, %" PRIu64 " bytes", ptv->pkts, ptv->bytes);
    return;
}

TmEcode ReceivePcapFileThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;
    if (ptv) {
        SCFree(ptv);
    }
    SCReturnInt(TM_ECODE_OK);
}

double prev_signaled_ts = 0;

TmEcode DecodePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    double curr_ts = p->ts.tv_sec + p->ts.tv_usec / 1000.0;
    if (curr_ts < prev_signaled_ts || (curr_ts - prev_signaled_ts) > 60.0) {
        prev_signaled_ts = curr_ts;
        FlowWakeupFlowManagerThread();
    }

    /* update the engine time representation based on the timestamp
     * of the packet. */
    TimeSet(&p->ts);

    /* call the decoder */
    pcap_g.Decoder(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

#ifdef DEBUG
    BUG_ON(p->pkt_src != PKT_SRC_WIRE && p->pkt_src != PKT_SRC_FFR);
#endif

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFileThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

void PcapIncreaseInvalidChecksum()
{
    (void) SC_ATOMIC_ADD(pcap_g.invalid_checksums, 1);
}

/* eof */

