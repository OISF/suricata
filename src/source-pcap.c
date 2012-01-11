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
 * Live pcap packet acquisition support
 */

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
#include "tm-threads.h"
#include "source-pcap.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "tmqh-packetpool.h"

extern uint8_t suricata_ctl_flags;

#define PCAP_STATE_DOWN 0
#define PCAP_STATE_UP 1

#define PCAP_RECONNECT_TIMEOUT 500000

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PcapThreadVars_
{
    /* thread specific handle */
    pcap_t *pcap_handle;
    /* handle state */
    unsigned char pcap_state;
    /* thread specific bpf */
    struct bpf_program filter;
    char *bpf_filter;

    /* data link type for the thread */
    int datalink;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    /* pcap buffer size */
    int pcap_buffer_size;

    ChecksumValidationMode checksum_mode;

#if LIBPCAP_VERSION_MAJOR == 0
    char iface[PCAP_IFACE_NAME_LENGTH];
#endif
    LiveDevice *livedev;
} PcapThreadVars;

TmEcode ReceivePcapThreadInit(ThreadVars *, void *, void **);
void ReceivePcapThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapThreadDeinit(ThreadVars *, void *);
TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodePcapThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePcap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Registration Function for RecievePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceivePcapRegister (void) {
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceivePcap";
    tmm_modules[TMM_RECEIVEPCAP].ThreadInit = ReceivePcapThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqLoop = ReceivePcapLoop;
    tmm_modules[TMM_RECEIVEPCAP].ThreadExitPrintStats = ReceivePcapThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEPCAP].flags = TM_FLAG_RECEIVE_TM;
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
    tmm_modules[TMM_DECODEPCAP].cap_flags = 0;
}

#if LIBPCAP_VERSION_MAJOR == 1
static int PcapTryReopen(PcapThreadVars *ptv)
{
    int pcap_activate_r;

    ptv->pcap_state = PCAP_STATE_DOWN;
    pcap_activate_r = pcap_activate(ptv->pcap_handle);
    if (pcap_activate_r != 0) {
        return pcap_activate_r;
    }
    /* set bpf filter if we have one */
    if (ptv->bpf_filter != NULL) {
        if(pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }
    }

    SCLogInfo("Recovering interface listening");
    ptv->pcap_state = PCAP_STATE_UP;
    return 0;
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
static int PcapTryReopen(PcapThreadVars *ptv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    ptv->pcap_state = PCAP_STATE_DOWN;
    pcap_close(ptv->pcap_handle);

    ptv->pcap_handle = pcap_open_live((char *)ptv->iface, LIBPCAP_SNAPLEN,
            LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_LIVE, "Problem creating pcap handler for live mode, error %s", errbuf);
        return -1;
    }

    /* set bpf filter if we have one */
    if (ptv->bpf_filter != NULL) {
        SCLogInfo("using bpf-filter \"%s\"", ptv->bpf_filter);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }
    }

    SCLogInfo("Recovering interface listening");
    ptv->pcap_state = PCAP_STATE_UP;
    return 0;
}

#endif

void PcapCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt) {
    SCEnter();

    PcapThreadVars *ptv = (PcapThreadVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }

    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = ptv->datalink;

    ptv->pkts++;
    ptv->bytes += h->caplen;
    SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
    p->livedev = ptv->livedev;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturn;
    }

    switch (ptv->checksum_mode) {
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
        case CHECKSUM_VALIDATION_DISABLE:
            p->flags |= PKT_IGNORE_CHECKSUM;
            break;
        default:
            break;
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
    }

    SCReturn;
}

/**
 *  \brief Main PCAP reading Loop function
 */
TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot)
{
    uint16_t packet_q_len = 0;
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;
    int r;

    SCEnter();

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP ||
            suricata_ctl_flags & SURICATA_KILL)
        {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        /* Right now we just support reading packets one at a time. */
        r = pcap_dispatch(ptv->pcap_handle, (int)packet_q_len,
                (pcap_handler)PcapCallbackLoop, (u_char *)ptv);
        if (unlikely(r < 0)) {
            int dbreak = 0;
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                    r, pcap_geterr(ptv->pcap_handle));
            do {
                usleep(PCAP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = PcapTryReopen(ptv);
            } while (r < 0);
            if (dbreak) {
                break;
            }
        } else if (ptv->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "Pcap callback PcapCallbackLoop failed");
            SCReturnInt(TM_ECODE_FAILED);
        }

        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceivePcap.
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
    PcapIfaceConfig *pcapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    ptv->livedev = LiveGetDevice(pcapconfig->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("using interface %s", (char *)pcapconfig->iface);

    ptv->checksum_mode = pcapconfig->checksum_mode;
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        SCLogInfo("Running in 'auto' checksum mode. Detection of interface state will require "
                  xstr(CHECKSUM_SAMPLE_COUNT) " packets.");
    }

    /* XXX create a general pcap setup function */
    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create((char *)pcapconfig->iface, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_CREATE, "Couldn't create a new pcap handler, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set Snaplen, Promisc, and Timeout. Must be called before pcap_activate */
    int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle,LIBPCAP_SNAPLEN);
    //printf("ReceivePcapThreadInit: pcap_set_snaplen(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_snaplen_r);
    if (pcap_set_snaplen_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_SNAPLEN, "Couldn't set snaplen, error: %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle,LIBPCAP_PROMISC);
    //printf("ReceivePcapThreadInit: pcap_set_promisc(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_promisc_r);
    if (pcap_set_promisc_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_PROMISC, "Couldn't set promisc mode, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle,LIBPCAP_COPYWAIT);
    //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_timeout_r);
    if (pcap_set_timeout_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_TIMEOUT, "Problems setting timeout, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
#ifdef HAVE_PCAP_SET_BUFF
    ptv->pcap_buffer_size = pcapconfig->buffer_size;
    if (ptv->pcap_buffer_size >= 0 && ptv->pcap_buffer_size <= INT_MAX) {
        if (ptv->pcap_buffer_size > 0)
            SCLogInfo("Going to use pcap buffer size of %" PRId32 "", ptv->pcap_buffer_size);

        int pcap_set_buffer_size_r = pcap_set_buffer_size(ptv->pcap_handle,ptv->pcap_buffer_size);
        //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_buffer_size_r);
        if (pcap_set_buffer_size_r != 0) {
            SCLogError(SC_ERR_PCAP_SET_BUFF_SIZE, "Problems setting pcap buffer size, error %s", pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }
#endif /* HAVE_PCAP_SET_BUFF */

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    //printf("ReceivePcapThreadInit: pcap_activate(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_activate_r);
    if (pcap_activate_r != 0) {
        SCLogError(SC_ERR_PCAP_ACTIVATE_HANDLE, "Couldn't activate the pcap handler, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
        ptv->pcap_state = PCAP_STATE_DOWN;
    } else {
        ptv->pcap_state = PCAP_STATE_UP;
    }

    /* set bpf filter if we have one */
    if (pcapconfig->bpf_filter) {
        ptv->bpf_filter = SCStrdup(pcapconfig->bpf_filter);
        /* free bpf as we are using a copy */
        SCFree(pcapconfig->bpf_filter);
        if(pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    pcapconfig->DerefFunc(pcapconfig);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();
    PcapIfaceConfig *pcapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (ptv == NULL) {
        /* Dereference config */
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    ptv->livedev = LiveGetDevice(pcapconfig->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("using interface %s", (char *)initdata);
    if(strlen(initdata)>PCAP_IFACE_NAME_LENGTH) {
        SCFree(ptv);
        /* Dereference config */
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    strlcpy(ptv->iface, (char *)initdata, PCAP_IFACE_NAME_LENGTH);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ptv->pcap_handle = pcap_open_live((char *)initdata, LIBPCAP_SNAPLEN,
                                        LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_LIVE, "Problem creating pcap handler for live mode, error %s", errbuf);
        SCFree(ptv);
        /* Dereference config */
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set bpf filter if we have one */
    if (pcapconfig->bpf_filter) {
        ptv->bpf_filter = SCStrdup(pcapconfig->bpf_filter);
        SCLogInfo("using bpf-filter \"%s\"", ptv->bpf_filter);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter, ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            /* Dereference config */
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            /* Dereference config */
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    *data = (void *)ptv;
    /* Dereference config */
    pcapconfig->DerefFunc(pcapconfig);
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
        * Additionally see http://tracker.icir.org/bro/ticket/18
        *
        * Note: ps_recv includes dropped packets and should be considered total.
        * Unless we start to look at ps_ifdrop which isn't supported everywhere.
        */
        SCLogInfo("(%s) Pcap Total:%" PRIu64 " Recv:%" PRIu64 " Drop:%" PRIu64 " (%02.1f%%).", tv->name,
        (uint64_t)pcap_s.ps_recv, (uint64_t)pcap_s.ps_recv - (uint64_t)pcap_s.ps_drop, (uint64_t)pcap_s.ps_drop,
        (((float)(uint64_t)pcap_s.ps_drop)/(float)(uint64_t)pcap_s.ps_recv)*100);

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

    if (ptv->bpf_filter) {
        SCFree(ptv->bpf_filter);
        ptv->bpf_filter = NULL;
    }
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
TmEcode DecodePcap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
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

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

void PcapTranslateIPToDevice(char *pcap_dev, size_t len)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp = NULL;
    pcap_if_t *devsp = NULL;

    struct addrinfo aiHints;
    struct addrinfo *aiList = NULL;
    int retVal = 0;

    memset(&aiHints, 0, sizeof(aiHints));
    aiHints.ai_family = AF_UNSPEC;
    aiHints.ai_flags = AI_NUMERICHOST;

    /* try to translate IP */
    if ((retVal = getaddrinfo(pcap_dev, NULL, &aiHints, &aiList)) != 0) {
        return;
    }

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        freeaddrinfo(aiList);
        return;
    }

    for (devsp = alldevsp; devsp ; devsp = devsp->next) {
        pcap_addr_t *ip = NULL;

        for (ip = devsp->addresses; ip ; ip = ip->next) {

            if (aiList->ai_family != ip->addr->sa_family) {
                continue;
            }

            if (ip->addr->sa_family == AF_INET) {
                if (memcmp(&((struct sockaddr_in*)aiList->ai_addr)->sin_addr, &((struct sockaddr_in*)ip->addr)->sin_addr, sizeof(struct in_addr))) {
                    continue;
                }
            } else if (ip->addr->sa_family == AF_INET6) {
                if (memcmp(&((struct sockaddr_in6*)aiList->ai_addr)->sin6_addr, &((struct sockaddr_in6*)ip->addr)->sin6_addr, sizeof(struct in6_addr))) {
                    continue;
                }
            } else {
                continue;
            }

            freeaddrinfo(aiList);

            memset(pcap_dev, 0, len);
            strlcpy(pcap_dev, devsp->name, len);

            pcap_freealldevs(alldevsp);
            return;
        }
    }

    freeaddrinfo(aiList);

    pcap_freealldevs(alldevsp);
}

/* eof */

