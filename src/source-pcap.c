/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "util-bpf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-datalink.h"
#include "util-device.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "util-time.h"
#include "tmqh-packetpool.h"

#define PCAP_STATE_DOWN 0
#define PCAP_STATE_UP 1

#define PCAP_RECONNECT_TIMEOUT 500000

/**
 * \brief 64bit pcap stats counters.
 *
 * libpcap only supports 32bit counters. They will eventually wrap around.
 *
 * Keep track of libpcap counters as 64bit counters to keep on counting even
 * if libpcap's 32bit counters wrap around.
 * Requires pcap_stats() to be called before 32bit stats wrap around twice,
 * which we do.
 */
typedef struct PcapStats64_ {
    uint64_t ps_recv;
    uint64_t ps_drop;
    uint64_t ps_ifdrop;
} PcapStats64;

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
    /* ptr to string from config */
    const char *bpf_filter;

    time_t last_stats_dump;

    /* data link type for the thread */
    int datalink;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
    uint16_t capture_kernel_ifdrops;

    ThreadVars *tv;
    TmSlot *slot;
    DecodeThreadVars *dtv;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    /* pcap buffer size */
    int pcap_buffer_size;
    int pcap_snaplen;
    int promisc;

    ChecksumValidationMode checksum_mode;

    LiveDevice *livedev;

    PcapStats64 last_stats64;
} PcapThreadVars;

static TmEcode ReceivePcapThreadInit(ThreadVars *, const void *, void **);
static TmEcode ReceivePcapThreadDeinit(ThreadVars *tv, void *data);
static void ReceivePcapThreadExitStats(ThreadVars *, void *);
static TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot);
static TmEcode ReceivePcapBreakLoop(ThreadVars *tv, void *data);

#ifdef UNITTESTS
static void SourcePcapRegisterTests(void);
#endif

/** protect pcap_compile and pcap_setfilter, as they are not thread safe:
 *  http://seclists.org/tcpdump/2009/q1/62 */
static SCMutex pcap_bpf_compile_lock = SCMUTEX_INITIALIZER;

/**
 * \brief Registration Function for ReceivePcap.
 */
void TmModuleReceivePcapRegister (void)
{
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceivePcap";
    tmm_modules[TMM_RECEIVEPCAP].ThreadInit = ReceivePcapThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].ThreadDeinit = ReceivePcapThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqLoop = ReceivePcapLoop;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqBreakLoop = ReceivePcapBreakLoop;
    tmm_modules[TMM_RECEIVEPCAP].ThreadExitPrintStats = ReceivePcapThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEPCAP].flags = TM_FLAG_RECEIVE_TM;
#ifdef UNITTESTS
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = SourcePcapRegisterTests;
#endif
}

/**
 * \brief Update 64 bit |last| value from |current32| value taking one
 * wrap-around into account.
 */
static inline void UpdatePcapStatsValue64(uint64_t *last, uint32_t current32)
{
    /* uint64_t -> uint32_t is defined behaviour. It slices lower 32bits. */
    uint32_t last32 = *last;

    /* Branchless code as wrap-around is defined for unsigned */
    *last += (uint32_t)(current32 - last32);

    /* Same calculation as:
    if (likely(current32 >= last32)) {
        *last += current32 - last32;
    } else {
        *last += (1ull << 32) + current32 - last32;
    }
    */
}

/**
 * \brief Update 64 bit |last| stat values with values from |current|
 * 32 bit pcap_stat.
 */
static inline void UpdatePcapStats64(
        PcapStats64 *last, const struct pcap_stat *current)
{
    UpdatePcapStatsValue64(&last->ps_recv, current->ps_recv);
    UpdatePcapStatsValue64(&last->ps_drop, current->ps_drop);
    UpdatePcapStatsValue64(&last->ps_ifdrop, current->ps_ifdrop);
}

static inline void PcapDumpCounters(PcapThreadVars *ptv)
{
    struct pcap_stat pcap_s;
    if (likely((pcap_stats(ptv->pcap_handle, &pcap_s) >= 0))) {
        UpdatePcapStats64(&ptv->last_stats64, &pcap_s);

        StatsSetUI64(ptv->tv, ptv->capture_kernel_packets,
                ptv->last_stats64.ps_recv);
        StatsSetUI64(
                ptv->tv, ptv->capture_kernel_drops, ptv->last_stats64.ps_drop);
        (void)SC_ATOMIC_SET(ptv->livedev->drop, ptv->last_stats64.ps_drop);
        StatsSetUI64(ptv->tv, ptv->capture_kernel_ifdrops,
                ptv->last_stats64.ps_ifdrop);
    }
}

static int PcapOpenInterface(PcapThreadVars *ptv)
{
    const char *iface = ptv->livedev->dev;

    if (ptv->pcap_handle) {
        pcap_close(ptv->pcap_handle);
        ptv->pcap_handle = NULL;
        if (ptv->filter.bf_insns) {
            SCBPFFree(&ptv->filter);
        }
    }

    if (LiveGetOffload() == 0) {
        (void)GetIfaceOffloading(iface, 1, 1);
    } else {
        DisableIfaceOffloading(ptv->livedev, 1, 1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create(iface, errbuf);
    if (ptv->pcap_handle == NULL) {
        if (strlen(errbuf)) {
            SCLogError("%s: could not create a new pcap handler, error %s", iface, errbuf);
        } else {
            SCLogError("%s: could not create a new pcap handler", iface);
        }
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (ptv->pcap_snaplen > 0) {
        /* set Snaplen. Must be called before pcap_activate */
        int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle, ptv->pcap_snaplen);
        if (pcap_set_snaplen_r != 0) {
            SCLogError(
                    "%s: could not set snaplen, error: %s", iface, pcap_geterr(ptv->pcap_handle));
            SCReturnInt(TM_ECODE_FAILED);
        }
        SCLogInfo("%s: snaplen set to %d", iface, ptv->pcap_snaplen);
    }

    if (ptv->promisc) {
        /* set Promisc, and Timeout. Must be called before pcap_activate */
        int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle, ptv->promisc);
        if (pcap_set_promisc_r != 0) {
            SCLogError("%s: could not set promisc mode, error %s", iface,
                    pcap_geterr(ptv->pcap_handle));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle, LIBPCAP_COPYWAIT);
    if (pcap_set_timeout_r != 0) {
        SCLogError("%s: could not set timeout, error %s", iface, pcap_geterr(ptv->pcap_handle));
        SCReturnInt(TM_ECODE_FAILED);
    }
#ifdef HAVE_PCAP_SET_BUFF
    if (ptv->pcap_buffer_size > 0) {
        SCLogInfo("%s: going to use pcap buffer size of %" PRId32, iface, ptv->pcap_buffer_size);

        int pcap_set_buffer_size_r = pcap_set_buffer_size(ptv->pcap_handle, ptv->pcap_buffer_size);
        if (pcap_set_buffer_size_r != 0) {
            SCLogError("%s: could not set pcap buffer size, error %s", iface,
                    pcap_geterr(ptv->pcap_handle));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }
#endif /* HAVE_PCAP_SET_BUFF */

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    if (pcap_activate_r != 0) {
        SCLogError("%s: could not activate the pcap handler, error %s", iface,
                pcap_geterr(ptv->pcap_handle));
        pcap_close(ptv->pcap_handle);
        ptv->pcap_handle = NULL;
        SCReturnInt(TM_ECODE_FAILED);
    }
    ptv->pcap_state = PCAP_STATE_UP;

    /* set bpf filter if we have one */
    if (ptv->bpf_filter) {
        SCMutexLock(&pcap_bpf_compile_lock);

        if (pcap_compile(ptv->pcap_handle, &ptv->filter, (char *)ptv->bpf_filter, 1, 0) < 0) {
            SCLogError("%s: bpf compilation error %s", iface, pcap_geterr(ptv->pcap_handle));
            SCMutexUnlock(&pcap_bpf_compile_lock);
            return TM_ECODE_FAILED;
        }

        if (pcap_setfilter(ptv->pcap_handle, &ptv->filter) < 0) {
            SCLogError("%s: could not set bpf filter %s", iface, pcap_geterr(ptv->pcap_handle));
            SCMutexUnlock(&pcap_bpf_compile_lock);
            return TM_ECODE_FAILED;
        }

        SCMutexUnlock(&pcap_bpf_compile_lock);
    }

    /* no offloading supported at all */
    (void)GetIfaceOffloading(iface, 1, 1);
    return TM_ECODE_OK;
}

static int PcapTryReopen(PcapThreadVars *ptv)
{
    ptv->pcap_state = PCAP_STATE_DOWN;

    if (PcapOpenInterface(ptv) != TM_ECODE_OK)
        return -1;

    SCLogInfo("%s: interface recovered, state is now \"up\"", ptv->livedev->dev);
    ptv->pcap_state = PCAP_STATE_UP;
    return 0;
}

static void PcapCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();

    PcapThreadVars *ptv = (PcapThreadVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = SCTIME_FROM_TIMEVAL(&h->ts);
    SCLogDebug("p->ts.tv_sec %" PRIuMAX "", (uintmax_t)SCTIME_SECS(p->ts));
    p->datalink = ptv->datalink;

    ptv->pkts++;
    ptv->bytes += h->caplen;
    (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
    p->livedev = ptv->livedev;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturn;
    }

    switch (ptv->checksum_mode) {
        case CHECKSUM_VALIDATION_AUTO:
            if (ChecksumAutoModeCheck(ptv->pkts,
                        SC_ATOMIC_GET(ptv->livedev->pkts),
                        SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        case CHECKSUM_VALIDATION_DISABLE:
            p->flags |= PKT_IGNORE_CHECKSUM;
            break;
        default:
            break;
    }

    /* update counters */
    DecodeUpdatePacketCounters(ptv->tv, ptv->dtv, p);

    DecodeLinkLayer(ptv->tv, ptv->dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(ptv->tv, ptv->dtv, p);

    if (TmThreadsProcessDecodePseudoPackets(ptv->tv, &ptv->dtv->decode_pq, ptv->slot) !=
            TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
        SCReturn;
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
    }

    /* Trigger one dump of stats every second */
    SCTime_t current_time = TimeGet();
    if ((time_t)SCTIME_SECS(current_time) != ptv->last_stats_dump) {
        PcapDumpCounters(ptv);
        ptv->last_stats_dump = SCTIME_SECS(current_time);
    }

    SCReturn;
}

#ifndef PCAP_ERROR_BREAK
#define PCAP_ERROR_BREAK -2
#endif

/**
 *  \brief Main PCAP reading Loop function
 */
static TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int packet_q_len = 64;
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        int r = pcap_dispatch(ptv->pcap_handle, packet_q_len,
                          (pcap_handler)PcapCallbackLoop, (u_char *)ptv);
        if (unlikely(r == 0 || r == PCAP_ERROR_BREAK || (r > 0 && r < packet_q_len))) {
            if (r == PCAP_ERROR_BREAK && ptv->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            TmThreadsCaptureHandleTimeout(tv, NULL);
        } else if (unlikely(r < 0)) {
            int dbreak = 0;
            SCLogError("error code %" PRId32 " %s", r, pcap_geterr(ptv->pcap_handle));
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
            SCLogError("Pcap callback PcapCallbackLoop failed");
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    PcapDumpCounters(ptv);
    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief PCAP Break Loop function.
 */
static TmEcode ReceivePcapBreakLoop(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    if (ptv->pcap_handle == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    pcap_breakloop(ptv->pcap_handle);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceivePcap.
 *
 * This is a setup function for receiving packets
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
static TmEcode ReceivePcapThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    PcapIfaceConfig *pcapconfig = (PcapIfaceConfig *)initdata;

    if (initdata == NULL) {
        SCLogError("initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCCalloc(1, sizeof(PcapThreadVars));
    if (unlikely(ptv == NULL)) {
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->tv = tv;

    ptv->dtv = DecodeThreadVarsAlloc(tv);
    if (ptv->dtv == NULL) {
        pcapconfig->DerefFunc(pcapconfig);
        ReceivePcapThreadDeinit(tv, ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    DecodeRegisterPerfCounters(ptv->dtv, tv);

    ptv->livedev = LiveGetDevice(pcapconfig->iface);
    if (ptv->livedev == NULL) {
        SCLogError("unable to find Live device");
        ReceivePcapThreadDeinit(tv, ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (LiveGetOffload() == 0) {
        (void)GetIfaceOffloading((char *)pcapconfig->iface, 1, 1);
    } else {
        DisableIfaceOffloading(ptv->livedev, 1, 1);
    }

    ptv->checksum_mode = pcapconfig->checksum_mode;
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        SCLogInfo("%s: running in 'auto' checksum mode. Detection of interface "
                  "state will require %llu packets",
                ptv->livedev->dev, CHECKSUM_SAMPLE_COUNT);
    }

    if (pcapconfig->snaplen == 0) {
        /* We set snaplen if we can get the MTU */
        ptv->pcap_snaplen = GetIfaceMaxPacketSize(ptv->livedev);
    } else {
        ptv->pcap_snaplen = pcapconfig->snaplen;
    }

    ptv->promisc = pcapconfig->promisc;
    ptv->pcap_buffer_size = pcapconfig->buffer_size;
    ptv->bpf_filter = pcapconfig->bpf_filter;

    if (PcapOpenInterface(ptv) != TM_ECODE_OK) {
        ReceivePcapThreadDeinit(tv, ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    ptv->pcap_state = PCAP_STATE_UP;

    ptv->datalink = pcap_datalink(ptv->pcap_handle);
    DatalinkSetGlobalType(ptv->datalink);

    pcapconfig->DerefFunc(pcapconfig);

    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
    ptv->capture_kernel_ifdrops = StatsRegisterCounter("capture.kernel_ifdrops",
            ptv->tv);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
static void ReceivePcapThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    struct pcap_stat pcap_s;

    if (pcap_stats(ptv->pcap_handle, &pcap_s) < 0) {
        SCLogError("%s: failed to get pcap_stats: %s", ptv->livedev->dev,
                pcap_geterr(ptv->pcap_handle));
        SCLogInfo("%s: packets %" PRIu64 ", bytes %" PRIu64 "", ptv->livedev->dev, ptv->pkts,
                ptv->bytes);
    } else {
        SCLogInfo("%s: packets %" PRIu64 ", bytes %" PRIu64 "", ptv->livedev->dev, ptv->pkts,
                ptv->bytes);

        /* these numbers are not entirely accurate as ps_recv contains packets
         * that are still waiting to be processed at exit. ps_drop only contains
         * packets dropped by the driver and not any packets dropped by the interface.
         * Additionally see http://tracker.icir.org/bro/ticket/18
         *
         * Note: ps_recv includes dropped packets and should be considered total.
         * Unless we start to look at ps_ifdrop which isn't supported everywhere.
         */
        UpdatePcapStats64(&ptv->last_stats64, &pcap_s);
        float drop_percent =
                likely(ptv->last_stats64.ps_recv > 0)
                        ? (((float)ptv->last_stats64.ps_drop) /
                                  (float)ptv->last_stats64.ps_recv) *
                                  100
                        : 0;
        SCLogInfo("%s: pcap total:%" PRIu64 " recv:%" PRIu64 " drop:%" PRIu64 " (%02.1f%%)",
                ptv->livedev->dev, ptv->last_stats64.ps_recv,
                ptv->last_stats64.ps_recv - ptv->last_stats64.ps_drop, ptv->last_stats64.ps_drop,
                drop_percent);
    }
}

static TmEcode ReceivePcapThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    if (ptv != NULL) {
        if (ptv->pcap_handle != NULL) {
            pcap_close(ptv->pcap_handle);
        }
        if (ptv->filter.bf_insns) {
            SCBPFFree(&ptv->filter);
        }
        DecodeThreadVarsFree(tv, ptv->dtv);
        SCFree(ptv);
    }
    SCReturnInt(TM_ECODE_OK);
}

void PcapTranslateIPToDevice(char *pcap_dev, size_t len)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp = NULL;

    struct addrinfo ai_hints;
    struct addrinfo *ai_list = NULL;

    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_flags = AI_NUMERICHOST;

    /* try to translate IP */
    if (getaddrinfo(pcap_dev, NULL, &ai_hints, &ai_list) != 0) {
        return;
    }

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        freeaddrinfo(ai_list);
        return;
    }

    for (pcap_if_t *devsp = alldevsp; devsp ; devsp = devsp->next) {
        for (pcap_addr_t *ip = devsp->addresses; ip ; ip = ip->next) {

            if (ai_list->ai_family != ip->addr->sa_family) {
                continue;
            }

            if (ip->addr->sa_family == AF_INET) {
                if (memcmp(&((struct sockaddr_in*)ai_list->ai_addr)->sin_addr,
                            &((struct sockaddr_in*)ip->addr)->sin_addr,
                            sizeof(struct in_addr)))
                {
                    continue;
                }
            } else if (ip->addr->sa_family == AF_INET6) {
                if (memcmp(&((struct sockaddr_in6*)ai_list->ai_addr)->sin6_addr,
                            &((struct sockaddr_in6*)ip->addr)->sin6_addr,
                            sizeof(struct in6_addr)))
                {
                    continue;
                }
            } else {
                continue;
            }

            freeaddrinfo(ai_list);

            memset(pcap_dev, 0, len);
            strlcpy(pcap_dev, devsp->name, len);

            pcap_freealldevs(alldevsp);
            return;
        }
    }

    freeaddrinfo(ai_list);

    pcap_freealldevs(alldevsp);
}

/*
 *  unittests
 */

#ifdef UNITTESTS
#include "tests/source-pcap.c"
/**
 *  \brief  Register the Unit tests for pcap source
 */
static void SourcePcapRegisterTests(void)
{
    SourcePcapRegisterStatsTests();
}
#endif /* UNITTESTS */
