/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 *
 *  Netfilter's netfilter_log support
 */
#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "tm-queuehandlers.h"
#include "tmqh-packetpool.h"

#include "runmodes.h"
#include "util-error.h"
#include "util-device.h"
#include "util-datalink.h"

#ifndef HAVE_NFLOG
/** Handle the case where no NFLOG support is compiled in.
 *
 */

TmEcode NoNFLOGSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveNFLOGRegister (void)
{
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = NoNFLOGSupportExit;
}

void TmModuleDecodeNFLOGRegister (void)
{
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = NoNFLOGSupportExit;
}

TmEcode NoNFLOGSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NFLOG_NOSUPPORT,"Error creating thread %s: you do not have support for nflog "
           "enabled please recompile with --enable-nflog", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have NFLOG support */

#include "source-nflog.h"

TmEcode ReceiveNFLOGThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveNFLOGLoop(ThreadVars *, void *, void *);
void ReceiveNFLOGThreadExitStats(ThreadVars *, void *);

TmEcode DecodeNFLOGThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeNFLOGThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeNFLOG(ThreadVars *, Packet *, void *);

static int runmode_workers;

/* Structure to hold thread specific variables */
typedef struct NFLOGThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;

    char *data;
    int datalen;

    uint16_t group;
    uint32_t nlbufsiz;
    uint32_t nlbufsiz_max;
    uint32_t qthreshold;
    uint32_t qtimeout;

    struct nflog_handle *h;
    struct nflog_g_handle *gh;

    LiveDevice *livedev;
    int nful_overrun_warned;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
} NFLOGThreadVars;

/**
 * \brief Registration function for ReceiveNFLOG
 */
void TmModuleReceiveNFLOGRegister (void)
{
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = ReceiveNFLOGThreadInit;
    tmm_modules[TMM_RECEIVENFLOG].Func = NULL;
    tmm_modules[TMM_RECEIVENFLOG].PktAcqLoop = ReceiveNFLOGLoop;
    tmm_modules[TMM_RECEIVENFLOG].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENFLOG].ThreadExitPrintStats = ReceiveNFLOGThreadExitStats;
    tmm_modules[TMM_RECEIVENFLOG].ThreadDeinit = ReceiveNFLOGThreadDeinit;
    tmm_modules[TMM_RECEIVENFLOG].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration function for DecodeNFLOG
 */
void TmModuleDecodeNFLOGRegister (void)
{
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = DecodeNFLOGThreadInit;
    tmm_modules[TMM_DECODENFLOG].Func = DecodeNFLOG;
    tmm_modules[TMM_DECODENFLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFLOG].ThreadDeinit = DecodeNFLOGThreadDeinit;
    tmm_modules[TMM_DECODENFLOG].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief NFLOG callback function
 * This function setup a packet from a nflog message
 */
static int NFLOGCallback(struct nflog_g_handle *gh, struct nfgenmsg *msg,
                         struct nflog_data *nfa, void *data)
{
    NFLOGThreadVars *ntv = (NFLOGThreadVars *) data;
    struct nfulnl_msg_packet_hdr *ph;
    char *payload;
    int ret;

    /* grab a packet*/
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL)
        return -1;

    PKT_SET_SRC(p, PKT_SRC_WIRE);

    ph = nflog_get_msg_packet_hdr(nfa);
    if (ph != NULL) {
        p->nflog_v.hw_protocol = ph->hw_protocol;
    }

    p->nflog_v.ifi = nflog_get_indev(nfa);
    p->nflog_v.ifo = nflog_get_outdev(nfa);

    ret = nflog_get_payload(nfa, &payload);

    if (ret > 0) {
        if (ret > 65536) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "NFLOG sent too big packet");
            SET_PKT_LEN(p, 0);
        } else if (runmode_workers)
            PacketSetData(p, (uint8_t *)payload, ret);
        else
            PacketCopyData(p, (uint8_t *)payload, ret);
    } else if (ret == -1)
        SET_PKT_LEN(p, 0);

    ret = nflog_get_timestamp(nfa, &p->ts);
    if (ret != 0) {
        memset(&p->ts, 0, sizeof(struct timeval));
        gettimeofday(&p->ts, NULL);
    }

    p->datalink = DLT_RAW;

#ifdef COUNTERS
    ntv->pkts++;
    ntv->bytes += GET_PKT_LEN(p);
#endif
    (void) SC_ATOMIC_ADD(ntv->livedev->pkts, 1);

    if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
        return -1;
    }

    return 0;
}

/**
 * \brief Receives packet from a nflog group via libnetfilter_log
 * This is a setup function for recieving packets via libnetfilter_log.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the group passed from the user
 * \param data pointer gets populated with NFLOGThreadVars
 * \retvalTM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on error
 */
TmEcode ReceiveNFLOGThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    NflogGroupConfig *nflconfig = (NflogGroupConfig *)initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NFLOGThreadVars *ntv = SCMalloc(sizeof(NFLOGThreadVars));
    if (unlikely(ntv == NULL)) {
        nflconfig->DerefFunc(nflconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ntv, 0, sizeof(NFLOGThreadVars));

    ntv->tv = tv;
    ntv->group = nflconfig->group;
    ntv->nlbufsiz = nflconfig->nlbufsiz;
    ntv->nlbufsiz_max = nflconfig->nlbufsiz_max;
    ntv->qthreshold = nflconfig->qthreshold;
    ntv->qtimeout = nflconfig->qtimeout;
    ntv->nful_overrun_warned = nflconfig->nful_overrun_warned;

    ntv->h = nflog_open();
    if (ntv->h == NULL) {
        SCLogError(SC_ERR_NFLOG_OPEN, "nflog_open() failed");
        SCFree(ntv);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("binding netfilter_log as nflog handler for AF_INET and AF_INET6");

    if (nflog_bind_pf(ntv->h, AF_INET) < 0) {
        FatalError(SC_ERR_FATAL, "nflog_bind_pf() for AF_INET failed");
    }
    if (nflog_bind_pf(ntv->h, AF_INET6) < 0) {
        FatalError(SC_ERR_FATAL, "nflog_bind_pf() for AF_INET6 failed");
    }

    ntv->gh = nflog_bind_group(ntv->h, ntv->group);
    if (!ntv->gh) {
        SCLogError(SC_ERR_NFLOG_OPEN, "nflog_bind_group() failed");
        SCFree(ntv);
        return TM_ECODE_FAILED;
    }

    if (nflog_set_mode(ntv->gh, NFULNL_COPY_PACKET, 0xFFFF) < 0) {
        SCLogError(SC_ERR_NFLOG_SET_MODE, "can't set packet_copy mode");
        SCFree(ntv);
        return TM_ECODE_FAILED;
    }

    nflog_callback_register(ntv->gh, &NFLOGCallback, (void *)ntv);

    if (ntv->nlbufsiz < ntv->nlbufsiz_max)
        ntv->nlbufsiz = nfnl_rcvbufsiz(nflog_nfnlh(ntv->h), ntv->nlbufsiz);
    else {
        SCLogError(SC_ERR_NFLOG_MAX_BUFSIZ, "Maximum buffer size (%d) in NFLOG "
                                            "has been reached", ntv->nlbufsiz);
        return TM_ECODE_FAILED;
    }

    if (nflog_set_qthresh(ntv->gh, ntv->qthreshold) >= 0)
        SCLogDebug("NFLOG netlink queue threshold has been set to %d",
                    ntv->qthreshold);
    else
        SCLogDebug("NFLOG netlink queue threshold can't be set to %d",
                    ntv->qthreshold);

    if (nflog_set_timeout(ntv->gh, ntv->qtimeout) >= 0)
        SCLogDebug("NFLOG netlink queue timeout has been set to %d",
                    ntv->qtimeout);
    else
        SCLogDebug("NFLOG netlink queue timeout can't be set to %d",
                    ntv->qtimeout);

    ntv->livedev = LiveGetDevice(nflconfig->numgroup);
    if (ntv->livedev == NULL) {
        SCLogError(SC_EINVAL, "Unable to find Live device");
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    struct timeval timev;
    timev.tv_sec = 1;
    timev.tv_usec = 0;

    int fd = nflog_fd(ntv->h);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        SCLogWarning(SC_WARN_NFLOG_SETSOCKOPT, "can't set socket "
                "timeout: %s", strerror(errno));
    }

#ifdef PACKET_STATISTICS
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
                                                       ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
                                                     ntv->tv);
#endif

    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode))
        runmode_workers = 1;
    else
        runmode_workers = 0;

#define T_DATA_SIZE 70000
    ntv->data = SCMalloc(T_DATA_SIZE);
    if (ntv->data == NULL) {
        nflconfig->DerefFunc(nflconfig);
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ntv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    DatalinkSetGlobalType(DLT_RAW);

    *data = (void *)ntv;

    nflconfig->DerefFunc(nflconfig);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief DeInit function unbind group and close nflog's handle
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLogThreadVars
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *tv, void *data)
{
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    SCLogDebug("closing nflog group %d", ntv->group);
    if (nflog_unbind_pf(ntv->h, AF_INET) < 0) {
        FatalError(SC_ERR_FATAL, "nflog_unbind_pf() for AF_INET failed");
    }

    if (nflog_unbind_pf(ntv->h, AF_INET6) < 0) {
        FatalError(SC_ERR_FATAL, "nflog_unbind_pf() for AF_INET6 failed");
    }

    if (ntv->gh) {
        nflog_unbind_group(ntv->gh);
        ntv->gh = NULL;
    }

    if (ntv->h) {
        nflog_close(ntv->h);
        ntv->h = NULL;
    }

    if (ntv->data != NULL) {
        SCFree(ntv->data);
        ntv->data = NULL;
    }
    ntv->datalen = 0;

    SCFree(ntv);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Increases netlink buffer size
 *
 * This function netlink's buffer size until
 * the max buffer size is reached
 *
 * \param data pointer that gets cast into NFLOGThreadVars
 * \param size netlink buffer size
 */
static int NFLOGSetnlbufsiz(void *data, unsigned int size)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    if (size < ntv->nlbufsiz_max) {
        ntv->nlbufsiz = nfnl_rcvbufsiz(nflog_nfnlh(ntv->h), ntv->nlbufsiz);
        return 1;
    }

    SCLogWarning(SC_WARN_NFLOG_MAXBUFSIZ_REACHED,
                 "Maximum buffer size (%d) in NFLOG has been "
                 "reached. Please, consider raising "
                 "`buffer-size` and `max-size` in nflog configuration",
                 ntv->nlbufsiz);
    return 0;

}

/**
 * \brief Recieves packets from a group via libnetfilter_log.
 *
 *  This function recieves packets from a group and passes
 *  the packet on to the nflog callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLOGThreadVars
 * \param slot slot containing task information
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode ReceiveNFLOGLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;
    int rv, fd;
    int ret = -1;

    ntv->slot = ((TmSlot *) slot)->slot_next;

    fd = nflog_fd(ntv->h);
    if (fd < 0) {
        SCLogError(SC_ERR_NFLOG_FD, "Can't obtain a file descriptor");
        SCReturnInt(TM_ECODE_FAILED);
    }

    while (1) {
        if (suricata_ctl_flags != 0)
            break;

        rv = recv(fd, ntv->data, ntv->datalen, 0);
        if (rv < 0) {
            /*We received an error on socket read */
            if (errno == EINTR || errno == EWOULDBLOCK) {
                /*Nothing for us to process */
                continue;
            } else if (errno == ENOBUFS) {
                if (!ntv->nful_overrun_warned) {
                    int s = ntv->nlbufsiz * 2;
                    if (NFLOGSetnlbufsiz((void *)ntv, s)) {
                        SCLogWarning(SC_WARN_NFLOG_LOSING_EVENTS,
                                "We are losing events, "
                                "increasing buffer size "
                                "to %d", ntv->nlbufsiz);
                    } else {
                        ntv->nful_overrun_warned = 1;
                    }
                }
                continue;
            } else {
                SCLogWarning(SC_WARN_NFLOG_RECV,
                             "Read from NFLOG fd failed: %s",
                             strerror(errno));
                SCReturnInt(TM_ECODE_FAILED);
            }
        }

        ret = nflog_handle_packet(ntv->h, ntv->data, rv);
        if (ret != 0)
            SCLogWarning(SC_ERR_NFLOG_HANDLE_PKT,
                         "nflog_handle_packet error %" PRId32 "", ret);

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NFLOGThreadVars
 */
void ReceiveNFLOGThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    SCLogNotice("(%s) Pkts %" PRIu32 ", Bytes %" PRIu64 "",
                 tv->name, ntv->pkts, ntv->bytes);
}


/**
 * \brief Decode IPv4/v6 packets.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into NFLOGThreadVars for ptv
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodeNFLOG(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    DecodeUpdatePacketCounters(tv, dtv, p);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else {
        SCLogDebug("packet unsupported by NFLOG, first byte: %02x", *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This an Init function for DecodeNFLOG
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to initilization data.
 * \param data pointer that gets cast into NFLOGThreadVars
 * \retval TM_ECODE_OK is returned on success
 * \retval TM_ECODE_FAILED is returned on error
 */
TmEcode DecodeNFLOGThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeNFLOGThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* NFLOG */
