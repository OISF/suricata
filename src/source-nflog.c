/* Copyright (C) 2013 Open Information Security Foundation
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

#ifndef HAVE_NFLOG
/** Handle the case where no NFLOG support is compiled in.
 *
 */

TmEcode NoNFLOGSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveNFLOGRegister (void) {
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = NoNFLOGSupportExit;
    tmm_modules[TMM_RECEIVENFLOG].Func = NULL;
    tmm_modules[TMM_RECEIVENFLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENFLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFLOG].cap_flags = SC_CAP_NET_ADMIN;
    tmm_modules[TMM_RECEIVENFLOG].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodeNFLOGRegister (void) {
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = NoNFLOGSupportExit;
    tmm_modules[TMM_DECODENFLOG].Func = NULL;
    tmm_modules[TMM_DECODENFLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFLOG].cap_flags = 0;
    tmm_modules[TMM_DECODENFLOG].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNFLOGSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NFLOG_NOSUPPORT,"Error creating thread %s: you do not have support for nflog "
           "enabled please recompile with --enable-nflog", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have NFLOG support */

#include "source-nflog.h"

TmEcode ReceiveNFLOGThreadInit(ThreadVars *, void *, void **);
TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveNFLOGLoop(ThreadVars *, void *, void *);
void ReceiveNFLOGThreadExitStats(ThreadVars *, void *);

TmEcode DecodeNFLOGThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeNFLOG(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

static int runmode_workers;

typedef struct NFLOGThreadVars_ {
    uint64_t bytes;
    uint64_t pkts;

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
} NFLOGThreadVars;

void TmModuleReceiveNFLOGRegister (void)
{
    tmm_modules[TMM_RECEIVENFLOG].name = "ReceiveNFLOG";
    tmm_modules[TMM_RECEIVENFLOG].ThreadInit = ReceiveNFLOGThreadInit;
    tmm_modules[TMM_RECEIVENFLOG].Func = NULL;
    tmm_modules[TMM_RECEIVENFLOG].PktAcqLoop = ReceiveNFLOGLoop;
    tmm_modules[TMM_RECEIVENFLOG].ThreadExitPrintStats = ReceiveNFLOGThreadExitStats;
    tmm_modules[TMM_RECEIVENFLOG].ThreadDeinit = ReceiveNFLOGThreadDeinit;
    tmm_modules[TMM_RECEIVENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFLOG].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodeNFLOGRegister (void)
{
    tmm_modules[TMM_DECODENFLOG].name = "DecodeNFLOG";
    tmm_modules[TMM_DECODENFLOG].ThreadInit = DecodeNFLOGThreadInit;
    tmm_modules[TMM_DECODENFLOG].Func = DecodeNFLOG;
    tmm_modules[TMM_DECODENFLOG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFLOG].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENFLOG].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFLOG].flags = TM_FLAG_DECODE_TM;
}

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

    return 0;
}

TmEcode ReceiveNFLOGThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    NflogGroupConfig *nflconfig = initdata;
    NFLOGThreadVars *ntv = SCMalloc(sizeof(NFLOGThreadVars));

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (unlikely(ntv == NULL)) {
        nflconfig->DerefFunc(nflconfig); 
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ntv, 0, sizeof(NFLOGThreadVars));

    ntv->tv = tv;
    ntv->group = nflconfig->group;

    ntv->h = nflog_open();
    if (!ntv->h) {
        SCLogError(SC_ERR_NFLOG_OPEN, "nflog_open() failed");
        return TM_ECODE_FAILED;
    }

    SCLogDebug("binding netfilter_log as nflog handler for AF_INET and AF_INET6");
 
    if (nflog_unbind_pf(ntv->h, AF_INET) < 0) {
        SCLogError(SC_ERR_NFLOG_UNBIND, "nflog_unbind_pf() for AF_INET failed");
        exit(EXIT_FAILURE);
    }

    if (nflog_unbind_pf(ntv->h, AF_INET6) < 0) {
        SCLogError(SC_ERR_NFLOG_UNBIND, "nflog_unbind_pf() for AF_INET6 failed");
        exit(EXIT_FAILURE);
    }

    if (nflog_bind_pf(ntv->h, AF_INET) < 0) {
        SCLogError(SC_ERR_NFLOG_BIND, "nflog_bind_pf() for AF_INET failed");
        exit(EXIT_FAILURE);
    }
    if (nflog_bind_pf(ntv->h, AF_INET6) < 0) {
        SCLogError(SC_ERR_NFLOG_BIND, "nflog_bind_pf() for AF_INET6 failed");
        exit(EXIT_FAILURE);
    }

    ntv->gh = nflog_bind_group(ntv->h, ntv->group);
    if (!ntv->gh) {
        SCLogError(SC_ERR_NFLOG_OPEN, "nflog_bind_group() failed");
        return TM_ECODE_FAILED;
    }

    if (nflog_set_mode(ntv->gh, NFULNL_COPY_PACKET, 0xFFFF) < 0) {
        SCLogError(SC_ERR_NFLOG_SET_MODE, "can't set packet_copy mode");
        return TM_ECODE_FAILED;
    }

    nflog_callback_register(ntv->gh, &NFLOGCallback, (void *)ntv);

    /*if (ntv->nlbufsiz < ntv->nlbufsiz_max)
        ntv->nlbufsiz = nfnl_rcvbufsiz(nflog_nfnlh(ntv->h), ntv->nlbufsiz);
    else {
        SCLogError(SC_ERR_NFLOG_MAX_BUFSIZ, "Maximum buffer size (%d) in NFLOG "
                                            "has been reached", ntv->nlbufsiz);
        return TM_ECODE_FAILED;
    }*/

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

    *data = (void *)ntv;
    
    nflconfig->DerefFunc(nflconfig);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveNFLOGThreadDeinit(ThreadVars *tv, void *data)
{
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;

    SCLogDebug("closing nflog group %d", ntv->group);
    if (ntv->gh) {
        nflog_unbind_group(ntv->gh);
        ntv->gh = NULL;
    }

    if (ntv->h) {
        nflog_close(ntv->h);
        ntv->h = NULL;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveNFLOGLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    NFLOGThreadVars *ntv = (NFLOGThreadVars *)data;
    int rv, fd;
    int ret = -1;

    fd = nflog_fd(ntv->h);

    while (1) {
        if (suricata_ctl_flags != 0)
            break;

            rv = recv(fd, ntv->data, ntv->datalen, 0);
            if (rv <= 0)
                SCReturnInt(TM_ECODE_FAILED);

            ret = nflog_handle_packet(ntv->h, ntv->data, rv);
            if (ret != 0)
                SCLogWarning(SC_ERR_NFLOG_HANDLE_PKT,
                             "nflog_handle_packet error %" PRId32 "", ret);

            SCPerfSyncCountersIfSignalled(tv);
    }
    SCReturnInt(TM_ECODE_OK);
}

void ReceiveNFLOGThreadExitStats(ThreadVars *tv, void *data)
{
    return;
}

TmEcode DecodeNFLOG(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else {
        SCLogDebug("packet unsupported by NFLOG, first byte: %02x", *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeNFLOGThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    
    SCReturnInt(TM_ECODE_OK);
}

#endif /* NFLOG */
