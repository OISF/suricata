/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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
 *  Netfilter's netfilter_queue support for reading packets from the
 *  kernel and setting verdicts back to it (inline mode).
 *  Supported on Linux and Windows.
 *
 * \todo test if Receive and Verdict if both are present
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "source-nfq.h"
#include "source-nfq-prototypes.h"
#include "action-globals.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-byte.h"
#include "util-privs.h"

#ifndef NFQ
/** Handle the case where no NFQ support is compiled in.
 *
 */

TmEcode NoNFQSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveNFQRegister (void) {
    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_RECEIVENFQ].Func = NULL;
    tmm_modules[TMM_RECEIVENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENFQ].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFQ].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleVerdictNFQRegister (void) {
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_VERDICTNFQ].Func = NULL;
    tmm_modules[TMM_VERDICTNFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTNFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTNFQ].RegisterTests = NULL;
    tmm_modules[TMM_VERDICTNFQ].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleDecodeNFQRegister (void) {
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_DECODENFQ].Func = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENFQ].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFQ].cap_flags = 0;
}

TmEcode NoNFQSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    printf("Error creating thread %s: you do not have support for nfqueue "
           "enabled please recompile with --enable-nfqueue\n", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have NFQ support */
#include <pthread.h>

extern int max_pending_packets;

#define NFQ_BURST_FACTOR 4
//#define NFQ_DFT_QUEUE_LEN NFQ_BURST_FACTOR * MAX_PENDING
//#define NFQ_NF_BUFSIZE 1500 * NFQ_DFT_QUEUE_LEN

/* shared vars for all for nfq queues and threads */
static NFQGlobalVars nfq_g;

static NFQThreadVars nfq_t[NFQ_MAX_QUEUE];
static uint16_t receive_queue_num = 0;
static uint16_t verdict_queue_num = 0;
static SCMutex nfq_init_lock;

TmEcode ReceiveNFQ(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode ReceiveNFQThreadInit(ThreadVars *, void *, void **);
void ReceiveNFQThreadExitStats(ThreadVars *, void *);

TmEcode VerdictNFQ(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode VerdictNFQThreadInit(ThreadVars *, void *, void **);
void VerdictNFQThreadExitStats(ThreadVars *, void *);
TmEcode VerdictNFQThreadDeinit(ThreadVars *, void *);

TmEcode DecodeNFQ(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode DecodeNFQThreadInit(ThreadVars *, void *, void **);

void TmModuleReceiveNFQRegister (void) {
    /* XXX create a general NFQ setup function */
    memset(&nfq_g, 0, sizeof(nfq_g));
    memset(&nfq_t, 0, sizeof(nfq_t));
    SCMutexInit(&nfq_init_lock, NULL);

    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].ThreadInit = ReceiveNFQThreadInit;
    tmm_modules[TMM_RECEIVENFQ].Func = ReceiveNFQ;
    tmm_modules[TMM_RECEIVENFQ].ThreadExitPrintStats = ReceiveNFQThreadExitStats;
    tmm_modules[TMM_RECEIVENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENFQ].RegisterTests = NULL;
}

void TmModuleVerdictNFQRegister (void) {
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].ThreadInit = VerdictNFQThreadInit;
    tmm_modules[TMM_VERDICTNFQ].Func = VerdictNFQ;
    tmm_modules[TMM_VERDICTNFQ].ThreadExitPrintStats = VerdictNFQThreadExitStats;
    tmm_modules[TMM_VERDICTNFQ].ThreadDeinit = VerdictNFQThreadDeinit;
    tmm_modules[TMM_VERDICTNFQ].RegisterTests = NULL;
}

void TmModuleDecodeNFQRegister (void) {
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].ThreadInit = DecodeNFQThreadInit;
    tmm_modules[TMM_DECODENFQ].Func = DecodeNFQ;
    tmm_modules[TMM_DECODENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENFQ].RegisterTests = NULL;
}

void NFQSetupPkt (Packet *p, void *data)
{
    struct nfq_data *tb = (struct nfq_data *)data;
    int ret;
    char *pktdata;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph != NULL) {
        p->nfq_v.id = ntohl(ph->packet_id);
        //p->nfq_v.hw_protocol = ntohs(p->nfq_v.ph->hw_protocol);
        p->nfq_v.hw_protocol = ph->hw_protocol;
    }
    p->nfq_v.mark = nfq_get_nfmark(tb);
    p->nfq_v.ifi  = nfq_get_indev(tb);
    p->nfq_v.ifo  = nfq_get_outdev(tb);

    ret = nfq_get_payload(tb, &pktdata);
    if (ret > 0) {
        /* nfq_get_payload returns a pointer to a part of memory
         * that is not preserved over the lifetime of our packet.
         * So we need to copy it. */
        if (ret > 65536) {
            /* Will not be able to copy data ! Set length to 0
             * to trigger an error in packet decoding.
             * This is unlikely to happen */
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "NFQ sent too big packet");
            p->pktlen = 0;
        } else {
            memcpy(p->pkt, pktdata, ret);
            p->pktlen = (size_t)ret;
        }
    } else if (ret ==  -1) {
        /* unable to get pointer to data, ensure packet length is zero.
         * This will trigger an error in packet decoding */
        p->pktlen = 0;
    }

    ret = nfq_get_timestamp(tb, &p->ts);
    if (ret != 0) {
        memset (&p->ts, 0, sizeof(struct timeval));
        gettimeofday(&p->ts, NULL);
    }

    p->datalink = DLT_RAW;
    return;
}

static int NFQCallBack(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    ThreadVars *tv = ntv->tv;

    /* grab a packet */
    Packet *p = tv->tmqh_in(tv);
    NFQSetupPkt(p, (void *)nfa);

#ifdef COUNTERS
    nfq_t->pkts++;
    nfq_t->bytes += p->pktlen;
#endif /* COUNTERS */

    /* pass on... */
    tv->tmqh_out(tv, p);

    return 0;
}

TmEcode NFQInitThread(NFQThreadVars *nfq_t, uint16_t queue_num, uint32_t queue_maxlen)
{
#ifndef OS_WIN32
    struct timeval tv;
#endif
    nfq_t->queue_num = queue_num;

    SCLogDebug("opening library handle");
    nfq_t->h = nfq_open();
    if (!nfq_t->h) {
        SCLogError(SC_ERR_NFQ_OPEN, "nfq_open() failed");
        return TM_ECODE_FAILED;
    }

    if (nfq_g.unbind == 0)
    {
        /* VJ: on my Ubuntu Hardy system this fails the first time it's
         * run. Ignoring the error seems to have no bad effects. */
        SCLogDebug("unbinding existing nf_queue handler for AF_INET (if any)");
        if (nfq_unbind_pf(nfq_t->h, AF_INET) < 0) {
            SCLogError(SC_ERR_NFQ_UNBIND, "nfq_unbind_pf() for AF_INET failed");
            exit(EXIT_FAILURE);
        }
        if (nfq_unbind_pf(nfq_t->h, AF_INET6) < 0) {
            SCLogError(SC_ERR_NFQ_UNBIND, "nfq_unbind_pf() for AF_INET6 failed");
            exit(EXIT_FAILURE);
        }
        nfq_g.unbind = 1;

        SCLogDebug("binding nfnetlink_queue as nf_queue handler for AF_INET and AF_INET6");

        if (nfq_bind_pf(nfq_t->h, AF_INET) < 0) {
            SCLogError(SC_ERR_NFQ_BIND, "nfq_bind_pf() for AF_INET failed");
            exit(EXIT_FAILURE);
        }
        if (nfq_bind_pf(nfq_t->h, AF_INET6) < 0) {
            SCLogError(SC_ERR_NFQ_BIND, "nfq_bind_pf() for AF_INET6 failed");
            exit(EXIT_FAILURE);
        }
    }

    SCLogInfo("binding this thread to queue '%" PRIu32 "'", nfq_t->queue_num);

    /* pass the thread memory as a void ptr so the
     * callback function has access to it. */
    nfq_t->qh = nfq_create_queue(nfq_t->h, nfq_t->queue_num, &NFQCallBack, (void *)nfq_t);
    if (nfq_t->qh == NULL)
    {
        SCLogError(SC_ERR_NFQ_CREATE_QUEUE, "nfq_create_queue failed");
        return TM_ECODE_FAILED;
    }

    SCLogDebug("setting copy_packet mode");

    /* 05DC = 1500 */
    //if (nfq_set_mode(nfq_t->qh, NFQNL_COPY_PACKET, 0x05DC) < 0) {
    if (nfq_set_mode(nfq_t->qh, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        SCLogError(SC_ERR_NFQ_SET_MODE, "can't set packet_copy mode");
        return TM_ECODE_FAILED;
    }

    /* XXX detect this at configure time & make it an option */
#define HAVE_NFQ_MAXLEN
#ifdef HAVE_NFQ_MAXLEN
    if (queue_maxlen > 0) {
        SCLogInfo("setting queue length to %" PRId32 "", queue_maxlen);

        /* non-fatal if it fails */
        if (nfq_set_queue_maxlen(nfq_t->qh, queue_maxlen) < 0) {
            SCLogWarning(SC_ERR_NFQ_MAXLEN, "can't set queue maxlen: your kernel probably "
                    "doesn't support setting the queue length");
        }
    }
#endif /* HAVE_NFQ_MAXLEN */

#ifndef OS_WIN32
    /* set netlink buffer size to a decent value */
    nfnl_rcvbufsiz(nfq_nfnlh(nfq_t->h), queue_maxlen * 1500);
    SCLogInfo("setting nfnl bufsize to %" PRId32 "", queue_maxlen * 1500);

    nfq_t->nh = nfq_nfnlh(nfq_t->h);
    nfq_t->fd = nfnl_fd(nfq_t->nh);

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if(setsockopt(nfq_t->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        SCLogWarning(SC_ERR_NFQ_SETSOCKOPT, "can't set socket timeout: %s", strerror(errno));
    }

    SCLogDebug("nfq_t->h %p, nfq_t->nh %p, nfq_t->qh %p, nfq_t->fd %" PRId32 "",
            nfq_t->h, nfq_t->nh, nfq_t->qh, nfq_t->fd);
#else /* OS_WIN32 */
    SCMutexInit(&nfq_t->mutex_qh, NULL);
    nfq_t->ovr.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    nfq_t->fd = nfq_fd(nfq_t->h);
    SCLogDebug("nfq_t->h %p, nfq_t->qh %p, nfq_t->fd %p", nfq_t->h, nfq_t->qh, nfq_t->fd);
#endif /* OS_WIN32 */

    return TM_ECODE_OK;
}

TmEcode ReceiveNFQThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCMutexLock(&nfq_init_lock);
    SCLogDebug("starting... will bind to queuenum %" PRIu32 "", receive_queue_num);

#ifndef OS_WIN32
    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
#endif /* OS_WIN32 */

    NFQThreadVars *ntv = &nfq_t[receive_queue_num];

    /* store the ThreadVars pointer in our NFQ thread context
     * as we will need it in our callback function */
    ntv->tv = tv;

    /* Extract the queue number from the specified command line argument */
    uint16_t queue_num = 0;
    if ((ByteExtractStringUint16(&queue_num, 10, strlen((char *)initdata),
                                      (char *)initdata)) < 0)
    {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified queue number %s is not "
                                        "valid", (char *)initdata);
        exit(EXIT_FAILURE);
    }

    int r = NFQInitThread(ntv, queue_num, (max_pending_packets * NFQ_BURST_FACTOR));
    if (r < 0) {
        SCLogError(SC_ERR_NFQ_THREAD_INIT, "nfq thread failed to initialize");

        SCMutexUnlock(&nfq_init_lock);
        exit(EXIT_FAILURE);
    }

    *data = (void *)ntv;
    receive_queue_num++;
    SCMutexUnlock(&nfq_init_lock);
    return TM_ECODE_OK;
}

TmEcode VerdictNFQThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCMutexLock(&nfq_init_lock);
    SCLogDebug("starting... will bind to queuenum %" PRIu32 "", verdict_queue_num);

    /* no initialization, ReceiveNFQ takes care of that */
    NFQThreadVars *ntv = &nfq_t[verdict_queue_num];

    *data = (void *)ntv;
    verdict_queue_num++;

    SCMutexUnlock(&nfq_init_lock);
    return TM_ECODE_OK;
}

TmEcode VerdictNFQThreadDeinit(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    SCLogDebug("starting... will close queuenum %" PRIu32 "", ntv->queue_num);
    nfq_destroy_queue(ntv->qh);

    return TM_ECODE_OK;
}

/**
 * \brief NFQ function to get a packet from the kernel
 *
 * \note separate functions for Linux and Win32 for readability.
 */
#ifndef OS_WIN32
void NFQRecvPkt(NFQThreadVars *t) {
    int rv, ret;
    char buf[70000];

    /* XXX what happens on rv == 0? */
    rv = recv(t->fd, buf, sizeof(buf), 0);

    if (rv < 0) {
        if (errno == EINTR || errno == EWOULDBLOCK
           ) {
            /* no error on timeout */
        } else {
#ifdef COUNTERS
            t->errs++;
#endif /* COUNTERS */
        }
    } else if(rv == 0) {
        SCLogWarning(SC_ERR_NFQ_RECV, "recv got returncode 0");
    } else {
#ifdef DBG_PERF
        if (rv > t->dbg_maxreadsize)
            t->dbg_maxreadsize = rv;
#endif /* DBG_PERF */

        //printf("NFQRecvPkt: t %p, rv = %" PRId32 "\n", t, rv);

        SCMutexLock(&t->mutex_qh);
        ret = nfq_handle_packet(t->h, buf, rv);
        SCMutexUnlock(&t->mutex_qh);

        if (ret != 0) {
            SCLogWarning(SC_ERR_NFQ_HANDLE_PKT, "nfq_handle_packet error %" PRId32 "", ret);
        }
    }
}
#else /* WIN32 version of NFQRecvPkt */
void NFQRecvPkt(NFQThreadVars *t) {
    int rv, ret;
    char buf[70000];
    static int timeouted = 0;

    if (timeouted) {
        if (WaitForSingleObject(t->ovr.hEvent, 1000) == WAIT_TIMEOUT) {
            rv = -1;
            errno = EINTR;
            goto process_rv;
        }
        timeouted = 0;
    }

read_packet_again:

    if (!ReadFile(t->fd, buf, sizeof(buf), (DWORD*)&rv, &t->ovr)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            rv = -1;
            errno = EIO;
        } else {
            if (WaitForSingleObject(t->ovr.hEvent, 1000) == WAIT_TIMEOUT) {
                rv = -1;
                errno = EINTR;
                timeouted = 1;
            } else {
                /* We needn't to call GetOverlappedResult() because it always
                 * fail with our error code ERROR_MORE_DATA. */
                goto read_packet_again;
            }
        }
    }

process_rv:

    if (rv < 0) {
        if (errno == EINTR) {
            /* no error on timeout */
        } else {
#ifdef COUNTERS
            t->errs++;
#endif /* COUNTERS */
        }
    } else if(rv == 0) {
        SCLogWarning(SC_ERR_NFQ_RECV, "recv got returncode 0");
    } else {
#ifdef DBG_PERF
        if (rv > t->dbg_maxreadsize)
            t->dbg_maxreadsize = rv;
#endif /* DBG_PERF */

        //printf("NFQRecvPkt: t %p, rv = %" PRId32 "\n", t, rv);

        SCMutexLock(&t->mutex_qh);
        ret = nfq_handle_packet(t->h, buf, rv);
        SCMutexUnlock(&t->mutex_qh);

        if (ret != 0) {
            SCLogWarning(SC_ERR_NFQ_HANDLE_PKT, "nfq_handle_packet error %" PRId32 "", ret);
        }
    }
}
#endif /* OS_WIN32 */

/**
 * \brief NFQ receive module main entry function: receive a packet from NFQ
 */
TmEcode ReceiveNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    //printf("%p receiving on queue %" PRIu32 "\n", ntv, ntv->queue_num);

    /* do our nfq magic */
    NFQRecvPkt(ntv);

    /* check if we have too many packets in the system
     * so we will wait for some to free up */
    SCMutexLock(&mutex_pending);
    if (pending > max_pending_packets) {
        SCondWait(&cond_pending, &mutex_pending);
    }
    SCMutexUnlock(&mutex_pending);
    return TM_ECODE_OK;
}

/**
 * \brief NFQ receive module stats printing function
 */
void ReceiveNFQThreadExitStats(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;
#ifdef COUNTERS
    SCLogInfo("(%s) Pkts %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
            tv->name, ntv->pkts, ntv->bytes, ntv->errs);
#endif
}

/**
 * \brief NFQ verdict module stats printing function
 */
void VerdictNFQThreadExitStats(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;
#ifdef COUNTERS
    SCLogInfo("(%s) Pkts accepted %" PRIu32 ", dropped %" PRIu32 "",
            tv->name, ntv->accepted, ntv->dropped);
#endif
}

/**
 * \brief NFQ verdict function
 */
void NFQSetVerdict(NFQThreadVars *t, Packet *p) {
    int ret;
    uint32_t verdict;

    //printf("%p verdicting on queue %" PRIu32 "\n", t, t->queue_num);

    if (p->action & ACTION_REJECT || p->action & ACTION_REJECT_BOTH ||
        p->action & ACTION_REJECT_DST || p->action & ACTION_DROP) {
        verdict = NF_DROP;
#ifdef COUNTERS
        t->dropped++;
#endif /* COUNTERS */
    } else {
        verdict = NF_ACCEPT;
#ifdef COUNTERS
        t->accepted++;
#endif /* COUNTERS */
    }

    SCMutexLock(&t->mutex_qh);
    ret = nfq_set_verdict(t->qh, p->nfq_v.id, verdict, 0, NULL);
    SCMutexUnlock(&t->mutex_qh);

    if (ret < 0) {
        SCLogWarning(SC_ERR_NFQ_SET_VERDICT, "nfq_set_verdict of %p failed %" PRId32 "", p, ret);
    }
}

/**
 * \brief NFQ verdict module packet entry function
 */
TmEcode VerdictNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    /* if this is a tunnel packet we check if we are ready to verdict
     * already. */
    if (IS_TUNNEL_PKT(p)) {
        char verdict = 1;
        //printf("VerdictNFQ: tunnel pkt: %p %s\n", p, p->root ? "upper layer" : "root");

        SCMutex *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        SCMutexLock(m);
        /* if there are more tunnel packets than ready to verdict packets,
         * we won't verdict this one */
        if (TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p)) {
            //printf("VerdictNFQ: not ready to verdict yet: TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p) = %" PRId32 " > %" PRId32 "\n", TUNNEL_PKT_TPR(p), TUNNEL_PKT_RTV(p));
            verdict = 0;
        }
        SCMutexUnlock(m);

        /* don't verdict if we are not ready */
        if (verdict == 1) {
            //printf("VerdictNFQ: setting verdict\n");
            NFQSetVerdict(ntv, p->root ? p->root : p);
        } else {
            TUNNEL_INCR_PKT_RTV(p);
        }
    } else {
        /* no tunnel, verdict normally */
        NFQSetVerdict(ntv, p);
    }
    return TM_ECODE_OK;
}

/**
 * \brief Decode a packet coming from NFQ
 */
TmEcode DecodeNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)p->pkt;
    IPV6Hdr *ip6h = (IPV6Hdr *)p->pkt;
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("IPv4 packet");

        DecodeIPV4(tv, dtv, p, p->pkt, p->pktlen, pq);
    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, dtv, p, p->pkt, p->pktlen, pq);
    } else {
        SCLogDebug("packet unsupported by NFQ, first byte: %02x", *p->pkt);
    }

    return TM_ECODE_OK;
}

/**
 * \brief Initialize the NFQ Decode threadvars
 */
TmEcode DecodeNFQThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed");
        return TM_ECODE_FAILED;
    }
    memset(dtv, 0, sizeof(DecodeThreadVars));

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}

#endif /* NFQ */

