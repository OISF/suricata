/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* TODO
 * - test in Receive and Verdict if both are present
 *
 *
 *
 */

#include <pthread.h>
#include <sys/signal.h>

#include "vips.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "source-nfq.h"
#include "source-nfq-prototypes.h"
#include "action-globals.h"

/* shared vars for all for nfq queues and threads */
static NFQGlobalVars nfq_g;
static NFQThreadVars nfq_t[NFQ_MAX_QUEUE];
static u_int16_t receive_queue_num = 0;
static u_int16_t verdict_queue_num = 0;

int ReceiveNFQ(ThreadVars *, Packet *, void *, PacketQueue *);
int ReceiveNFQThreadInit(ThreadVars *, void **);
void ReceiveNFQThreadExitStats(ThreadVars *, void *);

int VerdictNFQ(ThreadVars *, Packet *, void *, PacketQueue *);
int VerdictNFQThreadInit(ThreadVars *, void **);
void VerdictNFQThreadExitStats(ThreadVars *, void *);
int VerdictNFQThreadDeinit(ThreadVars *, void *);

int DecodeNFQ(ThreadVars *, Packet *, void *, PacketQueue *);

void TmModuleReceiveNFQRegister (void) {
    /* XXX create a general NFQ setup function */
    memset(&nfq_g, 0, sizeof(nfq_g));
    memset(&nfq_t, 0, sizeof(nfq_t));

    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].Init = ReceiveNFQThreadInit;
    tmm_modules[TMM_RECEIVENFQ].Func = ReceiveNFQ;
    tmm_modules[TMM_RECEIVENFQ].ExitPrintStats = ReceiveNFQThreadExitStats;
    tmm_modules[TMM_RECEIVENFQ].Deinit = NULL;
    tmm_modules[TMM_RECEIVENFQ].RegisterTests = NULL;
}

void TmModuleVerdictNFQRegister (void) {
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].Init = VerdictNFQThreadInit;
    tmm_modules[TMM_VERDICTNFQ].Func = VerdictNFQ;
    tmm_modules[TMM_VERDICTNFQ].ExitPrintStats = VerdictNFQThreadExitStats;
    tmm_modules[TMM_VERDICTNFQ].Deinit = VerdictNFQThreadDeinit;
    tmm_modules[TMM_VERDICTNFQ].RegisterTests = NULL;
}

void TmModuleDecodeNFQRegister (void) {
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].Init = NULL;
    tmm_modules[TMM_DECODENFQ].Func = DecodeNFQ;
    tmm_modules[TMM_DECODENFQ].ExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFQ].Deinit = NULL;
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
        memcpy(p->pkt, pktdata, ret);
        p->pktlen = (size_t)ret;
    }
/* XXX what if ret <= 0 ? */
/* XXX what if ret > 65536 ? */

    ret = nfq_get_timestamp(tb, &p->ts);
    if (ret < 0) {
        memset (&p->ts, 0, sizeof(struct timeval));
        gettimeofday(&p->ts, NULL);
    }

    return;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    ThreadVars *tv = ntv->tv;

    /* grab a packet */
    Packet *p = tv->tmqh_in(tv);
    NFQSetupPkt(p, (void *)nfa);

    p->pickup_q_id = tv->pickup_q_id;
    p->verdict_q_id = tv->verdict_q_id;

#ifdef COUNTERS
    nfq_t->pkts++;
    nfq_t->bytes += p->pktlen;
#endif /* COUNTERS */

    /* pass on... */
    tv->tmqh_out(tv, p);

    mutex_lock(&mutex_pending);
    pending++;
#ifdef DBG_PERF
    if (pending > dbg_maxpending)
        dbg_maxpending = pending;
#endif /* DBG_PERF */
    mutex_unlock(&mutex_pending);
    return 0;
}

int NFQInitThread(NFQThreadVars *nfq_t, u_int16_t queue_num, u_int32_t queue_maxlen)
{
    struct timeval tv;

    nfq_t->queue_num = queue_num;

    printf("NFQInitThread: opening library handle\n");
    nfq_t->h = nfq_open();
    if (!nfq_t->h) {
        printf("error during nfq_open()\n");
        return -1;
    }

    if (nfq_g.unbind == 0)
    {
        /* VJ: on my Ubuntu Hardy system this fails the first time it's
         * run. Ignoring the error seems to have no bad effects. */
        printf("NFQInitThread: unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(nfq_t->h, AF_INET) < 0) {
            printf("error during nfq_unbind_pf()\n");
            //return -1;
        }
        if (nfq_unbind_pf(nfq_t->h, AF_INET6) < 0) {
            printf("error during nfq_unbind_pf()\n");
            //return -1;
        }
        nfq_g.unbind = 1;

        printf("NFQInitThread: binding nfnetlink_queue as nf_queue handler for AF_INET\n");

        if (nfq_bind_pf(nfq_t->h, AF_INET) < 0) {
            printf("error during nfq_bind_pf()\n");
            return -1;
        }
        if (nfq_bind_pf(nfq_t->h, AF_INET6) < 0) {
            printf("error during nfq_bind_pf()\n");
            return -1;
        }
    }

    printf("NFQInitThread: binding this socket to queue '%u'\n", queue_num);

    /* pass the thread memory as a void ptr so the
     * callback function has access to it. */
    nfq_t->qh = nfq_create_queue(nfq_t->h, queue_num, &cb, (void *)nfq_t);
    if (nfq_t->qh == NULL)
    {
        printf("error during nfq_create_queue()\n");
        return -1;
    }

    printf("NFQInitThread: setting copy_packet mode\n");

    /* 05DC = 1500 */
    //if (nfq_set_mode(nfq_t->qh, NFQNL_COPY_PACKET, 0x05DC) < 0) {
    if (nfq_set_mode(nfq_t->qh, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        printf("can't set packet_copy mode\n");
        return -1;
    }

/* XXX detect this at configure time & make it an option */
#define HAVE_NFQ_MAXLEN
#ifdef HAVE_NFQ_MAXLEN
    if (queue_maxlen > 0) {
        printf("NFQInitThread: setting queue length to %d\n", queue_maxlen);

        /* non-fatal if it fails */
        if (nfq_set_queue_maxlen(nfq_t->qh, queue_maxlen) < 0) {
            printf("NFQInitThread: can't set queue maxlen: your kernel probably "
                   "doesn't support setting the queue length\n");
        }
    }
#endif

    nfq_t->nh = nfq_nfnlh(nfq_t->h);
    nfq_t->fd = nfnl_fd(nfq_t->nh);

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if(setsockopt(nfq_t->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        printf("NFQInitThread: can't set socket timeout: %s\n", strerror(errno));
    }

    printf("NFQInitThread: nfq_t->h %p, nfq_t->nh %p, nfq_t->qh %p, nfq_t->fd %d\n", nfq_t->h, nfq_t->nh, nfq_t->qh, nfq_t->fd);

    return 0;
}

int ReceiveNFQThreadInit(ThreadVars *tv, void **data) {
    //printf("ReceiveNFQThreadInit: starting... will bind to queuenum %u\n", receive_queue_num);

    NFQThreadVars *ntv = &nfq_t[receive_queue_num];

    /* store the ThreadVars pointer in our NFQ thread context
     * as we will need it in our cb function */
    ntv->tv = tv;

    int r = NFQInitThread(ntv,receive_queue_num,MAX_PENDING);
    if (r < 0) {
        printf("NFQInitThread failed\n");
        //return -1;
        exit(1);
    }

    *data = (void *)ntv;
    receive_queue_num++;
    return 0;
}

int VerdictNFQThreadInit(ThreadVars *tv, void **data) {
    //printf("VerdictNFQThreadInit: starting... will bind to queuenum %u\n", verdict_queue_num);

    /* no initialization, ReceiveNFQ takes care of that */
    NFQThreadVars *ntv = &nfq_t[verdict_queue_num];

    *data = (void *)ntv;
    verdict_queue_num++;
    return 0;
}

int VerdictNFQThreadDeinit(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    //printf("VerdictNFQThreadDeinit: starting... will close queuenum %u\n", ntv->queue_num);

    nfq_destroy_queue(ntv->qh);

    return 0;
}

void NFQRecvPkt(NFQThreadVars *t) {
    int rv, ret;
    char buf[70000];

    /* XXX what happens on rv == 0? */
    rv = recv(t->fd, buf, sizeof(buf), 0);
    if (rv < 0) {
        if (errno == EINTR || errno == EWOULDBLOCK) {
            /* no error on timeout */
        } else {
#ifdef COUNTERS
            t->errs++;
#endif /* COUNTERS */
        }
    } else if(rv == 0) {
        printf("NFQRecvPkt: rv = 0\n");
    } else {
#ifdef DBG_PERF
        if (rv > t->dbg_maxreadsize)
            t->dbg_maxreadsize = rv;
#endif /* DBG_PERF */

        mutex_lock(&t->mutex_qh);
        ret = nfq_handle_packet(t->h, buf, rv);
        mutex_unlock(&t->mutex_qh);

        if (ret != 0)
            printf("NFQRecvPkt: nfq_handle_packet error %d\n", ret);
    }
}

int ReceiveNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    /* XXX can we move this to initialization? */
    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    NFQRecvPkt(ntv);
    return 0;
}

void ReceiveNFQThreadExitStats(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;
#ifdef COUNTERS
    printf(" - (%s) Pkts %u, Bytes %llu, Errors %u\n", tv->name, ntv->pkts, ntv->bytes, ntv->errs);
#endif
}

void VerdictNFQThreadExitStats(ThreadVars *tv, void *data) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;
#ifdef COUNTERS
    printf(" - (%s) Pkts accepted %u, dropped %u\n", tv->name, ntv->accepted, ntv->dropped);
#endif
}

void NFQSetVerdict(NFQThreadVars *t, Packet *p) {
    int ret;
    u_int32_t verdict;

    if (p->action == ACTION_ALERT) {
       verdict = NF_ACCEPT;
    } else if (p->action == ACTION_PASS) {
       verdict = NF_ACCEPT;
    } else if (p->action == ACTION_DROP) {
       verdict = NF_DROP;
    } else if (p->action == ACTION_REJECT || p->action == ACTION_REJECT_DST ||
               p->action == ACTION_REJECT_BOTH){
       verdict = NF_DROP;
    } else {
       /* a verdict we don't know about, drop to be sure */
       verdict = NF_DROP;
    }

#ifdef COUNTERS
    if (verdict == NF_ACCEPT) t->accepted++;
    if (verdict == NF_DROP) t->dropped++;
#endif /* COUNTERS */

    mutex_lock(&t->mutex_qh);
    ret = nfq_set_verdict(t->qh, p->nfq_v.id, verdict, 0, NULL);
    mutex_unlock(&t->mutex_qh);

    if (ret < 0)
        printf("NFQSetVerdict: nfq_set_verdict of %p failed %d\n", p, ret);
}

int VerdictNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    NFQThreadVars *ntv = (NFQThreadVars *)data;

    /* if this is a tunnel packet we check if we are ready to verdict
     * already. */
    if (IS_TUNNEL_PKT(p)) {
        char verdict = 1;
        //printf("VerdictNFQ: tunnel pkt: %p %s\n", p, p->root ? "upper layer" : "root");

        pthread_mutex_t *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        mutex_lock(m);
        /* if there are more tunnel packets than ready to verdict packets,
         * we won't verdict this one */
        if (TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p)) {
            //printf("VerdictNFQ: not ready to verdict yet: TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p) = %d > %d\n", TUNNEL_PKT_TPR(p), TUNNEL_PKT_RTV(p));
            verdict = 0;
        }
        mutex_unlock(m);

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
    return 0;
}

/*
 *
 *
 *
 */
int DecodeNFQ(ThreadVars *t, Packet *p, void *data, PacketQueue *pq)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)p->pkt;
    IPV6Hdr *ip6h = (IPV6Hdr *)p->pkt;

#ifdef DEBUG
    printf("DecodeNFQ\n");
#endif

    if (IPV4_GET_RAW_VER(ip4h) == 4)
        DecodeIPV4(t, p, p->pkt, p->pktlen, pq);
    else if(IPV6_GET_RAW_VER(ip6h) == 6)
        DecodeIPV6(t, p, p->pkt, p->pktlen);

    return 0;
}

