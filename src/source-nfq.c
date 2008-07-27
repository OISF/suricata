/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

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

/* shared vars for all for nfq queues and threads */
static NFQGlobalVars nfq_g;

int ReceiveNFQ(ThreadVars *, Packet *, void *);
int VerdictNFQ(ThreadVars *, Packet *, void *);
int DecodeNFQ(ThreadVars *, Packet *, void *);

void TmModuleReceiveNFQRegister (void) {
    /* XXX create a general NFQ setup function */
    memset(&nfq_g, 0, sizeof(nfq_g));

    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].Init = NULL;
    tmm_modules[TMM_RECEIVENFQ].Func = ReceiveNFQ;
    tmm_modules[TMM_RECEIVENFQ].Deinit = NULL;
}

void TmModuleVerdictNFQRegister (void) {
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].Init = NULL;
    tmm_modules[TMM_VERDICTNFQ].Func = VerdictNFQ;
    tmm_modules[TMM_VERDICTNFQ].Deinit = NULL;
}

void TmModuleDecodeNFQRegister (void) {
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].Init = NULL;
    tmm_modules[TMM_DECODENFQ].Func = DecodeNFQ;
    tmm_modules[TMM_DECODENFQ].Deinit = NULL;
}

void NFQSetupPkt (Packet *p, void *data)
{
    struct nfq_data *tb = (struct nfq_data *)data;
    int ret;
    char *pktdata;

    p->nfq_v.ph = nfq_get_msg_packet_hdr(tb);
    if (p->nfq_v.ph != NULL) {
        p->nfq_v.id = ntohl(p->nfq_v.ph->packet_id);
        //p->nfq_v.hw_protocol = ntohs(p->nfq_v.ph->hw_protocol);
        p->nfq_v.hw_protocol = p->nfq_v.ph->hw_protocol;
    }
    p->nfq_v.mark = nfq_get_nfmark(tb);
    p->nfq_v.ifi  = nfq_get_indev(tb);
    p->nfq_v.ifo  = nfq_get_outdev(tb);

    ret = nfq_get_payload(tb, &pktdata);
    if (ret > 0) {
        /* nfq_get_payload returns a pointer to a part of memory
         * that is not preserved over the lifetime of out packet.
         * So we need to copy it. */
        memcpy(p->pkt, pktdata, ret);
        //bcopy(pktdata, p->pkt, ret);
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
    ThreadVars *th_v = (ThreadVars *)data;

    /* grab a packet */
    Packet *p = th_v->tmqh_in(th_v);
    NFQSetupPkt(p, (void *)nfa);

    p->pickup_q_id = th_v->pickup_q_id;
    p->verdict_q_id = th_v->verdict_q_id;

#ifdef COUNTERS
    th_v->nfq_t->pkts++;
#endif /* COUNTERS */

    /* pass on... */
    th_v->tmqh_out(th_v, p);

    mutex_lock(&mutex_pending);
    pending++;
#ifdef DBG_PERF
    if (pending > dbg_maxpending)
        dbg_maxpending = pending;
#endif /* DBG_PERF */
    mutex_unlock(&mutex_pending);
    return 0;
}

int NFQInitThread(ThreadVars *t, NFQThreadVars *nfq_t, u_int16_t queue_num, u_int32_t queue_maxlen)
{
    struct timeval tv;

    t->nfq_t = nfq_t;

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
            // return -1;
        }
        if (nfq_unbind_pf(nfq_t->h, AF_INET6) < 0) {
            printf("error during nfq_unbind_pf()\n");
            // return -1;
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
    nfq_t->qh = nfq_create_queue(nfq_t->h, queue_num, &cb, (void *)t);
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
    printf("NFQInitThread: setting queue length to %d\n", queue_maxlen);
    if (queue_maxlen > 0) {
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

int ReceiveNFQ(ThreadVars *tv, Packet *p, void *data) {
    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    NFQRecvPkt(tv->nfq_t);
    return 0;
}

void NFQSetVerdict(NFQThreadVars *t, Packet *p) {
    int ret;

    mutex_lock(&t->mutex_qh);
    ret = nfq_set_verdict(t->qh, p->nfq_v.id, NF_ACCEPT, 0, NULL);
    mutex_unlock(&t->mutex_qh);

    if (ret < 0)
        printf("NFQSetVerdict: nfq_set_verdict of %p failed %d\n", p, ret);
}

int VerdictNFQ(ThreadVars *tv, Packet *p, void *data) {

    NFQSetVerdict(tv->nfq_t, p);
    return 0;
}

/*
 *
 *
 *
 */
int DecodeNFQ(ThreadVars *t, Packet *p, void *data)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)p->pkt;
    IPV6Hdr *ip6h = (IPV6Hdr *)p->pkt;

#ifdef DEBUG
    printf("DecodeNFQ\n");
#endif

    if (IPV4_GET_RAW_VER(ip4h) == 4)
        DecodeIPV4(t, p, p->pkt, p->pktlen);
    else if(IPV6_GET_RAW_VER(ip6h) == 6)
        DecodeIPV6(t, p, p->pkt, p->pktlen);

    return 0;
}

