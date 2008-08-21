/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/signal.h>
#include <errno.h>

#include "vips.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "util-binsearch.h"

#include "detect-parse.h"
#include "detect-mpm.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "alert-fastlog.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"

#ifdef NFQ
#include "source-nfq.h"
#include "source-nfq-prototypes.h"
#endif /* NFQ */

#include "flow.h"

#include "util-cidr.h"
#include "util-unittest.h"

pthread_attr_t attr;

/*
 * we put this here, because we only use it here in main.
 */
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;

#define VIPS_SIGINT  0x01
#define VIPS_SIGHUP  0x02
#define VIPS_SIGTERM 0x04

static u_int8_t sigflags = 0;

static void handle_sigint(/*@unused@*/ int sig) { sigint_count = 1; sigflags |= VIPS_SIGINT; }
static void handle_sigterm(/*@unused@*/ int sig) { sigterm_count = 1; sigflags |= VIPS_SIGTERM; }
static void handle_sighup(/*@unused@*/ int sig) { sighup_count = 1; sigflags |= VIPS_SIGHUP; }

static void
setup_signal_handler(int sig, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

Packet *SetupPkt (void)
{
    mutex_lock(&packet_q.mutex_q);
    Packet *p = PacketDequeue(&packet_q);
    mutex_unlock(&packet_q.mutex_q);

    CLEAR_PACKET(p);

    //printf("p %p\n", p);
    return p;
}

void SetupTunnelPkt(ThreadVars *t, Packet *parent, u_int8_t *pkt, u_int16_t len, u_int8_t proto)
{
    /* get us a packet */
    mutex_lock(&packet_q.mutex_q);
    Packet *p = PacketDequeue(&packet_q);
    mutex_unlock(&packet_q.mutex_q);
    CLEAR_PACKET(p);

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    p->tunnel_proto = proto;
    p->pktlen = len;
    memcpy(&p->pkt, pkt, len);

    /* copy queue id's */
/* XXX review how to insert tunnel packets into the queue decoders use */
    p->pickup_q_id = parent->pickup_q_id;
    p->verdict_q_id = parent->verdict_q_id;

    /* set tunnel flags */
    SET_TUNNEL_PKT(p);
    INCR_PKT_TPR(p);

    /* enqueue the packet in the pickup_q */
    PacketQueue *pq = &trans_q[p->pickup_q_id];

    /* lock mutex and add the packet to the queue */
    mutex_lock(&pq->mutex_q);
    PacketEnqueue(pq, p);
    pthread_cond_signal(&pq->cond_q);
    mutex_unlock(&pq->mutex_q);
    return;
}

/* this function should only be called for tunnel packets
 * ( I could also add a check for that here, but better do
 * that at the caller, it saves us a functioncall for all
 * non-tunnel packets)
 *
 * the problem we have is this: we reinject a pseudo packet
 * into the pickup queue when we encounter a tunnel. This way
 * we can independently inspect both the raw packet and any
 * tunneled packet. We can however, reinject only one, and
 * we can only do it when all are inspected. This is why
 * all packets that are done set the RTV (Ready To Verdict)
 * flag. Each time a packet is done, it checks if it is the
 * last one. If not, we do nothing except return it to the
 * memory pool. If we have handled everything, verdict this
 * one.
 *
 */
static Packet * VerdictTunnelPacket(Packet *p) {
    char verdict = 1;
    Packet *vp = NULL;

    INCR_PKT_RTV(p);

    pthread_mutex_t *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;

    mutex_lock(m);
    /* if there are more tunnel packets than ready to verdict packets,
     * we won't verdict this one */
    if ((PKT_TPR(p)+1) > PKT_RTV(p)) {
        verdict = 0;
    }
    mutex_unlock(m);

    /* don't set a verdict, we are not done yet with all packets */
    if (verdict == 0) {
        /* if this is not the root, we don't need it any longer */
        if (!(IS_TUNNEL_ROOT_PKT(p))) {
            mutex_lock(&packet_q.mutex_q);
            PacketEnqueue(&packet_q, p);
            mutex_unlock(&packet_q.mutex_q);
        }
        return NULL;
    }

    /* okay, we are going to set a verdict */

    /* just verdict this one if it is the root */
    if (IS_TUNNEL_ROOT_PKT(p)) {
        return p;
    }

    /* not a tunnel root, so verdict p->root and get p
     * into the packet_q */
    vp = p->root;

    mutex_lock(&packet_q.mutex_q);
    PacketEnqueue(&packet_q, p);
    mutex_unlock(&packet_q.mutex_q);
    return vp;
}
#if 0
void *DecoderThread(void *td) {
    ThreadVars *th_v = (ThreadVars *)td;
    int run = 1;
    u_int32_t cnt = 0;

    printf("DecoderThread[%d] started...\n", th_v->tid);

    while(run) {
        Packet *p = th_v->tmqh_in(th_v);
        if (p == NULL) {
            if (threadflags & VIPS_KILLDECODE)
                run = 0;
        } else {
#ifdef COUNTERS
            cnt++;
#endif /* COUNTERS */

            if ((IS_TUNNEL_PKT(p))) {
                DecodeTunnel(th_v, p, p->pkt, p->pktlen);
            }
            else {
#ifdef NFQ
                DecodeNFQ(th_v, p);
#endif /* NFQ */
            }

            /* lock mutex and add the packet to the queue */
            th_v->tmqh_out(th_v,p);
        }
    }

    printf("DecoderThread[%d] cnt %u\n", th_v->tid, cnt);

    printf("DecoderThread[%d] ended...\n", th_v->tid);
    pthread_exit((void *) 0);
}

void *DetectThread(void *td) {
    ThreadVars *th_v = (ThreadVars *)td;
    int run = 1;
    u_int32_t cnt = 0;

    printf("DetectThread[%d] started... th_v %p\n", th_v->tid, th_v);

    while(run) {
        Packet *p = th_v->tmqh_in(th_v);
        if (p == NULL) {
            if (threadflags & VIPS_KILLDETECT)
                run = 0;
        } else {
#ifdef COUNTERS
            cnt++;
#endif /* COUNTERS */

            SigMatchSignatures(th_v, p);

            /* handle normal packets and packets containing tunnels
             * differently. Normal packets are just forwarded to the
             * next queue. Tunnel packets need more care. */
            if (!(IS_TUNNEL_PKT(p))) {
                th_v->tmqh_out(th_v, p);
            } else {
                /* verdict the packet VerdictTunnelPacket returns. The
                 * function handles the rest */
                Packet *vp = VerdictTunnelPacket(p);
                if (vp != NULL) {
                    th_v->tmqh_out(th_v, p);
                }
            }
        }
    }

    printf("DetectThread[%d] cnt %u\n", th_v->tid, cnt);
    printf("DetectThread[%d] ended...\n", th_v->tid);
    pthread_exit((void *) 0);
}
#endif

//ThreadVars th_v[NUM_THREADS];

int main(int argc, char **argv)
{
    int rc;
#ifdef NFQ
    NFQThreadVars nfq_t[2];
#endif
    sigset_t set;

    sigaddset(&set, SIGINT); 
    /* registering signals we use */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);
    //pthread_sigmask(SIG_BLOCK, &set, 0);

    /* hardcoded initialization code */
    MpmTableSetup(); /* load the pattern matchers */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    BinSearchInit();
    CIDRInit();
    SigParsePrepare();
    PatternMatchPrepare(mpm_ctx);

    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    TmModuleDetectRegister();
    TmModuleAlertFastlogRegister();
    TmModuleAlertFastlogIPv4Register();
    TmModuleAlertFastlogIPv6Register();
    TmModuleAlertUnifiedLogRegister();
    TmModuleAlertUnifiedAlertRegister();
    TmModuleDebugList();

    /* test and initialize the unittesting subsystem */
    UtRunSelftest(); /* inits and cleans up again */
    UtInitialize();
    TmModuleRegisterTests();
    MpmRegisterTests();
    SigTableRegisterTests();
    SigRegisterTests();
    //UtRunTests();
    //exit(1);

    //LoadConfig();
    //exit(1);

    /* initialize packet queues */
    memset(&packet_q,0,sizeof(packet_q));
    memset(&trans_q, 0,sizeof(trans_q));

    /* pre allocate packets */
    printf("Preallocating packets... packet size %u\n", sizeof(Packet));
    int i = 0;
    for (i = 0; i < MAX_PENDING; i++) {
        Packet *p = malloc(sizeof(Packet));
        if (p == NULL) {
            printf("ERROR: malloc failed: %s\n", strerror(errno));
            exit(1);
        }

        CLEAR_TCP_PACKET(p);
        CLEAR_PACKET(p);

        PacketEnqueue(&packet_q,p);
    }
    printf("Preallocating packets... done\n");

    FlowInitConfig();

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    memset(&nfq_t, 0, sizeof(nfq_t));

    SigLoadSignatures();

    /* create the threads */
    ThreadVars *tv_receivenfq = TmThreadCreate("ReceiveNFQ","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivenfq == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_receivenfq,tm_module);

    /* XXX this needs an api way of doing this */
    if (NFQInitThread(tv_receivenfq, &nfq_t[0], 0, MAX_PENDING) < 0)
        exit(1);

    if (TmThreadSpawn(tv_receivenfq) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_decode1 = TmThreadCreate("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module);

    if (TmThreadSpawn(tv_decode1) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_decode2 = TmThreadCreate("Decode2","pickup-queue","simple","decode-queue2","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_decode2,tm_module);

    if (TmThreadSpawn(tv_decode2) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect1 = TmThreadCreate("Detect1","decode-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module);

    /* XXX this needs an api way of doing this */
    //PatternMatcherThreadInit(tv_detect1);

    if (TmThreadSpawn(tv_detect1) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect2 = TmThreadCreate("Detect2","decode-queue2","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module);

    /* XXX this needs an api way of doing this */
    //PatternMatcherThreadInit(tv_detect2);

    if (TmThreadSpawn(tv_detect2) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_verdict = TmThreadCreate("Verdict","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("VerdictNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_verdict,tm_module);

    /* XXX this needs an api way of doing this */
    tv_verdict->nfq_t = &nfq_t[0];
    if (TmThreadSpawn(tv_verdict) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_alert = TmThreadCreate("AlertFastlog","alert-queue1","simple","alert-queue2","simple","1slot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_alert,tm_module);

    if (TmThreadSpawn(tv_alert) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_unified = TmThreadCreate("AlertUnifiedLog","alert-queue2","simple","packetpool","packetpool","2slot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_unified,tm_module);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_unified,tm_module);

    if (TmThreadSpawn(tv_unified) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }
/*
    ThreadVars *tv_unifiedalert = TmThreadCreate("AlertUnifiedAlert","alert-queue3","simple","packetpool","packetpool","1slot");
    if (tv_unifiedalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_unifiedalert,tm_module);

    if (TmThreadSpawn(tv_unifiedalert) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }
*/
    ThreadVars tv_flowmgr;
    memset(&tv_flowmgr, 0, sizeof(ThreadVars));
    printf("Creating FlowManagerThread...\n");
    tv_flowmgr.name = "FlowManagerThread";

    rc = pthread_create(&tv_flowmgr.t, &attr, FlowManagerThread, (void *)&tv_flowmgr);
    if (rc) {
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(1);
    }
    TmThreadAppend(&tv_flowmgr);

    while(1) {
        if (sigflags) {
            printf("signal received\n");

            if (sigflags & VIPS_SIGINT)  printf ("SIGINT\n");
            if (sigflags & VIPS_SIGHUP)  printf ("SIGHUP\n");
            if (sigflags & VIPS_SIGTERM) printf ("SIGTERM\n");

            TmThreadKillThreads();
#if 0
#ifdef DBG_PERF
            printf("th_v[0].nfq_t->dbg_maxreadsize %d\n", th_v[0].nfq_t->dbg_maxreadsize);
            //printf("th_v[1].nfq_t->dbg_maxreadsize %d\n", th_v[1].nfq_t->dbg_maxreadsize);
#endif /* DBG_PERF */
            printf("NFQ Stats 0: pkts %u, errs %u\n", th_v[0].nfq_t->pkts, th_v[0].nfq_t->errs);
            //printf("NFQ Stats 1: pkts %u, errs %u\n", th_v[1].nfq_t->pkts, th_v[1].nfq_t->errs);
            PatternMatcherThreadInfo(&th_v[3]);
            PatternMatcherThreadInfo(&th_v[4]);
#ifdef DBG_PERF
            printf("trans_q[0].dbg_maxlen %u\n", trans_q[0].dbg_maxlen);
            printf("trans_q[1].dbg_maxlen %u\n", trans_q[1].dbg_maxlen);
            printf("trans_q[2].dbg_maxlen %u\n", trans_q[2].dbg_maxlen);
            printf("trans_q[3].dbg_maxlen %u\n", trans_q[3].dbg_maxlen);
            printf("trans_q[4].dbg_maxlen %u\n", trans_q[4].dbg_maxlen);

            printf("dbg_maxpending %u\n", dbg_maxpending);
#endif /* DBG_PERF */
#endif
            break;//pthread_exit(NULL);
        }

        sleep(1);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(tv_receivenfq->nfq_t->qh);
    //printf("unbinding from queue 1\n");
    //nfq_destroy_queue(th_v[1].nfq_t->qh);

    FlowPrintFlows();
    FlowShutdown();

    SigGroupCleanup();
    SigCleanSignatures();

    pthread_exit(NULL);
}
