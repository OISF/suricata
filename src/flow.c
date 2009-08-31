/** Copyright (c) 2008 Victor Julien <victor@inliniac.net>
 *  \file
 *  Flow implementation.
 *
 *  IDEAS:
 *  - Maybe place the flow that we get a packet for on top of the
 *    list in the bucket. This rewards active flows.
 *
 */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "tm-modules.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"
#include "util-unittest.h"
#include "stream-tcp.h"

//#define FLOW_DEFAULT_HASHSIZE    262144
#define FLOW_DEFAULT_HASHSIZE    65536
//#define FLOW_DEFAULT_MEMCAP      128 * 1024 * 1024 /* 128 MB */
#define FLOW_DEFAULT_MEMCAP      32 * 1024 * 1024 /* 32 MB */

#define FLOW_DEFAULT_PREALLOC    10000

/*Protocols specific timeouts and free function*/
Protocols protocols[4];

void FlowRegisterTests (void);
void FlowInitProtocols();
static int FlowUpdateSpareFlows(void);
int FlowSetProtoTimeout(uint8_t , uint32_t ,uint32_t );
int FlowSetProtoEmergencyTimeout(uint8_t , uint32_t ,uint32_t );
static int FlowGetProtoMapping(uint8_t );
int FlowSetProtoFreeFunc(uint8_t, Flow *f, void (*Free)(void *));
/** \brief Update the flows position in the queue's
 *  \param f Flow to requeue.
 *
 * In-use flows are either in the flow_new_q or flow_est_q lists.
 */
static void FlowUpdateQueue(Flow *f)
{
    if (f->flags & FLOW_NEW_LIST) {
        /* in the new list -- we consider a flow no longer
         * new if we have seen at least 2 pkts in both ways. */
        if (f->todstpktcnt && f->tosrcpktcnt) {
            FlowRequeue(f, &flow_new_q, &flow_est_q);

            f->flags |= FLOW_EST_LIST; /* transition */
            f->flags &= ~FLOW_NEW_LIST;
        } else {
            FlowRequeue(f, &flow_new_q, &flow_new_q);
        }
    } else if (f->flags & FLOW_EST_LIST) {
        /* Pull and put back -- this way the flows on
         * top of the list are least recently used. */
        FlowRequeue(f, &flow_est_q, &flow_est_q);
    }
}


/** FlowPrune
 *
 * Inspect top (last recently used) flow from the queue and see if
 * we need to prune it.
 *
 * Use trylock here so prevent us from blocking the packet handling.
 *
 * \param q flow queue to prune
 * \param ts current time
 * \param timeout timeout to enforce
 *
 * \retval 0 on error, failed block, nothing to prune
 * \retval 1 on successfully pruned one
 */
static int FlowPrune (FlowQueue *q, struct timeval *ts)
{
    if (mutex_trylock(&q->mutex_q) != 0) {
        return 0;
    }

    Flow *f = q->top;
    if (f == NULL) {
        mutex_unlock(&q->mutex_q);
        return 0;
    }
    if (mutex_trylock(&f->m) != 0) {
        mutex_unlock(&q->mutex_q);
        return 0;
    }

    /* unlock list */
    mutex_unlock(&q->mutex_q);

    if (mutex_trylock(&f->fb->m) != 0) {
        mutex_unlock(&f->m);
        return 0;
    }

    uint32_t timeout = 0;
    uint8_t proto_map;

    proto_map = FlowGetProtoMapping(f->proto);
    if (!(FlowUpdateSpareFlows()) && (flow_flags & FLOW_EMERGENCY)) {
        if (f->flags & FLOW_EST_LIST)
            timeout = protocols[proto_map].emerg_est_timeout;
        else
            timeout = protocols[proto_map].emerg_new_timeout;
    } else {
        if (f->flags & FLOW_EST_LIST)
            timeout = protocols[proto_map].est_timeout;
        else
            timeout = protocols[proto_map].new_timeout;
    }

    DEBUGPRINT("got lock, now check: %" PRId64 "+%" PRIu32 "=(%" PRId64 ") < %" PRId64 "", f->lastts.tv_sec,
        timeout, f->lastts.tv_sec + timeout, ts->tv_sec);

    /** never prune a flow that is used by a packet or stream msg
     *  we are currently processing in one of the threads */
    if (f->use_cnt > 0) {
        mutex_unlock(&f->fb->m);
        mutex_unlock(&f->m);
        return 0;
    }

    /* do the timeout check */
    if ((f->lastts.tv_sec + timeout) >= ts->tv_sec) {
        mutex_unlock(&f->fb->m);
        mutex_unlock(&f->m);
        return 0;
    }

    /* remove from the hash */
    if (f->hprev)
            f->hprev->hnext = f->hnext;
    if (f->hnext)
            f->hnext->hprev = f->hprev;
    if (f->fb->f == f)
        f->fb->f = f->hnext;

    f->hnext = NULL;
    f->hprev = NULL;

    mutex_unlock(&f->fb->m);
    f->fb = NULL;

    FlowSetProtoFreeFunc (f->proto, f, protocols[proto_map].Freefunc);

    /* move to spare list */
    FlowRequeue(f, q, &flow_spare_q);

    mutex_unlock(&f->m);
    return 1;
}

/** \brief Time out flows.
 *  \param q flow queue to time out flows from
 *  \param ts current time
 *  \param timeout timeout to consider
 *  \retval cnt number of flows that are timed out
 */
static uint32_t FlowPruneFlows(FlowQueue *q, struct timeval *ts)
{
    uint32_t cnt = 0;
    while(FlowPrune(q, ts)) { cnt++; }
    return cnt;
}

/** \brief Make sure we have enough spare flows. 
 *
 *  Enforce the prealloc parameter, so keep at least prealloc flows in the
 *  spare queue and free flows going over the limit.
 *
 *  \retval 1 if the queue was properly updated (or if it already was in good shape)
 *  \retval 0 otherwise.
 */
static int FlowUpdateSpareFlows(void) {
    uint32_t toalloc = 0, tofree = 0, len;

    mutex_lock(&flow_spare_q.mutex_q);
    len = flow_spare_q.len;
    mutex_unlock(&flow_spare_q.mutex_q);

    if (len < flow_config.prealloc) {
        toalloc = flow_config.prealloc - len;

        uint32_t i;
        for (i = 0; i < toalloc; i++) {
            Flow *f = FlowAlloc();
            if (f == NULL)
                return 0;

            mutex_lock(&flow_spare_q.mutex_q);
            FlowEnqueue(&flow_spare_q,f);
            mutex_unlock(&flow_spare_q.mutex_q);
        }
    } else if (len > flow_config.prealloc) {
        tofree = len - flow_config.prealloc;

        uint32_t i;
        for (i = 0; i < tofree; i++) {
            Flow *f = FlowDequeue(&flow_spare_q);
            if (f == NULL)
                return 1;

            FlowFree(f);
        }
    }

    return 1;
}

/** \brief Set the IPOnly scanned flag for 'direction'. This function
  *        handles the locking too.
  * \param f Flow to set the flag in
  * \param direction direction to set the flag in
  */
void FlowSetIPOnlyFlag(Flow *f, char direction) {
    mutex_lock(&f->m);
    direction ? (f->flags |= FLOW_TOSERVER_IPONLY_SET) : (f->flags |= FLOW_TOCLIENT_IPONLY_SET);
    mutex_unlock(&f->m);
}

/** \brief decrease the use cnt of a flow
 *  \param tv thread vars (\todo unused?)
 *  \param p packet with flow to decrease use cnt for
 */
void FlowDecrUsecnt(ThreadVars *tv, Packet *p) {
    if (p == NULL || p->flow == NULL)
        return;

    mutex_lock(&p->flow->m);
    if (p->flow->use_cnt > 0)
        p->flow->use_cnt--;
    mutex_unlock(&p->flow->m);
}

/** \brief Entry point for packet flow handling
 *
 * This is called for every packet.
 *
 *  \param tv threadvars
 *  \param p packet to handle flow for
 */
void FlowHandlePacket (ThreadVars *tv, Packet *p)
{
    /* Get this packet's flow from the hash. FlowHandlePacket() will setup
     * a new flow if nescesary. If we get NULL, we're out of flow memory.
     * The returned flow is locked. */
    Flow *f = FlowGetFlowFromHash(p);
    if (f == NULL)
        return;

    f->use_cnt++;

    /* update the last seen timestamp of this flow */
    COPY_TIMESTAMP(&p->ts, &f->lastts);

    /* update flags and counters */
    if (CMP_PORT(f->sp,p->sp)) {
        f->flags |= FLOW_TO_DST_SEEN;
        f->todstpktcnt++;
        p->flowflags |= FLOW_PKT_TOSERVER;
    } else {
        f->flags |= FLOW_TO_SRC_SEEN;
        f->tosrcpktcnt++;
        p->flowflags |= FLOW_PKT_TOCLIENT;
    }
    f->bytecnt += p->pktlen;

    if (f->flags & FLOW_TO_DST_SEEN && f->flags & FLOW_TO_SRC_SEEN) {
        p->flowflags |= FLOW_PKT_ESTABLISHED;
    }

    /* update queue positions */
    FlowUpdateQueue(f);

    /* set the iponly stuff */
    if (f->flags & FLOW_TOCLIENT_IPONLY_SET)
        p->flowflags |= FLOW_PKT_TOCLIENT_IPONLY_SET;
    if (f->flags & FLOW_TOSERVER_IPONLY_SET)
        p->flowflags |= FLOW_PKT_TOSERVER_IPONLY_SET;

    /* set the flow in the packet */
    p->flow = f;

    mutex_unlock(&f->m);
}

/** \brief initialize the configuration
 *  \warning Not thread safe */
void FlowInitConfig (char quiet)
{
    if (quiet == FALSE)
        printf("Initializing Flow:\n");

    memset(&flow_config,  0, sizeof(flow_config));
    memset(&flow_spare_q, 0, sizeof(flow_spare_q));
    memset(&flow_new_q,   0, sizeof(flow_new_q));
    memset(&flow_est_q,   0, sizeof(flow_est_q));
    flow_memuse = 0;
    pthread_mutex_init(&flow_memuse_mutex, NULL);

    /* set defaults */
    flow_config.hash_rand   = rand(); /* XXX seed rand */
    flow_config.hash_size   = FLOW_DEFAULT_HASHSIZE;
    flow_config.memcap      = FLOW_DEFAULT_MEMCAP;
    flow_config.prealloc    = FLOW_DEFAULT_PREALLOC;
    /* init timeouts */
    flow_config.timeout_new = FLOW_DEFAULT_NEW_TIMEOUT;
    flow_config.timeout_est = FLOW_DEFAULT_EST_TIMEOUT;
    flow_config.emerg_timeout_new = FLOW_DEFAULT_EMERG_NEW_TIMEOUT;
    flow_config.emerg_timeout_est = FLOW_DEFAULT_EMERG_EST_TIMEOUT;

    /* alloc hash memory */
    flow_hash = calloc(flow_config.hash_size, sizeof(FlowBucket));
    if (flow_hash == NULL) {
        printf("calloc failed %s\n", strerror(errno));
        exit(1);
    }
    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));
    flow_config.memuse += (flow_config.hash_size * sizeof(FlowBucket));

    if (quiet == FALSE)
        printf("* Allocated %" PRIu32 " bytes of memory for the flow hash... %" PRIu32 " buckets of size %" PRIuMAX "\n",
            flow_config.memuse, flow_config.hash_size, (uintmax_t)sizeof(FlowBucket));

    /* pre allocate flows */
    uint32_t i = 0;
    for (i = 0; i < flow_config.prealloc; i++) {
        Flow *f = FlowAlloc();
        if (f == NULL) {
            printf("ERROR: FlowAlloc failed: %s\n", strerror(errno));
            exit(1);
        }
        FlowEnqueue(&flow_spare_q,f);
    }

    if (quiet == FALSE) {
        printf("* Preallocated %" PRIu32 " flows of size %" PRIuMAX "\n",
                flow_spare_q.len, (uintmax_t)sizeof(Flow));
        printf("* Flow memory usage: %" PRIu32 " bytes. Maximum: %" PRIu32 "\n",
                flow_config.memuse, flow_config.memcap);
    }

    FlowInitProtocols();

}

/** \brief print some flow stats
 *  \warning Not thread safe */
void FlowPrintQueueInfo (void)
{
    printf("* Flow Queue info:\n");
    printf(" - SPARE       %" PRIu32 " (", flow_spare_q.len);
#ifdef DBG_PERF
    printf("flow_spare_q.dbg_maxlen %" PRIu32 ")\n", flow_spare_q.dbg_maxlen);
#endif
    printf(" - NEW         %" PRIu32 " (", flow_new_q.len);
#ifdef DBG_PERF
    printf("flow_new_q.dbg_maxlen %" PRIu32 ")\n", flow_new_q.dbg_maxlen);
#endif
    printf(" - ESTABLISHED %" PRIu32 " (", flow_est_q.len);
#ifdef DBG_PERF
    printf("flow_est_q.dbg_maxlen %" PRIu32 ")\n", flow_est_q.dbg_maxlen);
#endif

#ifdef FLOWBITS_STATS
    printf("* Flowbits added: %" PRIu32 ", removed: %" PRIu32 ", ", flowbits_added, flowbits_removed);
    printf("max memory usage: %" PRIu32 "\n", flowbits_memuse_max);
#endif /* FLOWBITS_STATS */
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void FlowShutdown(void) {
    Flow *f;

    while((f = FlowDequeue(&flow_spare_q))) {
        FlowFree(f);
    }
    while((f = FlowDequeue(&flow_new_q))) {
        FlowFree(f);
    }
    while((f = FlowDequeue(&flow_est_q))) {
        FlowFree(f);
    }

    free(flow_hash);
    flow_memuse -= flow_config.hash_size * sizeof(FlowBucket);

    pthread_mutex_destroy(&flow_memuse_mutex);
}

/** \brief Thread that manages the various queue's and removes timed out flows.
 *  \param td ThreadVars casted to void ptr
 *
 * IDEAS/TODO
 * Create a 'emergency mode' in which flow handling threads can indicate
 * we are/seem to be under attack..... maybe this thread should check
 * key indicators for that like:
 * - number of flows created in the last x time
 * - avg number of pkts per flow (how?)
 * - avg flow age
 *
 * Keep an eye on the spare list, alloc flows if needed...
 */
void *FlowManagerThread(void *td)
{
    ThreadVars *th_v = (ThreadVars *)td;
    struct timeval ts;
    uint32_t established_cnt = 0, new_cnt = 0, nowcnt;
    uint32_t sleeping = 0;
    uint8_t emerg = FALSE;

    printf("%s started...\n", th_v->name);

    while (1)
    {
        TmThreadTestThreadUnPaused(th_v);

        if (sleeping >= 100 || flow_flags & FLOW_EMERGENCY)
        {
            /*uint32_t timeout_new = flow_config.timeout_new;
            uint32_t timeout_est = flow_config.timeout_est;
            printf("The Timeout values are %" PRIu32" and %" PRIu32"\n", timeout_est, timeout_new);*/
            if (flow_flags & FLOW_EMERGENCY) {
                emerg = TRUE;
                printf("Flow emergency mode entered...\n");
            }

            /* Get the time */
            memset(&ts, 0, sizeof(ts));
            TimeGet(&ts);
            DEBUGPRINT("ts %" PRId64 "", ts.tv_sec);

            /* see if we still have enough spare flows
            if (!(FlowUpdateSpareFlows()) && emerg == TRUE) {
                timeout_new = flow_config.emerg_timeout_new;
                timeout_est = flow_config.emerg_timeout_est;
            }*/

            /* prune new list */
            nowcnt = FlowPruneFlows(&flow_new_q, &ts);
            if (nowcnt) {
                DEBUGPRINT("Pruned %" PRIu32 " new flows...\n", nowcnt);
                new_cnt += nowcnt;
            }

            /* prune established list */
            nowcnt = FlowPruneFlows(&flow_est_q, &ts);
            if (nowcnt) {
                DEBUGPRINT("Pruned %" PRIu32 " established flows...\n", nowcnt);
                established_cnt += nowcnt;
            }

            sleeping = 0;

            /* Don't fear, FlowManagerThread is here...
             * clear emergency bit. */
            if (emerg == TRUE) {
                flow_flags &= ~FLOW_EMERGENCY;
                emerg = FALSE;
                printf("Flow emergency mode over, back to normal...\n");
            }
        }

        if (th_v->flags & THV_KILL) {
            break;
        }

        usleep(10);
        sleeping += 10;
    }

    printf("* %s ended: %" PRIu32 " new flows, %" PRIu32 " established flows were pruned\n", th_v->name, new_cnt, established_cnt);
    pthread_exit((void *) 0);
}

/** \brief spawn the flow manager thread */
void FlowManagerThreadSpawn()
{
    ThreadVars *tv_flowmgr = NULL;

    tv_flowmgr = TmThreadCreateMgmtThread("FlowManagerThread", FlowManagerThread, 0);

    if (tv_flowmgr == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_flowmgr) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return;
}

void FlowInitProtocols(void) {
    /*XXX GS initialze protocol specific free function pointers*/
    /*Default*/
    protocols[0].new_timeout = FLOW_DEFAULT_NEW_TIMEOUT;
    protocols[0].est_timeout = FLOW_DEFAULT_EST_TIMEOUT;
    protocols[0].emerg_new_timeout = FLOW_DEFAULT_EMERG_NEW_TIMEOUT;
    protocols[0].emerg_est_timeout = FLOW_DEFAULT_EMERG_EST_TIMEOUT;
    protocols[0].Freefunc = "";
    /*TCP*/
    protocols[1].new_timeout = FLOW_IPPROTO_TCP_NEW_TIMEOUT;
    protocols[1].est_timeout = FLOW_IPPROTO_TCP_EST_TIMEOUT;
    protocols[1].emerg_new_timeout = FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT;
    protocols[1].emerg_est_timeout = FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT;
    protocols[1].Freefunc = StreamTcpSessionPoolFree;
    /*UDP*/
    protocols[2].new_timeout = FLOW_IPPROTO_UDP_NEW_TIMEOUT;
    protocols[2].est_timeout = FLOW_IPPROTO_UDP_EST_TIMEOUT;
    protocols[2].emerg_new_timeout = FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT;
    protocols[2].emerg_est_timeout = FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT;
    protocols[2].Freefunc = "";
    /*ICMP*/
    protocols[3].new_timeout = FLOW_IPPROTO_ICMP_NEW_TIMEOUT;
    protocols[3].est_timeout = FLOW_IPPROTO_ICMP_EST_TIMEOUT;
    protocols[3].emerg_new_timeout = FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT;
    protocols[3].emerg_est_timeout = FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT;
    protocols[3].Freefunc = "";

}

int FlowSetProtoFreeFunc (uint8_t proto, Flow *f, void (*Free)(void *)) {
    /*XXX GS WIP*/
    //uint8_t proto_map;
    //proto_map = FlowGetProtoMapping(proto);
    Free(f->stream);
    memset(f, 0, sizeof(Flow));
    //FlowSetProtoFreeFunc(f->proto, );
    return 1;
}

int FlowSetProtoTimeout(uint8_t proto, uint32_t new_timeout, uint32_t est_timeout) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    protocols[proto_map].new_timeout = new_timeout;
    protocols[proto_map].est_timeout = est_timeout;

    return 1;
}

int FlowSetProtoEmergencyTimeout(uint8_t proto, uint32_t new_timeout, uint32_t est_timeout) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    protocols[proto_map].emerg_new_timeout = new_timeout;
    protocols[proto_map].emerg_est_timeout = est_timeout;

    return 1;
}

static int FlowGetProtoMapping(uint8_t proto) {

    switch (proto) {
        case IPPROTO_TCP:
            return 1;
        case IPPROTO_UDP:
            return 2;
        case IPPROTO_ICMP:
            return 3;
        default:
            return 0;
    }
}
static int FlowTest01 (void) {

    uint8_t proto_map;

    FlowInitConfig(TRUE);
    proto_map = FlowGetProtoMapping(IPPROTO_TCP);

    if ((protocols[proto_map].new_timeout != FLOW_IPPROTO_TCP_NEW_TIMEOUT) && (protocols[proto_map].est_timeout != FLOW_IPPROTO_TCP_EST_TIMEOUT)
            && (protocols[proto_map].emerg_new_timeout != FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT) && (protocols[proto_map].emerg_est_timeout != FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting TCP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_UDP);
    if ((protocols[proto_map].new_timeout != FLOW_IPPROTO_UDP_NEW_TIMEOUT) && (protocols[proto_map].est_timeout != FLOW_IPPROTO_UDP_EST_TIMEOUT)
            && (protocols[proto_map].emerg_new_timeout != FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT) && (protocols[proto_map].emerg_est_timeout != FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting UDP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_ICMP);
    if ((protocols[proto_map].new_timeout != FLOW_IPPROTO_ICMP_NEW_TIMEOUT) && (protocols[proto_map].est_timeout != FLOW_IPPROTO_ICMP_EST_TIMEOUT)
            && (protocols[proto_map].emerg_new_timeout != FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT) && (protocols[proto_map].emerg_est_timeout != FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting ICMP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_DCCP);
    if ((protocols[proto_map].new_timeout != FLOW_DEFAULT_NEW_TIMEOUT) && (protocols[proto_map].est_timeout != FLOW_DEFAULT_EST_TIMEOUT)
            && (protocols[proto_map].emerg_new_timeout != FLOW_DEFAULT_EMERG_NEW_TIMEOUT) && (protocols[proto_map].emerg_est_timeout != FLOW_DEFAULT_EMERG_EST_TIMEOUT)){
        printf ("failed in setting default flow timeout");
        return 0;
    }

    return 1;
}
void FlowRegisterTests (void) {
    UtRegisterTest("FlowTest01 -- Protocol Specific Timeouts", FlowTest01, 1);
}