/** Copyright (c) 2008 Victor Julien <victor@inliniac.net>
 *  \file
 *  Flow implementation.
 *
 *  IDEAS:
 *  - Maybe place the flow that we get a packet for on top of the
 *    list in the bucket. This rewards active flows.
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "util-random.h"
#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"
#include "util-unittest.h"

#include "util-debug.h"

//#define FLOW_DEFAULT_HASHSIZE    262144
#define FLOW_DEFAULT_HASHSIZE    65536
//#define FLOW_DEFAULT_MEMCAP      128 * 1024 * 1024 /* 128 MB */
#define FLOW_DEFAULT_MEMCAP      32 * 1024 * 1024 /* 32 MB */

#define FLOW_DEFAULT_PREALLOC    10000

void FlowRegisterTests (void);
void FlowInitFlowProto();
static int FlowUpdateSpareFlows(void);
int FlowSetProtoTimeout(uint8_t , uint32_t ,uint32_t ,uint32_t);
int FlowSetProtoEmergencyTimeout(uint8_t , uint32_t ,uint32_t ,uint32_t);
static int FlowClearMemory(Flow *,uint8_t );
int FlowSetProtoFreeFunc(uint8_t, void (*Free)(void *));
int FlowSetFlowStateFunc (uint8_t , int (*GetProtoState)(void *));

/** \brief Update the flows position in the queue's
 *  \param f Flow to requeue.
 *  \todo if we have a flow state func rely on that soly
 *
 *  In-use flows are in the flow_new_q, flow_est_q lists or flow_close_q lists.
 */
void FlowUpdateQueue(Flow *f)
{
    if (f->flags & FLOW_NEW_LIST) {
        /* in the new list -- we consider a flow no longer
         * new if we have seen at least 2 pkts in both ways. */
        if (f->todstpktcnt && f->tosrcpktcnt) {
            FlowRequeue(f, &flow_new_q[f->protomap], &flow_est_q[f->protomap]);

            f->flags |= FLOW_EST_LIST; /* transition */
            f->flags &= ~FLOW_NEW_LIST;
        } else {
            FlowRequeue(f, &flow_new_q[f->protomap], &flow_new_q[f->protomap]);
        }
    } else if (f->flags & FLOW_EST_LIST) {
        if (flow_proto[f->protomap].GetProtoState != NULL) {
            uint8_t state = flow_proto[f->protomap].GetProtoState(f->protoctx);
            if (state == FLOW_STATE_CLOSED) {
                f->flags |= FLOW_CLOSED_LIST; /* transition */
                f->flags &= ~FLOW_EST_LIST;

                //printf("FlowUpdateQueue %p was put into closing queue ts %"PRIuMAX"\n", f, (uintmax_t)f->lastts.tv_sec);
                FlowRequeue(f, &flow_est_q[f->protomap], &flow_close_q[f->protomap]);
            } else {
                /* Pull and put back -- this way the flows on
                 * top of the list are least recently used. */
                FlowRequeue(f, &flow_est_q[f->protomap], &flow_est_q[f->protomap]);
            }
        } else {
            /* Pull and put back -- this way the flows on
             * top of the list are least recently used. */
            FlowRequeue(f, &flow_est_q[f->protomap], &flow_est_q[f->protomap]);
        }
    } else if (f->flags & FLOW_CLOSED_LIST){
        /* Pull and put back -- this way the flows on
         * top of the list are least recently used. */
        FlowRequeue(f, &flow_close_q[f->protomap], &flow_close_q[f->protomap]);
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
    int mr = SCMutexTrylock(&q->mutex_q);
    if (mr != 0) {
        SCLogDebug("trylock failed");
        if (mr == EBUSY)
            SCLogDebug("was locked");
        if (mr == EINVAL)
            SCLogDebug("bad mutex value");
        return 0;
    }

    Flow *f = q->top;
    if (f == NULL) {
        SCMutexUnlock(&q->mutex_q);
        SCLogDebug("top is null");
        return 0;
    }
    if (SCMutexTrylock(&f->m) != 0) {
        SCLogDebug("cant lock 1");
        SCMutexUnlock(&q->mutex_q);
        return 0;
    }

    /* unlock list */
    SCMutexUnlock(&q->mutex_q);

    if (SCMutexTrylock(&f->fb->m) != 0) {
        SCMutexUnlock(&f->m);
        SCLogDebug("cant lock 2");
        return 0;
    }

    /*set the timeout value according to the flow operating mode, flow's state
      and protocol.*/
    uint32_t timeout = 0;

    if (flow_flags & FLOW_EMERGENCY) {
        if (flow_proto[f->protomap].GetProtoState != NULL) {
            switch(flow_proto[f->protomap].GetProtoState(f->protoctx)) {
                case FLOW_STATE_NEW:
                    timeout = flow_proto[f->protomap].emerg_new_timeout;
                    break;
                case FLOW_STATE_ESTABLISHED:
                    timeout = flow_proto[f->protomap].emerg_est_timeout;
                    break;
                case FLOW_STATE_CLOSED:
                    timeout = flow_proto[f->protomap].emerg_closed_timeout;
                    break;
            }
        } else {
            if (f->flags & FLOW_EST_LIST)
                timeout = flow_proto[f->protomap].emerg_est_timeout;
            else
                timeout = flow_proto[f->protomap].emerg_new_timeout;
        }
    } else { /* impliet not emergency */
        if (flow_proto[f->protomap].GetProtoState != NULL) {
            switch(flow_proto[f->protomap].GetProtoState(f->protoctx)) {
                case FLOW_STATE_NEW:
                    timeout = flow_proto[f->protomap].new_timeout;
                    break;
                case FLOW_STATE_ESTABLISHED:
                    timeout = flow_proto[f->protomap].est_timeout;
                    break;
                case FLOW_STATE_CLOSED:
                    timeout = flow_proto[f->protomap].closed_timeout;
                    break;
            }
        } else {
            if (f->flags & FLOW_EST_LIST)
                timeout = flow_proto[f->protomap].est_timeout;
            else
                timeout = flow_proto[f->protomap].new_timeout;
        }
    }

    SCLogDebug("got lock, now check: %" PRIdMAX "+%" PRIu32 "=(%" PRIdMAX ") < %" PRIdMAX "", (intmax_t)f->lastts.tv_sec,
        timeout, (intmax_t)f->lastts.tv_sec + timeout, (intmax_t)ts->tv_sec);

    /* do the timeout check */
    if ((f->lastts.tv_sec + timeout) >= ts->tv_sec) {
        SCMutexUnlock(&f->fb->m);
        SCMutexUnlock(&f->m);
        SCLogDebug("timeout check failed");
        return 0;
    }

    /** never prune a flow that is used by a packet or stream msg
     *  we are currently processing in one of the threads */
    if (f->use_cnt > 0) {
        SCLogDebug("timed out but use_cnt > 0: %"PRIu16", %p, proto %"PRIu8"", f->use_cnt, f, f->proto);
        SCMutexUnlock(&f->fb->m);
        SCMutexUnlock(&f->m);
        SCLogDebug("it is in one of the threads");
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

    SCMutexUnlock(&f->fb->m);
    f->fb = NULL;

    FlowClearMemory (f, f->protomap);

    /* move to spare list */
    FlowRequeue(f, q, &flow_spare_q);

    SCMutexUnlock(&f->m);
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

    SCMutexLock(&flow_spare_q.mutex_q);

    len = flow_spare_q.len;

    SCMutexUnlock(&flow_spare_q.mutex_q);

    if (len < flow_config.prealloc) {
        toalloc = flow_config.prealloc - len;

        uint32_t i;
        for (i = 0; i < toalloc; i++) {
            Flow *f = FlowAlloc();
            if (f == NULL)
                return 0;

            SCMutexLock(&flow_spare_q.mutex_q);
            FlowEnqueue(&flow_spare_q,f);
            SCMutexUnlock(&flow_spare_q.mutex_q);
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
    SCMutexLock(&f->m);
    direction ? (f->flags |= FLOW_TOSERVER_IPONLY_SET) : (f->flags |= FLOW_TOCLIENT_IPONLY_SET);
    SCMutexUnlock(&f->m);
}

/** \brief increase the use cnt of a flow
 *  \param tv thread vars (\todo unused?)
 *  \param p packet with flow to decrease use cnt for
 */
void FlowIncrUsecnt(ThreadVars *tv, Packet *p) {
    if (p == NULL || p->flow == NULL)
        return;

    SCMutexLock(&p->flow->m);
    p->flow->use_cnt++;
    SCMutexUnlock(&p->flow->m);
}
/** \brief decrease the use cnt of a flow
 *  \param tv thread vars (\todo unused?)
 *  \param p packet with flow to decrease use cnt for
 */
void FlowDecrUsecnt(ThreadVars *tv, Packet *p) {
    if (p == NULL || p->flow == NULL)
        return;

    SCMutexLock(&p->flow->m);
    if (p->flow->use_cnt > 0)
        p->flow->use_cnt--;
    SCMutexUnlock(&p->flow->m);
}

#define TOSERVER 0
#define TOCLIENT 1

/**
 *  \brief determine the direction of the packet compared to the flow
 *  \retval 0 to_server
 *  \retval 1 to_client
 */
static inline int FlowGetPacketDirection(Flow *f, Packet *p) {
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
        if (!(CMP_PORT(p->sp,p->dp))) {
            /* update flags and counters */
            if (CMP_PORT(f->sp,p->sp)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        } else {
            if (CMP_ADDR(&f->src,&p->src)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        }
    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        if (CMP_ADDR(&f->src,&p->src)) {
            return TOSERVER;
        } else {
            return TOCLIENT;
        }
    }

    /* default to toserver */
    return TOSERVER;
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
    if (FlowGetPacketDirection(f,p) == TOSERVER) {
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

    /*set the detection bypass flags*/
    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        SCLogDebug("setting FLOW_NOPACKET_INSPECTION flag on flow %p", f);
        DecodeSetNoPacketInspectionFlag(p);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        SCLogDebug("setting FLOW_NOPAYLOAD_INSPECTION flag on flow %p", f);
        DecodeSetNoPayloadInspectionFlag(p);
    }

    /* set the flow in the packet */
    p->flow = f;

    SCMutexUnlock(&f->m);
}

/** \brief initialize the configuration
 *  \warning Not thread safe */
void FlowInitConfig (char quiet)
{
    if (quiet == FALSE)
        SCLogInfo("initializing flow engine...");

    memset(&flow_config,  0, sizeof(flow_config));
    flow_memuse = 0;

    int ifq = 0;
    FlowQueueInit(&flow_spare_q);
    for (ifq = 0; ifq < FLOW_PROTO_MAX; ifq++) {
        FlowQueueInit(&flow_new_q[ifq]);
        FlowQueueInit(&flow_est_q[ifq]);
        FlowQueueInit(&flow_close_q[ifq]);
    }
    SCMutexInit(&flow_memuse_mutex, NULL);

    unsigned int seed = RandomTimePreseed();
    /* set defaults */
    flow_config.hash_rand   = (int)( FLOW_DEFAULT_HASHSIZE * (rand_r(&seed) / RAND_MAX + 1.0));

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
    uint32_t i = 0;

    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));
    for (i = 0; i < flow_config.hash_size; i++)
        SCMutexInit(&flow_hash[i].m, NULL);
    flow_config.memuse += (flow_config.hash_size * sizeof(FlowBucket));

    if (quiet == FALSE)
        SCLogInfo("allocated %" PRIu32 " bytes of memory for the flow hash... %" PRIu32 " buckets of size %" PRIuMAX "",
            flow_config.memuse, flow_config.hash_size, (uintmax_t)sizeof(FlowBucket));

    /* pre allocate flows */
    for (i = 0; i < flow_config.prealloc; i++) {
        Flow *f = FlowAlloc();
        if (f == NULL) {
            printf("ERROR: FlowAlloc failed: %s\n", strerror(errno));
            exit(1);
        }
        FlowEnqueue(&flow_spare_q,f);
    }

    if (quiet == FALSE) {
        SCLogInfo("preallocated %" PRIu32 " flows of size %" PRIuMAX "",
                flow_spare_q.len, (uintmax_t)sizeof(Flow));
        SCLogInfo("flow memory usage: %" PRIu32 " bytes, maximum: %" PRIu32 "",
                flow_config.memuse, flow_config.memcap);
    }

    FlowInitFlowProto();

}

/** \brief print some flow stats
 *  \warning Not thread safe */
void FlowPrintQueueInfo (void)
{
    int i;
    SCLogInfo("flow queue info:");
    SCLogInfo("spare flow queue %" PRIu32 "", flow_spare_q.len);
#ifdef DBG_PERF
    SCLogInfo("flow_spare_q.dbg_maxlen %" PRIu32 "", flow_spare_q.dbg_maxlen);
#endif
    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        SCLogInfo("proto [%"PRId32"] new flow queue %" PRIu32 " "
#ifdef DBG_PERF
                  " - flow_new_q.dbg_maxlen %" PRIu32 ""
#endif
                  ,i,flow_new_q[i].len
#ifdef DBG_PERF
                  ,flow_new_q[i].dbg_maxlen
#endif
                  );

        SCLogInfo("proto [%"PRId32"] establised flow queue %" PRIu32 " "
#ifdef DBG_PERF
                  " - flow_est_q.dbg_maxlen %" PRIu32 ""
#endif
                  ,i,flow_est_q[i].len
#ifdef DBG_PERF
                  ,flow_est_q[i].dbg_maxlen
#endif
                  );

        SCLogInfo("proto [%"PRId32"] closing flow queue %" PRIu32 " "
#ifdef DBG_PERF
                  " - flow_closing_q.dbg_maxlen %" PRIu32 ""
#endif
                  ,i,flow_close_q[i].len
#ifdef DBG_PERF
                  ,flow_close_q[i].dbg_maxlen
#endif
                  );

    }
#ifdef FLOWBITS_STATS
    SCLogInfo("flowbits added: %" PRIu32 ", removed: %" PRIu32 ", max memory usage: %" PRIu32 "",
        flowbits_added, flowbits_removed, flowbits_memuse_max);
#endif /* FLOWBITS_STATS */
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void FlowShutdown(void) {
    Flow *f;
    int i;

    while((f = FlowDequeue(&flow_spare_q))) {
        FlowFree(f);
    }
    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        while((f = FlowDequeue(&flow_new_q[i]))) {
            uint8_t proto_map = FlowGetProtoMapping(f->proto);
            FlowClearMemory(f, proto_map);
            FlowFree(f);
        }
        while((f = FlowDequeue(&flow_est_q[i]))) {
            uint8_t proto_map = FlowGetProtoMapping(f->proto);
            FlowClearMemory(f, proto_map);
            FlowFree(f);
        }
        while((f = FlowDequeue(&flow_close_q[i]))) {
            uint8_t proto_map = FlowGetProtoMapping(f->proto);
            FlowClearMemory(f, proto_map);
            FlowFree(f);
        }
    }

    free(flow_hash);
    flow_memuse -= flow_config.hash_size * sizeof(FlowBucket);

    SCMutexDestroy(&flow_memuse_mutex);
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
    uint32_t established_cnt = 0, new_cnt = 0, closing_cnt = 0, nowcnt;
    uint32_t sleeping = 0;
    uint8_t emerg = FALSE;

    SCLogDebug("%s started...", th_v->name);

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
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
            SCLogDebug("ts %" PRIdMAX "", (intmax_t)ts.tv_sec);

            /* see if we still have enough spare flows */
            FlowUpdateSpareFlows();

            int i;
            for (i = 0; i < FLOW_PROTO_MAX; i++) {
                /* prune closing list */
                nowcnt = FlowPruneFlows(&flow_close_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " closing flows...", nowcnt);
                    closing_cnt += nowcnt;
                }

                /* prune new list */
                nowcnt = FlowPruneFlows(&flow_new_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " new flows...", nowcnt);
                    new_cnt += nowcnt;
                }

                /* prune established list */
                nowcnt = FlowPruneFlows(&flow_est_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " established flows...", nowcnt);
                    established_cnt += nowcnt;
                }
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

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            SCPerfUpdateCounterArray(th_v->sc_perf_pca, &th_v->sc_perf_pctx, 0);
            break;
        }

        usleep(10);
        sleeping += 10;
    }

    SCLogInfo("%" PRIu32 " new flows, %" PRIu32 " established flows were timed out", new_cnt, established_cnt);
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
    if (TmThreadSpawn(tv_flowmgr) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return;
}

/**
 *  \brief  Function to set the default timeout, free function and flow state
 *          function for all supported flow_proto.
 */

void FlowInitFlowProto(void) {
    /*Default*/
    flow_proto[FLOW_PROTO_DEFAULT].new_timeout = FLOW_DEFAULT_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].est_timeout = FLOW_DEFAULT_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_new_timeout = FLOW_DEFAULT_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_est_timeout = FLOW_DEFAULT_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].emerg_closed_timeout = FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_DEFAULT].Freefunc = NULL;
    flow_proto[FLOW_PROTO_DEFAULT].GetProtoState = NULL;
    /*TCP*/
    flow_proto[FLOW_PROTO_TCP].new_timeout = FLOW_IPPROTO_TCP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].est_timeout = FLOW_IPPROTO_TCP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_new_timeout = FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_est_timeout = FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].emerg_closed_timeout = FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_TCP].Freefunc = NULL;
    flow_proto[FLOW_PROTO_TCP].GetProtoState = NULL;
    /*UDP*/
    flow_proto[FLOW_PROTO_UDP].new_timeout = FLOW_IPPROTO_UDP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].est_timeout = FLOW_IPPROTO_UDP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_new_timeout = FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_est_timeout = FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].emerg_closed_timeout = FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_UDP].Freefunc = NULL;
    flow_proto[FLOW_PROTO_UDP].GetProtoState = NULL;
    /*ICMP*/
    flow_proto[FLOW_PROTO_ICMP].new_timeout = FLOW_IPPROTO_ICMP_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].est_timeout = FLOW_IPPROTO_ICMP_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].closed_timeout = FLOW_DEFAULT_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_new_timeout = FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_est_timeout = FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].emerg_closed_timeout = FLOW_DEFAULT_EMERG_CLOSED_TIMEOUT;
    flow_proto[FLOW_PROTO_ICMP].Freefunc = NULL;
    flow_proto[FLOW_PROTO_ICMP].GetProtoState = NULL;
}

/**
 *  \brief  Function clear the flow memory before queueing it to spare flow
 *          queue.
 *
 *  \param  f           pointer to the flow needed to be cleared.
 *  \param  proto_map   mapped value of the protocol to FLOW_PROTO's.
 */

static int FlowClearMemory(Flow* f, uint8_t proto_map) {
    SCEnter();

    /* call the protocol specific free function if we have one */
    if (flow_proto[proto_map].Freefunc != NULL) {
        flow_proto[proto_map].Freefunc(f->protoctx);
    }
    f->protoctx = NULL;

    CLEAR_FLOW(f);
    SCReturnInt(1);
}

/**
 *  \brief  Function to set the function to get protocol specific flow state.
 *
 *  \param   proto  protocol of which function is needed to be set.
 *  \param   Free   Function pointer which will be called to free the protocol
 *                  specific memory.
 */

int FlowSetProtoFreeFunc (uint8_t proto, void (*Free)(void *)) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].Freefunc = Free;
    return 1;
}

/**
 *  \brief  Function to set the function to get protocol specific flow state.
 *
 *  \param   proto            protocol of which function is needed to be set.
 *  \param   GetFlowState     Function pointer which will be called to get state.
 */

int FlowSetFlowStateFunc (uint8_t proto, int (*GetProtoState)(void *)) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].GetProtoState = GetProtoState;
    return 1;
}

/**
 *  \brief   Function to set the timeout values for the specified protocol.
 *
 *  \param   proto            protocol of which timeout value is needed to be set.
 *  \param   new_timeout      timeout value for the new flows.
 *  \param   est_timeout      timeout value for the established flows.
 *  \param   closed_timeout   timeout value for the closed flows.
 */

int FlowSetProtoTimeout(uint8_t proto, uint32_t new_timeout, uint32_t est_timeout, uint32_t closed_timeout) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].new_timeout = new_timeout;
    flow_proto[proto_map].est_timeout = est_timeout;
    flow_proto[proto_map].closed_timeout = closed_timeout;

    return 1;
}

/**
 *  \brief   Function to set the emergency timeout values for the specified
 *           protocol.
 *
 *  \param   proto                  protocol of which timeout value is needed to be set.
 *  \param   emerg_new_timeout      timeout value for the new flows.
 *  \param   emerg_est_timeout      timeout value for the established flows.
 *  \param   emerg_closed_timeout   timeout value for the closed flows.
 */

int FlowSetProtoEmergencyTimeout(uint8_t proto, uint32_t emerg_new_timeout, uint32_t emerg_est_timeout, uint32_t emerg_closed_timeout) {

    uint8_t proto_map;
    proto_map = FlowGetProtoMapping(proto);

    flow_proto[proto_map].emerg_new_timeout = emerg_new_timeout;
    flow_proto[proto_map].emerg_est_timeout = emerg_est_timeout;
    flow_proto[proto_map].emerg_closed_timeout = emerg_closed_timeout;

    return 1;
}

/** \brief Set the No Packet Inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
void FlowLockSetNoPacketInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    SCMutexLock(&f->m);
    f->flags |= FLOW_NOPACKET_INSPECTION;
    SCMutexUnlock(&f->m);

    SCReturn;
}

/** \brief Set the No Packet Inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
void FlowSetNoPacketInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPACKET_INSPECTION;

    SCReturn;
}

/** \brief Set the No payload inspection Flag after locking the flow.
 *
 * \param f Flow to set the flag in
 */
void FlowLockSetNoPayloadInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    SCMutexLock(&f->m);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;
    SCMutexUnlock(&f->m);

    SCReturn;
}

/** \brief Set the No payload inspection Flag without locking the flow.
 *
 * \param f Flow to set the flag in
 */
void FlowSetNoPayloadInspectionFlag(Flow *f) {
    SCEnter();

    SCLogDebug("flow %p", f);
    f->flags |= FLOW_NOPAYLOAD_INSPECTION;

    SCReturn;
}

#ifdef UNITTESTS
#include "stream-tcp-private.h"
#include "threads.h"

/**
 *  \test   Test the setting of the per protocol timeouts.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest01 (void) {

    uint8_t proto_map;

    FlowInitFlowProto();
    proto_map = FlowGetProtoMapping(IPPROTO_TCP);

    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_TCP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_TCP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_TCP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_TCP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting TCP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_UDP);
    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_UDP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_UDP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_UDP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_UDP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting UDP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_ICMP);
    if ((flow_proto[proto_map].new_timeout != FLOW_IPPROTO_ICMP_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_IPPROTO_ICMP_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_IPPROTO_ICMP_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_IPPROTO_ICMP_EMERG_EST_TIMEOUT)){
        printf ("failed in setting ICMP flow timeout");
        return 0;
    }

    proto_map = FlowGetProtoMapping(IPPROTO_DCCP);
    if ((flow_proto[proto_map].new_timeout != FLOW_DEFAULT_NEW_TIMEOUT) && (flow_proto[proto_map].est_timeout != FLOW_DEFAULT_EST_TIMEOUT)
            && (flow_proto[proto_map].emerg_new_timeout != FLOW_DEFAULT_EMERG_NEW_TIMEOUT) && (flow_proto[proto_map].emerg_est_timeout != FLOW_DEFAULT_EMERG_EST_TIMEOUT)){
        printf ("failed in setting default flow timeout");
        return 0;
    }

    return 1;
}

/*Test function for the unit test FlowTest02*/

void test(void *f){}

/**
 *  \test   Test the setting of the per protocol free function to free the
 *          protocol specific memory.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest02 (void) {

    FlowSetProtoFreeFunc(IPPROTO_DCCP, test);
    FlowSetProtoFreeFunc(IPPROTO_TCP, test);
    FlowSetProtoFreeFunc(IPPROTO_UDP, test);
    FlowSetProtoFreeFunc(IPPROTO_ICMP, test);

    if (flow_proto[FLOW_PROTO_DEFAULT].Freefunc != test) {
        printf("Failed in setting default free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_TCP].Freefunc != test) {
        printf("Failed in setting TCP free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_UDP].Freefunc != test) {
        printf("Failed in setting UDP free function\n");
        return 0;
    }
    if (flow_proto[FLOW_PROTO_ICMP].Freefunc != test) {
        printf("Failed in setting ICMP free function\n");
        return 0;
    }
    return 1;
}

/**
 *  \brief   Function to test the prunning of the flow in different flow modes.
 *
 *  \param   f    Pointer to the flow to be prunned
 *  \param   ts   time value against which the flow will be checked
 *
 *  \retval on success returns 1 and on failure 0
 */

static int FlowTestPrune(Flow *f, struct timeval *ts) {

    FlowQueue *q = FlowQueueNew();

    int r = SCMutexInit(&q->mutex_q, NULL);

    if (r != 0) {
        SCLogDebug("Error initializing mutex!");
        return 0;
    }

    q->top = NULL;

    FlowEnqueue(q, f);
    if (q->len != 1) {
        printf("Failed in enqueue the flow in flowqueue\n");
        return 0;
    }

    FlowPrune(q, ts);
    if (q->len != 0) {
        printf("Failed in prunning the flow\n");
        return 0;
    }

    if (f->protoctx != NULL){
        printf("Failed in freeing the TcpSession\n");
        return 0;
    }
    return 1;
}

/**
 *  \test   Test the timing out of a flow with a fresh TcpSession
 *          (just initialized, no data segments) in normal mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest03 (void) {

    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));
    SCMutexInit(&f.m, NULL);

    TimeGet(&ts);
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    SCMutexInit(&fb.m, NULL);
    f.fb = &fb;

    f.proto = IPPROTO_TCP;

    if (FlowTestPrune(&f, &ts) != 1)
        return 0;

    return 1;
}

/**
 *  \test   Test the timing out of a flow with a TcpSession
 *          (with data segments) in normal mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest04 (void) {

    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;
    TcpSegment seg;
    TcpStream client;
    uint8_t payload[3] = {0x41, 0x41, 0x41};

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    SCMutexInit(&f.m, NULL);
    SCMutexInit(&fb.m, NULL);

    TimeGet(&ts);
    seg.payload = payload;
    seg.payload_len = 3;
    seg.next = NULL;
    seg.prev = NULL;
    client.seg_list = &seg;
    ssn.client = client;
    ssn.server = client;
    ssn.state = TCP_ESTABLISHED;
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;

    if (FlowTestPrune(&f, &ts) != 1)
        return 0;

    return 1;

}

/**
 *  \test   Test the timing out of a flow with a fresh TcpSession
 *          (just initialized, no data segments) in emergency mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest05 (void) {

    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));

    SCMutexInit(&f.m, NULL);
    SCMutexInit(&fb.m, NULL);

    TimeGet(&ts);
    ssn.state = TCP_SYN_SENT;
    f.lastts.tv_sec = ts.tv_sec - 300;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;
    f.flags = FLOW_EMERGENCY;

    if (FlowTestPrune(&f, &ts) != 1)
        return 0;

    return 1;
}

/**
 *  \test   Test the timing out of a flow with a TcpSession
 *          (with data segments) in emergency mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest06 (void) {

    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;
    TcpSegment seg;
    TcpStream client;
    uint8_t payload[3] = {0x41, 0x41, 0x41};

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    SCMutexInit(&fb.m, NULL);
    SCMutexInit(&f.m, NULL);

    TimeGet(&ts);
    seg.payload = payload;
    seg.payload_len = 3;
    seg.next = NULL;
    seg.prev = NULL;
    client.seg_list = &seg;
    ssn.client = client;
    ssn.server = client;
    ssn.state = TCP_ESTABLISHED;
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;
    f.flags = FLOW_EMERGENCY;

    if (FlowTestPrune(&f, &ts) != 1)
        return 0;

    return 1;

}
#endif /* UNITTESTS */

/**
 *  \brief   Function to register the Flow Unitests.
 */
void FlowRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("FlowTest01 -- Protocol Specific Timeouts", FlowTest01, 1);
    UtRegisterTest("FlowTest02 -- Setting Protocol Specific Free Function", FlowTest02, 1);
    UtRegisterTest("FlowTest03 -- Timeout a flow having fresh TcpSession", FlowTest03, 1);
    UtRegisterTest("FlowTest04 -- Timeout a flow having TcpSession with segments", FlowTest04, 1);
    UtRegisterTest("FlowTest05 -- Timeout a flow in emergency having fresh TcpSession", FlowTest05, 1);
    UtRegisterTest("FlowTest06 -- Timeout a flow in emergency having TcpSession with segments", FlowTest06, 1);
#endif /* UNITTESTS */
}
