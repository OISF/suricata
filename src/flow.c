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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Flow implementation.
 *
 *  \todo Maybe place the flow that we get a packet for on top of the
 *    list in the bucket. This rewards active flows.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "conf.h"
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
#include "util-unittest-helper.h"
#include "util-byte.h"

#include "util-debug.h"
#include "util-privs.h"

#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-parser.h"

#define FLOW_DEFAULT_EMERGENCY_RECOVERY 30
#define FLOW_DEFAULT_FLOW_PRUNE 5

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
static uint32_t FlowPruneFlowQueueCnt(FlowQueue *, struct timeval *, int);
int FlowKill (FlowQueue *);

/* Run mode selected at suricata.c */
extern int run_mode;

/** \brief Initialize the l7data ptr in the Flow session used by the L7 Modules
 *         for data storage.
 *
 *  \param f Flow to init the ptrs for
 *  \param cnt number of items in the array
 *
 *  \todo VJ use a pool?
 */
void FlowL7DataPtrInit(Flow *f) {
    if (f->aldata != NULL)
        return;

    uint32_t size = (uint32_t)(sizeof (void *) * AppLayerGetStorageSize());

/////////XXXPR pass to flow memcap   if (StreamTcpCheckMemcap(size) == 0)
/////////XXXPR pass to flow memcap        return;

    f->aldata = (void **) SCMalloc(size);
    if (f->aldata != NULL) {
      //  StreamTcpIncrMemuse(size);

        uint8_t u;
        for (u = 0; u < AppLayerGetStorageSize(); u++) {
            f->aldata[u] = NULL;
        }
    }
}

void FlowL7DataPtrFree(Flow *f) {
    if (f == NULL)
        return;

    if (f->aldata == NULL)
        return;

    AppLayerParserCleanupState(f);
    SCFree(f->aldata);
    f->aldata = NULL;

   //// uint32_t size = (uint32_t)(sizeof (void *) * StreamL7GetStorageSize());
////    StreamTcpDecrMemuse(size);
}

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
            FlowRequeue(f, &flow_new_q[f->protomap], &flow_est_q[f->protomap], 1);

            f->flags |= FLOW_EST_LIST; /* transition */
            f->flags &= ~FLOW_NEW_LIST;
        } else {
            FlowRequeue(f, &flow_new_q[f->protomap], &flow_new_q[f->protomap], 1);
        }
    } else if (f->flags & FLOW_EST_LIST) {
        if (flow_proto[f->protomap].GetProtoState != NULL) {
            uint8_t state = flow_proto[f->protomap].GetProtoState(f->protoctx);
            if (state == FLOW_STATE_CLOSED) {
                f->flags |= FLOW_CLOSED_LIST; /* transition */
                f->flags &=~ FLOW_EST_LIST;

                SCLogDebug("flow %p was put into closing queue ts %"PRIuMAX"", f, (uintmax_t)f->lastts.tv_sec);
                FlowRequeue(f, &flow_est_q[f->protomap], &flow_close_q[f->protomap], 1);
            } else {
                /* Pull and put back -- this way the flows on
                 * top of the list are least recently used. */
                FlowRequeue(f, &flow_est_q[f->protomap], &flow_est_q[f->protomap], 1);
            }
        } else {
            /* Pull and put back -- this way the flows on
             * top of the list are least recently used. */
            FlowRequeue(f, &flow_est_q[f->protomap], &flow_est_q[f->protomap], 1);
        }
    } else if (f->flags & FLOW_CLOSED_LIST){
        /* Pull and put back -- this way the flows on
         * top of the list are least recently used. */
        FlowRequeue(f, &flow_close_q[f->protomap], &flow_close_q[f->protomap], 1);
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
    SCEnter();
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

    if (SCSpinTrylock(&f->fb->s) != 0) {
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
    if ((int32_t)(f->lastts.tv_sec + timeout) >= ts->tv_sec) {
        SCSpinUnlock(&f->fb->s);
        SCMutexUnlock(&f->m);
        SCLogDebug("timeout check failed");
        return 0;
    }

    /** never prune a flow that is used by a packet or stream msg
     *  we are currently processing in one of the threads */
    if (SC_ATOMIC_GET(f->use_cnt) > 0) {
        SCLogDebug("timed out but use_cnt > 0: %"PRIu16", %p, proto %"PRIu8"", SC_ATOMIC_GET(f->use_cnt), f, f->proto);
        SCSpinUnlock(&f->fb->s);
        SCMutexUnlock(&f->m);
        SCLogDebug("it is in one of the threads");
        return 0;
    }

    /* this should not be possible */
    BUG_ON(SC_ATOMIC_GET(f->use_cnt) > 0);

    /* remove from the hash */
    if (f->hprev)
        f->hprev->hnext = f->hnext;
    if (f->hnext)
        f->hnext->hprev = f->hprev;
    if (f->fb->f == f)
        f->fb->f = f->hnext;

    f->hnext = NULL;
    f->hprev = NULL;

    SCSpinUnlock(&f->fb->s);
    f->fb = NULL;

    FlowClearMemory (f, f->protomap);

    /* move to spare list */
    FlowRequeue(f, q, &flow_spare_q, 1);

    SCMutexUnlock(&f->m);
    return 1;
}

/** \brief Time out flows.
 *  \param q flow queue to time out flows from
 *  \param ts current time
 *  \param timeout timeout to consider
 *  \retval cnt number of flows that are timed out
 */
static uint32_t FlowPruneFlowQueue(FlowQueue *q, struct timeval *ts)
{
    SCEnter();
    uint32_t cnt = 0;
    while(FlowPrune(q, ts)) { cnt++; }
    return cnt;
}

/** \brief Time out flows on new/estabhlished/close queues for each proto until
 *         we release cnt flows as max
 *         Called from the FlowManager
 *  \param ts current time
 *  \retval cnt number of flows that are timed out
 */
uint32_t FlowPruneFlowsCnt(struct timeval *ts, int cnt)
{
    SCEnter();
    uint32_t nowcnt = 0;
    int i = 0;

    for (; i < FLOW_PROTO_MAX; i++) {
        /* prune closing list */
        nowcnt = FlowPruneFlowQueueCnt(&flow_close_q[i], ts, cnt);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;

        /* prune new list */
        nowcnt = FlowPruneFlowQueueCnt(&flow_new_q[i], ts, cnt);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;

        /* prune established list */
        nowcnt = FlowPruneFlowQueueCnt(&flow_est_q[i], ts, cnt);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;
    }
    return cnt;
}

/** \brief FlowKillFlowQueueCnt It will try to kill try_cnt count of flows
 *         It will return the number of flows released, and can be 0 or more.
 *  \param q flow queue to time out flows from
 *  \param try_cnt try to prune this number of flows
 *  \retval cnt number of flows that are timed out
 */
static uint32_t FlowKillFlowQueueCnt(FlowQueue *q, int try_cnt, uint8_t mode)
{
    SCEnter();
    uint32_t cnt = 0;
    while (try_cnt--) {
        cnt += FlowKill(q);
    }
    SCLogDebug("EMERGENCY mode, Flows killed: %"PRIu32, cnt);
    return cnt;
}

/** FlowKill
 *
 * Inspect the top flows (last recently used) from the queue
 * and see if we can prune any it (this is if it's not in use).
 *
 * Use trylock here so prevent us from blocking the packet handling.
 *
 * \param q flow queue to prune
 *
 * \retval 0 on error, failed block, nothing to prune
 * \retval 1 on successfully pruned one
 */
int FlowKill (FlowQueue *q)
{
    SCEnter();
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

    /* This means that the queue is empty */
    if (f == NULL) {
        SCMutexUnlock(&q->mutex_q);
        SCLogDebug("top is null");
        return 0;
    }

    do {

        if (SCMutexTrylock(&f->m) != 0) {
            f = f->lnext;
            /* Skip to the next */
            continue;
        }

        if (SCSpinTrylock(&f->fb->s) != 0) {
            SCMutexUnlock(&f->m);
            f = f->lnext;
            continue;
        }

        /** never prune a flow that is used by a packet or stream msg
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(f->use_cnt) > 0) {
            SCSpinUnlock(&f->fb->s);
            SCMutexUnlock(&f->m);
            f = f->lnext;
            continue;
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

        SCSpinUnlock(&f->fb->s);
        f->fb = NULL;

        FlowClearMemory (f, f->protomap);

        /* move to spare list */
        FlowRequeue(f, q, &flow_spare_q, 0);

        SCMutexUnlock(&f->m);

        /* so.. we did it */
        /* unlock list */
        SCMutexUnlock(&q->mutex_q);
        return 1;
        break;

    } while (f != NULL);

    /* If we reach this point, then we didn't prune any */
    /* unlock list */
    SCMutexUnlock(&q->mutex_q);

    return 0;
}


/** \brief Try to kill cnt flows by last recently seen activity on new/estabhlished/close queues for each proto until
 *         we release cnt flows as max. Called only on emergency mode.
 * \param cnt number of flows to release
 * \retval cnt number of flows that are not killed (so 0 if we prune all of them)
 */
uint32_t FlowKillFlowsCnt(int cnt)
{
    SCEnter();
    uint32_t nowcnt = 0;
    int i = 0;

    /* Inspect the top of each protocol to select the last recently used */
    for (; i < FLOW_PROTO_MAX; i++) {
        /* prune closing list */
        nowcnt = FlowKillFlowQueueCnt(&flow_close_q[i], cnt, 0);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;

        /* prune new list */
        nowcnt = FlowKillFlowQueueCnt(&flow_new_q[i], cnt, 0);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;

        /* prune established list */
        nowcnt = FlowKillFlowQueueCnt(&flow_est_q[i], cnt, 0);
        if (nowcnt) {
            cnt -= nowcnt;
        }
        if (cnt <= 0) break;
    }

    return cnt;
}

/** \brief Time out flows will try to prune try_cnt count of flows
 *         It will return the number of flows released, and can be 0 or more.
 *         A more agressive aproach is calling this function with the emergency
 *         bit set (and there will be another even more agressive, killing
 *         flows without the criteria of time outs)
 *  \param q flow queue to time out flows from
 *  \param ts current time
 *  \param timeout timeout to consider
 *  \param try_cnt try to prune this number of flows if they are timed out
 *  \retval cnt number of flows that are timed out
 */
static uint32_t FlowPruneFlowQueueCnt(FlowQueue *q, struct timeval *ts, int try_cnt)
{
    SCEnter();
    uint32_t cnt = 0;
    while (try_cnt--) {
        cnt += FlowPrune(q, ts);
    }
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
    SCEnter();
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
            /* FlowDequeue locks the queue */
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

/** \brief Set the IPOnly scanned flag for 'direction'.
  *
  * \param f Flow to set the flag in
  * \param direction direction to set the flag in
  */
void FlowSetIPOnlyFlagNoLock(Flow *f, char direction) {
    direction ? (f->flags |= FLOW_TOSERVER_IPONLY_SET) : (f->flags |= FLOW_TOCLIENT_IPONLY_SET);
}

/**
 *  \brief increase the use cnt of a flow
 *
 *  \param f flow to decrease use cnt for
 */
void FlowIncrUsecnt(Flow *f) {
    if (f == NULL)
        return;

    SC_ATOMIC_ADD(f->use_cnt, 1);
}
/**
 *  \brief decrease the use cnt of a flow
 *
 *  \param f flow to decrease use cnt for
 */
void FlowDecrUsecnt(Flow *f) {
    if (f == NULL)
        return;

    SC_ATOMIC_SUB(f->use_cnt, 1);
}

/**
 *  \brief determine the direction of the packet compared to the flow
 *  \retval 0 to_server
 *  \retval 1 to_client
 */
int FlowGetPacketDirection(Flow *f, Packet *p) {
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

/**
 *  \brief Check to update "seen" flags
 *
 *  \param p packet
 *
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowUpdateSeenFlag(Packet *p) {
    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
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

    /* update the last seen timestamp of this flow */
    COPY_TIMESTAMP(&p->ts, &f->lastts);

    /* update flags and counters */
    if (FlowGetPacketDirection(f,p) == TOSERVER) {
        if (FlowUpdateSeenFlag(p)) {
            f->flags |= FLOW_TO_DST_SEEN;
        }
        f->todstpktcnt++;
        p->flowflags |= FLOW_PKT_TOSERVER;
    } else {
        if (FlowUpdateSeenFlag(p)) {
            f->flags |= FLOW_TO_SRC_SEEN;
        }
        f->tosrcpktcnt++;
        p->flowflags |= FLOW_PKT_TOCLIENT;
    }
    f->bytecnt += p->pktlen;

    if (f->flags & FLOW_TO_DST_SEEN && f->flags & FLOW_TO_SRC_SEEN) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", p);
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
    SC_ATOMIC_INIT(flow_memuse);

    int ifq = 0;
    FlowQueueInit(&flow_spare_q);
    for (ifq = 0; ifq < FLOW_PROTO_MAX; ifq++) {
        FlowQueueInit(&flow_new_q[ifq]);
        FlowQueueInit(&flow_est_q[ifq]);
        FlowQueueInit(&flow_close_q[ifq]);
    }

    unsigned int seed = RandomTimePreseed();
    /* set defaults */
    flow_config.hash_rand   = (int)( FLOW_DEFAULT_HASHSIZE * (rand_r(&seed) / RAND_MAX + 1.0));

    flow_config.hash_size   = FLOW_DEFAULT_HASHSIZE;
    flow_config.memcap      = FLOW_DEFAULT_MEMCAP;
    flow_config.prealloc    = FLOW_DEFAULT_PREALLOC;

    /* If we have specific config, overwrite the defaults with them,
     * otherwise, leave the default values */
    intmax_t val = 0;
    if (ConfGetInt("flow.emergency_recovery", &val) == 1) {
        if (val <= 100 && val >= 1) {
            flow_config.emergency_recovery = (uint8_t)val;
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "flow.emergency_recovery must be in the range of 1 and 100 (as percentage)");
            flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
        }
    } else {
            SCLogDebug("flow.emergency_recovery, using default value");
            flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
    }

    if (ConfGetInt("flow.prune_flows", &val) == 1) {
            flow_config.flow_try_release = (uint8_t)val;
    } else {
            SCLogDebug("flow.flow.prune_flows, using default value");
            flow_config.flow_try_release = FLOW_DEFAULT_FLOW_PRUNE;
    }

    /* Check if we have memcap and hash_size defined at config */
    char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("flow.memcap", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0)
            flow_config.memcap = configval;
    }
    if ((ConfGet("flow.hash_size", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0)
            flow_config.hash_size = configval;
    }
    if ((ConfGet("flow.prealloc", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0)
            flow_config.prealloc = configval;
    }
    SCLogDebug("Flow config from suricata.yaml: memcap: %"PRIu32", hash_size: "
               "%"PRIu32", prealloc: %"PRIu32, flow_config.memcap,
               flow_config.hash_size, flow_config.prealloc);

    /* alloc hash memory */
    flow_hash = SCCalloc(flow_config.hash_size, sizeof(FlowBucket));
    if (flow_hash == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in FlowInitConfig. Exiting...");
        exit(EXIT_FAILURE);
    }
    uint32_t i = 0;

    memset(flow_hash, 0, flow_config.hash_size * sizeof(FlowBucket));
    for (i = 0; i < flow_config.hash_size; i++)
        SCSpinInit(&flow_hash[i].s, 0);
    SC_ATOMIC_ADD(flow_memuse, (flow_config.hash_size * sizeof(FlowBucket)));

    if (quiet == FALSE)
        SCLogInfo("allocated %" PRIu32 " bytes of memory for the flow hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(flow_memuse), flow_config.hash_size,
                  (uintmax_t)sizeof(FlowBucket));

    /* pre allocate flows */
    for (i = 0; i < flow_config.prealloc; i++) {
        if (SC_ATOMIC_GET(flow_memuse) + sizeof(Flow) > flow_config.memcap) {
            printf("ERROR: FlowAlloc failed (max flow memcap reached): %s\n", strerror(errno));
            exit(1);
        }

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
                SC_ATOMIC_GET(flow_memuse), flow_config.memcap);
    }

    FlowInitFlowProto();

}

/** \brief print some flow stats
 *  \warning Not thread safe */
void FlowPrintQueueInfo (void)
{
    int i;
    SCLogDebug("flow queue info:");
    SCLogDebug("spare flow queue %" PRIu32 "", flow_spare_q.len);
#ifdef DBG_PERF
    SCLogDebug("flow_spare_q.dbg_maxlen %" PRIu32 "", flow_spare_q.dbg_maxlen);
#endif
    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        SCLogDebug("proto [%"PRId32"] new flow queue %" PRIu32 " "
#ifdef DBG_PERF
                  " - flow_new_q.dbg_maxlen %" PRIu32 ""
#endif
                  ,i,flow_new_q[i].len
#ifdef DBG_PERF
                  ,flow_new_q[i].dbg_maxlen
#endif
                  );

        SCLogDebug("proto [%"PRId32"] establised flow queue %" PRIu32 " "
#ifdef DBG_PERF
                  " - flow_est_q.dbg_maxlen %" PRIu32 ""
#endif
                  ,i,flow_est_q[i].len
#ifdef DBG_PERF
                  ,flow_est_q[i].dbg_maxlen
#endif
                  );

        SCLogDebug("proto [%"PRId32"] closing flow queue %" PRIu32 " "
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
    uint32_t u;

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

    if (flow_hash != NULL) {
        /* clean up flow mutexes */
        for (u = 0; u < flow_config.hash_size; u++) {
            SCSpinDestroy(&flow_hash[u].s);
        }
        SCFree(flow_hash);
        flow_hash = NULL;
    }
    SC_ATOMIC_SUB(flow_memuse, flow_config.hash_size * sizeof(FlowBucket));

    int ifq = 0;
    FlowQueueDestroy(&flow_spare_q);
    for (ifq = 0; ifq < FLOW_PROTO_MAX; ifq++) {
        FlowQueueDestroy(&flow_new_q[ifq]);
        FlowQueueDestroy(&flow_est_q[ifq]);
        FlowQueueDestroy(&flow_close_q[ifq]);
    }
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
    struct timeval tsdiff;
    uint32_t established_cnt = 0, new_cnt = 0, closing_cnt = 0, nowcnt;
    uint32_t sleeping = 0;
    uint8_t emerg = FALSE;
    uint32_t last_sec = 0;

    memset(&ts, 0, sizeof(ts));

    /* set the thread name */
    SCSetThreadName(th_v->name);
    SCLogDebug("%s started...", th_v->name);

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);

    FlowHashDebugInit();

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
    while (1)
    {
        TmThreadTestThreadUnPaused(th_v);

        if (sleeping >= 100 || flow_flags & FLOW_EMERGENCY)
        {
            if (flow_flags & FLOW_EMERGENCY) {
                emerg = TRUE;
                SCLogDebug("Flow emergency mode entered...");
            }

            /* Get the time */
            memset(&ts, 0, sizeof(ts));
            TimeGet(&ts);
            SCLogDebug("ts %" PRIdMAX "", (intmax_t)ts.tv_sec);

            if (((uint32_t)ts.tv_sec - last_sec) > 600) {
                FlowHashDebugPrint((uint32_t)ts.tv_sec);
                last_sec = (uint32_t)ts.tv_sec;
            }

            /* see if we still have enough spare flows */
            FlowUpdateSpareFlows();

            int i;
            for (i = 0; i < FLOW_PROTO_MAX; i++) {
                /* prune closing list */
                nowcnt = FlowPruneFlowQueue(&flow_close_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " closing flows...", nowcnt);
                    closing_cnt += nowcnt;
                }

                /* prune new list */
                nowcnt = FlowPruneFlowQueue(&flow_new_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " new flows...", nowcnt);
                    new_cnt += nowcnt;
                }

                /* prune established list */
                nowcnt = FlowPruneFlowQueue(&flow_est_q[i], &ts);
                if (nowcnt) {
                    SCLogDebug("Pruned %" PRIu32 " established flows...", nowcnt);
                    established_cnt += nowcnt;
                }
            }

            sleeping = 0;

            /* Don't fear, FlowManagerThread is here...
             * clear emergency bit if we have at least xx flows pruned. */
            if (emerg == TRUE) {
                uint32_t len = 0;

                SCMutexLock(&flow_spare_q.mutex_q);

                len = flow_spare_q.len;

                SCMutexUnlock(&flow_spare_q.mutex_q);

                SCLogDebug("flow_sparse_q.len = %"PRIu32" prealloc: %"PRIu32
                           "flow_spare_q status: %"PRIu32"%% flows at the queue",
                           len, flow_config.prealloc, len * 100 / flow_config.prealloc);
                /* only if we have pruned this "emergency_recovery" percentage
                 * of flows, we will unset the emergency bit */
                if (len * 100 / flow_config.prealloc > flow_config.emergency_recovery) {
                    flow_flags &= ~FLOW_EMERGENCY;
                    emerg = FALSE;
                    SCLogInfo("Flow emergency mode over, back to normal... unsetting"
                              " FLOW_EMERGENCY bit (ts.tv_sec: %"PRIuMAX", "
                              "ts.tv_usec:%"PRIuMAX") flow_spare_q status(): %"PRIu32
                              "%% flows at the queue", (uintmax_t)ts.tv_sec,
                              (uintmax_t)ts.tv_usec, len * 100 / flow_config.prealloc);
                }
            }
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            SCPerfUpdateCounterArray(th_v->sc_perf_pca, &th_v->sc_perf_pctx, 0);
            break;
        }

        if (run_mode != MODE_PCAP_FILE) {
            usleep(10);
            sleeping += 10;
        } else {
            /* If we are reading a pcap, how long the pcap timestamps
             * says that has passed */
            memset(&tsdiff, 0, sizeof(tsdiff));
            TimeGet(&tsdiff);

            if (tsdiff.tv_sec == ts.tv_sec &&
                tsdiff.tv_usec > ts.tv_usec &&
                tsdiff.tv_usec - ts.tv_usec < 10) {
                /* if it has passed less than 10 usec, sleep that usecs */
                sleeping += tsdiff.tv_usec - ts.tv_usec;
                usleep(tsdiff.tv_usec - ts.tv_usec);
            } else {
                /* Else update the sleeping var but don't sleep so long */
                if (tsdiff.tv_sec == ts.tv_sec && tsdiff.tv_usec > ts.tv_usec)
                    sleeping += tsdiff.tv_usec - ts.tv_usec;
                else if (tsdiff.tv_sec == ts.tv_sec + 1)
                    sleeping += tsdiff.tv_usec + (1000000 - ts.tv_usec);
                else
                    sleeping += 100;
                usleep(1);
            }
        }
    }

    FlowHashDebugDeinit();

    SCLogInfo("%" PRIu32 " new flows, %" PRIu32 " established flows were "
              "timed out, %"PRIu32" flows in closed state", new_cnt,
              established_cnt, closing_cnt);
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

    /* Let's see if we have custom timeouts defined from config */
    const char *new = NULL;
    const char *established = NULL;
    const char *closed = NULL;
    const char *emergency_new = NULL;
    const char *emergency_established = NULL;
    const char *emergency_closed = NULL;

    ConfNode *flow_timeouts = ConfGetNode("flow-timeouts");
    if (flow_timeouts != NULL) {
        ConfNode *proto = NULL;
        uint32_t configval = 0;

        /* Defaults. */
        proto = ConfNodeLookupChild(flow_timeouts, "default");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency_new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency_established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency_closed");

            if (new != NULL && ByteExtractStringUint32(&configval, 10,
                                                    strlen(new), new) > 0) {

                    flow_proto[FLOW_PROTO_DEFAULT].new_timeout = configval;
            }
            if (established != NULL && ByteExtractStringUint32(&configval,
                                    10, strlen(established), established) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].est_timeout = configval;
            }
            if (closed != NULL && ByteExtractStringUint32(&configval, 10,
                                                  strlen(closed), closed) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].closed_timeout = configval;
            }
            if (emergency_new != NULL && ByteExtractStringUint32(&configval,
                                10, strlen(emergency_new), emergency_new) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                    strlen(emergency_established), emergency_established) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_est_timeout= configval;
            }
            if (emergency_closed != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                    strlen(emergency_closed), emergency_closed) > 0) {

                flow_proto[FLOW_PROTO_DEFAULT].emerg_closed_timeout = configval;
            }
        }

        /* TCP. */
        proto = ConfNodeLookupChild(flow_timeouts, "tcp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency_new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency_established");
            emergency_closed = ConfNodeLookupChildValue(proto,
                "emergency_closed");

            if (new != NULL && ByteExtractStringUint32(&configval, 10,
                                                        strlen(new), new) > 0) {

                flow_proto[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (established != NULL && ByteExtractStringUint32(&configval,
                                    10, strlen(established), established) > 0) {

                flow_proto[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (closed != NULL && ByteExtractStringUint32(&configval, 10,
                                                  strlen(closed), closed) > 0) {

                flow_proto[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (emergency_new != NULL && ByteExtractStringUint32(&configval,
                                10, strlen(emergency_new), emergency_new) > 0) {
                flow_proto[FLOW_PROTO_TCP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                    strlen(emergency_established), emergency_established) > 0) {

                flow_proto[FLOW_PROTO_TCP].emerg_est_timeout = configval;
            }
            if (emergency_closed != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                              strlen(emergency_closed), emergency_closed) > 0) {

                flow_proto[FLOW_PROTO_TCP].emerg_closed_timeout = configval;
            }
        }

        /* UDP. */
        proto = ConfNodeLookupChild(flow_timeouts, "udp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency_new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency_established");
            if (new != NULL && ByteExtractStringUint32(&configval, 10,
                                                        strlen(new), new) > 0) {
                flow_proto[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (established != NULL && ByteExtractStringUint32(&configval,
                                    10, strlen(established), established) > 0) {
                flow_proto[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (emergency_new != NULL && ByteExtractStringUint32(&configval,
                                10, strlen(emergency_new), emergency_new) > 0) {
                flow_proto[FLOW_PROTO_UDP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                    strlen(emergency_established), emergency_established) > 0) {
                flow_proto[FLOW_PROTO_UDP].emerg_est_timeout = configval;
            }
        }

        /* ICMP. */
        proto = ConfNodeLookupChild(flow_timeouts, "icmp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency_new");
            emergency_established = ConfNodeLookupChildValue(proto,
                "emergency_established");

            if (new != NULL && ByteExtractStringUint32(&configval, 10,
                                                        strlen(new), new) > 0) {

                flow_proto[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (established != NULL && ByteExtractStringUint32(&configval,
                                    10, strlen(established), established) > 0) {

                flow_proto[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (emergency_new != NULL && ByteExtractStringUint32(&configval,
                                10, strlen(emergency_new), emergency_new) > 0) {

                flow_proto[FLOW_PROTO_ICMP].emerg_new_timeout = configval;
            }
            if (emergency_established != NULL &&
                    ByteExtractStringUint32(&configval, 10,
                    strlen(emergency_established), emergency_established) > 0) {

                flow_proto[FLOW_PROTO_ICMP].emerg_est_timeout = configval;
            }
        }
    }
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

    FLOW_RECYCLE(f);

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
    if (q == NULL) {
        goto error;
    }

    q->top = NULL;

    FlowEnqueue(q, f);
    if (q->len != 1) {
        printf("Failed in enqueue the flow in flowqueue: ");
        goto error;
    }

    SCLogDebug("calling FlowPrune");
    FlowPrune(q, ts);
    if (q->len != 0) {
        printf("Failed in prunning the flow: ");
        goto error;
    }

    if (f->protoctx != NULL){
        printf("Failed in freeing the TcpSession: ");
        goto error;
    }

    return 1;

error:
    if (q != NULL) {
        FlowQueueDestroy(q);
    }
    return 0;
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

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));

    SCSpinInit(&fb.s, 0);

    FLOW_INITIALIZE(&f);

    TimeGet(&ts);
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;

    f.proto = IPPROTO_TCP;

    if (FlowTestPrune(&f, &ts) != 1) {
        SCSpinDestroy(&fb.s);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    SCSpinDestroy(&fb.s);
    FLOW_DESTROY(&f);

    FlowQueueDestroy(&flow_spare_q);
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

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    SCSpinInit(&fb.s, 0);
    FLOW_INITIALIZE(&f);

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

    if (FlowTestPrune(&f, &ts) != 1) {
        SCSpinDestroy(&fb.s);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }
    SCSpinDestroy(&fb.s);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
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

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));

    SCSpinInit(&fb.s, 0);
    FLOW_INITIALIZE(&f);

    TimeGet(&ts);
    ssn.state = TCP_SYN_SENT;
    f.lastts.tv_sec = ts.tv_sec - 300;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;
    f.flags = FLOW_EMERGENCY;

    if (FlowTestPrune(&f, &ts) != 1) {
        SCSpinDestroy(&fb.s);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    SCSpinDestroy(&fb.s);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
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

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    SCSpinInit(&fb.s, 0);
    FLOW_INITIALIZE(&f);

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

    if (FlowTestPrune(&f, &ts) != 1) {
        SCSpinDestroy(&fb.s);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    SCSpinDestroy(&fb.s);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
    return 1;

}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest07 (void) {

    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (SC_ATOMIC_GET(flow_memuse) + sizeof(Flow) < flow_config.memcap) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* should time out normal */
    TimeSetIncrementTime(2000);
    ini = end + 1;
    end = end + 2;;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine released 5 flows by normal timeout */
    if (flow_spare_q.len == 5)
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest08 (void) {

    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (SC_ATOMIC_GET(flow_memuse) + sizeof(Flow) < flow_config.memcap) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* By default we use 30  for timing out new flows. This means
     * that the Emergency mode should be set */
    TimeSetIncrementTime(20);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine released 5 flows by emergency timeout */
    if (flow_spare_q.len == 5 && (flow_flags & FLOW_EMERGENCY))
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowTest09 (void) {

    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (SC_ATOMIC_GET(flow_memuse) + sizeof(Flow) < flow_config.memcap) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* No timeout will work */
    TimeSetIncrementTime(5);
    ini = end + 1;
    end = end + 2;
    UTHBuildPacketOfFlows(ini, end, 0);

    /* This means that the engine release 5 flows by killing them */
    if (flow_spare_q.len == 5 && (flow_flags & FLOW_EMERGENCY))
        result = 1;

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
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
    UtRegisterTest("FlowTest07 -- Test flow Allocations when it reach memcap", FlowTest07, 1);
    UtRegisterTest("FlowTest08 -- Test flow Allocations when it reach memcap", FlowTest08, 1);
    UtRegisterTest("FlowTest09 -- Test flow Allocations when it reach memcap", FlowTest09, 1);
#endif /* UNITTESTS */
}
