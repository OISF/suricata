/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Simple output queue handler that makes sure all packets of the same flow
 * are sent to the same queue. We support different kind of q handlers.  Have
 * a look at "autofp-scheduler" conf to further undertsand the various q
 * handlers we provide.
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tmqh-flow.h"

#include "tm-queuehandlers.h"

#include "conf.h"
#include "util-unittest.h"

Packet *TmqhInputFlow(ThreadVars *t);
void TmqhOutputFlowHash(ThreadVars *t, Packet *p);
void TmqhOutputFlowActivePackets(ThreadVars *t, Packet *p);
void TmqhOutputFlowRoundRobin(ThreadVars *t, Packet *p);
void *TmqhOutputFlowSetupCtx(char *queue_str);
void TmqhOutputFlowFreeCtx(void *ctx);
void TmqhFlowRegisterTests(void);

void TmqhFlowRegister(void)
{
    tmqh_table[TMQH_FLOW].name = "flow";
    tmqh_table[TMQH_FLOW].InHandler = TmqhInputFlow;
    tmqh_table[TMQH_FLOW].OutHandlerCtxSetup = TmqhOutputFlowSetupCtx;
    tmqh_table[TMQH_FLOW].OutHandlerCtxFree = TmqhOutputFlowFreeCtx;
    tmqh_table[TMQH_FLOW].RegisterTests = TmqhFlowRegisterTests;

    char *scheduler = NULL;
    if (ConfGet("autofp-scheduler", &scheduler) == 1) {
        if (strcasecmp(scheduler, "round-robin") == 0) {
            SCLogInfo("AutoFP mode using \"Round Robin\" flow load balancer");
            tmqh_table[TMQH_FLOW].OutHandler = TmqhOutputFlowRoundRobin;
        } else if (strcasecmp(scheduler, "active-packets") == 0) {
            SCLogInfo("AutoFP mode using \"Active Packets\" flow load balancer");
            tmqh_table[TMQH_FLOW].OutHandler = TmqhOutputFlowActivePackets;
        } else if (strcasecmp(scheduler, "hash") == 0) {
            SCLogInfo("AutoFP mode using \"Hash\" flow load balancer");
            tmqh_table[TMQH_FLOW].OutHandler = TmqhOutputFlowHash;
        } else {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry \"%s\" "
                       "for autofp-scheduler in conf.  Killing engine.",
                       scheduler);
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("AutoFP mode using default \"Active Packets\" flow load balancer");
        tmqh_table[TMQH_FLOW].OutHandler = TmqhOutputFlowActivePackets;
    }

    return;
}

/* same as 'simple' */
Packet *TmqhInputFlow(ThreadVars *tv)
{
    PacketQueue *q = &trans_q[tv->inq->id];

    StatsSyncCountersIfSignalled(tv);

    SCMutexLock(&q->mutex_q);
    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCCondWait(&q->cond_q, &q->mutex_q);
    }

    if (q->len > 0) {
        Packet *p = PacketDequeue(q);
        SCMutexUnlock(&q->mutex_q);
        return p;
    } else {
        /* return NULL if we have no pkt. Should only happen on signals. */
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }
}

static int StoreQueueId(TmqhFlowCtx *ctx, char *name)
{
    void *ptmp;
    Tmq *tmq = TmqGetQueueByName(name);
    if (tmq == NULL) {
        tmq = TmqCreateQueue(SCStrdup(name));
        if (tmq == NULL)
            return -1;
    }
    tmq->writer_cnt++;

    uint16_t id = tmq->id;

    if (ctx->queues == NULL) {
        ctx->size = 1;
        ctx->queues = SCMalloc(ctx->size * sizeof(TmqhFlowMode));
        if (ctx->queues == NULL) {
            return -1;
        }
        memset(ctx->queues, 0, ctx->size * sizeof(TmqhFlowMode));
    } else {
        ctx->size++;
        ptmp = SCRealloc(ctx->queues, ctx->size * sizeof(TmqhFlowMode));
        if (ptmp == NULL) {
            SCFree(ctx->queues);
            ctx->queues = NULL;
            return -1;
        }
        ctx->queues = ptmp;

        memset(ctx->queues + (ctx->size - 1), 0, sizeof(TmqhFlowMode));
    }
    ctx->queues[ctx->size - 1].q = &trans_q[id];
    SC_ATOMIC_INIT(ctx->queues[ctx->size - 1].total_packets);
    SC_ATOMIC_INIT(ctx->queues[ctx->size - 1].total_flows);

    return 0;
}

/**
 * \brief setup the queue handlers ctx
 *
 * Parses a comma separated string "queuename1,queuename2,etc"
 * and sets the ctx up to devide flows over these queue's.
 *
 * \param queue_str comma separated string with output queue names
 *
 * \retval ctx queues handlers ctx or NULL in error
 */
void *TmqhOutputFlowSetupCtx(char *queue_str)
{
    if (queue_str == NULL || strlen(queue_str) == 0)
        return NULL;

    SCLogDebug("queue_str %s", queue_str);

    TmqhFlowCtx *ctx = SCMalloc(sizeof(TmqhFlowCtx));
    if (unlikely(ctx == NULL))
        return NULL;
    memset(ctx,0x00,sizeof(TmqhFlowCtx));

    char *str = SCStrdup(queue_str);
    if (unlikely(str == NULL)) {
        goto error;
    }
    char *tstr = str;

    /* parse the comma separated string */
    do {
        char *comma = strchr(tstr,',');
        if (comma != NULL) {
            *comma = '\0';
            char *qname = tstr;
            int r = StoreQueueId(ctx,qname);
            if (r < 0)
                goto error;
        } else {
            char *qname = tstr;
            int r = StoreQueueId(ctx,qname);
            if (r < 0)
                goto error;
        }
        tstr = comma ? (comma + 1) : comma;
    } while (tstr != NULL);

    SC_ATOMIC_INIT(ctx->round_robin_idx);

    SCFree(str);
    return (void *)ctx;

error:
    SCFree(ctx);
    if (str != NULL)
        SCFree(str);
    return NULL;
}

void TmqhOutputFlowFreeCtx(void *ctx)
{
    int i;
    TmqhFlowCtx *fctx = (TmqhFlowCtx *)ctx;

    SCLogInfo("AutoFP - Total flow handler queues - %" PRIu16,
              fctx->size);
    for (i = 0; i < fctx->size; i++) {
        SCLogInfo("AutoFP - Queue %-2"PRIu32 " - pkts: %-12"PRIu64" flows: %-12"PRIu64, i,
                SC_ATOMIC_GET(fctx->queues[i].total_packets),
                SC_ATOMIC_GET(fctx->queues[i].total_flows));
        SC_ATOMIC_DESTROY(fctx->queues[i].total_packets);
        SC_ATOMIC_DESTROY(fctx->queues[i].total_flows);
    }

    SCFree(fctx->queues);

    return;
}

/**
 * \brief select the queue to output in a round robin fashion.
 *
 * \param tv thread vars
 * \param p packet
 */
void TmqhOutputFlowRoundRobin(ThreadVars *tv, Packet *p)
{
    int16_t qid = 0;

    TmqhFlowCtx *ctx = (TmqhFlowCtx *)tv->outctx;

    /* if no flow we use the first queue,
     * should be rare */
    if (p->flow != NULL) {
        qid = SC_ATOMIC_GET(p->flow->autofp_tmqh_flow_qid);
        if (qid == -1) {
            qid = SC_ATOMIC_ADD(ctx->round_robin_idx, 1);
            if (qid >= ctx->size) {
                SC_ATOMIC_RESET(ctx->round_robin_idx);
                qid = 0;
            }
            (void) SC_ATOMIC_ADD(ctx->queues[qid].total_flows, 1);
            (void) SC_ATOMIC_SET(p->flow->autofp_tmqh_flow_qid, qid);
        }
    } else {
        qid = ctx->last++;

        if (ctx->last == ctx->size)
            ctx->last = 0;
    }
    (void) SC_ATOMIC_ADD(ctx->queues[qid].total_packets, 1);

    PacketQueue *q = ctx->queues[qid].q;
    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}

/**
 * \brief select the queue to output to based on queue lengths.
 *
 * \param tv thread vars
 * \param p packet
 */
void TmqhOutputFlowActivePackets(ThreadVars *tv, Packet *p)
{
    int16_t qid = 0;

    TmqhFlowCtx *ctx = (TmqhFlowCtx *)tv->outctx;

    /* if no flow we use the first queue,
     * should be rare */
    if (p->flow != NULL) {
        qid = SC_ATOMIC_GET(p->flow->autofp_tmqh_flow_qid);
        if (qid == -1) {
            uint16_t i = 0;
            int lowest_id = 0;
            TmqhFlowMode *queues = ctx->queues;
            uint32_t lowest = queues[i].q->len;
            for (i = 1; i < ctx->size; i++) {
                if (queues[i].q->len < lowest) {
                    lowest = queues[i].q->len;
                    lowest_id = i;
                }
            }
            qid = lowest_id;
            (void) SC_ATOMIC_SET(p->flow->autofp_tmqh_flow_qid, lowest_id);
            (void) SC_ATOMIC_ADD(ctx->queues[qid].total_flows, 1);
        }
    } else {
        qid = ctx->last++;

        if (ctx->last == ctx->size)
            ctx->last = 0;
    }
    (void) SC_ATOMIC_ADD(ctx->queues[qid].total_packets, 1);

    PacketQueue *q = ctx->queues[qid].q;
    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}

/**
 * \brief select the queue to output based on address hash.
 *
 * \param tv thread vars.
 * \param p packet.
 */
void TmqhOutputFlowHash(ThreadVars *tv, Packet *p)
{
    int16_t qid = 0;

    TmqhFlowCtx *ctx = (TmqhFlowCtx *)tv->outctx;

    /* if no flow we use the first queue,
     * should be rare */
    if (p->flow != NULL) {
        qid = SC_ATOMIC_GET(p->flow->autofp_tmqh_flow_qid);
        if (qid == -1) {
#if __WORDSIZE == 64
            uint64_t addr = (uint64_t)p->flow;
#else
            uint32_t addr = (uint32_t)p->flow;
#endif
            addr >>= 7;

            /* we don't have to worry about possible overflow, since
             * ctx->size will be lesser than 2 ** 31 for sure */
            qid = addr % ctx->size;
            (void) SC_ATOMIC_SET(p->flow->autofp_tmqh_flow_qid, qid);
            (void) SC_ATOMIC_ADD(ctx->queues[qid].total_flows, 1);
        }
    } else {
        qid = ctx->last++;

        if (ctx->last == ctx->size)
            ctx->last = 0;
    }
    (void) SC_ATOMIC_ADD(ctx->queues[qid].total_packets, 1);

    PacketQueue *q = ctx->queues[qid].q;
    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}

#ifdef UNITTESTS

static int TmqhOutputFlowSetupCtxTest01(void)
{
    int retval = 0;
    Tmq *tmq = NULL;
    TmqhFlowCtx *fctx = NULL;

    TmqResetQueues();

    tmq = TmqCreateQueue("queue1");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("queue2");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("another");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("yetanother");
    if (tmq == NULL)
        goto end;

    char *str = "queue1,queue2,another,yetanother";
    void *ctx = TmqhOutputFlowSetupCtx(str);

    if (ctx == NULL)
        goto end;

    fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 4)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0].q != &trans_q[0])
        goto end;
    if (fctx->queues[1].q != &trans_q[1])
        goto end;
    if (fctx->queues[2].q != &trans_q[2])
        goto end;
    if (fctx->queues[3].q != &trans_q[3])
        goto end;

    retval = 1;
end:
    if (fctx != NULL)
        TmqhOutputFlowFreeCtx(fctx);
    TmqResetQueues();
    return retval;
}

static int TmqhOutputFlowSetupCtxTest02(void)
{
    int retval = 0;
    Tmq *tmq = NULL;
    TmqhFlowCtx *fctx = NULL;

    TmqResetQueues();

    tmq = TmqCreateQueue("queue1");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("queue2");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("another");
    if (tmq == NULL)
        goto end;
    tmq = TmqCreateQueue("yetanother");
    if (tmq == NULL)
        goto end;

    char *str = "queue1";
    void *ctx = TmqhOutputFlowSetupCtx(str);

    if (ctx == NULL)
        goto end;

    fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 1)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0].q != &trans_q[0])
        goto end;

    retval = 1;
end:
    if (fctx != NULL)
        TmqhOutputFlowFreeCtx(fctx);
    TmqResetQueues();
    return retval;
}

static int TmqhOutputFlowSetupCtxTest03(void)
{
    int retval = 0;
    TmqhFlowCtx *fctx = NULL;

    TmqResetQueues();

    char *str = "queue1,queue2,another,yetanother";
    void *ctx = TmqhOutputFlowSetupCtx(str);

    if (ctx == NULL)
        goto end;

    fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 4)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0].q != &trans_q[0])
        goto end;
    if (fctx->queues[1].q != &trans_q[1])
        goto end;
    if (fctx->queues[2].q != &trans_q[2])
        goto end;
    if (fctx->queues[3].q != &trans_q[3])
        goto end;

    retval = 1;
end:
    if (fctx != NULL)
        TmqhOutputFlowFreeCtx(fctx);
    TmqResetQueues();
    return retval;
}

#endif /* UNITTESTS */

void TmqhFlowRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("TmqhOutputFlowSetupCtxTest01", TmqhOutputFlowSetupCtxTest01, 1);
    UtRegisterTest("TmqhOutputFlowSetupCtxTest02", TmqhOutputFlowSetupCtxTest02, 1);
    UtRegisterTest("TmqhOutputFlowSetupCtxTest03", TmqhOutputFlowSetupCtxTest03, 1);
#endif

    return;
}
