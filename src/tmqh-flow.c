/**
 * \file
 * \author Victor Julien <victor@inliniac.net>
 *
 * Simple output queue handler that makes sure all packets of the same flow
 * are sent to the same queue. This is done by simply hashing the flow's
 * memory address as thats readable from a packet without the need to lock
 * the flow itself.
 *
 * \todo we can also think about a queue handler that takes queue load into
 *       account.
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

#include "util-unittest.h"

/** \brief Ctx for the flow queue handler
 *  \param size number of queues to output to
 *  \param queues array of queue id's this flow handler outputs to */
typedef struct TmqhFlowCtx_ {
    uint16_t size;
    uint16_t *queues;
    uint16_t last;
} TmqhFlowCtx;

Packet *TmqhInputFlow(ThreadVars *t);
void TmqhOutputFlow(ThreadVars *t, Packet *p);
void *TmqhOutputFlowSetupCtx(char *queue_str);
void TmqhFlowRegisterTests(void);

void TmqhFlowRegister (void) {
    tmqh_table[TMQH_FLOW].name = "flow";
    tmqh_table[TMQH_FLOW].InHandler = TmqhInputFlow;
    tmqh_table[TMQH_FLOW].OutHandler = TmqhOutputFlow;
    tmqh_table[TMQH_FLOW].OutHandlerCtxSetup = TmqhOutputFlowSetupCtx;
    tmqh_table[TMQH_FLOW].OutHandlerCtxFree = NULL;
    tmqh_table[TMQH_FLOW].RegisterTests = TmqhFlowRegisterTests;
}

/* same as 'simple' */
Packet *TmqhInputFlow(ThreadVars *tv)
{
    PacketQueue *q = &trans_q[tv->inq->id];

    SCMutexLock(&q->mutex_q);
    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCondWait(&q->cond_q, &q->mutex_q);
    }

    if (tv->sc_perf_pctx.perf_flag == 1)
        SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);

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

static int StoreQueueId(TmqhFlowCtx *ctx, char *name) {
    Tmq *tmq = TmqGetQueueByName(name);
    if (tmq == NULL) {
        tmq = TmqCreateQueue(strdup(name));
        if (tmq == NULL)
            return -1;
    }
    tmq->writer_cnt++;

    uint16_t id = tmq->id;
    //printf("StoreQueueId: id %u\n", id);

    if (ctx->queues == NULL) {
        ctx->size = 1;
        ctx->queues = malloc(ctx->size * sizeof(uint16_t));
    } else {
        ctx->size++;
        ctx->queues = realloc(ctx->queues, ctx->size * sizeof(uint16_t));
    }
    if (ctx->queues == NULL) {
        return -1;
    }

    ctx->queues[ctx->size - 1] = id;
    return 0;
}

/** \brief setup the queue handlers ctx
 *
 *  Parses a comma separated string "queuename1,queuename2,etc"
 *  and sets the ctx up to devide flows over these queue's.
 *
 *  \param queue_str comma separated string with output queue names
 *  \retval ctx queues handlers ctx or NULL in error
 */
void *TmqhOutputFlowSetupCtx(char *queue_str) {
    if (queue_str == NULL || strlen(queue_str) == 0)
        return NULL;

    TmqhFlowCtx *ctx = malloc(sizeof(TmqhFlowCtx));
    if (ctx == NULL)
        return NULL;
    memset(ctx,0x00,sizeof(TmqhFlowCtx));

    char *str = strdup(queue_str);
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

    free(str);
    return (void *)ctx;
error:
    free(ctx);
    free(str);
    return NULL;
}

/** \brief select the queue to output to based on flow
 *  \param tv thread vars
 *  \param p packet
 */
void TmqhOutputFlow(ThreadVars *tv, Packet *p)
{
    uint16_t qid = 0;

    TmqhFlowCtx *ctx = (TmqhFlowCtx *)tv->outctx;
    if (ctx == NULL) {
        abort();
    }

    /* if no flow we use the first queue,
     * should be rare */
    if (p->flow != NULL) {
#if __WORDSIZE == 64
        uint64_t addr = (uint64_t)p->flow;
#else
        uint32_t addr = (uint32_t)p->flow;
#endif
        addr >>= 7;

        uint16_t idx = addr % ctx->size;
        qid = ctx->queues[idx];
    } else {
        ctx->last++;

        if (ctx->last == ctx->size)
            ctx->last = 0;

        qid = ctx->queues[ctx->last];
    }

    PacketQueue *q = &trans_q[qid];
    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
}

#ifdef UNITTESTS
static int TmqhOutputFlowSetupCtxTest01(void) {
    int retval = 0;
    Tmq *tmq = NULL;

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

    TmqhFlowCtx *fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 4)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0] != 0)
        goto end;
    if (fctx->queues[1] != 1)
        goto end;
    if (fctx->queues[2] != 2)
        goto end;
    if (fctx->queues[3] != 3)
        goto end;

    retval = 1;
end:
    TmqResetQueues();
    return retval;
}

static int TmqhOutputFlowSetupCtxTest02(void) {
    int retval = 0;
    Tmq *tmq = NULL;

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

    TmqhFlowCtx *fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 1)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0] != 0)
        goto end;

    retval = 1;
end:
    TmqResetQueues();
    return retval;
}

static int TmqhOutputFlowSetupCtxTest03(void) {
    int retval = 0;

    TmqResetQueues();

    char *str = "queue1,queue2,another,yetanother";
    void *ctx = TmqhOutputFlowSetupCtx(str);

    if (ctx == NULL)
        goto end;

    TmqhFlowCtx *fctx = (TmqhFlowCtx *)ctx;

    if (fctx->size != 4)
        goto end;

    if (fctx->queues == NULL)
        goto end;

    if (fctx->queues[0] != 0)
        goto end;
    if (fctx->queues[1] != 1)
        goto end;
    if (fctx->queues[2] != 2)
        goto end;
    if (fctx->queues[3] != 3)
        goto end;

    retval = 1;
end:
    TmqResetQueues();
    return retval;
}

#endif /* UNITTESTS */

void TmqhFlowRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("TmqhOutputFlowSetupCtxTest01", TmqhOutputFlowSetupCtxTest01, 1);
    UtRegisterTest("TmqhOutputFlowSetupCtxTest02", TmqhOutputFlowSetupCtxTest02, 1);
    UtRegisterTest("TmqhOutputFlowSetupCtxTest03", TmqhOutputFlowSetupCtxTest03, 1);
#endif
}

