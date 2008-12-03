/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"

/* Flow implementation
 *
 * IDEAS:
 * - Maybe place the flow that we get a packet for on top of the
 *   list in the bucket. This rewards active flows.
 *
 */


/* FlowUpdateQueue
 *
 * In-use flows are either in the flow_new_q or flow_est_q lists.
 *
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


/* FlowPrune
 *
 * Inspect top (last recently used) flow from the queue and see if
 * we need to prune it.
 *
 * Use trylock here so prevent us from blocking the packet handling.
 *
 * Arguments:
 *     q:       flow queue to prune
 *     ts:      current time
 *     timeout: timeout to enforce
 *
 * returns 0 on error, failed block, nothing to prune
 * returns 1 on successfully pruned one
 */
static int FlowPrune (FlowQueue *q, struct timeval *ts, u_int32_t timeout)
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

    DEBUGPRINT("got lock, now check: %ld+%u=(%ld) < %ld", f->lastts.tv_sec,
        timeout, f->lastts.tv_sec + timeout, ts->tv_sec);

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

    /* move to spare list */
    FlowRequeue(f, q, &flow_spare_q);

    mutex_unlock(&f->m);
    return 1;
}

/* FlowPruneFlows
 *
 * Returns: number of flows that are pruned.
 */
static u_int32_t FlowPruneFlows(FlowQueue *q, struct timeval *ts, u_int32_t timeout)
{
    u_int32_t cnt = 0;
    while(FlowPrune(q, ts, timeout)) { cnt++; }
    return cnt;
}

/* FlowUpdateSpareFlows
 *
 * Enforce the prealloc parameter, so keep at least prealloc flows in the
 * spare queue and free flows going over the limit.
 *
 * Returns 1 if the queue was properly updated (or if it already was in good
 * shape). Returns 0 otherwise.
 */
static int FlowUpdateSpareFlows(void) {
    u_int32_t toalloc = 0, tofree = 0, len;

    mutex_lock(&flow_spare_q.mutex_q);
    len = flow_spare_q.len;
    mutex_unlock(&flow_spare_q.mutex_q);

    if (len < flow_config.prealloc) {
        toalloc = flow_config.prealloc - len;

        u_int32_t i;
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

        u_int32_t i;
        for (i = 0; i < tofree; i++) {
            Flow *f = FlowDequeue(&flow_spare_q);
            if (f == NULL)
                return 1;

            FlowFree(f);
        }
    }

    return 1;
}

/* FlowHandlePacket
 *
 * This is called for every packet.
 *
 * Returns: nothing.
 */
void FlowHandlePacket (ThreadVars *th_v, Packet *p)
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

    /* update queue positions */
    FlowUpdateQueue(f);

    /* set the flow in the packet */
    p->flow = f;

    mutex_unlock(&f->m);
}

//#define FLOW_DEFAULT_HASHSIZE    262144
#define FLOW_DEFAULT_HASHSIZE    65536
//#define FLOW_DEFAULT_MEMCAP      128 * 1024 * 1024 /* 128 MB */
#define FLOW_DEFAULT_MEMCAP      32 * 1024 * 1024 /* 32 MB */

#define FLOW_DEFAULT_NEW_TIMEOUT 30
#define FLOW_DEFAULT_EST_TIMEOUT 300

#define FLOW_DEFAULT_EMERG_NEW_TIMEOUT 10
#define FLOW_DEFAULT_EMERG_EST_TIMEOUT 100

#define FLOW_DEFAULT_PREALLOC    10000

/* Not Thread safe */
void FlowInitConfig (void)
{
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

    printf("* Allocated %u bytes of memory for the flow hash... %u buckets of size %u\n",
        flow_config.memuse, flow_config.hash_size, sizeof(FlowBucket));

    /* pre allocate flows */
    u_int32_t i = 0;
    for (i = 0; i < flow_config.prealloc; i++) {
        Flow *f = FlowAlloc();
        if (f == NULL) {
            printf("ERROR: FlowAlloc failed: %s\n", strerror(errno));
            exit(1);
        }
        FlowEnqueue(&flow_spare_q,f);
    }
    printf("* Preallocated %u flows of size %u\n",
        flow_spare_q.len, sizeof(Flow));
    printf("* Flow memory usage: %u bytes. Maximum: %u\n",
        flow_config.memuse, flow_config.memcap);
}

/* Not Thread safe */
void FlowPrintFlows (void)
{
/*
    int i;
    printf("Flows:\n");
    for (i = 0; i < flow_config.hash_size; i++) {
        FlowBucket *fb = &flow_hash[i];

        if (fb->f != NULL) {
            printf("Flow %u->%u: %u pkts (tosrc %d todst %u) %llu bytes\n",
                fb->f->sp, fb->f->dp, fb->f->tosrcpktcnt+fb->f->todstpktcnt, fb->f->tosrcpktcnt,
                fb->f->todstpktcnt, fb->f->bytecnt);
            FlowVarPrint(fb->f->flowvar);

            if (fb->f->hnext != NULL) {
                Flow *f = fb->f->hnext;
                while (f) {
                    printf("  Flow %u->%u: %u pkts (tosrc %d todst %u) %llu bytes\n",
                        f->sp, f->dp, f->tosrcpktcnt+f->todstpktcnt, f->tosrcpktcnt,
                        f->todstpktcnt, f->bytecnt);
                    FlowVarPrint(f->flowvar);
                    f = f->hnext;
                }
            }
        }
    }
*/
    printf("Flow Queue info:\n");
    printf("SPARE       %u\n", flow_spare_q.len);
#ifdef DBG_PERF
    printf("  flow_spare_q.dbg_maxlen %u\n", flow_spare_q.dbg_maxlen);
#endif
    printf("NEW         %u\n", flow_new_q.len);
#ifdef DBG_PERF
    printf("  flow_new_q.dbg_maxlen %u\n", flow_new_q.dbg_maxlen);
#endif
    printf("ESTABLISHED %u\n", flow_est_q.len);
#ifdef DBG_PERF
    printf("  flow_est_q.dbg_maxlen %u\n", flow_est_q.dbg_maxlen);
#endif
}

/* Not thread safe */
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
}

/* FlowManagerThread
 *
 * Thread that manages the various queue's and removes timed out flows.
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
    u_int32_t established_cnt = 0, new_cnt = 0, nowcnt;
    u_int32_t sleeping = 0;
    u_int8_t emerg = FALSE;

    printf("%s started...\n", th_v->name);

    while (1)
    {
        if (sleeping >= 100 || flow_flags & FLOW_EMERGENCY)
        {
            u_int32_t timeout_new = flow_config.timeout_new;
            u_int32_t timeout_est = flow_config.timeout_est;

            if (flow_flags & FLOW_EMERGENCY) {
                emerg = TRUE;
                printf("Flow emergency mode entered...\n");
            }

            /* Get the time */
            memset(&ts, 0, sizeof(ts));
            gettimeofday(&ts, NULL);
            DEBUGPRINT("ts %ld", ts.tv_sec);

            /* see if we still have enough spare flows */
            if (!(FlowUpdateSpareFlows()) && emerg == TRUE) {
                timeout_new = flow_config.emerg_timeout_new;
                timeout_est = flow_config.emerg_timeout_est;
            }

            /* prune new list */
            nowcnt = FlowPruneFlows(&flow_new_q, &ts, timeout_new);
            if (nowcnt) {
                DEBUGPRINT("Pruned %u new flows...\n", nowcnt);
                new_cnt += nowcnt;
            }

            /* prune established list */
            nowcnt = FlowPruneFlows(&flow_est_q, &ts, timeout_est);
            if (nowcnt) {
                DEBUGPRINT("Pruned %u established flows...\n", nowcnt);
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

    printf("%s ended: %u new flows, %u established flows pruned\n", th_v->name, new_cnt, established_cnt);
    pthread_exit((void *) 0);
}

