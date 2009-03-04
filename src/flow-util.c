/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "threads.h"

#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-var.h"

/* Allocate a flow */
Flow *FlowAlloc(void)
{
    Flow *f;

    mutex_lock(&flow_memuse_mutex);
    if (flow_memuse + sizeof(Flow) > flow_config.memcap) {
        mutex_unlock(&flow_memuse_mutex);
        return NULL;
    }
    f = malloc(sizeof(Flow));
    if (f == NULL) {
        mutex_unlock(&flow_memuse_mutex);
        return NULL;
    }
    flow_memuse += sizeof(Flow);
    mutex_unlock(&flow_memuse_mutex);

    pthread_mutex_init(&f->m, NULL);
    f->lnext = NULL;
    f->lprev = NULL;
    f->hnext = NULL;
    f->hprev = NULL;

    f->flowvar = NULL;

    return f;
}

void FlowFree(Flow *f)
{
    mutex_lock(&flow_memuse_mutex);
    flow_memuse -= sizeof(Flow);
    mutex_unlock(&flow_memuse_mutex);

    GenericVarFree(f->flowvar);

    free(f);
}

/* initialize the flow from the first packet
 * we see from it. */
void FlowInit(Flow *f, Packet *p)
{
    CLEAR_FLOW(f);

    f->proto = p->proto;
    f->recursion_level = p->recursion_level;

    if (p->ip4h != NULL) { /* XXX MACRO */
        SET_IPV4_SRC_ADDR(p,&f->src);
        SET_IPV4_DST_ADDR(p,&f->dst);
    } else if (p->ip6h != NULL) { /* XXX MACRO */
        SET_IPV6_SRC_ADDR(p,&f->src);
        SET_IPV6_DST_ADDR(p,&f->dst);
    } /* XXX handle default */
    else {
        printf("FIXME: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
    }

    if (p->tcph != NULL) { /* XXX MACRO */
        SET_TCP_SRC_PORT(p,&f->sp);
        SET_TCP_DST_PORT(p,&f->dp);
    } else if (p->udph != NULL) { /* XXX MACRO */
        SET_UDP_SRC_PORT(p,&f->sp);
        SET_UDP_DST_PORT(p,&f->dp);
    } /* XXX handle default */
    else {
        printf("FIXME: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
    }

    COPY_TIMESTAMP(&p->ts, &f->startts);
}

