/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "threads.h"

#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-var.h"
#include "util-debug.h"

/* Allocate a flow */
Flow *FlowAlloc(void)
{
    Flow *f;

    SCMutexLock(&flow_memuse_mutex);
    if (flow_memuse + sizeof(Flow) > flow_config.memcap) {
        SCMutexUnlock(&flow_memuse_mutex);
        return NULL;
    }
    f = malloc(sizeof(Flow));
    if (f == NULL) {
        SCMutexUnlock(&flow_memuse_mutex);
        return NULL;
    }
    flow_memuse += sizeof(Flow);
    SCMutexUnlock(&flow_memuse_mutex);

    SCMutexInit(&f->m, NULL);
    f->lnext = NULL;
    f->lprev = NULL;
    f->hnext = NULL;
    f->hprev = NULL;

    f->flowvar = NULL;

    return f;
}

/** free the memory of a flow */
void FlowFree(Flow *f)
{
    SCMutexLock(&flow_memuse_mutex);
    flow_memuse -= sizeof(Flow);
    SCMutexUnlock(&flow_memuse_mutex);

    free(f);
}

/**
 *  \brief   Function to map the protocol to the defined FLOW_PROTO_* enumeration.
 *
 *  \param   proto  protocol which is needed to be mapped
 */

int FlowGetProtoMapping(uint8_t proto) {

    switch (proto) {
        case IPPROTO_TCP:
            return FLOW_PROTO_TCP;
        case IPPROTO_UDP:
            return FLOW_PROTO_UDP;
        case IPPROTO_ICMP:
            return FLOW_PROTO_ICMP;
        default:
            return FLOW_PROTO_DEFAULT;
    }
}

/* initialize the flow from the first packet
 * we see from it. */
void FlowInit(Flow *f, Packet *p)
{
    SCEnter();
    SCLogDebug("flow %p", f);

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
        printf("FIXME: %s:%s:%" PRId32 "\n", __FILE__, __FUNCTION__, __LINE__);
    }

    if (p->tcph != NULL) { /* XXX MACRO */
        SET_TCP_SRC_PORT(p,&f->sp);
        SET_TCP_DST_PORT(p,&f->dp);
    } else if (p->udph != NULL) { /* XXX MACRO */
        SET_UDP_SRC_PORT(p,&f->sp);
        SET_UDP_DST_PORT(p,&f->dp);
    } else if (p->icmpv4h != NULL) {
        f->type = p->type;
        f->code = p->code;
    } else if (p->icmpv6h != NULL) {
        f->type = p->type;
        f->code = p->code;
    } /* XXX handle default */
    else {
        printf("FIXME: %s:%s:%" PRId32 "\n", __FILE__, __FUNCTION__, __LINE__);
    }

    COPY_TIMESTAMP(&p->ts, &f->startts);

    f->protomap = FlowGetProtoMapping(f->proto);

    SCReturn;
}

