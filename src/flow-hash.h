/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_HASH_H__
#define __FLOW_HASH_H__

/* flow hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a flow or list of flows. All these flows have
 * the same hashkey (the hash is a chained hash). When doing modifications
 * to the list, the entire bucket is locked. */
typedef struct FlowBucket_ {
    Flow *f;
    SCMutex m;
} FlowBucket;

/* prototypes */

Flow *FlowGetFlowFromHash(Packet *);

#endif /* __FLOW_HASH_H__ */

