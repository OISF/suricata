/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __FLOW_UTIL_H__
#define __FLOW_UTIL_H__

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)

/* only clear the parts that won't be overwritten
 * in FlowInit anyway */
#define CLEAR_FLOW(f) { \
    (f)->sp = 0; \
    (f)->dp = 0; \
    (f)->flags = 0; \
    (f)->todstpktcnt = 0; \
    (f)->tosrcpktcnt = 0; \
    (f)->bytecnt = 0; \
    (f)->lastts.tv_sec = 0; \
    (f)->lastts.tv_usec = 0; \
    GenericVarFree((f)->flowvar); \
    (f)->flowvar = NULL; \
    (f)->protoctx = NULL; \
    (f)->use_cnt = 0; \
}

Flow *FlowAlloc(void);
void FlowFree(Flow *);
int FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, Packet *);

#endif /* __FLOW_UTIL_H__ */

