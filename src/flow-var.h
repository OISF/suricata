/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __FLOW_VAR_H__
#define __FLOW_VAR_H__

#include "flow.h"

typedef struct _FlowVar {
    char *name;
    u_int8_t *value;
    u_int16_t value_len;
    struct _FlowVar *next; /* right now just implement this as a list,
                            * in the long run we have thing of something
                            * faster. */
} FlowVar;

void FlowVarAdd(Flow *, char *, u_int8_t *, u_int16_t);
FlowVar *FlowVarGet(Flow *, char *);
void FlowVarFree(FlowVar *);
void FlowVarPrint(FlowVar *);

#endif /* __FLOW_VAR_H__ */

