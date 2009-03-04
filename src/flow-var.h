/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __FLOW_VAR_H__
#define __FLOW_VAR_H__

#include "flow.h"
#include "util-var.h"

typedef struct _FlowVar {
    u_int8_t type; /* type, DETECT_FLOWVAR in this case */
    u_int16_t idx; /* name idx */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
    u_int8_t *value;
    u_int16_t value_len;
} FlowVar;

void FlowVarAdd(Flow *, u_int8_t, u_int8_t *, u_int16_t);
FlowVar *FlowVarGet(Flow *, u_int8_t);
void FlowVarFree(FlowVar *);
void FlowVarPrint(GenericVar *);

#endif /* __FLOW_VAR_H__ */

