/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */
#ifndef __FLOW_BIT_H__
#define __FLOW_BIT_H__

#include "flow.h"
#include "util-var.h"

typedef struct FlowBit_ {
    u_int8_t type; /* type, DETECT_FLOWBITS in this case */
    u_int16_t idx; /* name idx */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
} FlowBit;

void FlowBitFree(FlowBit *);
void FlowBitRegisterTests(void);

void FlowBitSet(Flow *, u_int16_t);
void FlowBitUnset(Flow *, u_int16_t);
void FlowBitToggle(Flow *, u_int16_t);
int FlowBitIsset(Flow *, u_int16_t);
int FlowBitIsnotset(Flow *, u_int16_t);
#endif /* __FLOW_BIT_H__ */

