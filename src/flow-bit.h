/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */
#ifndef __FLOW_BIT_H__
#define __FLOW_BIT_H__

#include "flow.h"
#include "util-var.h"

typedef struct FlowBit_ {
    uint8_t type; /* type, DETECT_FLOWBITS in this case */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
    uint16_t idx; /* name idx */
} FlowBit;

void FlowBitFree(FlowBit *);
void FlowBitRegisterTests(void);

void FlowBitSet(Flow *, uint16_t);
void FlowBitUnset(Flow *, uint16_t);
void FlowBitToggle(Flow *, uint16_t);
int FlowBitIsset(Flow *, uint16_t);
int FlowBitIsnotset(Flow *, uint16_t);
#endif /* __FLOW_BIT_H__ */

