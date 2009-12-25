/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */
#ifndef __FLOW_ALERT_SID_H__
#define __FLOW_ALERT_SID_H__

#include "flow.h"
#include "util-var.h"

typedef struct FlowAlertSid_ {
    uint8_t type; /* type, DETECT_FLOWALERTSID in this case */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
    uint32_t sid; /* sid */
} FlowAlertSid;

void FlowAlertSidFree(FlowAlertSid *);
void FlowAlertSidRegisterTests(void);

void FlowAlertSidSet(Flow *, uint32_t);
void FlowAlertSidUnset(Flow *, uint32_t);
void FlowAlertSidToggle(Flow *, uint32_t);
int FlowAlertSidIsset(Flow *, uint32_t);
int FlowAlertSidIsnotset(Flow *, uint32_t);

#endif /* __FLOW_ALERT_SID_H__ */

