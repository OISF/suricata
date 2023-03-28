/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate flow events and invoke corresponding callback.
 *
 */

#ifndef __OUTPUT_CALLBACK_FLOW_H__
#define __OUTPUT_CALLBACK_FLOW_H__

#include "flow.h"
#include "util-events.h"


/* Register the output module */
void CallbackFlowLogRegister(void);
/* Create a flow event object from a flow. */
void CallbackFlowLog(const Flow *f, FlowInfo *flow);

#endif /* __OUTPUT_CALLBACK_FLOW_H__ */
