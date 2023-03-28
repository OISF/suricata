/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate alerts and invoke corresponding callback.
 *
 */

#ifndef __OUTPUT_CALLBACK_ALERT_H__
#define __OUTPUT_CALLBACK_ALERT_H__

#include "decode.h"
#include "util-events.h"

/* Register the output module */
void CallbackAlertLogRegister(void);
/* Create an alert object from a packet alert. */
void AlertCallbackHeader(const Packet *p, const PacketAlert *pa, Alert *alert);
#endif /* __OUTPUT_CALLBACK_ALERT_H__ */
