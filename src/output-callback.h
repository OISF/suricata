/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Common utilities for event callbacks.
 *
 */

#ifndef __OUTPUT_CALLBACK_H__
#define __OUTPUT_CALLBACK_H__

#include "output-json.h"
#include "util-events.h"

#define OUTPUT_DIR_PACKET_FLOW_TOCLIENT "to_client"
#define OUTPUT_DIR_PACKET_FLOW_TOSERVER "to_server"

void EventAddCommonInfo(const Packet *p, enum OutputJsonLogDirection dir, Common *common);

#endif /* __OUTPUT_CALLBACK_H__ */
