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
#define LOG_HTTP_DIR_DOWNLOAD           "download"
#define LOG_HTTP_DIR_UPLOAD             "upload"

/* Add information common to all events. */
void EventAddCommonInfo(const Packet *p, enum OutputJsonLogDirection dir, Common *common,
                        JsonAddrInfo *addr);
/* Add app layer information (alert and fileinfo). */
void CallbackAddAppLayer(const Packet *p, const uint64_t tx_id, app_layer *app_layer);
/* Free any memory allocated for app layer information (alert and fileinfo). */
void CallbackCleanupAppLayer(const Packet *p, const uint64_t tx_id, app_layer *app_layer);

#endif /* __OUTPUT_CALLBACK_H__ */
