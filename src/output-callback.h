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

/* Define alias for callbacks. */
typedef OutputJsonCommonSettings OutputCallbackCommonSettings;

/*
 * Global configuration callback context data
 */
typedef struct OutputCallbackCtx {
    OutputCallbackCommonSettings cfg;
} OutputCallbackCtx;


/* Add information common to all events. */
void EventAddCommonInfo(const Packet *p, enum OutputJsonLogDirection dir, Common *common,
                        JsonAddrInfo *addr, OutputCallbackCommonSettings *cfg);
/* Add common information from a flow object. */
void EventAddCommonInfoFromFlow(const Flow *f, Common *common, JsonAddrInfo *addr,
                                OutputCallbackCommonSettings *cfg);
/* Add app layer information (alert and fileinfo). */
void CallbackAddAppLayer(const Packet *p, const uint64_t tx_id, AppLayer *app_layer);
/* Free any memory allocated for app layer information (alert and fileinfo). */
void CallbackCleanupAppLayer(const Packet *p, const uint64_t tx_id, AppLayer *app_layer);
/* Register the output module. */
void OutputCallbackRegister(void);
#endif /* __OUTPUT_CALLBACK_H__ */
