/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate HTTP events and invoke corresponding callback.
 *
 */

#ifndef __OUTPUT_CALLBACK_HTTP_H__
#define __OUTPUT_CALLBACK_HTTP_H__

#define LOG_HTTP_DIR_DOWNLOAD "download"
#define LOG_HTTP_DIR_UPLOAD   "upload"

#include "flow.h"

/* Register the output module. */
void CallbackHttpLogRegister(void);
/* Generate a HTTP event. */
bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, HttpInfo *http);
/* Cleanup all the heap allocated strings in the event. */
void CallbackHttpCleanupInfo(HttpInfo *http);

#endif /* __OUTPUT_CALLBACK_HTTP_H__ */
