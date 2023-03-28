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

#define LOG_HTTP_DIR_DOWNLOAD           "download"
#define LOG_HTTP_DIR_UPLOAD             "upload"
#define LOG_HTTP_REQ_HEADERS 8
#define LOG_HTTP_RES_HEADERS 16

#include "flow.h"

/* Register the output module. */
void CallbackHttpLogRegister(void);
/* Generate a HTTP event. */
bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, const char *dir, HttpInfo *http);

#endif /* __OUTPUT_CALLBACK_HTTP_H__ */
