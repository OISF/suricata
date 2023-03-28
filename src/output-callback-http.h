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

#include "flow.h"


/* Register the output module. */
void CallbackHttpLogRegister(void);
/* Generate a HTTP event. */
bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, const char *dir, HttpInfo *http);

#endif /* __OUTPUT_CALLBACK_HTTP_H__ */
