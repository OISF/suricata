/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate stats events and invoke corresponding callback.
 *
 */

#ifndef __OUTPUT_CALLBACK_STATS_H__
#define __OUTPUT_CALLBACK_STATS_H__

#include "decode.h"
#include "tm-modules.h"
#include "output-json-stats.h"
#include "util-callbacks.h"


void CallbackStatsLogInit(void *user_ctx, CallbackFuncStats cb);
void CallbackStatsLogger(const StatsTable *st);
#endif /* __OUTPUT_CALLBACK_STATS_H__ */
