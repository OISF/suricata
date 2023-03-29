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


int CallbackStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st);
void CallbackStatsLogRegister(void);
void CallbackStatsRegisterCallback(void *user_ctx, CallbackFuncStats cb);
#endif /* __OUTPUT_CALLBACK_STATS_H__ */
