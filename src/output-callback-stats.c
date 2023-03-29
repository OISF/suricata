/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate stats events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"
#include "output.h"
#include "output-callback-stats.h"
#include "util-debug.h"

#define MODULE_NAME "CallbackStatsLog"


typedef struct CallbackStatsCtx {
    uint32_t flags;
    CallbackFuncStats *cb;
    void *user_ctx;
} CallbackStatsCtx;

static CallbackStatsCtx StatsCtx;

/* Mock ThreadInit/DeInit methods.
 * Callback doest store any per-thread information. */
static TmEcode CallbackStatsLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackStatsLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

void CallbackStatsRegisterCallback(void *user_ctx, CallbackFuncStats cb) {
    StatsCtx.cb = cb;
    StatsCtx.user_ctx = user_ctx;
}

static OutputInitResult CallbackStatsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };

    if (!StatsEnabled()) {
        SCLogError("callback.stats: stats are disabled globally: set stats.enabled to true.");
        return result;
    }

    /* Enable aggregated stats by default. */
    StatsCtx.flags = JSON_STATS_TOTALS;

    if (conf != NULL) {
        const char *totals = ConfNodeLookupChildValue(conf, "totals");
        const char *threads = ConfNodeLookupChildValue(conf, "threads");

        SCLogDebug("totals %s threads %s", totals, threads);

        if ((totals != NULL && ConfValIsFalse(totals)) &&
            (threads != NULL && ConfValIsFalse(threads))) {
            SCLogError("Cannot disable both totals and threads in stats logging");
            return result;
        }

        if (totals != NULL && ConfValIsFalse(totals)) {
            StatsCtx.flags &= ~JSON_STATS_TOTALS;
        }
        if (threads != NULL && ConfValIsTrue(threads)) {
            StatsCtx.flags |= JSON_STATS_THREADS;
        }
    }

    SCLogDebug("stats flags %08x", flags);

    result.ok = true;
    return result;
}

int CallbackStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st) {
    if (StatsCtx.cb == NULL) {
        SCLogError("Stats callback is NULL, stats cannot be provided");
        return 0;
    }

    struct timeval tval;
    gettimeofday(&tval, NULL);

    json_t *js = json_object();
    if (unlikely(js == NULL)) {
        return 0;
    }

    char timebuf[64];
    CreateIsoTimeString(SCTIME_FROM_TIMEVAL(&tval), timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));
    json_object_set_new(js, "event_type", json_string("stats"));

    json_t *js_stats = StatsToJSON(st, StatsCtx.flags);
    if (js_stats == NULL) {
        json_decref(js);
        return 0;
    }

    json_object_set_new(js, "stats", js_stats);

    /* Invoke stats callback. */
    const char *line = json_dumps(js, 0);
    if (line != NULL) {
        StatsCtx.cb((void *)line, strlen(line), StatsCtx.user_ctx);
        SCFree((void *)line);
    }

    json_object_clear(js_stats);
    json_object_del(js, "stats");
    json_object_clear(js);
    json_decref(js);
    return 0;
}

void CallbackStatsLogRegister(void) {
    OutputRegisterStatsSubModule(LOGGER_CALLBACK_STATS, "callback", MODULE_NAME, "callback.stats",
                                 CallbackStatsLogInitSub, CallbackStatsLogger,
                                 CallbackStatsLogThreadInit, CallbackStatsLogThreadDeinit, NULL);
}
