/* Copyright (C) 2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements JSON stats counters logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "output.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"

#include "output-json.h"
#include "output-json-stats.h"

#define MODULE_NAME "JsonStatsLog"

#ifdef HAVE_LIBJANSSON

typedef struct OutputStatsCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} OutputStatsCtx;

typedef struct JsonStatsLogThread_ {
    OutputStatsCtx *statslog_ctx;
    MemBuffer *buffer;
} JsonStatsLogThread;

static json_t *OutputStats2Json(json_t *js, const char *key)
{
    void *iter;

    const char *dot = index(key, '.');
    if (dot == NULL)
        return NULL;

    size_t predot_len = (dot - key) + 1;
    char s[predot_len];
    strlcpy(s, key, predot_len);

    iter = json_object_iter_at(js, s);
    const char *s2 = index(dot+1, '.');

    json_t *value = json_object_iter_value(iter);
    if (value == NULL) {
        value = json_object();
        json_object_set_new(js, s, value);
    }
    if (s2 != NULL) {
        return OutputStats2Json(value, &key[dot-key+1]);
    }
    return value;
}

/** \brief turn StatsTable into a json object
 *  \param flags JSON_STATS_* flags for controlling output
 */
json_t *StatsToJSON(const StatsTable *st, uint8_t flags)
{
    const char delta_suffix[] = "_delta";
    struct timeval tval;
    gettimeofday(&tval, NULL);

    json_t *js_stats = json_object();
    if (unlikely(js_stats == NULL)) {
        return NULL;
    }

    /* Uptime, in seconds. */
    double up_time_d = difftime(tval.tv_sec, st->start_time);
    json_object_set_new(js_stats, "uptime",
        json_integer((int)up_time_d));

    uint32_t u = 0;
    if (flags & JSON_STATS_TOTALS) {
        for (u = 0; u < st->nstats; u++) {
            if (st->stats[u].name == NULL)
                continue;
            const char *name = st->stats[u].name;
            const char *shortname = name;
            if (rindex(name, '.') != NULL) {
                shortname = &name[rindex(name, '.') - name + 1];
            }
            json_t *js_type = OutputStats2Json(js_stats, name);
            if (js_type != NULL) {
                json_object_set_new(js_type, shortname,
                    json_integer(st->stats[u].value));

                if (flags & JSON_STATS_DELTAS) {
                    char deltaname[strlen(shortname) + strlen(delta_suffix) + 1];
                    snprintf(deltaname, sizeof(deltaname), "%s%s", shortname,
                        delta_suffix);
                    json_object_set_new(js_type, deltaname,
                        json_integer(st->stats[u].value - st->stats[u].pvalue));
                }
            }
        }
    }

    /* per thread stats - stored in a "threads" object. */
    if (st->tstats != NULL && (flags & JSON_STATS_THREADS)) {
        /* for each thread (store) */
        json_t *threads = json_object();
        if (unlikely(threads == NULL)) {
            json_decref(js_stats);
            return NULL;
        }
        uint32_t x;
        for (x = 0; x < st->ntstats; x++) {
            uint32_t offset = x * st->nstats;

            /* for each counter */
            for (u = offset; u < (offset + st->nstats); u++) {
                if (st->tstats[u].name == NULL)
                    continue;

                char str[256];
                snprintf(str, sizeof(str), "%s.%s", st->tstats[u].tm_name, st->tstats[u].name);
                char *shortname = &str[rindex(str, '.') - str + 1];
                json_t *js_type = OutputStats2Json(threads, str);

                if (js_type != NULL) {
                    json_object_set_new(js_type, shortname, json_integer(st->tstats[u].value));

                    if (flags & JSON_STATS_DELTAS) {
                        char deltaname[strlen(shortname) + strlen(delta_suffix) + 1];
                        snprintf(deltaname, sizeof(deltaname), "%s%s",
                            shortname, delta_suffix);
                        json_object_set_new(js_type, deltaname,
                            json_integer(st->tstats[u].value - st->tstats[u].pvalue));
                    }
                }
            }
        }
        json_object_set_new(js_stats, "threads", threads);
    }
    return js_stats;
}

static int JsonStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st)
{
    SCEnter();
    JsonStatsLogThread *aft = (JsonStatsLogThread *)thread_data;

    struct timeval tval;
    gettimeofday(&tval, NULL);

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return 0;
    char timebuf[64];
    CreateIsoTimeString(&tval, timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));
    json_object_set_new(js, "event_type", json_string("stats"));

    json_t *js_stats = StatsToJSON(st, aft->statslog_ctx->flags);
    if (js_stats == NULL) {
        json_decref(js);
        return 0;
    }

    json_object_set_new(js, "stats", js_stats);

    OutputJSONBuffer(js, aft->statslog_ctx->file_ctx, &aft->buffer);
    MemBufferReset(aft->buffer);

    json_object_clear(js_stats);
    json_object_del(js, "stats");
    json_object_clear(js);
    json_decref(js);

    SCReturnInt(0);
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonStatsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonStatsLogThread *aft = SCMalloc(sizeof(JsonStatsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonStatsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogStats.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->statslog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonStatsLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonStatsLogThread *aft = (JsonStatsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonStatsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputStatsLogDeinit(OutputCtx *output_ctx)
{

    OutputStatsCtx *stats_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = stats_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(stats_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "stats.json"
static OutputCtx *OutputStatsLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_STATS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputStatsCtx *stats_ctx = SCMalloc(sizeof(OutputStatsCtx));
    if (unlikely(stats_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    stats_ctx->flags = JSON_STATS_TOTALS;

    if (conf != NULL) {
        const char *totals = ConfNodeLookupChildValue(conf, "totals");
        const char *threads = ConfNodeLookupChildValue(conf, "threads");
        const char *deltas = ConfNodeLookupChildValue(conf, "deltas");
        SCLogDebug("totals %s threads %s deltas %s", totals, threads, deltas);

        if (totals != NULL && ConfValIsFalse(totals)) {
            stats_ctx->flags &= ~JSON_STATS_TOTALS;
        }
        if (threads != NULL && ConfValIsTrue(threads)) {
            stats_ctx->flags |= JSON_STATS_THREADS;
        }
        if (deltas != NULL && ConfValIsTrue(deltas)) {
            stats_ctx->flags |= JSON_STATS_DELTAS;
        }
        SCLogDebug("stats_ctx->flags %08x", stats_ctx->flags);
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(stats_ctx);
        return NULL;
    }

    stats_ctx->file_ctx = file_ctx;

    output_ctx->data = stats_ctx;
    output_ctx->DeInit = OutputStatsLogDeinit;

    return output_ctx;
}

static void OutputStatsLogDeinitSub(OutputCtx *output_ctx)
{
    OutputStatsCtx *stats_ctx = output_ctx->data;
    SCFree(stats_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputStatsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    OutputStatsCtx *stats_ctx = SCMalloc(sizeof(OutputStatsCtx));
    if (unlikely(stats_ctx == NULL))
        return NULL;

    stats_ctx->flags = JSON_STATS_TOTALS;

    if (conf != NULL) {
        const char *totals = ConfNodeLookupChildValue(conf, "totals");
        const char *threads = ConfNodeLookupChildValue(conf, "threads");
        const char *deltas = ConfNodeLookupChildValue(conf, "deltas");
        SCLogDebug("totals %s threads %s deltas %s", totals, threads, deltas);

        if ((totals != NULL && ConfValIsFalse(totals)) &&
                (threads != NULL && ConfValIsFalse(threads))) {
            SCFree(stats_ctx);
            SCLogError(SC_ERR_JSON_STATS_LOG_NEGATED,
                    "Cannot disable both totals and threads in stats logging");
            return NULL;
        }

        if (totals != NULL && ConfValIsFalse(totals)) {
            stats_ctx->flags &= ~JSON_STATS_TOTALS;
        }
        if (threads != NULL && ConfValIsTrue(threads)) {
            stats_ctx->flags |= JSON_STATS_THREADS;
        }
        if (deltas != NULL && ConfValIsTrue(deltas)) {
            stats_ctx->flags |= JSON_STATS_DELTAS;
        }
        SCLogDebug("stats_ctx->flags %08x", stats_ctx->flags);
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(stats_ctx);
        return NULL;
    }

    stats_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = stats_ctx;
    output_ctx->DeInit = OutputStatsLogDeinitSub;

    return output_ctx;
}

void JsonStatsLogRegister(void) {
    /* register as separate module */
    OutputRegisterStatsModule(LOGGER_JSON_STATS, MODULE_NAME, "stats-json",
        OutputStatsLogInit, JsonStatsLogger, JsonStatsLogThreadInit,
        JsonStatsLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterStatsSubModule(LOGGER_JSON_STATS, "eve-log", MODULE_NAME,
        "eve-log.stats", OutputStatsLogInitSub, JsonStatsLogger,
        JsonStatsLogThreadInit, JsonStatsLogThreadDeinit, NULL);
}

#else

void JsonStatsLogRegister (void)
{
}

#endif
