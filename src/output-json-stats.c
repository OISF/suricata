/* Copyright (C) 2014-2020 Open Information Security Foundation
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
#include "detect-engine.h"

#include "util-time.h"

#include "output-json.h"
#include "output-json-stats.h"

#define MODULE_NAME "JsonStatsLog"

extern bool stats_decoder_events;
extern const char *stats_decoder_events_prefix;

/**
 * specify which engine info will be printed in stats log.
 * ALL means both last reload and ruleset stats.
 */
typedef enum OutputEngineInfo_ {
    OUTPUT_ENGINE_LAST_RELOAD = 0,
    OUTPUT_ENGINE_RULESET,
    OUTPUT_ENGINE_ALL,
} OutputEngineInfo;

typedef struct OutputStatsCtx_ {
    LogFileCtx *file_ctx;
    uint8_t flags; /** Store mode */
} OutputStatsCtx;

typedef struct JsonStatsLogThread_ {
    OutputStatsCtx *statslog_ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} JsonStatsLogThread;

static json_t *EngineStats2Json(const DetectEngineCtx *de_ctx,
                                const OutputEngineInfo output)
{
    struct timeval last_reload;
    char timebuf[64];
    const SigFileLoaderStat *sig_stat = NULL;

    json_t *jdata = json_object();
    if (jdata == NULL) {
        return NULL;
    }

    if (output == OUTPUT_ENGINE_LAST_RELOAD || output == OUTPUT_ENGINE_ALL) {
        last_reload = de_ctx->last_reload;
        CreateIsoTimeString(&last_reload, timebuf, sizeof(timebuf));
        json_object_set_new(jdata, "last_reload", json_string(timebuf));
    }

    sig_stat = &de_ctx->sig_stat;
    if ((output == OUTPUT_ENGINE_RULESET || output == OUTPUT_ENGINE_ALL) &&
        sig_stat != NULL)
    {
        json_object_set_new(jdata, "rules_loaded",
                            json_integer(sig_stat->good_sigs_total));
        json_object_set_new(jdata, "rules_failed",
                            json_integer(sig_stat->bad_sigs_total));
    }

    return jdata;
}

static TmEcode OutputEngineStats2Json(json_t **jdata, const OutputEngineInfo output)
{
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx == NULL) {
        goto err1;
    }
    /* Since we need to deference de_ctx pointer, we don't want to lost it. */
    DetectEngineCtx *list = de_ctx;

    json_t *js_tenant_list = json_array();
    json_t *js_tenant = NULL;

    if (js_tenant_list == NULL) {
        goto err2;
    }

    while(list) {
        js_tenant = json_object();
        if (js_tenant == NULL) {
            goto err3;
        }
        json_object_set_new(js_tenant, "id", json_integer(list->tenant_id));

        json_t *js_stats = EngineStats2Json(list, output);
        if (js_stats == NULL) {
            goto err4;
        }
        json_object_update(js_tenant, js_stats);
        json_array_append_new(js_tenant_list, js_tenant);
        json_decref(js_stats);
        list = list->next;
    }

    DetectEngineDeReference(&de_ctx);
    *jdata = js_tenant_list;
    return TM_ECODE_OK;

err4:
    json_object_clear(js_tenant);
    json_decref(js_tenant);

err3:
    json_object_clear(js_tenant_list);
    json_decref(js_tenant_list);

err2:
    DetectEngineDeReference(&de_ctx);

err1:
    json_object_set_new(*jdata, "message", json_string("Unable to get info"));
    return TM_ECODE_FAILED;
}

TmEcode OutputEngineStatsReloadTime(json_t **jdata) {
    return OutputEngineStats2Json(jdata, OUTPUT_ENGINE_LAST_RELOAD);
}

TmEcode OutputEngineStatsRuleset(json_t **jdata) {
    return OutputEngineStats2Json(jdata, OUTPUT_ENGINE_RULESET);
}

static json_t *OutputStats2Json(json_t *js, const char *key)
{
    void *iter;

    const char *dot = strchr(key, '.');
    if (dot == NULL)
        return NULL;
    if (strlen(dot) > 2) {
        if (*(dot + 1) == '.' && *(dot + 2) != '\0')
            dot = strchr(dot + 2, '.');
    }

    size_t predot_len = (dot - key) + 1;
    char s[predot_len];
    strlcpy(s, key, predot_len);

    iter = json_object_iter_at(js, s);
    const char *s2 = strchr(dot+1, '.');

    json_t *value = json_object_iter_value(iter);
    if (value == NULL) {
        value = json_object();

        if (!strncmp(s, "detect", 6)) {
            json_t *js_engine = NULL;

            TmEcode ret = OutputEngineStats2Json(&js_engine, OUTPUT_ENGINE_ALL);
            if (ret == TM_ECODE_OK && js_engine) {
                json_object_set_new(value, "engines", js_engine);
            }
        }
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
            if (strrchr(name, '.') != NULL) {
                shortname = &name[strrchr(name, '.') - name + 1];
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
                char *shortname = &str[strrchr(str, '.') - str + 1];
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

    OutputJSONBuffer(js, aft->file_ctx, &aft->buffer);
    MemBufferReset(aft->buffer);

    json_object_clear(js_stats);
    json_object_del(js, "stats");
    json_object_clear(js);
    json_decref(js);

    SCReturnInt(0);
}

static TmEcode JsonStatsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonStatsLogThread *aft = SCCalloc(1, sizeof(JsonStatsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogStats.  \"initdata\" argument NULL");
        goto error_exit;
    }

    aft->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->statslog_ctx = ((OutputCtx *)initdata)->data;

    aft->file_ctx = LogFileEnsureExists(aft->statslog_ctx->file_ctx, t->id);
    if (!aft->file_ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    if (aft->buffer != NULL) {
        MemBufferFree(aft->buffer);
    }
    SCFree(aft);
    return TM_ECODE_FAILED;
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

static void OutputStatsLogDeinitSub(OutputCtx *output_ctx)
{
    OutputStatsCtx *stats_ctx = output_ctx->data;
    SCFree(stats_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputStatsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    if (!StatsEnabled()) {
        SCLogError(SC_ERR_STATS_LOG_GENERIC,
                "eve.stats: stats are disabled globally: set stats.enabled to true. "
                "See %s/configuration/suricata-yaml.html#stats", GetDocURL());
        return result;
    }

    OutputStatsCtx *stats_ctx = SCMalloc(sizeof(OutputStatsCtx));
    if (unlikely(stats_ctx == NULL))
        return result;

    if (stats_decoder_events &&
            strcmp(stats_decoder_events_prefix, "decoder") == 0) {
        SCLogWarning(SC_WARN_EVE_MISSING_EVENTS, "eve.stats will not display "
                "all decoder events correctly. See #2225. Set a prefix in "
                "stats.decoder-events-prefix.");
    }

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
            return result;
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
        return result;
    }

    stats_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = stats_ctx;
    output_ctx->DeInit = OutputStatsLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonStatsLogRegister(void) {
    /* register as child of eve-log */
    OutputRegisterStatsSubModule(LOGGER_JSON_STATS, "eve-log", MODULE_NAME,
        "eve-log.stats", OutputStatsLogInitSub, JsonStatsLogger,
        JsonStatsLogThreadInit, JsonStatsLogThreadDeinit, NULL);
}
