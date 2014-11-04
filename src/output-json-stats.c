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

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define MODULE_NAME "LogStatsLog"

typedef struct OutputStatsCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} OutputStatsCtx;


typedef struct JsonStatsLogThread_ {
    OutputStatsCtx *statslog_ctx;
    //MemBuffer *buffer;
} JsonStatsLogThread;

static void *eve_file_ctx = NULL;
static void *eve_buffer = NULL;

static
json_t *SCPerfLookupJson(json_t *js, char *key)
{
    void *iter;
    char *s = strndup(key, index(key, '.') - key);

    iter = json_object_iter_at(js, s);
    char *s1 = index(key, '.');
    char *s2 = index(s1+1, '.');

    json_t *value = json_object_iter_value(iter);
    if (value == NULL) {
        value = json_object();
        json_object_set(js, s, value);
    }
    if (s2 != NULL) {
        return SCPerfLookupJson(value, &key[index(key,'.')-key+1]);
    }
    return value;
}

static int JsonStatsLogger(ThreadVars *tv, void *thread_data, StatsTable *st)
{
    SCEnter();
    /*JsonStatsLogThread *aft = (JsonStatsLogThread *)thread_data; */

    struct timeval tval;
    struct tm *tms;

    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    /* Calculate the Engine uptime */
    int up_time = (int)difftime(tval.tv_sec, st->start_time);
    int sec = up_time % 60;     // Seconds in a minute
    int in_min = up_time / 60;
    int min = in_min % 60;      // Minutes in a hour
    int in_hours = in_min / 60;
    int hours = in_hours % 24;  // Hours in a day
    int days = in_hours / 24;

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return 0;

    json_object_set_new(js, "event_type", json_string("stats"));
    json_t *js_stats = json_object();
    if (unlikely(js_stats == NULL)) {
        json_decref(js);
        return 0;
    }
    char date[128];
    snprintf(date, sizeof(date),
             "%" PRId32 "/%" PRId32 "/%04d -- %02d:%02d:%02d",
             tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900, tms->tm_hour,
             tms->tm_min, tms->tm_sec);

    json_object_set_new(js_stats, "date", json_string(date));

    char uptime[128];
    snprintf(uptime, sizeof(uptime),
             "%"PRId32"d, %02dh %02dm %02ds", days, hours, min, sec);

    json_object_set_new(js_stats, "uptime", json_string(uptime));

    uint32_t u = 0;
    for (u = 0; u < st->nstats; u++) {
        if (st->stats[u].name == NULL)
            break;
        char str[256];
        snprintf(str, sizeof(str), "%s.%s", st->stats[u].tm_name, st->stats[u].name);
        json_t *js_type = SCPerfLookupJson(js_stats, str);

        if (js_type != NULL) {
            json_object_set_new(js_type, &str[rindex(str, '.')-str+1], json_integer(st->stats[u].value));
        }
    }
    json_object_set_new(js, "stats", js_stats);

    if (eve_file_ctx != NULL && eve_buffer != NULL) {
        OutputJSONBuffer(js, eve_file_ctx, eve_buffer);
    }
    json_object_clear(js);
    json_decref(js);

    SCReturnInt(0);
}

void SCPerfRegisterEveFile(void *file_ctx, void *buffer)
{
    eve_file_ctx = file_ctx;
    eve_buffer = buffer;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonStatsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonStatsLogThread *aft = SCMalloc(sizeof(JsonStatsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonStatsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for json stats.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->statslog_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonStatsLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonStatsLogThread *aft = (JsonStatsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

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
OutputCtx *OutputStatsLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputStatsCtx *stats_ctx = SCMalloc(sizeof(OutputStatsCtx));
    if (unlikely(stats_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
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

OutputCtx *OutputStatsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;
    MemBuffer *buffer;

    OutputStatsCtx *stats_ctx = SCMalloc(sizeof(OutputStatsCtx));
    if (unlikely(stats_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(stats_ctx);
        return NULL;
    }

    stats_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = stats_ctx;
    output_ctx->DeInit = OutputStatsLogDeinitSub;

    buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (buffer == NULL) {
        SCFree(stats_ctx);
        SCFree(output_ctx);
        return NULL;
    }

#if 0
    if (conf) {
        const char *interval_s = ConfNodeLookupChildValue(conf, "interval");
        if (interval_s != NULL)
            interval = (uint32_t) atoi(interval_s);
    }
#endif

#ifdef NOTYET
    SCPerfRegisterEveFile(stats_ctx->file_ctx, buffer, interval);
#endif
    SCPerfRegisterEveFile(stats_ctx->file_ctx, buffer);

    return output_ctx;
}

#if 0
/** \internal
 *  \brief Condition function for Stats logger
 *  \retval bool true or false -- log now?
 */
static int JsonStatsCondition(ThreadVars *tv, const Packet *p) {
    return FALSE;
}
#endif

void TmModuleJsonStatsLogRegister (void) {
    tmm_modules[TMM_JSONSTATSLOG].name = "JsonStatsLog";
    tmm_modules[TMM_JSONSTATSLOG].ThreadInit = JsonStatsLogThreadInit;
    tmm_modules[TMM_JSONSTATSLOG].ThreadDeinit = JsonStatsLogThreadDeinit;
    tmm_modules[TMM_JSONSTATSLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONSTATSLOG].cap_flags = 0;
    tmm_modules[TMM_JSONSTATSLOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterStatsModule("JsonStatsLog", "stats", OutputStatsLogInit,
                              JsonStatsLogger);

    /* also register as child of eve-log */
    OutputRegisterStatsSubModule("eve-log", "JsonStatsLog", "eve-log.stats",
                                  OutputStatsLogInitSub, JsonStatsLogger);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonStatsLogRegister (void)
{
    tmm_modules[TMM_JSONSTATSLOG].name = "JsonStatsLog";
    tmm_modules[TMM_JSONSTATSLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
