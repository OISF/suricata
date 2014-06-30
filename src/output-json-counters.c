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
 * \author Tom DeCanio <tom.decanio@fireeye.com>
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

static int JsonStatsLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    return 0;
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

    SCPerfRegisterEveFile(stats_ctx->file_ctx, buffer);

    return output_ctx;
}

/** \internal
 *  \brief Condition function for Stats logger
 *  \retval bool true or false -- log now?
 */
static int JsonStatsCondition(ThreadVars *tv, const Packet *p) {
    return FALSE;
}

void TmModuleJsonStatsLogRegister (void) {
    tmm_modules[TMM_JSONSTATSLOG].name = "JsonStatsLog";
    tmm_modules[TMM_JSONSTATSLOG].ThreadInit = JsonStatsLogThreadInit;
    tmm_modules[TMM_JSONSTATSLOG].ThreadDeinit = JsonStatsLogThreadDeinit;
    tmm_modules[TMM_JSONSTATSLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONSTATSLOG].cap_flags = 0;
    tmm_modules[TMM_JSONSTATSLOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterPacketModule("JsonSshLog", "stats-json-log", OutputStatsLogInit,
            JsonStatsLogger, JsonStatsCondition);

    /* also register as child of eve-log */
    OutputRegisterPacketSubModule("eve-log", "JsonSshLog", "eve-log.stats", OutputStatsLogInitSub,
            JsonStatsLogger, JsonStatsCondition);
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
