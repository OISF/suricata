/* Copyright (C) 2013-2016 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Logs vars in JSON format.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-misc.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-vars.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"

#define MODULE_NAME "JsonMetadataLog"

#ifdef HAVE_LIBJANSSON

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct VarsJsonOutputCtx_ {
    LogFileCtx* file_ctx;
} VarsJsonOutputCtx;

typedef struct JsonVarsLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    MemBuffer *json_buffer;
    VarsJsonOutputCtx* json_output_ctx;
} JsonVarsLogThread;

static int VarsJson(ThreadVars *tv, JsonVarsLogThread *aft, const Packet *p)
{
    json_t *js = CreateJSONHeader((Packet *)p, 0, "metadata");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    JsonAddMetadata(p, p->flow, js);
    OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);
    json_object_del(js, "metadata");
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

static int JsonVarsLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonVarsLogThread *aft = thread_data;

    return VarsJson(tv, aft, p);
}

static int JsonVarsLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->pktvar) {
        return TRUE;
    }
    return FALSE;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonVarsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonVarsLogThread *aft = SCMalloc(sizeof(JsonVarsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonVarsLogThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogVars.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->json_buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->json_buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    VarsJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = json_output_ctx->file_ctx;
    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonVarsLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonVarsLogThread *aft = (JsonVarsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->json_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonVarsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonVarsLogDeInitCtx(OutputCtx *output_ctx)
{
    VarsJsonOutputCtx *json_output_ctx = (VarsJsonOutputCtx *) output_ctx->data;
    if (json_output_ctx != NULL) {
        LogFileFreeCtx(json_output_ctx->file_ctx);
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

static void JsonVarsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    VarsJsonOutputCtx *json_output_ctx = (VarsJsonOutputCtx *) output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "metadata.json"

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonVarsLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    VarsJsonOutputCtx *json_output_ctx = NULL;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("VarsFastLogInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    json_output_ctx = SCMalloc(sizeof(VarsJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        SCFree(output_ctx);
        return result;
    }
    memset(json_output_ctx, 0, sizeof(VarsJsonOutputCtx));

    json_output_ctx->file_ctx = logfile_ctx;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonVarsLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonVarsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    VarsJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCMalloc(sizeof(VarsJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(VarsJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonVarsLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    if (output_ctx != NULL) {
        SCFree(output_ctx);
    }

    return result;
}

void JsonVarsLogRegister (void)
{
    /* Kept for compatibility. */
    OutputRegisterPacketModule(LOGGER_JSON_METADATA, MODULE_NAME,
        "metadata-json-log", JsonVarsLogInitCtx, JsonVarsLogger,
        JsonVarsLogCondition, JsonVarsLogThreadInit,
        JsonVarsLogThreadDeinit, NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_METADATA, "eve-log", MODULE_NAME,
        "eve-log.metadata", JsonVarsLogInitCtxSub, JsonVarsLogger,
        JsonVarsLogCondition, JsonVarsLogThreadInit, JsonVarsLogThreadDeinit,
        NULL);

    /* Kept for compatibility. */
    OutputRegisterPacketModule(LOGGER_JSON_METADATA, MODULE_NAME,
        "vars-json-log", JsonVarsLogInitCtx, JsonVarsLogger,
        JsonVarsLogCondition, JsonVarsLogThreadInit, JsonVarsLogThreadDeinit,
        NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_METADATA, "eve-log", MODULE_NAME,
        "eve-log.vars", JsonVarsLogInitCtxSub, JsonVarsLogger,
        JsonVarsLogCondition, JsonVarsLogThreadInit, JsonVarsLogThreadDeinit,
        NULL);
}

#else

void JsonVarsLogRegister (void)
{
}

#endif
