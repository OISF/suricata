/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author FirstName LastName <yourname@domain>
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
#include "detect-metadata.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-template-packet.h"

#define MODULE_NAME "JsonTemplatePacketLog"

#ifdef HAVE_LIBJANSSON

typedef struct TemplatePacketJsonOutputCtx_ {
    LogFileCtx* file_ctx;
} TemplatePacketJsonOutputCtx;

typedef struct JsonTemplatePacketLogThread_ {
    LogFileCtx *file_ctx;
    MemBuffer *json_buffer;
    TemplatePacketJsonOutputCtx *json_output_ctx;
    uint64_t count;
} JsonTemplatePacketLogThread;

static int JsonTemplatePacketLogger(ThreadVars *tv, void *thread_data,
    const Packet *p)
{
    JsonTemplatePacketLogThread *aft = thread_data;

    /* Do nothing is packet is no IPv4 or IPv6. */
    if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
        return 0;
    }

    /* For the purpose of this example template we're logging the
     * number of packets logged per thread, so up the counter here. */
    aft->count++;

    MemBufferReset(aft->json_buffer);

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "template-packet");
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    /* This is where the information specific to this packet logger is
     * logged. */
    json_t *template = json_object();
    if (unlikely(template == NULL)) {
        json_decref(js);
        return TM_ECODE_OK;
    }
    json_object_set_new(template, "count", json_integer(aft->count));


    /* Add the packet data to the root JSON object. */
    json_object_set_new(js, "template", template);

    OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);
    json_decref(js);

    return TM_ECODE_OK;
}

static int JsonTemplatePacketLogCondition(ThreadVars *tv, const Packet *p)
{
    return TRUE;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonTemplatePacketLogThreadInit(ThreadVars *t,
    const void *initdata, void **data)
{
    JsonTemplatePacketLogThread *aft = SCCalloc(1, sizeof(JsonTemplatePacketLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTemplatePacket.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->json_buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->json_buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    TemplatePacketJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = json_output_ctx->file_ctx;
    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonTemplatePacketLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonTemplatePacketLogThread *aft = (JsonTemplatePacketLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->json_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonTemplatePacketLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonTemplatePacketLogDeInitCtx(OutputCtx *output_ctx)
{
    TemplatePacketJsonOutputCtx *json_output_ctx = (TemplatePacketJsonOutputCtx *) output_ctx->data;
    if (json_output_ctx != NULL) {
        LogFileFreeCtx(json_output_ctx->file_ctx);
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

static void JsonTemplatePacketLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    TemplatePacketJsonOutputCtx *json_output_ctx = (TemplatePacketJsonOutputCtx *) output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "template-packet.json"

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonTemplatePacketLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    TemplatePacketJsonOutputCtx *json_output_ctx = NULL;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("JsonTemplatePacket: Could not create new LogFileCtx");
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

    json_output_ctx = SCMalloc(sizeof(TemplatePacketJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        SCFree(output_ctx);
        return result;
    }
    memset(json_output_ctx, 0, sizeof(TemplatePacketJsonOutputCtx));

    json_output_ctx->file_ctx = logfile_ctx;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonTemplatePacketLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonTemplatePacketLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    TemplatePacketJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCMalloc(sizeof(TemplatePacketJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(TemplatePacketJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonTemplatePacketLogDeInitCtxSub;

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

void JsonTemplatePacketLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_JSON_TEMPLATE_PACKET, MODULE_NAME,
        "template-packet-json-log", JsonTemplatePacketLogInitCtx,
        JsonTemplatePacketLogger, JsonTemplatePacketLogCondition,
        JsonTemplatePacketLogThreadInit, JsonTemplatePacketLogThreadDeinit,
        NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_TEMPLATE_PACKET, "eve-log",
        MODULE_NAME, "eve-log.template-packet", JsonTemplatePacketLogInitCtxSub,
        JsonTemplatePacketLogger, JsonTemplatePacketLogCondition,
        JsonTemplatePacketLogThreadInit, JsonTemplatePacketLogThreadDeinit,
        NULL);
}

#else

void JsonTemplatePacketLogRegister (void)
{
}

#endif
