/* Copyright (C) 2019 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Logs anomalies in JSON format.
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

#include "detect-parse.h"
#include "detect-engine.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-anomaly.h"

#include "util-byte.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonAnomalyLog"

#ifdef HAVE_LIBJANSSON

#define LOG_JSON_PACKETHDR      BIT_U16(0)

typedef struct AnomalyJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;
    OutputJsonCommonSettings cfg;
} AnomalyJsonOutputCtx;

typedef struct JsonAnomalyLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    MemBuffer *json_buffer;
    AnomalyJsonOutputCtx* json_output_ctx;
} JsonAnomalyLogThread;

static int AnomalyJson(ThreadVars *tv, JsonAnomalyLogThread *aft, const Packet *p)
{
    bool is_ip_pkt = PKT_IS_IPV4(p) || PKT_IS_IPV6(p);

    char timebuf[64];
    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (int i = 0; i < p->events.cnt; i++) {
        MemBufferReset(aft->json_buffer);

        json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "anomaly");

        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }

        json_t *ajs = json_object();
        if (unlikely(ajs == NULL)) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        if (!is_ip_pkt) {
            json_object_set_new(js, "timestamp", json_string(timebuf));
        } else {
            JsonFiveTuple((const Packet *)p, LOG_DIR_PACKET, js);
            JsonAddCommonOptions(&aft->json_output_ctx->cfg, p, p->flow, js);
        }

        if (aft->json_output_ctx->flags & LOG_JSON_PACKETHDR) {
            JsonPacket(p, js, GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
        }

        uint8_t event_code = p->events.events[i];
        if (event_code < DECODE_EVENT_MAX) {
            const char *event = DEvents[event_code].event_name;
            json_object_set_new(ajs, "type",
                                EVENT_IS_DECODER_PACKET_ERROR(event_code) ? 
                                    json_string("packet") : json_string("stream"));
            json_object_set_new(ajs, "event", json_string(event));
        } else {
            /* include event code with unrecognized events */
            uint32_t offset = 0;
            char unknown_event_buf[8];
            json_object_set_new(ajs, "type", json_string("unknown"));
            PrintBufferData(unknown_event_buf, &offset, 8, "%d", event_code);
            json_object_set_new(ajs, "code", json_string(unknown_event_buf));
        }

        /* anomaly */
        json_object_set_new(js, "anomaly", ajs);
        OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);

        json_object_clear(js);
        json_decref(js);
    }

    return TM_ECODE_OK;
}


static int JsonAnomalyLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAnomalyLogThread *aft = thread_data;
    return AnomalyJson(tv, aft, p);
}

static int JsonAnomalyLogCondition(ThreadVars *tv, const Packet *p)
{
    return p->events.cnt > 0 ? TRUE : FALSE;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonAnomalyLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonAnomalyLogThread *aft = SCCalloc(1, sizeof(JsonAnomalyLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogAnomaly.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->json_buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->json_buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    AnomalyJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = json_output_ctx->file_ctx;
    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonAnomalyLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonAnomalyLogThread *aft = (JsonAnomalyLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->json_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonAnomalyLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonAnomalyLogDeInitCtx(OutputCtx *output_ctx)
{
    AnomalyJsonOutputCtx *json_output_ctx = (AnomalyJsonOutputCtx *) output_ctx->data;
    if (json_output_ctx != NULL) {
        LogFileFreeCtx(json_output_ctx->file_ctx);
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

static void JsonAnomalyLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    AnomalyJsonOutputCtx *json_output_ctx = (AnomalyJsonOutputCtx *) output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "anomaly.json"
static void SetFlag(const ConfNode *conf, const char *name, uint16_t flag, uint16_t *out_flags)
{
    DEBUG_VALIDATE_BUG_ON(conf == NULL);
    const char *setting = ConfNodeLookupChildValue(conf, name);
    if (setting != NULL) {
        if (ConfValIsTrue(setting)) {
            *out_flags |= flag;
        } else {
            *out_flags &= ~flag;
        }
    }
}

static void JsonAnomalyLogConf(AnomalyJsonOutputCtx *json_output_ctx,
        ConfNode *conf)
{
    uint16_t flags = 0;
    if (conf != NULL) {
        SetFlag(conf, "packethdr", LOG_JSON_PACKETHDR, &flags);
    }
    json_output_ctx->flags |= flags;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonAnomalyLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    AnomalyJsonOutputCtx *json_output_ctx = NULL;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("JsonAnomalyLogInitCtx: Could not create new LogFileCtx");
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

    json_output_ctx = SCCalloc(1, sizeof(AnomalyJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        SCFree(output_ctx);
        return result;
    }

    json_output_ctx->file_ctx = logfile_ctx;
    JsonAnomalyLogConf(json_output_ctx, conf);

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonAnomalyLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonAnomalyLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    AnomalyJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCCalloc(1, sizeof(AnomalyJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }

    json_output_ctx->file_ctx = ajt->file_ctx;
    JsonAnomalyLogConf(json_output_ctx, conf);
    json_output_ctx->cfg = ajt->cfg;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonAnomalyLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    SCFree(output_ctx);

    return result;
}

void JsonAnomalyLogRegister (void)
{
    OutputRegisterPacketModule(LOGGER_JSON_ANOMALY, MODULE_NAME, "anomaly-json-log",
        JsonAnomalyLogInitCtx, JsonAnomalyLogger, JsonAnomalyLogCondition,
        JsonAnomalyLogThreadInit, JsonAnomalyLogThreadDeinit, NULL);

    OutputRegisterPacketSubModule(LOGGER_JSON_ANOMALY, "eve-log", MODULE_NAME,
        "eve-log.anomaly", JsonAnomalyLogInitCtxSub, JsonAnomalyLogger,
        JsonAnomalyLogCondition, JsonAnomalyLogThreadInit, JsonAnomalyLogThreadDeinit,
        NULL);
}

#else

void JsonAnomalyLogRegister (void)
{
}

#endif
