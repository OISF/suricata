/* Copyright (C) 2019-2022 Open Information Security Foundation
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
#include "app-layer.h"
#include "app-layer-events.h"
#include "app-layer-parser.h"

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
#include "util-enum.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-validate.h"

#define MODULE_NAME "JsonAnomalyLog"

#define ANOMALY_EVENT_TYPE      "anomaly"
#define LOG_JSON_DECODE_TYPE    BIT_U16(0)
#define LOG_JSON_STREAM_TYPE    BIT_U16(1)
#define LOG_JSON_APPLAYER_TYPE  BIT_U16(2)
#define LOG_JSON_PACKETHDR      BIT_U16(3)

#define LOG_JSON_PACKET_TYPE   (LOG_JSON_DECODE_TYPE | LOG_JSON_STREAM_TYPE)
#define ANOMALY_DEFAULTS       LOG_JSON_APPLAYER_TYPE

#define TX_ID_UNUSED UINT64_MAX

typedef struct AnomalyJsonOutputCtx_ {
    uint16_t flags;
    OutputJsonCtx *eve_ctx;
} AnomalyJsonOutputCtx;

typedef struct JsonAnomalyLogThread_ {
    AnomalyJsonOutputCtx* json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonAnomalyLogThread;

/*
 * Restrict the anomaly logger count due to decoder state maintenance issues
 */

#define MAX_ANOMALY_LOGGERS 1
static int anomaly_loggers = 0;
static bool OutputAnomalyLoggerEnable(void)
{
    if (anomaly_loggers < MAX_ANOMALY_LOGGERS) {
        anomaly_loggers++;
        return true;
    }
    return false;
}

static void OutputAnomalyLoggerDisable(void)
{
    if (anomaly_loggers)
        anomaly_loggers--;
}

static int AnomalyDecodeEventJson(ThreadVars *tv, JsonAnomalyLogThread *aft,
                                  const Packet *p)
{
    const uint16_t log_type = aft->json_output_ctx->flags;
    const bool log_stream = log_type & LOG_JSON_STREAM_TYPE;
    const bool log_decode = log_type & LOG_JSON_DECODE_TYPE;

    for (int i = 0; i < p->events.cnt; i++) {
        uint8_t event_code = p->events.events[i];
        bool is_decode = EVENT_IS_DECODER_PACKET_ERROR(event_code);
        if (is_decode && !log_decode)
            continue;
        if (!is_decode && !log_stream)
            continue;

        JsonBuilder *js = CreateEveHeader(
                p, LOG_DIR_PACKET, ANOMALY_EVENT_TYPE, NULL, aft->json_output_ctx->eve_ctx);
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(js, ANOMALY_EVENT_TYPE);

        if (event_code < DECODE_EVENT_MAX) {
            const char *event = DEvents[event_code].event_name;
            if (EVENT_IS_DECODER_PACKET_ERROR(event_code)) {
                JB_SET_STRING(js, "type", "decode");
            } else {
                JB_SET_STRING(js, "type", "stream");
            }
            jb_set_string(js, "event", event);
        } else {
            JB_SET_STRING(js, "type", "unknown");
            jb_set_uint(js, "code", event_code);
        }

        /* Close anomaly object. */
        jb_close(js);

        if (aft->json_output_ctx->flags & LOG_JSON_PACKETHDR) {
            EvePacket(p, js, GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
        }

        OutputJsonBuilderBuffer(js, aft->ctx);
        jb_free(js);
    }

    return TM_ECODE_OK;
}

static int AnomalyAppLayerDecoderEventJson(JsonAnomalyLogThread *aft,
                        const Packet *p, AppLayerDecoderEvents *decoder_events,
                        bool is_pktlayer, const char *layer, uint64_t tx_id)
{
    const char *alprotoname = AppLayerGetProtoName(p->flow->alproto);

    SCLogDebug("decoder_events %p event_count %d (last logged %d) %s",
                decoder_events, decoder_events->cnt,
                decoder_events->event_last_logged,
                tx_id != TX_ID_UNUSED ? "tx" : "no-tx");

    for (int i = decoder_events->event_last_logged; i < decoder_events->cnt; i++) {
        JsonBuilder *js;
        if (tx_id != TX_ID_UNUSED) {
            js = CreateEveHeaderWithTxId(p, LOG_DIR_PACKET, ANOMALY_EVENT_TYPE, NULL, tx_id,
                    aft->json_output_ctx->eve_ctx);
        } else {
            js = CreateEveHeader(
                    p, LOG_DIR_PACKET, ANOMALY_EVENT_TYPE, NULL, aft->json_output_ctx->eve_ctx);
        }
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }


        jb_open_object(js, ANOMALY_EVENT_TYPE);

        jb_set_string(js, "app_proto", alprotoname);

        const char *event_name = NULL;
        uint8_t event_code = decoder_events->events[i];
        AppLayerEventType event_type;
        int r;
        if (is_pktlayer) {
            r = AppLayerGetEventInfoById(event_code, &event_name, &event_type);
        } else {
            r = AppLayerParserGetEventInfoById(p->flow->proto, p->flow->alproto,
                                               event_code, &event_name, &event_type);
        }
        if (r == 0) {
            JB_SET_STRING(js, "type", "applayer");
            jb_set_string(js, "event", event_name);
        } else {
            JB_SET_STRING(js, "type", "unknown");
            jb_set_uint(js, "code", event_code);
        }

        jb_set_string(js, "layer", layer);

        /* anomaly */
        jb_close(js);
        OutputJsonBuilderBuffer(js, aft->ctx);
        jb_free(js);

        /* Current implementation assumes a single owner for this value */
        decoder_events->event_last_logged++;
    }

    return TM_ECODE_OK;
}

static int JsonAnomalyTxLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                               Flow *f, void *state, void *tx, uint64_t tx_id)
{
    JsonAnomalyLogThread *aft = thread_data;
    if (!(aft->json_output_ctx->flags & LOG_JSON_APPLAYER_TYPE)) {
        return TM_ECODE_OK;
    }

    AppLayerDecoderEvents *decoder_events;
    decoder_events = AppLayerParserGetEventsByTx(f->proto, f->alproto, tx);
    if (decoder_events && decoder_events->event_last_logged < decoder_events->cnt) {
        SCLogDebug("state %p, tx: %p, tx_id: %"PRIu64, state, tx, tx_id);
        AnomalyAppLayerDecoderEventJson(aft, p, decoder_events, false,
                                        "proto_parser", tx_id);
    }
    return TM_ECODE_OK;
}

static inline bool AnomalyHasParserEvents(const Packet *p)
{
    return (p->flow && p->flow->alparser &&
            AppLayerParserHasDecoderEvents(p->flow->alparser));
}

static inline bool AnomalyHasPacketAppLayerEvents(const Packet *p)
{
    return p->app_layer_events && p->app_layer_events->cnt;
}

static int AnomalyJson(ThreadVars *tv, JsonAnomalyLogThread *aft, const Packet *p)
{
    int rc = TM_ECODE_OK;

    /* decode or stream */
    if (aft->json_output_ctx->flags & LOG_JSON_PACKET_TYPE) {
        if (p->events.cnt) {
            rc = AnomalyDecodeEventJson(tv, aft, p);
        }
    }

    /* applayer */
    if (aft->json_output_ctx->flags & LOG_JSON_APPLAYER_TYPE) {
        /* app layer proto detect events */
        if (rc == TM_ECODE_OK && AnomalyHasPacketAppLayerEvents(p)) {
            rc = AnomalyAppLayerDecoderEventJson(aft, p, p->app_layer_events,
                                                 true, "proto_detect", TX_ID_UNUSED);
        }

        /* parser state events */
        if (rc == TM_ECODE_OK && AnomalyHasParserEvents(p)) {
            SCLogDebug("Checking for anomaly events; alproto %d", p->flow->alproto);
            AppLayerDecoderEvents *parser_events = AppLayerParserGetDecoderEvents(p->flow->alparser);
            if (parser_events && (parser_events->event_last_logged < parser_events->cnt)) {
                rc = AnomalyAppLayerDecoderEventJson(aft, p, parser_events,
                                                     false, "parser", TX_ID_UNUSED);
            }
        }
    }

    return rc;
}

static int JsonAnomalyLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAnomalyLogThread *aft = thread_data;
    return AnomalyJson(tv, aft, p);
}

static int JsonAnomalyLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return p->events.cnt > 0 ||
           (p->app_layer_events && p->app_layer_events->cnt > 0) ||
           AnomalyHasParserEvents(p);
}

static TmEcode JsonAnomalyLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonAnomalyLogThread *aft = SCCalloc(1, sizeof(JsonAnomalyLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogAnomaly.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    AnomalyJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

    aft->ctx = CreateEveThreadCtx(t, json_output_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }
    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonAnomalyLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonAnomalyLogThread *aft = (JsonAnomalyLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonAnomalyLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonAnomalyLogDeInitCtxSubHelper(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    AnomalyJsonOutputCtx *json_output_ctx = (AnomalyJsonOutputCtx *) output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

static void JsonAnomalyLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputAnomalyLoggerDisable();

    JsonAnomalyLogDeInitCtxSubHelper(output_ctx);
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
    static bool warn_no_flags = false;
    static bool warn_no_packet = false;
    uint16_t flags = ANOMALY_DEFAULTS;
    if (conf != NULL) {
        /* Check for metadata to enable/disable. */
        ConfNode *typeconf = ConfNodeLookupChild(conf, "types");
        if (typeconf != NULL) {
            SetFlag(typeconf, "applayer", LOG_JSON_APPLAYER_TYPE, &flags);
            SetFlag(typeconf, "stream", LOG_JSON_STREAM_TYPE, &flags);
            SetFlag(typeconf, "decode", LOG_JSON_DECODE_TYPE, &flags);
        }
        SetFlag(conf, "packethdr", LOG_JSON_PACKETHDR, &flags);
    }
    if (((flags & (LOG_JSON_DECODE_TYPE | LOG_JSON_PACKETHDR)) == LOG_JSON_PACKETHDR) && !warn_no_packet) {
        SCLogWarning(SC_WARN_ANOMALY_CONFIG, "Anomaly logging configured to include packet headers, however decode "
                     "type logging has not been selected. Packet headers will not be logged.");
        warn_no_packet = true;
        flags &= ~LOG_JSON_PACKETHDR;
    }

    if (flags == 0 && !warn_no_flags) {
        SCLogWarning(SC_WARN_ANOMALY_CONFIG, "Anomaly logging has been configured; however, no logging types "
                     "have been selected. Select one or more logging types.");
        warn_no_flags = true;
    }
    json_output_ctx->flags |= flags;
}

static OutputInitResult JsonAnomalyLogInitCtxHelper(ConfNode *conf, OutputCtx *parent_ctx)
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

    JsonAnomalyLogConf(json_output_ctx, conf);
    json_output_ctx->eve_ctx = ajt;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonAnomalyLogDeInitCtxSubHelper;

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    SCFree(output_ctx);

    return result;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonAnomalyLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{

    if (!OutputAnomalyLoggerEnable()) {
        OutputInitResult result = { NULL, false };
        SCLogError(SC_ERR_CONF_YAML_ERROR, "only one 'anomaly' logger "
                "can be enabled");
        return result;
    }

    OutputInitResult result = JsonAnomalyLogInitCtxHelper(conf, parent_ctx);
    if (result.ok) {
        result.ctx->DeInit = JsonAnomalyLogDeInitCtxSub;
    }

    return result;
}

void JsonAnomalyLogRegister (void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_ANOMALY, "eve-log", MODULE_NAME,
        "eve-log.anomaly", JsonAnomalyLogInitCtxSub, JsonAnomalyLogger,
        JsonAnomalyLogCondition, JsonAnomalyLogThreadInit, JsonAnomalyLogThreadDeinit,
        NULL);

    OutputRegisterTxSubModule(LOGGER_JSON_ANOMALY, "eve-log", MODULE_NAME,
        "eve-log.anomaly", JsonAnomalyLogInitCtxHelper, ALPROTO_UNKNOWN,
        JsonAnomalyTxLogger, JsonAnomalyLogThreadInit,
        JsonAnomalyLogThreadDeinit, NULL);
}
