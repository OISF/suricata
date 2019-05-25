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
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonAnomalyLog"

#ifdef HAVE_LIBJANSSON

#define ANOMALY_EVENT_TYPE      "anomaly"
#define LOG_JSON_PACKETHDR      BIT_U16(0)
#define TX_ID_UNUSED UINT64_MAX

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

static int AnomalyDecodeEventJson(ThreadVars *tv, JsonAnomalyLogThread *aft,
                                  const Packet *p)
{
    bool is_ip_pkt = PKT_IS_IPV4(p) || PKT_IS_IPV6(p);

    char timebuf[64];
    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (int i = 0; i < p->events.cnt; i++) {
        MemBufferReset(aft->json_buffer);

        json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, ANOMALY_EVENT_TYPE);

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
            json_object_set_new(ajs, "type", json_string("unknown"));
            json_object_set_new(ajs, "code", json_integer(event_code));
        }

        /* anomaly */
        json_object_set_new(js, ANOMALY_EVENT_TYPE, ajs);
        OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);

        json_object_clear(js);
        json_decref(js);
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
        MemBufferReset(aft->json_buffer);

        json_t *js;
        if (tx_id != TX_ID_UNUSED) {
            js = CreateJSONHeaderWithTxId(p, LOG_DIR_PACKET,
                                          ANOMALY_EVENT_TYPE, tx_id);
        } else {
            js = CreateJSONHeader(p, LOG_DIR_PACKET, ANOMALY_EVENT_TYPE);
        }
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }

        json_t *ajs = json_object();
        if (unlikely(ajs == NULL)) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        JsonAddCommonOptions(&aft->json_output_ctx->cfg, p, p->flow, js);

        json_object_set_new(js, "app_proto", json_string(alprotoname));

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
            json_object_set_new(ajs, "type", json_string("applayer"));
            json_object_set_new(ajs, "event", json_string(event_name));
        } else {
            json_object_set_new(ajs, "type", json_string("unknown"));
            json_object_set_new(ajs, "code", json_integer(event_code));
        }

        /* log event number (and total) */
        char event_no_buf[16];
        snprintf(event_no_buf, sizeof(event_no_buf), "%d (of %d)",
                        i+1, decoder_events->cnt);
        json_object_set_new(ajs, "event_no", json_string(event_no_buf));
        json_object_set_new(ajs, "layer", json_string(layer));

        /* anomaly */
        json_object_set_new(js, ANOMALY_EVENT_TYPE, ajs);
        OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);

        json_object_clear(js);
        json_decref(js);

        /* Current implementation assumes a single owner for this value */
        decoder_events->event_last_logged++;
    }

    return TM_ECODE_OK;
}

static int JsonAnomalyTxLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                               Flow *f, void *state, void *tx, uint64_t tx_id)
{
    AppLayerDecoderEvents *decoder_events;
    decoder_events = AppLayerParserGetEventsByTx(f->proto, f->alproto, tx);
    if (decoder_events && decoder_events->event_last_logged < decoder_events->cnt) {
        SCLogDebug("state %p, tx: %p, tx_id: %"PRIu64, state, tx, tx_id);
        JsonAnomalyLogThread *aft = thread_data;
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

    if (p->events.cnt) {
        rc = AnomalyDecodeEventJson(tv, aft, p);
    }

    /* app layer events */
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

    return rc;
}

static int JsonAnomalyLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAnomalyLogThread *aft = thread_data;
    return AnomalyJson(tv, aft, p);
}

static int JsonAnomalyLogCondition(ThreadVars *tv, const Packet *p)
{
    return p->events.cnt > 0 ||
           (p->app_layer_events && p->app_layer_events->cnt > 0) ||
           AnomalyHasParserEvents(p);
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonAnomalyLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonAnomalyLogThread *aft = SCCalloc(1, sizeof(JsonAnomalyLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
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
    OutputRegisterPacketSubModule(LOGGER_JSON_ANOMALY, "eve-log", MODULE_NAME,
        "eve-log.anomaly", JsonAnomalyLogInitCtxSub, JsonAnomalyLogger,
        JsonAnomalyLogCondition, JsonAnomalyLogThreadInit, JsonAnomalyLogThreadDeinit,
        NULL);

    OutputRegisterTxSubModule(LOGGER_JSON_ANOMALY, "eve-log", MODULE_NAME,
        "eve-log.anomaly", JsonAnomalyLogInitCtxSub, ALPROTO_UNKNOWN,
        JsonAnomalyTxLogger, JsonAnomalyLogThreadInit,
        JsonAnomalyLogThreadDeinit, NULL);
}

#else

void JsonAnomalyLogRegister (void)
{
}

#endif
