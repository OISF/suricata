/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#include "suricata-common.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "output-json-mqtt.h"

#define MQTT_LOG_PASSWORDS BIT_U32(0)
#define MQTT_DEFAULTS (MQTT_LOG_PASSWORDS)

typedef struct LogMQTTFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogMQTTFileCtx;

typedef struct LogMQTTLogThread_ {
    LogMQTTFileCtx *mqttlog_ctx;
    uint32_t        count;
    OutputJsonThreadCtx *ctx;
} LogMQTTLogThread;

bool JsonMQTTAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    MQTTState *state = FlowGetAppState(f);
    if (state) {
        MQTTTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_MQTT, state, tx_id);
        if (tx) {
            return rs_mqtt_logger_log(state, tx, MQTT_DEFAULTS, js);
        }
    }

    return false;
}

static int JsonMQTTLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogMQTTLogThread *thread = thread_data;
    enum OutputJsonLogDirection dir;

    if (rs_mqtt_tx_is_toclient((MQTTTransaction*) tx)) {
        dir = LOG_DIR_FLOW_TOCLIENT;
    } else {
        dir = LOG_DIR_FLOW_TOSERVER;
    }

    JsonBuilder *js = CreateEveHeader(p, dir, "mqtt", NULL, thread->mqttlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_mqtt_logger_log(state, tx, thread->mqttlog_ctx->flags, js))
        goto error;

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputMQTTLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogMQTTFileCtx *mqttlog_ctx = (LogMQTTFileCtx *)output_ctx->data;
    SCFree(mqttlog_ctx);
    SCFree(output_ctx);
}

static void JsonMQTTLogParseConfig(ConfNode *conf, LogMQTTFileCtx *mqttlog_ctx)
{
    const char *query = ConfNodeLookupChildValue(conf, "passwords");
    if (query != NULL) {
        if (ConfValIsTrue(query)) {
            mqttlog_ctx->flags |= MQTT_LOG_PASSWORDS;
        } else {
            mqttlog_ctx->flags &= ~MQTT_LOG_PASSWORDS;
        }
    } else {
        mqttlog_ctx->flags |= MQTT_LOG_PASSWORDS;
    }
}

static OutputInitResult OutputMQTTLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogMQTTFileCtx *mqttlog_ctx = SCCalloc(1, sizeof(*mqttlog_ctx));
    if (unlikely(mqttlog_ctx == NULL)) {
        return result;
    }
    mqttlog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(mqttlog_ctx);
        return result;
    }
    output_ctx->data = mqttlog_ctx;
    output_ctx->DeInit = OutputMQTTLogDeInitCtxSub;

    JsonMQTTLogParseConfig(conf, mqttlog_ctx);

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MQTT);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonMQTTLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMQTTLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogMQTT.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->mqttlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->mqttlog_ctx->eve_ctx);
    if (unlikely(thread->ctx == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonMQTTLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMQTTLogThread *thread = (LogMQTTLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonMQTTLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_MQTT, "eve-log",
        "JsonMQTTLog", "eve-log.mqtt",
        OutputMQTTLogInitSub, ALPROTO_MQTT, JsonMQTTLogger,
        JsonMQTTLogThreadInit, JsonMQTTLogThreadDeinit, NULL);
}
