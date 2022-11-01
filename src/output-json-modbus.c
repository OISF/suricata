/* Copyright (C) 2019-2020 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect.h"
#include "output-json.h"
#include "app-layer-parser.h"
#include "output-json-modbus.h"

typedef struct LogModbusFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCtx *eve_ctx;
} LogModbusFileCtx;

typedef struct JsonModbusLogThread_ {
    LogModbusFileCtx *modbuslog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonModbusLogThread;

static int JsonModbusLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    JsonModbusLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_FLOW, "modbus", NULL, thread->modbuslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }
    if (!rs_modbus_to_json(tx, js)) {
        jb_free(js);
        return TM_ECODE_FAILED;
    }
    OutputJsonBuilderBuffer(js, thread->ctx);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputModbusLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogModbusFileCtx *modbuslog_ctx = (LogModbusFileCtx *)output_ctx->data;
    SCFree(modbuslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputModbusLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogModbusFileCtx *modbuslog_ctx = SCCalloc(1, sizeof(*modbuslog_ctx));
    if (unlikely(modbuslog_ctx == NULL)) {
        return result;
    }
    modbuslog_ctx->file_ctx = ajt->file_ctx;
    modbuslog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(modbuslog_ctx);
        return result;
    }
    output_ctx->data = modbuslog_ctx;
    output_ctx->DeInit = OutputModbusLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MODBUS);

    SCLogDebug("modbus log sub-module initialized.");

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonModbusLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogModbus. \"initdata\" is NULL.");
        return TM_ECODE_FAILED;
    }

    JsonModbusLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    thread->modbuslog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->modbuslog_ctx->eve_ctx);
    if (thread->ctx == NULL) {
        goto error_exit;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonModbusLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonModbusLogThread *thread = (JsonModbusLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

bool JsonModbusAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    void *state = FlowGetAppState(f);
    if (state) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_MODBUS, state, tx_id);
        if (tx) {
            return rs_modbus_to_json(tx, js);
        }
    }

    return false;
}

void JsonModbusLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonModbusLog", "eve-log.modbus",
            OutputModbusLogInitSub, ALPROTO_MODBUS, JsonModbusLogger, JsonModbusLogThreadInit,
            JsonModbusLogThreadDeinit, NULL);

    SCLogDebug("modbus json logger registered.");
}
