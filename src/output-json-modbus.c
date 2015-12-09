/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Implements Modbus JSON logging portion of the engine.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-modbus.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define LOG_MODBUS_NO_FLAG     0
#define LOG_MODBUS_USE_DICT    (1<<0)

typedef struct LogModbusFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogModbusFileCtx;

typedef struct LogModbusLogThread_ {
    LogModbusFileCtx *modbuslog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogModbusLogThread;

static json_t *JsonModbusLogRegisters(ModbusTransaction *modbustx,
                                      uint8_t quantity, uint8_t use_dict)
{
    uint16_t val;
    int i = 0;
    if (use_dict) {
        char key[6];
        json_t *data_dict = json_object();
        if (data_dict == NULL)
            goto end;
        for (i = 0; i < quantity; i++) {
            val = ntohs(*(modbustx->data + i));
            snprintf(key, sizeof(key), "%d", i);
            json_object_set_new(data_dict, key, json_integer(val));
        }
        return data_dict;
    } else {
        json_t *data_array = json_array();
        if (data_array == NULL)
            goto end;
        for (i = 0; i < quantity; i++) {
            val = ntohs(*(modbustx->data + i));
            json_array_append_new(data_array, json_integer(val));
        }
        return data_array;
    }
end:
    return NULL;
}

static json_t *JsonModbusLogBits(ModbusTransaction *modbustx,
                                 uint8_t quantity, uint8_t use_dict)
{
    uint16_t val;
    int i = 0;
    if (use_dict & LOG_MODBUS_USE_DICT) {
        char key[6];
        json_t *data_dict = json_object();
        if (data_dict == NULL)
            goto end;
        for (i = 0; i < quantity; i++) {
            val = *((uint8_t*)modbustx->data + (i >> 3)) & (1 << (i % 8)) ? 1 : 0;
            snprintf(key, sizeof(key), "%d", i);
            json_object_set_new(data_dict, key, json_integer(val));
        }
        return data_dict;
    } else {
        json_t *data_array = json_array();
        if (data_array == NULL)
            goto end;
        for (i = 0; i < quantity; i++) {
            val = *(modbustx->data + (i >> 3)) & (1 << (i % 8)) ? 1 : 0;
            json_array_append_new(data_array, json_integer(val));
        }
        return data_array;
    }
end:
    return NULL;
}

static void JsonModbusLog(json_t *modbusjs, ModbusTransaction *modbustx,
                          uint8_t use_dict)
{
    json_object_set_new(modbusjs, "transaction_id", json_integer(modbustx->transactionId));
    json_object_set_new(modbusjs, "length", json_integer(modbustx->length));
    json_object_set_new(modbusjs, "function",
                        json_string(ModbusGetFunctionName(modbustx->function))
                       );
    if (modbustx->function == MODBUS_FUNC_DIAGNOSTIC) {
        json_object_set_new(modbusjs, "subfunction",
                            json_string(ModbusGetSubFunctionName(modbustx->subFunction))
                           );
    }

    if (modbustx->exception) {
        json_object_set_new(modbusjs, "exception",
                            json_string(ModbusGetExceptionName(modbustx->exception))
                           );
    }

    if (modbustx->type & MODBUS_TYP_READ) {
        json_t *read = json_object();
        if (read) {
            json_object_set_new(read, "address", json_integer(modbustx->read.address));
            json_object_set_new(read, "quantity", json_integer(modbustx->read.quantity));
            if (modbustx->read.quantity && modbustx->data) {
                json_t *value = NULL;
                if (modbustx->type  & MODBUS_TYP_BIT_ACCESS_MASK) {
                    value = JsonModbusLogBits(modbustx, modbustx->read.quantity,
                                              use_dict);
                } else {
                    value = JsonModbusLogRegisters(modbustx, modbustx->read.quantity,
                                                   use_dict);
                }
                if (value) {
                    json_object_set_new(read, "value", value);
                }
            }
            json_object_set_new(modbusjs, "read", read);
        }
    }
    if (modbustx->type & MODBUS_TYP_WRITE) {
        json_t *write = json_object();
        if (write) {
            json_object_set_new(write, "address", json_integer(modbustx->write.address));
            json_object_set_new(write, "quantity", json_integer(modbustx->write.quantity));
            json_object_set_new(write, "count", json_integer(modbustx->write.count));
            if (modbustx->function == MODBUS_FUNC_WRITESINGLEREG) {
                json_object_set(write, "value", json_integer(*(modbustx->data)));
            } else if (modbustx->type & MODBUS_TYP_WRITE_MULTIPLE &&
                       modbustx->write.count && modbustx->data) {
                json_t *value;
                if (modbustx->type  & MODBUS_TYP_BIT_ACCESS_MASK) {
                    value = JsonModbusLogBits(modbustx, modbustx->write.quantity,
                                              use_dict);
                } else {
                    value = JsonModbusLogRegisters(modbustx, modbustx->write.quantity,
                                                   use_dict);
                }
                if (value) {
                    json_object_set_new(write, "value", value);
                }
            }
            json_object_set_new(modbusjs, "write", write);
        }

    }
    switch (modbustx->category) {
        case MODBUS_CAT_PUBLIC_ASSIGNED:
            json_object_set_new(modbusjs, "category", json_string("assigned"));
            break;
        case MODBUS_CAT_PUBLIC_UNASSIGNED:
            json_object_set_new(modbusjs, "category", json_string("unassigned"));
            break;
        case MODBUS_CAT_USER_DEFINED:
            json_object_set_new(modbusjs, "category", json_string("user"));
            break;
        case MODBUS_CAT_RESERVED:
            json_object_set_new(modbusjs, "category", json_string("reserved"));
            break;
    }

    json_object_set_new(modbusjs, "replied", json_integer(modbustx->replied));
}

static int JsonModbusLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    ModbusTransaction *modbustx = tx;
    LogModbusLogThread *thread = thread_data;
    MemBuffer *buffer = thread->buffer;
    uint8_t use_dict = 0;
    json_t *js, *modbusjs;

    js = CreateJSONHeader((Packet *)p, 0, "modbus");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    modbusjs = json_object();
    if (unlikely(modbusjs == NULL)) {
        goto error;
    }

    if (thread->modbuslog_ctx->flags & LOG_MODBUS_USE_DICT) {
        use_dict = 1;
    }

    JsonModbusLog(modbusjs, modbustx, use_dict);

    json_object_set_new(js, "modbus", modbusjs);

    MemBufferReset(buffer);
    OutputJSONBuffer(js, thread->modbuslog_ctx->file_ctx, &buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    if (modbusjs != NULL) {
        json_decref(modbusjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

json_t *JsonModbusAddMetadata(const Flow *f, uint64_t tx_id)
{
    ModbusState *modbus_state = (ModbusState *)FlowGetAppState(f);

    if (modbus_state) {
        ModbusTransaction *modbustx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_MODBUS, modbus_state, tx_id);

        if (modbustx) {
            json_t *mjs = json_object();
            if (unlikely(mjs == NULL))
                return NULL;

            JsonModbusLog(mjs, modbustx, 0);

            return mjs;
        }
    }

    return NULL;
}

static void OutputModbusLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogModbusFileCtx *modbuslog_ctx = (LogModbusFileCtx *)output_ctx->data;
    SCFree(modbuslog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputModbusLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogModbusFileCtx *modbuslog_ctx = SCCalloc(1, sizeof(*modbuslog_ctx));
    if (unlikely(modbuslog_ctx == NULL)) {
        return NULL;
    }
    modbuslog_ctx->file_ctx = ajt->file_ctx;

    if (conf) {
        const char *dict = ConfNodeLookupChildValue(conf, "array-as-dict");

        if (dict != NULL) {
            if (ConfValIsTrue(dict)) {
                modbuslog_ctx->flags = LOG_MODBUS_USE_DICT;
            }
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(modbuslog_ctx);
        return NULL;
    }
    output_ctx->data = modbuslog_ctx;
    output_ctx->DeInit = OutputModbusLogDeInitCtxSub;

    SCLogInfo("Modbus log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MODBUS);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonModbusLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogModbusLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for Modbus.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->modbuslog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonModbusLogThreadDeinit(ThreadVars *t, void *data)
{
    LogModbusLogThread *thread = (LogModbusLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void TmModuleJsonModbusLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.modbus") == NULL) {
        return;
    }

    tmm_modules[TMM_JSONMODBUSLOG].name = "JsonModbusLog";
    tmm_modules[TMM_JSONMODBUSLOG].ThreadInit = JsonModbusLogThreadInit;
    tmm_modules[TMM_JSONMODBUSLOG].ThreadDeinit = JsonModbusLogThreadDeinit;
    tmm_modules[TMM_JSONMODBUSLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONMODBUSLOG].cap_flags = 0;
    tmm_modules[TMM_JSONMODBUSLOG].flags = TM_FLAG_LOGAPI_TM;

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule("eve-log", "JsonModbusLog", "eve-log.modbus",
        OutputModbusLogInitSub, ALPROTO_MODBUS, JsonModbusLogger);

    SCLogInfo("Modbus JSON logger registered.");
}

#else /* No JSON support. */

static TmEcode JsonModbusLogThreadInit(ThreadVars *t, void *initdata,
    void **data)
{
    SCLogInfo("Cannot initialize JSON output for modbus. "
        "JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonModbusLogRegister(void)
{
    tmm_modules[TMM_JSONMODBUSLOG].name = "JsonModbusLog";
    tmm_modules[TMM_JSONMODBUSLOG].ThreadInit = JsonModbusLogThreadInit;
}

#endif /* HAVE_LIBJANSSON */
