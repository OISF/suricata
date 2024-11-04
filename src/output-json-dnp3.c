/* Copyright (C) 2015-2021 Open Information Security Foundation
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
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

#include "detect-dnp3.h"

#include "output.h"
#include "output-json.h"
#include "output-json-dnp3.h"
#include "output-json-dnp3-objects.h"

typedef struct LogDNP3FileCtx_ {
    uint32_t    flags;
    uint8_t     include_object_data;
    OutputJsonCtx *eve_ctx;
} LogDNP3FileCtx;

typedef struct LogDNP3LogThread_ {
    LogDNP3FileCtx *dnp3log_ctx;
    OutputJsonThreadCtx *ctx;
} LogDNP3LogThread;

static void JsonDNP3LogLinkControl(JsonBuilder *js, uint8_t lc)
{
    jb_set_bool(js, "dir", DNP3_LINK_DIR(lc));
    jb_set_bool(js, "pri", DNP3_LINK_PRI(lc));
    jb_set_bool(js, "fcb", DNP3_LINK_FCB(lc));
    jb_set_bool(js, "fcv", DNP3_LINK_FCV(lc));
    jb_set_uint(js, "function_code", DNP3_LINK_FC(lc));
}

static void JsonDNP3LogIin(JsonBuilder *js, uint16_t iin)
{
    if (iin) {
        jb_open_array(js, "indicators");

        int mapping = 0;
        do {
            if (iin & DNP3IndicatorsMap[mapping].value) {
                jb_append_string(js, DNP3IndicatorsMap[mapping].name);
            }
            mapping++;
        } while (DNP3IndicatorsMap[mapping].name != NULL);
        jb_close(js);
    }
}

static void JsonDNP3LogApplicationControl(JsonBuilder *js, uint8_t ac)
{
    jb_set_bool(js, "fir", DNP3_APP_FIR(ac));
    jb_set_bool(js, "fin", DNP3_APP_FIN(ac));
    jb_set_bool(js, "con", DNP3_APP_CON(ac));
    jb_set_bool(js, "uns", DNP3_APP_UNS(ac));
    jb_set_uint(js, "sequence", DNP3_APP_SEQ(ac));
}

/**
 * \brief Log the items (points) for an object.
 *
 * TODO: Autogenerate this function based on object definitions.
 */
static void JsonDNP3LogObjectItems(JsonBuilder *js, DNP3Object *object)
{
    DNP3Point *item;

    TAILQ_FOREACH(item, object->points, next) {
        jb_start_object(js);

        jb_set_uint(js, "prefix", item->prefix);
        jb_set_uint(js, "index", item->index);
        if (DNP3PrefixIsSize(object->prefix_code)) {
            jb_set_uint(js, "size", item->size);
        }

        OutputJsonDNP3SetItem(js, object, item);
        jb_close(js);
    }
}

/**
 * \brief Log the application layer objects.
 *
 * \param objects A list of DNP3 objects.
 * \param jb A JsonBuilder instance with an open array.
 */
static void JsonDNP3LogObjects(JsonBuilder *js, DNP3ObjectList *objects)
{
    DNP3Object *object;

    TAILQ_FOREACH(object, objects, next) {
        jb_start_object(js);
        jb_set_uint(js, "group", object->group);
        jb_set_uint(js, "variation", object->variation);
        jb_set_uint(js, "qualifier", object->qualifier);
        jb_set_uint(js, "prefix_code", object->prefix_code);
        jb_set_uint(js, "range_code",  object->range_code);
        jb_set_uint(js, "start", object->start);
        jb_set_uint(js, "stop", object->stop);
        jb_set_uint(js, "count", object->count);

        if (object->points != NULL && !TAILQ_EMPTY(object->points)) {
            jb_open_array(js, "points");
            JsonDNP3LogObjectItems(js, object);
            jb_close(js);
        }

        jb_close(js);
    }
}

static void JsonDNP3LogRequest(JsonBuilder *js, DNP3Transaction *dnp3tx)
{
    JB_SET_STRING(js, "type", "request");

    jb_open_object(js, "control");
    JsonDNP3LogLinkControl(js, dnp3tx->lh.control);
    jb_close(js);

    jb_set_uint(js, "src", DNP3_SWAP16(dnp3tx->lh.src));
    jb_set_uint(js, "dst", DNP3_SWAP16(dnp3tx->lh.dst));

    jb_open_object(js, "application");

    jb_open_object(js, "control");
    JsonDNP3LogApplicationControl(js, dnp3tx->ah.control);
    jb_close(js);

    jb_set_uint(js, "function_code", dnp3tx->ah.function_code);

    if (!TAILQ_EMPTY(&dnp3tx->objects)) {
        jb_open_array(js, "objects");
        JsonDNP3LogObjects(js, &dnp3tx->objects);
        jb_close(js);
    }

    jb_set_bool(js, "complete", dnp3tx->complete);

    /* Close application. */
    jb_close(js);
}

static void JsonDNP3LogResponse(JsonBuilder *js, DNP3Transaction *dnp3tx)
{
    if (dnp3tx->ah.function_code == DNP3_APP_FC_UNSOLICITED_RESP) {
        JB_SET_STRING(js, "type", "unsolicited_response");
    } else {
        JB_SET_STRING(js, "type", "response");
    }

    jb_open_object(js, "control");
    JsonDNP3LogLinkControl(js, dnp3tx->lh.control);
    jb_close(js);

    jb_set_uint(js, "src", DNP3_SWAP16(dnp3tx->lh.src));
    jb_set_uint(js, "dst", DNP3_SWAP16(dnp3tx->lh.dst));

    jb_open_object(js, "application");

    jb_open_object(js, "control");
    JsonDNP3LogApplicationControl(js, dnp3tx->ah.control);
    jb_close(js);

    jb_set_uint(js, "function_code", dnp3tx->ah.function_code);

    if (!TAILQ_EMPTY(&dnp3tx->objects)) {
        jb_open_array(js, "objects");
        JsonDNP3LogObjects(js, &dnp3tx->objects);
        jb_close(js);
    }

    jb_set_bool(js, "complete", dnp3tx->complete);

    /* Close application. */
    jb_close(js);

    jb_open_object(js, "iin");
    JsonDNP3LogIin(js, (uint16_t)(dnp3tx->iin.iin1 << 8 | dnp3tx->iin.iin2));
    jb_close(js);
}

bool AlertJsonDnp3(void *vtx, JsonBuilder *js)
{
    DNP3Transaction *tx = (DNP3Transaction *)vtx;
    bool logged = false;
    jb_open_object(js, "dnp3");
    if (tx->is_request && tx->done) {
        jb_open_object(js, "request");
        JsonDNP3LogRequest(js, tx);
        jb_close(js);
        logged = true;
    }
    if (!tx->is_request && tx->done) {
        jb_open_object(js, "response");
        JsonDNP3LogResponse(js, tx);
        jb_close(js);
        logged = true;
    }
    jb_close(js);
    return logged;
}

static int JsonDNP3LoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW, "dnp3", NULL, thread->dnp3log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "dnp3");
    JsonDNP3LogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDNP3LoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW, "dnp3", NULL, thread->dnp3log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "dnp3");
    JsonDNP3LogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDNP3Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonDNP3LoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonDNP3LoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

static void OutputDNP3LogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDNP3FileCtx *dnp3log_ctx = (LogDNP3FileCtx *)output_ctx->data;
    SCFree(dnp3log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputDNP3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogDNP3FileCtx *dnp3log_ctx = SCCalloc(1, sizeof(*dnp3log_ctx));
    if (unlikely(dnp3log_ctx == NULL)) {
        return result;
    }
    dnp3log_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnp3log_ctx);
        return result;
    }
    output_ctx->data = dnp3log_ctx;
    output_ctx->DeInit = OutputDNP3LogDeInitCtxSub;

    SCLogInfo("DNP3 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNP3);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


static TmEcode JsonDNP3LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDNP3LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for DNP3.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->dnp3log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->dnp3log_ctx->eve_ctx);
    if (thread->ctx == NULL) {
        goto error_exit;
    }

    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonDNP3LogThreadDeinit(ThreadVars *t, void *data)
{
    LogDNP3LogThread *thread = (LogDNP3LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDNP3LogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDNP3Log", "eve-log.dnp3",
            OutputDNP3LogInitSub, ALPROTO_DNP3, JsonDNP3Logger, JsonDNP3LogThreadInit,
            JsonDNP3LogThreadDeinit);
}
