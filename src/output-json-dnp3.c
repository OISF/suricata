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
#include "util-buffer.h"
#include "util-crypt.h"
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

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogDNP3FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
    uint8_t     include_object_data;
    OutputJsonCommonSettings cfg;
} LogDNP3FileCtx;

typedef struct LogDNP3LogThread_ {
    LogDNP3FileCtx *dnp3log_ctx;
    MemBuffer      *buffer;
} LogDNP3LogThread;

static json_t *JsonDNP3LogLinkControl(uint8_t lc)
{
    json_t *lcjs = json_object();
    if (unlikely(lcjs == NULL)) {
        return NULL;
    }

    json_object_set_new(lcjs, "dir", json_boolean(DNP3_LINK_DIR(lc)));
    json_object_set_new(lcjs, "pri", json_boolean(DNP3_LINK_PRI(lc)));
    json_object_set_new(lcjs, "fcb", json_boolean(DNP3_LINK_FCB(lc)));
    json_object_set_new(lcjs, "fcv", json_boolean(DNP3_LINK_FCV(lc)));
    json_object_set_new(lcjs, "function_code", json_integer(DNP3_LINK_FC(lc)));

    return lcjs;
}

static json_t *JsonDNP3LogIin(uint16_t iin)
{
    json_t *iinjs = json_object();
    if (unlikely(iinjs == NULL)) {
        return NULL;
    }

    json_t *indicators = json_array();
    if (unlikely(indicators == NULL)) {
        json_decref(iinjs);
        return NULL;
    }

    if (iin) {
        int mapping = 0;
        do {
            if (iin & DNP3IndicatorsMap[mapping].value) {
                json_array_append_new(indicators,
                    json_string(DNP3IndicatorsMap[mapping].name));
            }
            mapping++;
        } while (DNP3IndicatorsMap[mapping].name != NULL);
    }
    json_object_set_new(iinjs, "indicators", indicators);

    return iinjs;
}

static json_t *JsonDNP3LogApplicationControl(uint8_t ac)
{
    json_t *acjs = json_object();
    if (unlikely(acjs == NULL)) {
        return NULL;
    }

    json_object_set_new(acjs, "fir", json_boolean(DNP3_APP_FIR(ac)));
    json_object_set_new(acjs, "fin", json_boolean(DNP3_APP_FIN(ac)));
    json_object_set_new(acjs, "con", json_boolean(DNP3_APP_CON(ac)));
    json_object_set_new(acjs, "uns", json_boolean(DNP3_APP_UNS(ac)));
    json_object_set_new(acjs, "sequence", json_integer(DNP3_APP_SEQ(ac)));

    return acjs;
}

/**
 * \brief Log the items (points) for an object.
 *
 * TODO: Autogenerate this function based on object definitions.
 */
static json_t *JsonDNP3LogObjectItems(DNP3Object *object)
{
    DNP3Point *item;
    json_t *jsitems;

    if (unlikely((jsitems = json_array()) == NULL)) {
        return NULL;
    }

    TAILQ_FOREACH(item, object->points, next) {
        json_t *js = json_object();
        if (unlikely(js == NULL)) {
            break;
        }

        json_object_set_new(js, "prefix", json_integer(item->prefix));
        json_object_set_new(js, "index", json_integer(item->index));
        if (DNP3PrefixIsSize(object->prefix_code)) {
            json_object_set_new(js, "size", json_integer(item->size));
        }

        OutputJsonDNP3SetItem(js, object, item);
        json_array_append_new(jsitems, js);
    }

    return jsitems;
}

/**
 * \brief Log the application layer objects.
 *
 * \param objects A list of DNP3 objects.
 *
 * \retval a json_t pointer containing the logged DNP3 objects.
 */
static json_t *JsonDNP3LogObjects(DNP3ObjectList *objects)
{
    DNP3Object *object;
    json_t *js = json_array();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    TAILQ_FOREACH(object, objects, next) {
        json_t *objs = json_object();
        if (unlikely(objs == NULL)) {
            goto error;
        }
        json_object_set_new(objs, "group", json_integer(object->group));
        json_object_set_new(objs, "variation",
            json_integer(object->variation));
        json_object_set_new(objs, "qualifier", json_integer(object->qualifier));
        json_object_set_new(objs, "prefix_code",
            json_integer(object->prefix_code));
        json_object_set_new(objs, "range_code",
            json_integer(object->range_code));
        json_object_set_new(objs, "start", json_integer(object->start));
        json_object_set_new(objs, "stop", json_integer(object->stop));
        json_object_set_new(objs, "count", json_integer(object->count));

        if (object->points != NULL && !TAILQ_EMPTY(object->points)) {
            json_t *points = JsonDNP3LogObjectItems(object);
            if (points != NULL) {
                json_object_set_new(objs, "points", points);
            }
        }

        json_array_append_new(js, objs);
    }

    return js;
error:
    json_decref(js);
    return NULL;
}

json_t *JsonDNP3LogRequest(DNP3Transaction *dnp3tx)
{
    json_t *dnp3js = json_object();
    if (dnp3js == NULL) {
        return NULL;;
    }
    json_object_set_new(dnp3js, "type", json_string("request"));

    json_t *lcjs = JsonDNP3LogLinkControl(dnp3tx->request_lh.control);
    if (lcjs != NULL) {
        json_object_set_new(dnp3js, "control", lcjs);
    }

    json_object_set_new(dnp3js, "src", json_integer(dnp3tx->request_lh.src));
    json_object_set_new(dnp3js, "dst", json_integer(dnp3tx->request_lh.dst));

    /* DNP3 application layer. */
    json_t *al = json_object();
    if (al == NULL) {
        goto error;
    }
    json_object_set_new(dnp3js, "application", al);

    json_t *acjs = JsonDNP3LogApplicationControl(dnp3tx->request_ah.control);
    if (acjs != NULL) {
        json_object_set_new(al, "control", acjs);
    }

    json_object_set_new(al, "function_code",
        json_integer(dnp3tx->request_ah.function_code));

    json_t *objects = JsonDNP3LogObjects(&dnp3tx->request_objects);
    if (objects != NULL) {
        json_object_set_new(al, "objects", objects);
    }
    json_object_set_new(al, "complete",
        json_boolean(dnp3tx->request_complete));

    return dnp3js;

error:
    json_decref(dnp3js);
    return NULL;
}

json_t *JsonDNP3LogResponse(DNP3Transaction *dnp3tx)
{
    json_t *dnp3js = json_object();
    if (dnp3js == NULL) {
        return NULL;
    }
    if (dnp3tx->response_ah.function_code == DNP3_APP_FC_UNSOLICITED_RESP) {
        json_object_set_new(dnp3js, "type",
            json_string("unsolicited_response"));
    }
    else {
        json_object_set_new(dnp3js, "type", json_string("response"));
    }

    json_t *lcjs = JsonDNP3LogLinkControl(dnp3tx->response_lh.control);
    if (lcjs != NULL) {
        json_object_set_new(dnp3js, "control", lcjs);
    }

    json_object_set_new(dnp3js, "src", json_integer(dnp3tx->response_lh.src));
    json_object_set_new(dnp3js, "dst", json_integer(dnp3tx->response_lh.dst));

    /* DNP3 application layer. */
    json_t *al = json_object();
    if (al == NULL) {
        goto error;
    }
    json_object_set_new(dnp3js, "application", al);

    json_t *acjs = JsonDNP3LogApplicationControl(dnp3tx->response_ah.control);
    if (acjs != NULL) {
        json_object_set_new(al, "control", acjs);
    }

    json_object_set_new(al, "function_code",
        json_integer(dnp3tx->response_ah.function_code));

    json_t *iinjs = JsonDNP3LogIin(dnp3tx->response_iin.iin1 << 8 |
        dnp3tx->response_iin.iin2);
    if (iinjs != NULL) {
        json_object_set_new(dnp3js, "iin", iinjs);
    }

    json_t *objects = JsonDNP3LogObjects(&dnp3tx->response_objects);
    if (objects != NULL) {
        json_object_set_new(al, "objects", objects);
    }
    json_object_set_new(al, "complete",
        json_boolean(dnp3tx->response_complete));

    return dnp3js;

error:
    json_decref(dnp3js);
    return NULL;
}

static int JsonDNP3LoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    MemBuffer *buffer = (MemBuffer *)thread->buffer;

    MemBufferReset(buffer);
    if (tx->has_request && tx->request_done) {
        json_t *js = CreateJSONHeader(p, LOG_DIR_FLOW, "dnp3");
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }

        JsonAddCommonOptions(&thread->dnp3log_ctx->cfg, p, f, js);

        json_t *dnp3js = JsonDNP3LogRequest(tx);
        if (dnp3js != NULL) {
            json_object_set_new(js, "dnp3", dnp3js);
            OutputJSONBuffer(js, thread->dnp3log_ctx->file_ctx, &buffer);
        }
        json_decref(js);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDNP3LoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    MemBuffer *buffer = (MemBuffer *)thread->buffer;

    MemBufferReset(buffer);
    if (tx->has_response && tx->response_done) {
        json_t *js = CreateJSONHeader(p, LOG_DIR_FLOW, "dnp3");
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }

        JsonAddCommonOptions(&thread->dnp3log_ctx->cfg, p, f, js);

        json_t *dnp3js = JsonDNP3LogResponse(tx);
        if (dnp3js != NULL) {
            json_object_set_new(js, "dnp3", dnp3js);
            OutputJSONBuffer(js, thread->dnp3log_ctx->file_ctx, &buffer);
        }
        json_decref(js);
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

#define DEFAULT_LOG_FILENAME "dnp3.json"

static OutputInitResult OutputDNP3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogDNP3FileCtx *dnp3log_ctx = SCCalloc(1, sizeof(*dnp3log_ctx));
    if (unlikely(dnp3log_ctx == NULL)) {
        return result;
    }
    dnp3log_ctx->file_ctx = json_ctx->file_ctx;
    dnp3log_ctx->cfg = json_ctx->cfg;

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

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonDNP3LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDNP3LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for DNP3.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->dnp3log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonDNP3LogThreadDeinit(ThreadVars *t, void *data)
{
    LogDNP3LogThread *thread = (LogDNP3LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDNP3LogRegister(void)
{
    /* Register direction aware eve sub-modules. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNP3_TS, "eve-log",
        "JsonDNP3Log", "eve-log.dnp3", OutputDNP3LogInitSub, ALPROTO_DNP3,
        JsonDNP3LoggerToServer, 0, 1, JsonDNP3LogThreadInit,
        JsonDNP3LogThreadDeinit, NULL);
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNP3_TC, "eve-log",
        "JsonDNP3Log", "eve-log.dnp3", OutputDNP3LogInitSub, ALPROTO_DNP3,
        JsonDNP3LoggerToClient, 1, 1, JsonDNP3LogThreadInit,
        JsonDNP3LogThreadDeinit, NULL);
}

#else

void JsonDNP3LogRegister (void)
{
}

#endif
