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

#define DNP3_LOG_MAX_STRING  ((size_t)8 * 1024)
#define DNP3_LOG_MAX_BYTES   ((size_t)128 * 1024)
#define DNP3_LOG_MAX_OBJECTS 64
#define DNP3_LOG_MAX_POINTS  256
#define DNP3_LOG_OBJECT_COST 128
#define DNP3_LOG_POINT_COST  256

static void DNP3LogCtxInit(DNP3LogCtx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->remaining = DNP3_LOG_MAX_BYTES;
}

/* Returns false when the cost no longer fits; callers stop emitting. */
static bool DNP3LogConsume(DNP3LogCtx *ctx, size_t cost)
{
    if (cost > ctx->remaining) {
        ctx->truncated = true;
        return false;
    }
    ctx->remaining -= cost;
    return true;
}

void DNP3LogSetStringFromBytes(
        DNP3LogCtx *ctx, SCJsonBuilder *js, const char *key, const uint8_t *bytes, size_t len)
{
    const size_t limit = MIN(len, DNP3_LOG_MAX_STRING);
    if (!DNP3LogConsume(ctx, limit + 24)) {
        return;
    }
    if (len == 0) {
        SCJbSetString(js, key, "");
        return;
    }
    if (len > limit) {
        ctx->truncated = true;
    }
    SCJbSetStringFromBytesLimited(js, key, bytes, (uint32_t)len, (uint32_t)DNP3_LOG_MAX_STRING);
}

void DNP3LogSetString(
        DNP3LogCtx *ctx, SCJsonBuilder *js, const char *key, const char *val, size_t maxlen)
{
    size_t len = 0;
    while (len < maxlen && val[len] != '\0') {
        len++;
    }
    DNP3LogSetStringFromBytes(ctx, js, key, (const uint8_t *)val, len);
}

void DNP3LogSetBase64(
        DNP3LogCtx *ctx, SCJsonBuilder *js, const char *key, const uint8_t *bytes, size_t len)
{
    const size_t limit = MIN(len, DNP3_LOG_MAX_STRING);
    if (limit == 0) {
        return;
    }
    /* Charge for the base64 expansion. */
    if (!DNP3LogConsume(ctx, limit + limit / 3 + 24)) {
        return;
    }
    if (len > limit) {
        ctx->truncated = true;
    }
    SCJbSetBase64(js, key, bytes, (uint32_t)limit);
}

static void JsonDNP3LogFlags(SCJsonBuilder *js, const DNP3LogCtx *ctx)
{
    if (ctx->truncated) {
        SCJbSetBool(js, "truncated", true);
    }
    if (ctx->objects_truncated) {
        SCJbSetBool(js, "objects_truncated", true);
    }
    if (ctx->points_truncated) {
        SCJbSetBool(js, "points_truncated", true);
    }
    if (ctx->password_redacted) {
        SCJbSetBool(js, "password_redacted", true);
    }
}

static void JsonDNP3LogLinkControl(SCJsonBuilder *js, uint8_t lc)
{
    SCJbSetBool(js, "dir", DNP3_LINK_DIR(lc));
    SCJbSetBool(js, "pri", DNP3_LINK_PRI(lc));
    SCJbSetBool(js, "fcb", DNP3_LINK_FCB(lc));
    SCJbSetBool(js, "fcv", DNP3_LINK_FCV(lc));
    SCJbSetUint(js, "function_code", DNP3_LINK_FC(lc));
}

static void JsonDNP3LogApplicationControl(SCJsonBuilder *js, uint8_t ac)
{
    SCJbSetBool(js, "fir", DNP3_APP_FIR(ac));
    SCJbSetBool(js, "fin", DNP3_APP_FIN(ac));
    SCJbSetBool(js, "con", DNP3_APP_CON(ac));
    SCJbSetBool(js, "uns", DNP3_APP_UNS(ac));
    SCJbSetUint(js, "sequence", DNP3_APP_SEQ(ac));
}

/**
 * \brief Log the items (points) for an object.
 *
 * TODO: Autogenerate this function based on object definitions.
 */
static void JsonDNP3LogObjectItems(SCJsonBuilder *js, DNP3Object *object, DNP3LogCtx *ctx)
{
    DNP3Point *item;

    if (ctx->points >= DNP3_LOG_MAX_POINTS || ctx->remaining < DNP3_LOG_POINT_COST) {
        ctx->points_truncated = true;
        ctx->truncated = true;
        return;
    }

    SCJbOpenArray(js, "points");
    TAILQ_FOREACH(item, object->points, next) {
        if (ctx->points >= DNP3_LOG_MAX_POINTS || !DNP3LogConsume(ctx, DNP3_LOG_POINT_COST)) {
            ctx->points_truncated = true;
            ctx->truncated = true;
            break;
        }
        ctx->points++;

        SCJbStartObject(js);

        SCJbSetUint(js, "prefix", item->prefix);
        SCJbSetUint(js, "index", item->index);
        if (DNP3PrefixIsSize(object->prefix_code)) {
            SCJbSetUint(js, "size", item->size);
        }

        OutputJsonDNP3SetItem(js, object, item, ctx);
        SCJbClose(js);
    }
    SCJbClose(js);
}

/**
 * \brief Log the application layer objects.
 *
 * \param objects A list of DNP3 objects.
 * \param js A SCJsonBuilder instance with an open object.
 */
static void JsonDNP3LogObjects(SCJsonBuilder *js, DNP3ObjectList *objects, DNP3LogCtx *ctx)
{
    DNP3Object *object;
    uint32_t count = 0;

    if (ctx->remaining < DNP3_LOG_OBJECT_COST) {
        ctx->objects_truncated = true;
        ctx->truncated = true;
        return;
    }

    SCJbOpenArray(js, "objects");
    TAILQ_FOREACH(object, objects, next) {
        if (count >= DNP3_LOG_MAX_OBJECTS || !DNP3LogConsume(ctx, DNP3_LOG_OBJECT_COST)) {
            ctx->objects_truncated = true;
            ctx->truncated = true;
            break;
        }
        count++;

        SCJbStartObject(js);
        SCJbSetUint(js, "group", object->group);
        SCJbSetUint(js, "variation", object->variation);
        SCJbSetUint(js, "qualifier", object->qualifier);
        SCJbSetUint(js, "prefix_code", object->prefix_code);
        SCJbSetUint(js, "range_code", object->range_code);
        SCJbSetUint(js, "start", object->start);
        SCJbSetUint(js, "stop", object->stop);
        SCJbSetUint(js, "count", object->count);

        if (object->points != NULL && !TAILQ_EMPTY(object->points)) {
            JsonDNP3LogObjectItems(js, object, ctx);
        }

        SCJbClose(js);
    }
    SCJbClose(js);
}

static void JsonDNP3LogRequest(SCJsonBuilder *js, DNP3Transaction *dnp3tx, DNP3LogCtx *ctx)
{
    JB_SET_STRING(js, "type", "request");

    SCJbOpenObject(js, "control");
    JsonDNP3LogLinkControl(js, dnp3tx->lh.control);
    SCJbClose(js);

    SCJbSetUint(js, "src", DNP3_SWAP16(dnp3tx->lh.src));
    SCJbSetUint(js, "dst", DNP3_SWAP16(dnp3tx->lh.dst));

    SCJbOpenObject(js, "application");

    SCJbOpenObject(js, "control");
    JsonDNP3LogApplicationControl(js, dnp3tx->ah.control);
    SCJbClose(js);

    SCJbSetUint(js, "function_code", dnp3tx->ah.function_code);

    if (!TAILQ_EMPTY(&dnp3tx->objects)) {
        JsonDNP3LogObjects(js, &dnp3tx->objects, ctx);
    }

    SCJbSetBool(js, "complete", dnp3tx->complete);

    /* Close application. */
    SCJbClose(js);
}

static void JsonDNP3LogResponse(SCJsonBuilder *js, DNP3Transaction *dnp3tx, DNP3LogCtx *ctx)
{
    if (dnp3tx->ah.function_code == DNP3_APP_FC_UNSOLICITED_RESP) {
        JB_SET_STRING(js, "type", "unsolicited_response");
    } else {
        JB_SET_STRING(js, "type", "response");
    }

    SCJbOpenObject(js, "control");
    JsonDNP3LogLinkControl(js, dnp3tx->lh.control);
    SCJbClose(js);

    SCJbSetUint(js, "src", DNP3_SWAP16(dnp3tx->lh.src));
    SCJbSetUint(js, "dst", DNP3_SWAP16(dnp3tx->lh.dst));

    SCJbOpenObject(js, "application");

    SCJbOpenObject(js, "control");
    JsonDNP3LogApplicationControl(js, dnp3tx->ah.control);
    SCJbClose(js);

    SCJbSetUint(js, "function_code", dnp3tx->ah.function_code);

    if (!TAILQ_EMPTY(&dnp3tx->objects)) {
        JsonDNP3LogObjects(js, &dnp3tx->objects, ctx);
    }

    SCJbSetBool(js, "complete", dnp3tx->complete);

    /* Close application. */
    SCJbClose(js);

    SCJbOpenObject(js, "iin");
    SCJsonDNP3LogIin(js, (uint16_t)(dnp3tx->iin.iin1 << 8 | dnp3tx->iin.iin2));
    SCJbClose(js);
}

bool AlertJsonDnp3(const void *vtx, void *js)
{
    DNP3Transaction *tx = (DNP3Transaction *)vtx;
    if (tx->done && tx->buffer == NULL) {
        /* Carrier TX for app-layer event, don't log. */
        return false;
    }
    DNP3LogCtx ctx;
    DNP3LogCtxInit(&ctx);

    bool logged = false;
    SCJbOpenObject(js, "dnp3");
    if (tx->is_request && tx->done) {
        SCJbOpenObject(js, "request");
        JsonDNP3LogRequest(js, tx, &ctx);
        SCJbClose(js);
        logged = true;
    }
    if (!tx->is_request && tx->done) {
        SCJbOpenObject(js, "response");
        JsonDNP3LogResponse(js, tx, &ctx);
        SCJbClose(js);
        logged = true;
    }
    JsonDNP3LogFlags(js, &ctx);
    SCJbClose(js);
    return logged;
}

static int JsonDNP3LoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    SCJsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_FLOW, "dnp3", NULL, thread->dnp3log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    DNP3LogCtx dnp3_ctx;
    DNP3LogCtxInit(&dnp3_ctx);

    SCJbOpenObject(js, "dnp3");
    JsonDNP3LogRequest(js, tx, &dnp3_ctx);
    JsonDNP3LogFlags(js, &dnp3_ctx);
    SCJbClose(js);
    OutputJsonBuilderBuffer(tv, p, p->flow, js, thread->ctx);
    SCJbFree(js);

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDNP3LoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *tx = vtx;

    SCJsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_FLOW, "dnp3", NULL, thread->dnp3log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    DNP3LogCtx dnp3_ctx;
    DNP3LogCtxInit(&dnp3_ctx);

    SCJbOpenObject(js, "dnp3");
    JsonDNP3LogResponse(js, tx, &dnp3_ctx);
    JsonDNP3LogFlags(js, &dnp3_ctx);
    SCJbClose(js);
    OutputJsonBuilderBuffer(tv, p, p->flow, js, thread->ctx);
    SCJbFree(js);

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDNP3Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = vtx;
    if (tx->done && tx->buffer == NULL) {
        /* Carrier TX for app-layer event, don't log. */
        SCReturnInt(TM_ECODE_OK);
    }
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

static OutputInitResult OutputDNP3LogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
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

    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNP3);

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
