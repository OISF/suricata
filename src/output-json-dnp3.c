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

#include "util-debug.h"

#include "output.h"
#include "app-layer.h"
#include "app-layer-dnp3.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "detect-dnp3.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

/* Appears not all current distros have jansson that defines this. */
#ifndef json_boolean
#define json_boolean(val)      ((val) ? json_true() : json_false())
#endif

typedef struct LogDNP3FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogDNP3FileCtx;

typedef struct LogDNP3LogThread_ {
    LogDNP3FileCtx *dnp3log_ctx;
    uint32_t        count;
    MemBuffer      *buffer;
} LogDNP3LogThread;

static json_t *JsonDNP3LogLinkControl(uint8_t lc)
{
    json_t *lcjs = json_object();
    if (unlikely(lcjs == NULL)) {
        return NULL;
    }

    json_object_set_new(lcjs, "value", json_integer(lc));
    json_object_set_new(lcjs, "dir", json_boolean(DNP3_LINK_DIR(lc)));
    json_object_set_new(lcjs, "pri", json_boolean(DNP3_LINK_PRI(lc)));
    json_object_set_new(lcjs, "fcb", json_boolean(DNP3_LINK_FCB(lc)));
    json_object_set_new(lcjs, "fcv", json_boolean(DNP3_LINK_FCV(lc)));
    json_object_set_new(lcjs, "function_code", json_integer(DNP3_LINK_FC(lc)));

    return lcjs;
}

static json_t *JsonDNP3LogTransportHeader(DNP3TransportHeader th)
{
    json_t *thjs = json_object();
    if (unlikely(thjs == NULL)) {
        return NULL;
    }

    json_object_set_new(thjs, "value", json_integer((uint8_t)th));
    json_object_set_new(thjs, "fin", json_boolean(DNP3_TRANSPORT_FIN(th)));
    json_object_set_new(thjs, "fir", json_boolean(DNP3_TRANSPORT_FIR(th)));
    json_object_set_new(thjs, "sequence", json_integer(DNP3_TRANSPORT_SEQ(th)));

    return thjs;
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

    json_object_set_new(iinjs, "value", json_integer(iin));
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

    json_object_set_new(acjs, "value", json_integer(ac));
    json_object_set_new(acjs, "fir", json_boolean(DNP3_APP_FIR(ac)));
    json_object_set_new(acjs, "fin", json_boolean(DNP3_APP_FIN(ac)));
    json_object_set_new(acjs, "con", json_boolean(DNP3_APP_CON(ac)));
    json_object_set_new(acjs, "uns", json_boolean(DNP3_APP_UNS(ac)));
    json_object_set_new(acjs, "sequence", json_integer(DNP3_APP_SEQ(ac)));

    return acjs;
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

        json_array_append_new(js, objs);
    }

    return js;
error:
    json_decref(js);
    return NULL;
}

static void JsonDNP3LogRequest(LogDNP3LogThread *thread,
    const Packet *p, DNP3Transaction *dnp3tx)
{
    json_t *js;
    MemBuffer *buffer = (MemBuffer *)thread->buffer;

    MemBufferReset(buffer);

    js = CreateJSONHeader((Packet *)p, 1, "dnp3");
    if (unlikely(js == NULL)) {
        return;
    }

    json_t *dnp3js = json_object();
    if (dnp3js == NULL) {
        return;
    }
    json_object_set_new(dnp3js, "type", json_string("request"));

    json_t *lcjs = JsonDNP3LogLinkControl(dnp3tx->request_ll_control);
    if (lcjs != NULL) {
        json_object_set_new(dnp3js, "control", lcjs);
    }

    json_object_set_new(dnp3js, "src", json_integer(dnp3tx->session->master));
    json_object_set_new(dnp3js, "dst", json_integer(dnp3tx->session->slave));
    json_object_set_new(js, "dnp3", dnp3js);

    json_t *thjs = JsonDNP3LogTransportHeader(dnp3tx->request_th);
    if (thjs != NULL) {
        json_object_set_new(dnp3js, "transport", thjs);
    }

    /* DNP3 application layer. */
    json_t *al = json_object();
    if (al == NULL) {
        goto done;
    }
    json_object_set_new(dnp3js, "application", al);

    json_t *acjs = JsonDNP3LogApplicationControl(dnp3tx->request_al_control);
    if (acjs != NULL) {
        json_object_set_new(al, "control", acjs);
    }

    json_object_set_new(al, "function_code",
        json_integer(dnp3tx->request_al_fc));

    json_t *objects = JsonDNP3LogObjects(&dnp3tx->request_objects);
    if (objects != NULL) {
        json_object_set_new(al, "objects", objects);
    }

    OutputJSONBuffer(js, thread->dnp3log_ctx->file_ctx, buffer);
done:
    json_object_del(js, "dnp3");
    json_decref(js);
}

static void JsonDNP3LogResponse(LogDNP3LogThread *thread,
    const Packet *p, DNP3Transaction *dnp3tx)
{
    json_t *js;
    MemBuffer *buffer = (MemBuffer *)thread->buffer;

    MemBufferReset(buffer);

    js = CreateJSONHeader((Packet *)p, 0, "dnp3");
    if (unlikely(js == NULL)) {
        return;
    }

    json_t *dnp3js = json_object();
    if (dnp3js == NULL) {
        return;
    }
    json_object_set_new(dnp3js, "type", json_string("response"));

    json_t *lcjs = JsonDNP3LogLinkControl(dnp3tx->response_ll_control);
    if (lcjs != NULL) {
        json_object_set_new(dnp3js, "control", lcjs);
    }

    json_object_set_new(dnp3js, "src", json_integer(dnp3tx->session->slave));
    json_object_set_new(dnp3js, "dst", json_integer(dnp3tx->session->master));

    json_t *thjs = JsonDNP3LogTransportHeader(dnp3tx->response_th);
    if (thjs != NULL) {
        json_object_set_new(dnp3js, "transport", thjs);
    }

    /* DNP3 application layer. */
    json_t *al = json_object();
    if (al == NULL) {
        goto done;
    }
    json_object_set_new(dnp3js, "application", al);

    json_t *acjs = JsonDNP3LogApplicationControl(dnp3tx->response_al_control);
    if (acjs != NULL) {
        json_object_set_new(al, "control", acjs);
    }

    json_object_set_new(al, "function_code",
        json_integer(dnp3tx->response_al_fc));

    json_t *iinjs = JsonDNP3LogIin(dnp3tx->iin1 << 8 | dnp3tx->iin2);
    if (iinjs != NULL) {
        json_object_set_new(dnp3js, "iin", iinjs);
    }

    json_t *objects = JsonDNP3LogObjects(&dnp3tx->response_objects);
    if (objects != NULL) {
        json_object_set_new(al, "objects", objects);
    }

    json_object_set_new(js, "dnp3", dnp3js);

    OutputJSONBuffer(js, thread->dnp3log_ctx->file_ctx, buffer);
done:
    json_object_del(js, "dnp3");
    json_decref(js);
}

static int JsonDNP3Logger(ThreadVars *tv, void *thread_data, const Packet *p,
    Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();
    LogDNP3LogThread *thread = (LogDNP3LogThread *)thread_data;
    DNP3Transaction *dnp3tx = tx;

    if (dnp3tx->request_done) {
        JsonDNP3LogRequest(thread, p, dnp3tx);
    }
    if (dnp3tx->response_done) {
        JsonDNP3LogResponse(thread, p, dnp3tx);
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

static OutputCtx *OutputDNP3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogDNP3FileCtx *dnp3log_ctx = SCCalloc(1, sizeof(*dnp3log_ctx));
    if (unlikely(dnp3log_ctx == NULL)) {
        return NULL;
    }
    dnp3log_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnp3log_ctx);
        return NULL;
    }
    output_ctx->data = dnp3log_ctx;
    output_ctx->DeInit = OutputDNP3LogDeInitCtxSub;

    SCLogInfo("DNP3 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNP3);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonDNP3LogThreadInit(ThreadVars *t, void *initdata, void **data)
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

void TmModuleJsonDNP3LogRegister(void)
{
    tmm_modules[TMM_JSONDNP3LOG].name = "JsonDNP3Log";
    tmm_modules[TMM_JSONDNP3LOG].ThreadInit = JsonDNP3LogThreadInit;
    tmm_modules[TMM_JSONDNP3LOG].ThreadDeinit = JsonDNP3LogThreadDeinit;
    tmm_modules[TMM_JSONDNP3LOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONDNP3LOG].cap_flags = 0;
    tmm_modules[TMM_JSONDNP3LOG].flags = TM_FLAG_LOGAPI_TM;

    /* Register as en eve sub-module. */
    OutputRegisterTxSubModule("eve-log", "JsonDNP3Log", "eve-log.dnp3",
        OutputDNP3LogInitSub, ALPROTO_DNP3, JsonDNP3Logger);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonDNP3LogRegister (void)
{
    tmm_modules[TMM_JSONDNP3LOG].name = "JsonDNP3Log";
    tmm_modules[TMM_JSONDNP3LOG].ThreadInit = OutputJsonThreadInit;
}

#endif
