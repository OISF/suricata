/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements JA3 JSON logging.
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
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"
#include "util-ja3.h"

#include "output-json.h"
#include "output-json-ja3.h"

#ifdef HAVE_LIBJANSSON

#define MODULE_NAME "LogJa3Log"
#define DEFAULT_LOG_FILENAME "ja3.json"

#define OUTPUT_BUFFER_SIZE 65535

#define LOG_JA3_FIELD_HASH (1 << 0)
#define LOG_JA3_FIELD_STR  (1 << 1)

typedef struct {
    const char *name;
    uint64_t flag;
} Ja3Fields;

Ja3Fields ja3_fields[] = {
    { "hash", LOG_JA3_FIELD_HASH },
    { "str",  LOG_JA3_FIELD_STR },
    { NULL,   -1 }
};

typedef struct OutputJa3Ctx_ {
    LogFileCtx *file_ctx;
    uint64_t fields;
    bool include_metadata;
} OutputJa3Ctx;

typedef struct JsonJa3LogThread_ {
    OutputJa3Ctx *ja3log_ctx;
    MemBuffer *buffer;
} JsonJa3LogThread;

void JsonJa3LogHash(json_t *js, SSLState *ssl_state, const char *name)
{
    if (ssl_state->ja3_hash != NULL) {
        json_object_set_new(js, name,
                            json_string(ssl_state->ja3_hash));
    }
}

void JsonJa3LogStr(json_t *js, SSLState *ssl_state, const char *name)
{
    if ((ssl_state->ja3_str != NULL) &&
            (ssl_state->ja3_str->data != NULL)) {
        json_object_set_new(js, name,
                            json_string(ssl_state->ja3_str->data));
    }
}

static int JsonJa3Logger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonJa3LogThread *aft = (JsonJa3LogThread *)thread_data;
    OutputJa3Ctx *ja3_ctx = aft->ja3log_ctx;

    SSLState *ssl_state = (SSLState *)state;
    if (unlikely(ssl_state == NULL)) {
        return 0;
    }

    json_t *js = CreateJSONHeader((Packet *)p, 1, "ja3");
    if (unlikely(js == NULL)) {
        return 0;
    }

    if (ja3_ctx->include_metadata) {
        JsonAddMetadata(p, f, js);
    }

    json_t *tjs = json_object();
    if (tjs == NULL) {
        json_decref(js);
        return 0;
    }

    /* Reset */
    MemBufferReset(aft->buffer);

    /* JA3 hash */
    if (ja3_ctx->fields & LOG_JA3_FIELD_HASH)
        JsonJa3LogHash(tjs, ssl_state, "hash");

    /* JA3 str */
    if (ja3_ctx->fields & LOG_JA3_FIELD_STR)
        JsonJa3LogStr(tjs, ssl_state, "str");

    json_object_set_new(js, "ja3", tjs);

    OutputJSONBuffer(js, ja3_ctx->file_ctx, &aft->buffer);
    json_object_clear(js);
    json_decref(js);

    return 0;
}

static TmEcode JsonJa3LogThreadInit(ThreadVars *t, const void *initdata,
                                    void **data)
{
    JsonJa3LogThread *aft = SCMalloc(sizeof(JsonJa3LogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    memset(aft, 0, sizeof(JsonJa3LogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for eve-log ja3 'initdata' "
                   "argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->ja3log_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;

    return TM_ECODE_OK;
}

static TmEcode JsonJa3LogThreadDeinit(ThreadVars *t, void *data)
{
    JsonJa3LogThread *aft = (JsonJa3LogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* Clear memory */
    memset(aft, 0, sizeof(JsonJa3LogThread));

    SCFree(aft);

    return TM_ECODE_OK;
}

static void OutputJa3LogDeinit(OutputCtx *output_ctx)
{
    OutputJa3Ctx *ja3_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = ja3_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(ja3_ctx);
    SCFree(output_ctx);
}

static OutputJa3Ctx *OutputJa3InitCtx(ConfNode *conf)
{
    /* Check if JA3 is disabled */
    if (Ja3IsDisabled("logger"))
        return NULL;

    OutputJa3Ctx *ja3_ctx = SCMalloc(sizeof(OutputJa3Ctx));
    if (unlikely(ja3_ctx == NULL))
        return NULL;

    ja3_ctx->fields = 0;

    if (conf == NULL)
        return ja3_ctx;

    ConfNode *custom = ConfNodeLookupChild(conf, "custom");
    if (custom) {
        ConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next)
        {
            Ja3Fields *valid_fields = ja3_fields;
            for ( ; valid_fields->name != NULL; valid_fields++) {
                if (strcasecmp(field->val, valid_fields->name) == 0) {
                    ja3_ctx->fields |= valid_fields->flag;
                    break;
                }
            }
        }
    } else {
        /* Enable all fields, if "custom" is not specified */
        ja3_ctx->fields |= LOG_JA3_FIELD_HASH;
        ja3_ctx->fields |= LOG_JA3_FIELD_STR;
    }

    return ja3_ctx;
}

static OutputInitResult OutputJa3LogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_JA3_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputJa3Ctx *ja3_ctx = OutputJa3InitCtx(conf);
    if (unlikely(ja3_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(ja3_ctx);
        return result;
    }

    ja3_ctx->file_ctx = file_ctx;

    output_ctx->data = ja3_ctx;
    output_ctx->DeInit = OutputJa3LogDeinit;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void OutputJa3LogDeinitSub(OutputCtx *output_ctx)
{
    OutputJa3Ctx *ja3_ctx = output_ctx->data;
    SCFree(ja3_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputJa3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputJa3Ctx *ja3_ctx = OutputJa3InitCtx(conf);
    if (unlikely(ja3_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ja3_ctx);
        return result;
    }

    ja3_ctx->file_ctx = ojc->file_ctx;
    ja3_ctx->include_metadata = ojc->include_metadata;

    output_ctx->data = ja3_ctx;
    output_ctx->DeInit = OutputJa3LogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonJa3LogRegister(void)
{
    /* Register as a separate module */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_JA3, "JsonJa3Log",
        "ja3-json-log", OutputJa3LogInit, ALPROTO_TLS, JsonJa3Logger,
        TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE, JsonJa3LogThreadInit,
        JsonJa3LogThreadDeinit, NULL);

    /* Also register as a child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_JA3, "eve-log",
        "JsonJa3Log", "eve-log.ja3", OutputJa3LogInitSub, ALPROTO_TLS,
        JsonJa3Logger, TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE,
        JsonJa3LogThreadInit, JsonJa3LogThreadDeinit, NULL);
}

#else /* HAVE_LIBJANSSON */

void JsonJa3LogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */

