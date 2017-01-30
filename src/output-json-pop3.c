/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * Implements POP3 JSON logging portion of the engine.
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
#include "app-layer-pop3.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"
#include "output-json-email-common.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

static int JsonPop3Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();
#if 1
    JsonEmailLogThread *jhl = (JsonEmailLogThread *)thread_data;
    MemBuffer *buffer = (MemBuffer *)jhl->buffer;

    json_t *js = CreateJSONHeaderWithTxId((Packet *)p, 1, "pop3", tx_id);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    /* reset */
    MemBufferReset(buffer);

    if (JsonEmailLogJson(jhl, js, p, f, state, tx, tx_id) == TM_ECODE_OK) {
        OutputJSONBuffer(js, jhl->emaillog_ctx->file_ctx, &jhl->buffer);
    }
    json_object_del(js, "email");

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);

#else
    SCReturnInt(JsonEmailLogger(tv, thread_data, p, "pop3", f, state, tx, tx_id));
#endif
}

#define DEFAULT_LOG_FILENAME "pop3.json"
OutputCtx *OutputPop3LogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputJsonEmailCtx *email_ctx = SCMalloc(sizeof(OutputJsonEmailCtx));
    if (unlikely(email_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(email_ctx);
        return NULL;
    }

    email_ctx->file_ctx = file_ctx;

    output_ctx->data = email_ctx;
    output_ctx->DeInit = NULL;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POP3);

    return output_ctx;
}

static OutputCtx *OutputPop3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputJsonEmailCtx *email_ctx = SCMalloc(sizeof(OutputJsonEmailCtx));
    if (unlikely(email_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(email_ctx);
        return NULL;
    }

    email_ctx->file_ctx = ojc->file_ctx;

    OutputEmailInitConf(conf, email_ctx);

    output_ctx->data = email_ctx;
    output_ctx->DeInit = NULL;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POP3);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonPop3LogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonEmailLogThread *aft = SCMalloc(sizeof(JsonEmailLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonEmailLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->emaillog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonPop3LogThreadDeinit(ThreadVars *t, void *data)
{
    JsonEmailLogThread *aft = (JsonEmailLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonEmailLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonPop3LogRegister (void) {
    /* register as separate module */
    OutputRegisterTxModule(LOGGER_JSON_POP3, "JsonPop3Log", "pop3-json-log",
                           OutputPop3LogInit, ALPROTO_POP3, JsonPop3Logger,
                           JsonPop3LogThreadInit, JsonPop3LogThreadDeinit,
                           NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_POP3, "eve-log", "JsonPop3Log",
                              "eve-log.pop3", OutputPop3LogInitSub,
                               ALPROTO_POP3, JsonPop3Logger,
                               JsonPop3LogThreadInit, JsonPop3LogThreadDeinit,
                               NULL);
}

#else

void JsonPop3LogRegister (void)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
}

#endif
