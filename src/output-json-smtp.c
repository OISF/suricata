/* Copyright (C) 2007-2015 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements SMTP JSON logging portion of the engine.
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
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"

#ifdef HAVE_LIBJANSSON

static json_t *JsonSmtpDataLogger(const Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    json_t *sjs = json_object();
    SMTPTransaction *tx = vtx;
    SMTPString *rcptto_str;
    if (sjs == NULL) {
        return NULL;
    }
    if (((SMTPState *)state)->helo) {
        json_object_set_new(sjs, "helo",
                            json_string((const char *)((SMTPState *)state)->helo));
    }
    if (tx->mail_from) {
        json_object_set_new(sjs, "mail_from",
                            json_string((const char *)tx->mail_from));
    }
    if (!TAILQ_EMPTY(&tx->rcpt_to_list)) {
        json_t *js_rcptto = json_array();
        if (likely(js_rcptto != NULL)) {
            TAILQ_FOREACH(rcptto_str, &tx->rcpt_to_list, next) {
                json_array_append_new(js_rcptto, json_string((char *)rcptto_str->str));
            }
            json_object_set_new(sjs, "rcpt_to", js_rcptto);
        }
    }

    return sjs;
}

static int JsonSmtpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();
    JsonEmailLogThread *jhl = (JsonEmailLogThread *)thread_data;

    json_t *sjs;
    json_t *js = CreateJSONHeaderWithTxId((Packet *)p, 1, "smtp", tx_id);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    /* reset */
    MemBufferReset(jhl->buffer);

    sjs = JsonSmtpDataLogger(f, state, tx, tx_id);
    if (sjs) {
        json_object_set_new(js, "smtp", sjs);
    }

    if (JsonEmailLogJson(jhl, js, p, f, state, tx, tx_id) == TM_ECODE_OK) {
        OutputJSONBuffer(js, jhl->emaillog_ctx->file_ctx, &jhl->buffer);
    }
    json_object_del(js, "email");
    if (sjs) {
        json_object_del(js, "smtp");
    }

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);

}

json_t *JsonSMTPAddMetadata(const Flow *f, uint64_t tx_id)
{
    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(f);
    if (smtp_state) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, smtp_state, tx_id);

        if (tx) {
            return JsonSmtpDataLogger(f, smtp_state, tx, tx_id);
        }
    }

    return NULL;
}

static void OutputSmtpLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonEmailCtx *email_ctx = output_ctx->data;
    if (email_ctx != NULL) {
        LogFileFreeCtx(email_ctx->file_ctx);
        SCFree(email_ctx);
    }
    SCFree(output_ctx);
}

static void OutputSmtpLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    OutputJsonEmailCtx *email_ctx = output_ctx->data;
    if (email_ctx != NULL) {
        SCFree(email_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "smtp.json"
static OutputCtx *OutputSmtpLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_SMTP_LOG_GENERIC, "couldn't create new file_ctx");
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
    output_ctx->DeInit = OutputSmtpLogDeInitCtx;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);

    return output_ctx;
}

static OutputCtx *OutputSmtpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
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
    output_ctx->DeInit = OutputSmtpLogDeInitCtxSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonSmtpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonEmailLogThread *aft = SCMalloc(sizeof(JsonEmailLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonEmailLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogSMTP.  \"initdata\" argument NULL");
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

static TmEcode JsonSmtpLogThreadDeinit(ThreadVars *t, void *data)
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

void JsonSmtpLogRegister (void) {
    /* register as separate module */
    OutputRegisterTxModule(LOGGER_JSON_SMTP, "JsonSmtpLog", "smtp-json-log",
        OutputSmtpLogInit, ALPROTO_SMTP, JsonSmtpLogger, JsonSmtpLogThreadInit,
        JsonSmtpLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_SMTP, "eve-log", "JsonSmtpLog",
        "eve-log.smtp", OutputSmtpLogInitSub, ALPROTO_SMTP, JsonSmtpLogger,
        JsonSmtpLogThreadInit, JsonSmtpLogThreadDeinit, NULL);
}

#else

void JsonSmtpLogRegister (void)
{
}

#endif
