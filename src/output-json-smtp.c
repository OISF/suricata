/* Copyright (C) 2007-2022 Open Information Security Foundation
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

static void EveSmtpDataLogger(const Flow *f, void *state, void *vtx, uint64_t tx_id, JsonBuilder *js)
{
    SMTPTransaction *tx = vtx;
    SMTPString *rcptto_str;
    if (((SMTPState *)state)->helo) {
        jb_set_string(js, "helo", (const char *)((SMTPState *)state)->helo);
    }
    if (tx->mail_from) {
        jb_set_string(js, "mail_from", (const char *)tx->mail_from);
    }
    if (!TAILQ_EMPTY(&tx->rcpt_to_list)) {
        jb_open_array(js, "rcpt_to");
        TAILQ_FOREACH(rcptto_str, &tx->rcpt_to_list, next) {
            jb_append_string(js, (char *)rcptto_str->str);
        }
        jb_close(js);
    }
}

static int JsonSmtpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();
    JsonEmailLogThread *jhl = (JsonEmailLogThread *)thread_data;

    JsonBuilder *jb = CreateEveHeaderWithTxId(
            p, LOG_DIR_FLOW, "smtp", NULL, tx_id, jhl->emaillog_ctx->eve_ctx);
    if (unlikely(jb == NULL))
        return TM_ECODE_OK;

    jb_open_object(jb, "smtp");
    EveSmtpDataLogger(f, state, tx, tx_id, jb);
    jb_close(jb);

    EveEmailLogJson(jhl, jb, p, f, state, tx, tx_id);
    OutputJsonBuilderBuffer(jb, jhl->ctx);

    jb_free(jb);

    SCReturnInt(TM_ECODE_OK);

}

bool EveSMTPAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(f);
    if (smtp_state) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, smtp_state, tx_id);
        if (tx) {
            EveSmtpDataLogger(f, smtp_state, tx, tx_id, js);
            return true;
        }
    }

    return false;
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

static OutputInitResult OutputSmtpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputJsonEmailCtx *email_ctx = SCMalloc(sizeof(OutputJsonEmailCtx));
    if (unlikely(email_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(email_ctx);
        return result;
    }

    email_ctx->eve_ctx = ojc;

    OutputEmailInitConf(conf, email_ctx);

    output_ctx->data = email_ctx;
    output_ctx->DeInit = OutputSmtpLogDeInitCtxSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonSmtpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonEmailLogThread *aft = SCCalloc(1, sizeof(JsonEmailLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSMTP.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->emaillog_ctx = ((OutputCtx *)initdata)->data;

    aft->ctx = CreateEveThreadCtx(t, aft->emaillog_ctx->eve_ctx);
    if (aft->ctx == NULL) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonSmtpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonEmailLogThread *aft = (JsonEmailLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonEmailLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonSmtpLogRegister (void) {
    /* register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_SMTP, "eve-log", "JsonSmtpLog",
        "eve-log.smtp", OutputSmtpLogInitSub, ALPROTO_SMTP, JsonSmtpLogger,
        JsonSmtpLogThreadInit, JsonSmtpLogThreadDeinit, NULL);
}
