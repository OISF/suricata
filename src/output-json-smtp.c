/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"

#include "util-debug.h"

#include "output.h"
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"

#include "output-json.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"

#define SMTP_LOG_MAX_STRING     (8 * 1024)
#define SMTP_LOG_MAX_RCPT       64
#define SMTP_LOG_MAX_RCPT_BYTES (32 * 1024)

static void SmtpAppendStringLimited(SCJsonBuilder *js, const char *str, size_t limit)
{
    size_t len = strlen(str);
    if (len <= limit) {
        SCJbAppendString(js, str);
        return;
    }
    size_t extra = len - limit;
    char suffix[64];
    int suffix_len = snprintf(suffix, sizeof(suffix), "[truncated %zu additional bytes]", extra);
    if (suffix_len < 0) {
        SCJbAppendString(js, str);
        return;
    }
    uint8_t *buf = SCMalloc(limit + (size_t)suffix_len);
    if (buf == NULL) {
        SCJbAppendString(js, str);
        return;
    }
    memcpy(buf, str, limit);
    memcpy(buf + limit, suffix, (size_t)suffix_len);
    SCJbAppendStringFromBytes(js, buf, (uint32_t)(limit + (size_t)suffix_len));
    SCFree(buf);
}

static void SmtpSetStringLimited(SCJsonBuilder *js, const char *key, const char *str)
{
    size_t len = strlen(str);
    if (len <= SMTP_LOG_MAX_STRING) {
        SCJbSetStringFromBytes(js, key, (const uint8_t *)str, (uint32_t)len);
        return;
    }
    size_t extra = len - SMTP_LOG_MAX_STRING;
    char suffix[64];
    int suffix_len = snprintf(suffix, sizeof(suffix), "[truncated %zu additional bytes]", extra);
    if (suffix_len < 0) {
        SCJbSetStringFromBytes(js, key, (const uint8_t *)str, (uint32_t)len);
        return;
    }
    uint8_t *buf = SCMalloc(SMTP_LOG_MAX_STRING + (size_t)suffix_len);
    if (buf == NULL) {
        SCJbSetStringFromBytes(js, key, (const uint8_t *)str, (uint32_t)len);
        return;
    }
    memcpy(buf, str, SMTP_LOG_MAX_STRING);
    memcpy(buf + SMTP_LOG_MAX_STRING, suffix, (size_t)suffix_len);
    SCJbSetStringFromBytes(js, key, buf, (uint32_t)(SMTP_LOG_MAX_STRING + (size_t)suffix_len));
    SCFree(buf);
}

static void EveSmtpDataLogger(void *state, void *vtx, SCJsonBuilder *js)
{
    if (state == NULL || vtx == NULL) {
        return;
    }

    SMTPTransaction *tx = vtx;
    SMTPString *rcptto_str;
    bool truncated = false;

    if (((SMTPState *)state)->helo) {
        if (strlen((const char *)((SMTPState *)state)->helo) > SMTP_LOG_MAX_STRING)
            truncated = true;
        SmtpSetStringLimited(js, "helo", (const char *)((SMTPState *)state)->helo);
    }
    if (tx->mail_from) {
        if (strlen((const char *)tx->mail_from) > SMTP_LOG_MAX_STRING)
            truncated = true;
        SmtpSetStringLimited(js, "mail_from", (const char *)tx->mail_from);
    }
    if (!TAILQ_EMPTY(&tx->rcpt_to_list)) {
        size_t budget = SMTP_LOG_MAX_RCPT_BYTES;
        size_t count = 0;
        bool rcpt_truncated = false;
        SCJbOpenArray(js, "rcpt_to");
        TAILQ_FOREACH (rcptto_str, &tx->rcpt_to_list, next) {
            if (count >= SMTP_LOG_MAX_RCPT || budget == 0) {
                rcpt_truncated = true;
                break;
            }
            size_t len = strlen((const char *)rcptto_str->str);
            size_t limit = len < budget ? len : budget;
            if (limit > SMTP_LOG_MAX_STRING)
                limit = SMTP_LOG_MAX_STRING;
            if (limit < len)
                rcpt_truncated = true;
            budget -= limit;
            count++;
            SmtpAppendStringLimited(js, (const char *)rcptto_str->str, limit);
        }
        SCJbClose(js);
        if (rcpt_truncated) {
            SCJbSetBool(js, "rcpt_to_truncated", true);
            truncated = true;
        }
    }
    if (truncated) {
        SCJbSetBool(js, "truncated", true);
    }
}

static int JsonSmtpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();
    JsonEmailLogThread *jhl = (JsonEmailLogThread *)thread_data;

    SCJsonBuilder *jb = CreateEveHeaderWithTxId(
            p, LOG_DIR_FLOW, "smtp", NULL, tx_id, jhl->emaillog_ctx->eve_ctx);
    if (unlikely(jb == NULL))
        return TM_ECODE_OK;

    SCJbOpenObject(jb, "smtp");
    EveSmtpDataLogger(state, tx, jb);
    SCJbClose(jb);

    EveEmailLogJson(jhl, jb, p, f, state, tx, tx_id);
    OutputJsonBuilderBuffer(tv, p, p->flow, jb, jhl->ctx);

    SCJbFree(jb);

    SCReturnInt(TM_ECODE_OK);

}

bool EveSMTPAddMetadata(const Flow *f, uint64_t tx_id, SCJsonBuilder *js)
{
    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(f);
    if (smtp_state) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, smtp_state, tx_id);
        if (tx) {
            EveSmtpDataLogger(smtp_state, tx, js);
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

static OutputInitResult OutputSmtpLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputJsonEmailCtx *email_ctx = SCCalloc(1, sizeof(OutputJsonEmailCtx));
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
    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);

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
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonSmtpLog", "eve-log.smtp",
            OutputSmtpLogInitSub, ALPROTO_SMTP, JsonSmtpLogger, JsonSmtpLogThreadInit,
            JsonSmtpLogThreadDeinit);
}
