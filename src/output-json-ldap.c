/* Copyright (C) 2024 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and in output-json-ldap.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Ldap.
 */

#include "suricata-common.h"
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

#include "output-json-ldap.h"
#include "rust.h"

typedef struct LogLdapFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogLdapFileCtx;

typedef struct LogLdapLogThread_ {
    LogLdapFileCtx *ldaplog_ctx;
    OutputJsonThreadCtx *ctx;
} LogLdapLogThread;

static int JsonLdapLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonLdapLogger");
    LogLdapLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "ldap", NULL, thread->ldaplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_ldap_logger_log(tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputLdapLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogLdapFileCtx *ldaplog_ctx = (LogLdapFileCtx *)output_ctx->data;
    SCFree(ldaplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputLdapLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogLdapFileCtx *ldaplog_ctx = SCCalloc(1, sizeof(*ldaplog_ctx));
    if (unlikely(ldaplog_ctx == NULL)) {
        return result;
    }
    ldaplog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ldaplog_ctx);
        return result;
    }
    output_ctx->data = ldaplog_ctx;
    output_ctx->DeInit = OutputLdapLogDeInitCtxSub;

    SCLogNotice("Ldap log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_LDAP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonLdapLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogLdapLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogLdap.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->ldaplog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->ldaplog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonLdapLogThreadDeinit(ThreadVars *t, void *data)
{
    LogLdapLogThread *thread = (LogLdapLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonLdapLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonLdapLog", "eve-log.ldap",
            OutputLdapLogInitSub, ALPROTO_LDAP, JsonLdapLogger,
            JsonLdapLogThreadInit, JsonLdapLogThreadDeinit, NULL);

    SCLogNotice("Ldap JSON logger registered.");
}
