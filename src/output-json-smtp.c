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
#include "output-json-email-common.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

static int JsonSmtpLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    SCEnter();
    int r = JsonEmailLogger(tv, thread_data, p);
    SCReturnInt(r);
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
OutputCtx *OutputSmtpLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
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
    AlertJsonThread *ajt = parent_ctx->data;

    OutputJsonEmailCtx *email_ctx = SCMalloc(sizeof(OutputJsonEmailCtx));
    if (unlikely(email_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(email_ctx);
        return NULL;
    }

    email_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = email_ctx;
    output_ctx->DeInit = OutputSmtpLogDeInitCtxSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonSmtpLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

/** \internal
 *  \brief Condition function for SMTP logger
 *  \retval bool true or false -- log now?
 */
static int JsonSmtpCondition(ThreadVars *tv, const Packet *p) {
    if (p->flow == NULL) {
        return FALSE;
    }

    if (!(PKT_IS_TCP(p))) {
        return FALSE;
    }

    FLOWLOCK_RDLOCK(p->flow);
    uint16_t proto = FlowGetAppProtocol(p->flow);
    if (proto != ALPROTO_SMTP)
        goto dontlog;

    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(p->flow);
    if (smtp_state == NULL) {
        SCLogDebug("no smtp state, so no request logging");
        goto dontlog;
    }

    FLOWLOCK_UNLOCK(p->flow);
    return TRUE;
dontlog:
    FLOWLOCK_UNLOCK(p->flow);
    return FALSE;
}

void TmModuleJsonSmtpLogRegister (void) {
    tmm_modules[TMM_JSONSMTPLOG].name = "JsonSmtpLog";
    tmm_modules[TMM_JSONSMTPLOG].ThreadInit = JsonSmtpLogThreadInit;
    tmm_modules[TMM_JSONSMTPLOG].ThreadDeinit = JsonSmtpLogThreadDeinit;
    tmm_modules[TMM_JSONSMTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONSMTPLOG].cap_flags = 0;
    tmm_modules[TMM_JSONSMTPLOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterPacketModule("JsonSmtpLog", "smtp-json-log",
                               OutputSmtpLogInit,
                               JsonSmtpLogger,
                               JsonSmtpCondition);

    /* also register as child of eve-log */
    OutputRegisterPacketSubModule("eve-log", "JsonSmtpLog",
                                  "eve-log.smtp",
                                  OutputSmtpLogInitSub,
                                  JsonSmtpLogger,
                                  JsonSmtpCondition);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonSmtpLogRegister (void)
{
    tmm_modules[TMM_JSONSMTPLOG].name = "JsonSmtpLog";
    tmm_modules[TMM_JSONSMTPLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
