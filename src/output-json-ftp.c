/* Copyright (C) 2017-2020 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implement JSON/eve logging app-layer FTP.
 */


#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-mem.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-ftp.h"
#include "output-json-ftp.h"

typedef struct LogFTPFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogFTPFileCtx;

typedef struct LogFTPLogThread_ {
    LogFileCtx *file_ctx;
    LogFTPFileCtx *ftplog_ctx;
    MemBuffer          *buffer;
} LogFTPLogThread;

static void EveFTPLogCommand(Flow *f, FTPTransaction *tx, JsonBuilder *jb)
{
    /* Preallocate array objects to simplify failure case */
    JsonBuilder *js_resplist = NULL;
    if (!TAILQ_EMPTY(&tx->response_list)) {
        js_resplist = jb_new_array();

        if (unlikely(js_resplist == NULL)) {
            return;
        }
    }
    jb_set_string(jb, "command", tx->command_descriptor->command_name);
    uint32_t min_length = tx->command_descriptor->command_length + 1; /* command + space */
    if (tx->request_length > min_length) {
        jb_set_string_from_bytes(jb,
                "command_data",
                (const uint8_t *)tx->request + min_length,
                tx->request_length - min_length - 1);
        if (tx->request_truncated) {
            JB_SET_TRUE(jb, "command_truncated");
        } else {
            JB_SET_FALSE(jb, "command_truncated");
        }
    }

    bool reply_truncated = false;

    if (!TAILQ_EMPTY(&tx->response_list)) {
        int resp_code_cnt = 0;
        int resp_cnt = 0;
        FTPString *response;
        bool is_cc_array_open = false;
        TAILQ_FOREACH(response, &tx->response_list, next) {
            /* handle multiple lines within the response, \r\n delimited */
            uint8_t *where = response->str;
            uint16_t length = 0;
            uint16_t pos;
            if (!reply_truncated && response->truncated) {
                reply_truncated = true;
            }
            if (response->len > 0 && response->len <= UINT16_MAX) {
                length = (uint16_t)response->len - 1;
            } else if (response->len > UINT16_MAX) {
                length = UINT16_MAX;
            }
            while ((pos = JsonGetNextLineFromBuffer((const char *)where, length)) != UINT16_MAX) {
                uint16_t offset = 0;
                /* Try to find a completion code for this line */
                if (pos >= 3)  {
                    /* Gather the completion code if present */
                    if (isdigit(where[0]) && isdigit(where[1]) && isdigit(where[2])) {
                        if (!is_cc_array_open) {
                            jb_open_array(jb, "completion_code");
                            is_cc_array_open = true;
                        }
                        jb_append_string_from_bytes(jb, (const uint8_t *)where, 3);
                        resp_code_cnt++;
                        offset = 4;
                    }
                }
                /* move past 3 character completion code */
                if (pos >= offset) {
                    jb_append_string_from_bytes(js_resplist, (const uint8_t *)where + offset, pos - offset);
                    resp_cnt++;
                }

                where += pos;
                length -= pos;
            }
        }

        if (is_cc_array_open) {
            jb_close(jb);
        }
        if (resp_cnt) {
            jb_close(js_resplist);
            jb_set_object(jb, "reply", js_resplist);
        }
        jb_free(js_resplist);
    }

    if (tx->dyn_port) {
        jb_set_uint(jb, "dynamic_port", tx->dyn_port);
    }

    if (tx->command_descriptor->command == FTP_COMMAND_PORT ||
        tx->command_descriptor->command == FTP_COMMAND_EPRT) {
        if (tx->active) {
            JB_SET_STRING(jb, "mode", "active");
        } else {
            JB_SET_STRING(jb, "mode", "passive");
        }
    }

    if (tx->done) {
        JB_SET_STRING(jb, "reply_received", "yes");
    } else {
        JB_SET_STRING(jb, "reply_received", "no");
    }

    if (reply_truncated) {
        JB_SET_TRUE(jb, "reply_truncated");
    } else {
        JB_SET_FALSE(jb, "reply_truncated");
    }
}


static int JsonFTPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();

    const char *event_type;
    if (f->alproto == ALPROTO_FTPDATA) {
        event_type = "ftp_data";
    } else {
        event_type = "ftp";
    }
    FTPTransaction *tx = vtx;
    LogFTPLogThread *thread = thread_data;
    LogFTPFileCtx *ftp_ctx = thread->ftplog_ctx;

    JsonBuilder *jb = CreateEveHeaderWithTxId(p, LOG_DIR_FLOW, event_type, NULL, tx_id);
    if (likely(jb)) {
        EveAddCommonOptions(&ftp_ctx->cfg, p, f, jb);
        jb_open_object(jb, event_type);
        if (f->alproto == ALPROTO_FTPDATA) {
            EveFTPDataAddMetadata(f, jb);
        } else {
            EveFTPLogCommand(f, tx, jb);
        }

        if (!jb_close(jb)) {
            goto fail;
        }

        MemBufferReset(thread->buffer);
        OutputJsonBuilderBuffer(jb, thread->file_ctx, &thread->buffer);

        jb_free(jb);
    }
    return TM_ECODE_OK;

fail:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static void OutputFTPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogFTPFileCtx *ftplog_ctx = (LogFTPFileCtx *)output_ctx->data;
    SCFree(ftplog_ctx);
    SCFree(output_ctx);
}


static OutputInitResult OutputFTPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogFTPFileCtx *ftplog_ctx = SCCalloc(1, sizeof(*ftplog_ctx));
    if (unlikely(ftplog_ctx == NULL)) {
        return result;
    }
    ftplog_ctx->file_ctx = ajt->file_ctx;
    ftplog_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ftplog_ctx);
        return result;
    }
    output_ctx->data = ftplog_ctx;
    output_ctx->DeInit = OutputFTPLogDeInitCtxSub;

    SCLogDebug("FTP log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_FTP);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_FTPDATA);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonFTPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogFTPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogFTP.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->ftplog_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->ftplog_ctx->file_ctx, t->id);
    if (!thread->file_ctx) {
        goto error_exit;
    }

    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonFTPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogFTPLogThread *thread = (LogFTPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    /* clear memory */
    memset(thread, 0, sizeof(LogFTPLogThread));
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonFTPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_FTP, "eve-log", "JsonFTPLog",
                              "eve-log.ftp", OutputFTPLogInitSub,
                              ALPROTO_FTP, JsonFTPLogger,
                              JsonFTPLogThreadInit, JsonFTPLogThreadDeinit,
                              NULL);
    OutputRegisterTxSubModule(LOGGER_JSON_FTP, "eve-log", "JsonFTPLog",
                              "eve-log.ftp", OutputFTPLogInitSub,
                              ALPROTO_FTPDATA, JsonFTPLogger,
                              JsonFTPLogThreadInit, JsonFTPLogThreadDeinit,
                              NULL);

    SCLogDebug("FTP JSON logger registered.");
}
