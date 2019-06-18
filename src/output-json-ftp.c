/* Copyright (C) 2017 Open Information Security Foundation
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
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-ftp.h"
#include "output-json-ftp.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogFTPFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogFTPFileCtx;

typedef struct LogFTPLogThread_ {
    LogFTPFileCtx *ftplog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogFTPLogThread;

/*
 * \brief Returns the ending offset of the next line.
 *
 * Here, "next line" is defined as terminating on
 * - Newline character
 * - Null character
 *
 * \param buffer Contains zero or more characters.
 * \param len Size, in bytes, of buffer.
 *
 * \retval Offset from the start of buffer indicating the where the
 * next "line ends". The characters between the input buffer and this
 * value comprise the line.
 *
 * NULL is found first or a newline isn't found, then
 */
static uint16_t JsonGetNextLineFromBuffer(const char *buffer, const uint16_t len)
{
    if (!buffer || *buffer == '\0')
        return UINT16_MAX;

    char *c = strchr(buffer, '\n');
    return c == NULL ? len : c - buffer + 1;
}

static json_t *JsonFTPLogCommand(Flow *f, FTPTransaction *tx)
{
    json_t *cjs = json_object();
    if (!cjs) {
        return cjs;
    }

    /* Preallocate array objects to simplify failure case */
    json_t *js_resplist;
    json_t *js_respcode_list;
    if (!TAILQ_EMPTY(&tx->response_list)) {
        js_resplist = json_array();
        js_respcode_list = json_array();

        if (unlikely(js_resplist == NULL || js_respcode_list == NULL)) {
            if (js_resplist) {
                json_decref(js_resplist);
            } else {
                json_decref(js_respcode_list);
            }
            return cjs;
        }
    }

    json_object_set_new(cjs, "command",
                        json_string(tx->command_descriptor->command_name_upper));
    uint32_t min_length = tx->command_descriptor->command_length + 1; /* command + space */
    if (tx->request_length > min_length) {
        json_object_set_new(cjs, "command_data",
                            JsonAddStringN((const char *)tx->request + min_length,
                                           tx->request_length - min_length));
    } else {
        json_object_set_new(cjs, "command_data", json_string(NULL));
    }

    if (!TAILQ_EMPTY(&tx->response_list)) {
        FTPString *response;
        TAILQ_FOREACH(response, &tx->response_list, next) {
            /* handle multiple lines within the response, \r\n delimited */
            uint8_t *where = response->str;
            uint16_t length = response->len;
            uint16_t pos;
            while ((pos = JsonGetNextLineFromBuffer((const char *)where, length)) != UINT16_MAX) {
                uint16_t offset = 0;
                /* Try to find a completion code for this line */
                if (pos >= 3)  {
                    /* Gather the completion code if present */
                    if (isdigit(where[0]) && isdigit(where[1]) && isdigit(where[2])) {
                        json_array_append_new(js_respcode_list,
                                              JsonAddStringN((const char *)where, 3));
                        offset = 4;
                    }
                }
                /* move past 3 character completion code */
                if (pos >= offset) {
                    json_array_append_new(js_resplist,
                                          JsonAddStringN((const char *)where + offset, pos - offset));
                }

                where += pos;
                length -= pos;
            }
        }

        json_object_set_new(cjs, "reply", js_resplist);
        json_object_set_new(cjs, "completion_code", js_respcode_list);
    }

    if (tx->dyn_port) {
        json_object_set_new(cjs, "dynamic_port", json_integer(tx->dyn_port));
    }

    if (tx->command_descriptor->command == FTP_COMMAND_PORT ||
        tx->command_descriptor->command == FTP_COMMAND_EPRT) {
        json_object_set_new(cjs, "mode",
                json_string((char *)(tx->active ? "active" : "passive")));
    }

    json_object_set_new(cjs, "reply_received",
            json_string((char *)(tx->done ? "yes" : "no")));

    return cjs;
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

    json_t *js = CreateJSONHeaderWithTxId(p, LOG_DIR_FLOW, event_type, tx_id);
    if (likely(js)) {
        JsonAddCommonOptions(&ftp_ctx->cfg, p, f, js);
        json_t *cjs = NULL;
        if (f->alproto == ALPROTO_FTPDATA) {
            cjs = JsonFTPDataAddMetadata(f);
        } else {
            cjs = JsonFTPLogCommand(f, tx);
        }

        if (cjs) {
            json_object_set_new(js, event_type, cjs);
        }

        MemBufferReset(thread->buffer);
        OutputJSONBuffer(js, thread->ftplog_ctx->file_ctx, &thread->buffer);

        json_object_clear(js);
        json_decref(js);
    }
    return TM_ECODE_OK;
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

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonFTPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogFTPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogFTP.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->ftplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
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
#else /* HAVE_LIBJANSSON */

void JsonFTPLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
