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
 * Log files we track.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "app-layer-parser.h"

#include "detect-filemagic.h"

#include "stream.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-atomic.h"
#include "util-file.h"
#include "util-time.h"
#include "util-buffer.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct OutputFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t file_cnt;
} OutputFileCtx;

typedef struct JsonFileLogThread_ {
    OutputFileCtx *filelog_ctx;
    MemBuffer *buffer;
} JsonFileLogThread;

static json_t *LogFileMetaGetUri(const Packet *p, const File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud->request_uri_normalized != NULL) {
                char *s = bstr_util_strdup_to_c(tx_ud->request_uri_normalized);
                if (s != NULL) {
                    js = json_string(s);
                    SCFree(s);
                }
            }
            return js;
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetHost(const Packet *p, const File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            char *s = bstr_util_strdup_to_c(tx->request_hostname);
            if (s != NULL) {
                js = json_string(s);
                SCFree(s);
            }
            return js;
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetReferer(const Packet *p, const File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "Referer");
            if (h != NULL) {
                char *s = bstr_util_strdup_to_c(h->value);
                if (s != NULL) {
                    js = json_string(s);
                    SCFree(s);
                }
                return js;
            }
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetUserAgent(const Packet *p, const File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "User-Agent");
            if (h != NULL) {
                char *s = bstr_util_strdup_to_c(h->value);
                if (s != NULL) {
                    js = json_string(s);
                    SCFree(s);
                }
                return js;
            }
        }
    }

    return json_string("<unknown>");
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void FileWriteJsonRecord(JsonFileLogThread *aft, const Packet *p, const File *ff) {
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    json_t *js = CreateJSONHeader((Packet *)p, 0, "fileinfo"); //TODO const
    if (unlikely(js == NULL))
        return;

    /* reset */
    MemBufferReset(buffer);

    json_t *hjs = json_object();
    if (unlikely(hjs == NULL)) {
        json_decref(js);
        return;
    }

    json_object_set_new(hjs, "url", LogFileMetaGetUri(p, ff));
    json_object_set_new(hjs, "hostname", LogFileMetaGetHost(p, ff));
    json_object_set_new(hjs, "http_refer", LogFileMetaGetReferer(p, ff));
    json_object_set_new(hjs, "http_user_agent", LogFileMetaGetUserAgent(p, ff));
    json_object_set_new(js, "http", hjs);

    json_t *fjs = json_object();
    if (unlikely(fjs == NULL)) {
        json_decref(hjs);
        json_decref(js);
        return;
    }

    char *s = BytesToString(ff->name, ff->name_len);
    json_object_set_new(fjs, "filename", json_string(s));
    if (s != NULL)
        SCFree(s);
    if (ff->magic)
        json_object_set_new(fjs, "magic", json_string((char *)ff->magic));
    else
        json_object_set_new(fjs, "magic", json_string("unknown"));
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            json_object_set_new(fjs, "state", json_string("CLOSED"));
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                size_t x;
                int i;
                char *s = SCMalloc(256);
                if (likely(s != NULL)) {
                    for (i = 0, x = 0; x < sizeof(ff->md5); x++) {
                        i += snprintf(&s[i], 255-i, "%02x", ff->md5[x]);
                    }
                    json_object_set_new(fjs, "md5", json_string(s));
                    SCFree(s);
                }
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            json_object_set_new(fjs, "state", json_string("TRUNCATED"));
            break;
        case FILE_STATE_ERROR:
            json_object_set_new(fjs, "state", json_string("ERROR"));
            break;
        default:
            json_object_set_new(fjs, "state", json_string("UNKNOWN"));
            break;
    }
    json_object_set_new(fjs, "stored",
                        (ff->flags & FILE_STORED) ? json_true() : json_false());
    json_object_set_new(fjs, "size", json_integer(ff->size));

    /* originally just 'file', but due to bug 1127 naming it fileinfo */
    json_object_set_new(js, "fileinfo", fjs);
    OutputJSONBuffer(js, aft->filelog_ctx->file_ctx, buffer);
    json_object_del(js, "fileinfo");
    json_object_del(js, "http");

    json_object_clear(js);
    json_decref(js);
}

static int JsonFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff)
{
    SCEnter();
    JsonFileLogThread *aft = (JsonFileLogThread *)thread_data;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    FileWriteJsonRecord(aft, p, ff);
    return 0;
}


#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonFileLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonFileLogThread *aft = SCMalloc(sizeof(JsonFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonFileLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->filelog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonFileLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFileLogThread *aft = (JsonFileLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonFileLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputFileLogDeinitSub(OutputCtx *output_ctx)
{
    OutputFileCtx *ff_ctx = output_ctx->data;
    SCFree(ff_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *OutputFileLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    OutputFileCtx *output_file_ctx = SCMalloc(sizeof(OutputFileCtx));
    if (unlikely(output_file_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(output_file_ctx);
        return NULL;
    }

    output_file_ctx->file_ctx = ajt->file_ctx;

    if (conf) {
        const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
        if (force_magic != NULL && ConfValIsTrue(force_magic)) {
            FileForceMagicEnable();
            SCLogInfo("forcing magic lookup for logged files");
        }

        const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
        if (force_md5 != NULL && ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
            FileForceMd5Enable();
            SCLogInfo("forcing md5 calculation for logged files");
#else
            SCLogInfo("md5 calculation requires linking against libnss");
#endif
        }
    }

    output_ctx->data = output_file_ctx;
    output_ctx->DeInit = OutputFileLogDeinitSub;

    FileForceTrackingEnable();
    return output_ctx;
}

void TmModuleJsonFileLogRegister (void) {
    tmm_modules[TMM_JSONFILELOG].name = "JsonFileLog";
    tmm_modules[TMM_JSONFILELOG].ThreadInit = JsonFileLogThreadInit;
    tmm_modules[TMM_JSONFILELOG].ThreadDeinit = JsonFileLogThreadDeinit;
    tmm_modules[TMM_JSONFILELOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as child of eve-log */
    OutputRegisterFileSubModule("eve-log", "JsonFileLog", "eve-log.files",
            OutputFileLogInitSub, JsonFileLogger);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonFileLogRegister (void)
{
    tmm_modules[TMM_JSONFILELOG].name = "JsonFileLog";
    tmm_modules[TMM_JSONFILELOG].ThreadInit = OutputJsonThreadInit;
}

#endif
