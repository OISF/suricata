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

#include "log-file.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-http.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"

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

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void FileWriteJsonRecord(JsonFileLogThread *aft, const Packet *p, const File *ff)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    json_t *js = CreateJSONHeader((Packet *)p, 0, "fileinfo"); //TODO const
    json_t *hjs = NULL;
    if (unlikely(js == NULL))
        return;

    /* reset */
    MemBufferReset(buffer);

    switch (p->flow->alproto) {
        case ALPROTO_HTTP:
            hjs = JsonHttpAddMetadata(p->flow, ff->txid);
            if (hjs)
                json_object_set_new(js, "http", hjs);
            break;
        case ALPROTO_SMTP:
            hjs = JsonSMTPAddMetadata(p->flow, ff->txid);
            if (hjs)
                json_object_set_new(js, "smtp", hjs);
            hjs = JsonEmailAddMetadata(p->flow, ff->txid);
            if (hjs)
                json_object_set_new(js, "email", hjs);
            break;
    }


    json_t *fjs = json_object();
    if (unlikely(fjs == NULL)) {
        json_decref(js);
        return;
    }

    char *s = BytesToString(ff->name, ff->name_len);
    json_object_set_new(fjs, "filename", json_string(s));
    if (s != NULL)
        SCFree(s);
    if (ff->magic)
        json_object_set_new(fjs, "magic", json_string((char *)ff->magic));
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            json_object_set_new(fjs, "state", json_string("CLOSED"));
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                size_t x;
                int i;
                char s[256];
                for (i = 0, x = 0; x < sizeof(ff->md5); x++) {
                    i += snprintf(&s[i], 255-i, "%02x", ff->md5[x]);
                }
                json_object_set_new(fjs, "md5", json_string(s));
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
    if (ff->flags & FILE_STORED) {
        json_object_set_new(fjs, "file_id", json_integer(ff->file_id));
    }
    json_object_set_new(fjs, "size", json_integer(ff->size));
    json_object_set_new(fjs, "tx_id", json_integer(ff->txid));

    /* originally just 'file', but due to bug 1127 naming it fileinfo */
    json_object_set_new(js, "fileinfo", fjs);
    OutputJSONBuffer(js, aft->filelog_ctx->file_ctx, buffer);
    json_object_del(js, "fileinfo");

    switch (p->flow->alproto) {
        case ALPROTO_HTTP:
            json_object_del(js, "http");
            break;
        case ALPROTO_SMTP:
            json_object_del(js, "smtp");
            json_object_del(js, "email");
            break;
    }

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
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputFileCtx *output_file_ctx = SCMalloc(sizeof(OutputFileCtx));
    if (unlikely(output_file_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(output_file_ctx);
        return NULL;
    }

    output_file_ctx->file_ctx = ojc->file_ctx;

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

void TmModuleJsonFileLogRegister (void)
{
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
