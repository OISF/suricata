/* Copyright (C) 2018-2020 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "output.h"
#include "output-json.h"
#include "util-buffer.h"
#include "util-file.h"
#include "util-streaming-buffer.h"

OutputJsonThreadCtx *CreateEveThreadCtx(ThreadVars *t, OutputJsonCtx *ctx)
{
    OutputJsonThreadCtx *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return NULL;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error;
    }

    thread->file_ctx = LogFileEnsureExists(t->id, ctx->file_ctx);
    if (!thread->file_ctx) {
        goto error;
    }

    thread->ctx = ctx;

    return thread;

error:
    if (thread->buffer) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return NULL;
}

void FreeEveThreadCtx(OutputJsonThreadCtx *ctx)
{
    if (ctx != NULL && ctx->buffer != NULL) {
        MemBufferFree(ctx->buffer);
    }
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

static void OutputJsonLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCFree(output_ctx);
}

int OutputJsonLogFlush(ThreadVars *tv, void *thread_data, const Packet *p)
{
    OutputJsonThreadCtx *aft = thread_data;
    LogFileCtx *file_ctx = aft->ctx->file_ctx;
    SCLogDebug("%s flushing %s", tv->name, file_ctx->filename);
    LogFileFlush(file_ctx);
    return 0;
}

OutputInitResult OutputJsonLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }
    output_ctx->data = parent_ctx->data;
    output_ctx->DeInit = OutputJsonLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


TmEcode JsonLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        return TM_ECODE_FAILED;
    }

    OutputJsonThreadCtx *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(t->id, thread->ctx->file_ctx);
    if (!thread->file_ctx) {
        goto error_exit;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;

error_exit:
    if (thread->buffer) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

TmEcode JsonLogThreadDeinit(ThreadVars *t, void *data)
{
    OutputJsonThreadCtx *thread = (OutputJsonThreadCtx *)data;
    FreeEveThreadCtx(thread);
    return TM_ECODE_OK;
}

/**
 * \brief Log PE metadata if file starts with MZ header
 *
 * Checks if the file has PE header data (MZ signature) and logs
 * the PE metadata using the Rust SCPeLogJson function.
 *
 * \param file The File object to check for PE metadata
 * \param jb The JSON builder to append PE metadata to
 */
void EveFilePeMetadataLog(const File *file, SCJsonBuilder *jb)
{
    if (file == NULL || file->sb == NULL) {
        return;
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint64_t offset = 0;
    StreamingBufferGetData(file->sb, &data, &data_len, &offset);

    /* Only log PE metadata if we have the start of the file and it has MZ signature */
    if (offset == 0 && data != NULL && data_len >= 64 && data[0] == 'M' && data[1] == 'Z') {
        SCPeLogJson(data, data_len, jb);
    }
}
