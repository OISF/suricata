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

    thread->file_ctx = LogFileEnsureExists(ctx->file_ctx, t->id);
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

OutputInitResult OutputJsonLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
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
    thread->file_ctx = LogFileEnsureExists(thread->ctx->file_ctx, t->id);
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
