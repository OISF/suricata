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

/**
 * \file
 *
 */

#include "suricata-common.h"
#include "suricata.h"

#include "util-spm.h"
#include "util-spm-mm.h"

#ifdef HAVE_MEMMEM
#include "util-debug.h"
#include "util-error.h"
#include "util-memcpy.h"
#include "util-validate.h"

/** \param needle lowercase version of the pattern to look for
 *
 *  Convert haystack data to lowercase before inspecting it with
 *  `memmem`. Do this in a sliding window manner. */
const uint8_t *SCMemimem(const uint8_t *haystack, uint32_t haystack_len, const uint8_t *needle,
        const uint32_t needle_len)
{
    if (needle_len > haystack_len)
        return NULL;
    uint32_t slice_size = MAX(MIN(haystack_len, 128), needle_len * 3);
    uint8_t slice[slice_size];
    uint32_t o = 0;
    do {
        const uint32_t size = MIN(haystack_len - o, slice_size);
        MemcpyToLower(slice, haystack + o, size);
        uint8_t *found = memmem(slice, size, needle, needle_len);
        if (found) {
            size_t slice_offset = found - slice;
            return haystack + (o + slice_offset);
        }
        o += (size - (needle_len - 1));
    } while (o + needle_len <= haystack_len);
    return NULL;
}

uint8_t *MMScan(const SpmCtx *ctx, SpmThreadCtx *_thread_ctx, const uint8_t *haystack,
        uint32_t haystack_len)
{
    const SpmMmCtx *sctx = ctx->ctx;

    if (sctx->nocase) {
        return (uint8_t *)SCMemimem(haystack, haystack_len, sctx->needle, sctx->needle_len);
    } else {
        return memmem(haystack, haystack_len, sctx->needle, sctx->needle_len);
    }
}

static SpmCtx *MMInitCtx(const uint8_t *needle, uint16_t needle_len, int nocase,
        SpmGlobalThreadCtx *global_thread_ctx)
{
    SpmCtx *ctx = SCCalloc(1, sizeof(SpmCtx));
    if (ctx == NULL) {
        SCLogDebug("Unable to alloc SpmCtx.");
        return NULL;
    }

    SpmMmCtx *sctx = SCCalloc(1, sizeof(SpmMmCtx) + needle_len);
    if (sctx == NULL) {
        SCFree(ctx);
        return NULL;
    }

    sctx->nocase = nocase;
    sctx->needle_len = needle_len;
    if (nocase)
        MemcpyToLower(sctx->needle, needle, needle_len);
    else
        memcpy(sctx->needle, needle, needle_len);

    ctx->ctx = sctx;
    ctx->matcher = SPM_MM;
    return ctx;
}

static void MMDestroyCtx(SpmCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    SpmMmCtx *sctx = ctx->ctx;
    if (sctx != NULL) {
        SCFree(sctx);
    }

    SCFree(ctx);
}

static SpmGlobalThreadCtx *MMInitGlobalThreadCtx(void)
{
    SpmGlobalThreadCtx *global_thread_ctx = SCCalloc(1, sizeof(SpmGlobalThreadCtx));
    if (global_thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmThreadCtx.");
        return NULL;
    }
    global_thread_ctx->matcher = SPM_MM;
    return global_thread_ctx;
}

static void MMDestroyGlobalThreadCtx(SpmGlobalThreadCtx *global_thread_ctx)
{
    if (global_thread_ctx == NULL) {
        return;
    }
    SCFree(global_thread_ctx);
}

static void MMDestroyThreadCtx(SpmThreadCtx *thread_ctx)
{
    if (thread_ctx == NULL) {
        return;
    }
    SCFree(thread_ctx);
}

static SpmThreadCtx *MMMakeThreadCtx(const SpmGlobalThreadCtx *global_thread_ctx)
{
    SpmThreadCtx *thread_ctx = SCCalloc(1, sizeof(SpmThreadCtx));
    if (thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmThreadCtx.");
        return NULL;
    }
    thread_ctx->matcher = SPM_MM;
    return thread_ctx;
}
#endif /* HAVE_MEMMEM */

void SpmMMRegister(void)
{
#ifdef HAVE_MEMMEM
    spm_table[SPM_MM].name = "mm";
    spm_table[SPM_MM].Scan = MMScan;
    spm_table[SPM_MM].InitCtx = MMInitCtx;
    spm_table[SPM_MM].DestroyCtx = MMDestroyCtx;
    spm_table[SPM_MM].InitGlobalThreadCtx = MMInitGlobalThreadCtx;
    spm_table[SPM_MM].DestroyGlobalThreadCtx = MMDestroyGlobalThreadCtx;
    spm_table[SPM_MM].MakeThreadCtx = MMMakeThreadCtx;
    spm_table[SPM_MM].DestroyThreadCtx = MMDestroyThreadCtx;
#endif /* HAVE_MEMMEM */
}
