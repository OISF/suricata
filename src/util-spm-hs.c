/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Justin Viiret <justin.viiret@intel.com>
 *
 * Single pattern matcher that uses the Hyperscan regex matcher.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "util-hyperscan.h"
#include "util-spm-hs.h"

#ifdef BUILD_HYPERSCAN

#include <hs.h>

/**
 * \internal
 * \brief Hyperscan match callback, called by hs_scan.
 */
static int MatchEvent(unsigned int id, unsigned long long from,
                      unsigned long long to, unsigned int flags, void *context)
{
    uint64_t *match_offset = context;
    BUG_ON(*match_offset != UINT64_MAX);
    *match_offset = to;
    return 1; /* Terminate matching. */
}

typedef struct SpmHsCtx_ {
    hs_database_t *db;
    uint16_t needle_len;
} SpmHsCtx;

static void HSDestroyCtx(SpmCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    SpmHsCtx *sctx = ctx->ctx;
    if (sctx) {
        hs_free_database(sctx->db);
        SCFree(sctx);
    }
    SCFree(ctx);
}

static int HSBuildDatabase(const uint8_t *needle, uint16_t needle_len,
                            int nocase, SpmHsCtx *sctx,
                            SpmGlobalThreadCtx *global_thread_ctx)
{
    char *expr = HSRenderPattern(needle, needle_len);
    if (expr == NULL) {
        SCLogDebug("HSRenderPattern returned NULL");
        return -1;
    }

    unsigned flags = nocase ? HS_FLAG_CASELESS : 0;

    hs_database_t *db = NULL;
    hs_compile_error_t *compile_err = NULL;
    hs_error_t err = hs_compile(expr, flags, HS_MODE_BLOCK, NULL, &db,
                                &compile_err);
    if (err != HS_SUCCESS) {
        SCLogError(SC_ERR_FATAL, "Unable to compile '%s' with Hyperscan, "
                                 "returned %d.", expr, err);
        exit(EXIT_FAILURE);
    }

    SCFree(expr);

    /* Update scratch for this database. */
    hs_scratch_t *scratch = global_thread_ctx->ctx;
    err = hs_alloc_scratch(db, &scratch);
    if (err != HS_SUCCESS) {
        /* If scratch allocation failed, this is not recoverable:  other SPM
         * contexts may need this scratch space. */
        SCLogError(SC_ERR_FATAL,
                   "Unable to alloc scratch for Hyperscan, returned %d.", err);
        exit(EXIT_FAILURE);
    }
    global_thread_ctx->ctx = scratch;
    sctx->db = db;
    sctx->needle_len = needle_len;

    return 0;
}

static SpmCtx *HSInitCtx(const uint8_t *needle, uint16_t needle_len, int nocase,
                         SpmGlobalThreadCtx *global_thread_ctx)
{
    SpmCtx *ctx = SCMalloc(sizeof(SpmCtx));
    if (ctx == NULL) {
        SCLogDebug("Unable to alloc SpmCtx.");
        return NULL;
    }
    memset(ctx, 0, sizeof(SpmCtx));
    ctx->matcher = SPM_HS;

    SpmHsCtx *sctx = SCMalloc(sizeof(SpmHsCtx));
    if (sctx == NULL) {
        SCLogDebug("Unable to alloc SpmHsCtx.");
        SCFree(ctx);
        return NULL;
    }
    ctx->ctx = sctx;

    memset(sctx, 0, sizeof(SpmHsCtx));
    if (HSBuildDatabase(needle, needle_len, nocase, sctx,
                        global_thread_ctx) != 0) {
        SCLogDebug("HSBuildDatabase failed.");
        HSDestroyCtx(ctx);
        return NULL;
    }

    return ctx;
}

static uint8_t *HSScan(const SpmCtx *ctx, SpmThreadCtx *thread_ctx,
                       const uint8_t *haystack, uint32_t haystack_len)
{
    const SpmHsCtx *sctx = ctx->ctx;
    hs_scratch_t *scratch = thread_ctx->ctx;

    if (unlikely(haystack_len == 0)) {
        return NULL;
    }

    uint64_t match_offset = UINT64_MAX;
    hs_error_t err = hs_scan(sctx->db, (const char *)haystack, haystack_len, 0,
                             scratch, MatchEvent, &match_offset);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        /* An error value (other than HS_SCAN_TERMINATED) from hs_scan()
         * indicates that it was passed an invalid database or scratch region,
         * which is not something we can recover from at scan time. */
        SCLogError(SC_ERR_FATAL, "Hyperscan returned fatal error %d.", err);
        exit(EXIT_FAILURE);
    }

    if (match_offset == UINT64_MAX) {
        return NULL;
    }

    BUG_ON(match_offset < sctx->needle_len);

    /* Note: existing API returns non-const ptr */
    return (uint8_t *)haystack + (match_offset - sctx->needle_len);
}

static SpmGlobalThreadCtx *HSInitGlobalThreadCtx(void)
{
    SpmGlobalThreadCtx *global_thread_ctx = SCMalloc(sizeof(SpmGlobalThreadCtx));
    if (global_thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmGlobalThreadCtx.");
        return NULL;
    }
    memset(global_thread_ctx, 0, sizeof(*global_thread_ctx));
    global_thread_ctx->matcher = SPM_HS;

    /* We store scratch in the HS-specific ctx. This will be initialized as
     * patterns are compiled by SpmInitCtx. */
    global_thread_ctx->ctx = NULL;

    return global_thread_ctx;
}

static void HSDestroyGlobalThreadCtx(SpmGlobalThreadCtx *global_thread_ctx)
{
    if (global_thread_ctx == NULL) {
        return;
    }
    hs_free_scratch(global_thread_ctx->ctx);
    SCFree(global_thread_ctx);
}

static void HSDestroyThreadCtx(SpmThreadCtx *thread_ctx)
{
    if (thread_ctx == NULL) {
        return;
    }
    hs_free_scratch(thread_ctx->ctx);
    SCFree(thread_ctx);
}

static SpmThreadCtx *HSMakeThreadCtx(const SpmGlobalThreadCtx *global_thread_ctx)
{
    SpmThreadCtx *thread_ctx = SCMalloc(sizeof(SpmThreadCtx));
    if (thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmThreadCtx.");
        return NULL;
    }
    memset(thread_ctx, 0, sizeof(*thread_ctx));
    thread_ctx->matcher = SPM_HS;

    if (global_thread_ctx->ctx != NULL) {
        hs_scratch_t *scratch = NULL;
        hs_error_t err = hs_clone_scratch(global_thread_ctx->ctx, &scratch);
        if (err != HS_SUCCESS) {
            SCLogError(SC_ERR_FATAL, "Unable to clone scratch (error %d).",
                       err);
            exit(EXIT_FAILURE);
        }
        thread_ctx->ctx = scratch;
    }

    return thread_ctx;
}

void SpmHSRegister(void)
{
    spm_table[SPM_HS].name = "hs";
    spm_table[SPM_HS].InitGlobalThreadCtx = HSInitGlobalThreadCtx;
    spm_table[SPM_HS].DestroyGlobalThreadCtx = HSDestroyGlobalThreadCtx;
    spm_table[SPM_HS].MakeThreadCtx = HSMakeThreadCtx;
    spm_table[SPM_HS].DestroyThreadCtx = HSDestroyThreadCtx;
    spm_table[SPM_HS].InitCtx = HSInitCtx;
    spm_table[SPM_HS].DestroyCtx = HSDestroyCtx;
    spm_table[SPM_HS].Scan = HSScan;
}

#endif /* BUILD_HYPERSCAN */
