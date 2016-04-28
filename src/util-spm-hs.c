/* Copyright (C) 2016 Open Information Security Foundation
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

static SpmCtx *HSInitCtx(const uint8_t *needle, uint16_t needle_len, int nocase,
                         SpmThreadCtx *thread_ctx)
{
    char *expr = HSRenderPattern(needle, needle_len);
    if (expr == NULL) {
        SCLogError(SC_ERR_FATAL, "Unable to alloc string. Exiting.");
        exit(EXIT_FAILURE);
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
    hs_scratch_t *scratch = thread_ctx->ctx;
    hs_alloc_scratch(db, &scratch);
    thread_ctx->ctx = scratch;

    SpmHsCtx *sctx = SCMalloc(sizeof(SpmHsCtx));
    if (sctx == NULL) {
        SCLogError(SC_ERR_FATAL, "Unable to alloc SpmHsCtx. Exiting.");
        exit(EXIT_FAILURE);
    }
    memset(sctx, 0, sizeof(SpmHsCtx));
    sctx->db = db;
    sctx->needle_len = needle_len;

    SpmCtx *ctx = SCMalloc(sizeof(SpmCtx));
    if (ctx == NULL) {
        SCLogError(SC_ERR_FATAL, "Unable to alloc SpmCtx. Exiting.");
        exit(EXIT_FAILURE);
    }
    memset(ctx, 0, sizeof(SpmCtx));
    ctx->matcher = SPM_HS;
    ctx->ctx = sctx;
    return ctx;
}

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

static uint8_t *HSScan(const SpmCtx *ctx, SpmThreadCtx *thread_ctx,
                       const uint8_t *haystack, uint16_t haystack_len)
{
    const SpmHsCtx *sctx = ctx->ctx;
    hs_scratch_t *scratch = thread_ctx->ctx;

    uint64_t match_offset = UINT64_MAX;
    hs_error_t err = hs_scan(sctx->db, (const char *)haystack, haystack_len, 0,
                             scratch, MatchEvent, &match_offset);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        SCLogError(SC_ERR_FATAL, "Scan with Hyperscan returned error %d.", err);
        return NULL;
    }

    if (match_offset == UINT64_MAX) {
        return NULL;
    }

    BUG_ON(match_offset < sctx->needle_len);
    BUG_ON(match_offset > UINT16_MAX); /* haystack_len is a uint16_t */

    /* Note: existing API returns non-const ptr */
    return (uint8_t *)haystack + (match_offset - sctx->needle_len);
}

static SpmThreadCtx *HSInitThreadCtx(void)
{
    SpmThreadCtx *thread_ctx = SCMalloc(sizeof(SpmThreadCtx));
    if (thread_ctx == NULL) {
        SCLogError(SC_ERR_FATAL, "Unable to alloc SpmThreadCtx. Exiting.");
        exit(EXIT_FAILURE);
    }
    memset(thread_ctx, 0, sizeof(*thread_ctx));
    thread_ctx->matcher = SPM_HS;

    /* We store scratch in the HS-specific ctx. This will be initialized as
     * patterns are compiled by SpmInitCtx. */
    thread_ctx->ctx = NULL;

    return thread_ctx;
}

static void HSDestroyThreadCtx(SpmThreadCtx *thread_ctx)
{
    if (thread_ctx == NULL) {
        return;
    }
    hs_free_scratch(thread_ctx->ctx);
    SCFree(thread_ctx);
}

static SpmThreadCtx *HSCloneThreadCtx(const SpmThreadCtx *thread_ctx)
{
    SpmThreadCtx *cloned_ctx = SCMalloc(sizeof(SpmThreadCtx));
    if (cloned_ctx == NULL) {
        SCLogError(SC_ERR_FATAL, "Unable to alloc SpmThreadCtx. Exiting.");
        exit(EXIT_FAILURE);
    }
    memset(cloned_ctx, 0, sizeof(*cloned_ctx));
    cloned_ctx->matcher = SPM_HS;

    if (thread_ctx->ctx != NULL) {
        hs_scratch_t *scratch = NULL;
        hs_error_t err = hs_clone_scratch(thread_ctx->ctx, &scratch);
        if (err != HS_SUCCESS) {
            SCLogError(SC_ERR_FATAL, "Unable to clone scratch (error %d).",
                       err);
            exit(EXIT_FAILURE);
        }
        cloned_ctx->ctx = scratch;
    }

    return cloned_ctx;
}

void SpmHSRegister(void)
{
    spm_table[SPM_HS].name = "hs";
    spm_table[SPM_HS].InitThreadCtx = HSInitThreadCtx;
    spm_table[SPM_HS].DestroyThreadCtx = HSDestroyThreadCtx;
    spm_table[SPM_HS].CloneThreadCtx = HSCloneThreadCtx;
    spm_table[SPM_HS].InitCtx = HSInitCtx;
    spm_table[SPM_HS].DestroyCtx = HSDestroyCtx;
    spm_table[SPM_HS].Scan = HSScan;
}

#endif /* BUILD_HYPERSCAN */
