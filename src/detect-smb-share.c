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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-share.h"
#ifdef HAVE_RUST
#include "rust.h"
#include "rust-smb-detect-gen.h"

#define BUFFER_NAME "smb_named_pipe"
#define KEYWORD_NAME BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_NAMED_PIPE

static int g_smb_named_pipe_buffer_id = 0;

/** \brief SMB NAMED PIPE Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxSmbNamedPipe(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    uint8_t *buffer;
    uint32_t buffer_len;

    if (rs_smb_tx_get_named_pipe(txv, &buffer, &buffer_len) != 1) {
        return;
    }

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxSmbNamedPipeRequestRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxSmbNamedPipe,
        ALPROTO_SMB, 0,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
}

static int InspectEngineSmbNamedPipe(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    uint32_t buffer_len = 0;
    uint8_t *buffer = NULL;

    if (rs_smb_tx_get_named_pipe(tx, &buffer, &buffer_len) != 1)
        goto end;
    if (buffer == NULL ||buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0, DETECT_CI_FLAGS_SINGLE,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE,
                                          NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

end:
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectSmbNamedPipeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_smb_named_pipe_buffer_id;
    return 0;
}

void DetectSmbNamedPipeRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNamedPipeSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxSmbNamedPipeRequestRegister);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            InspectEngineSmbNamedPipe);

    g_smb_named_pipe_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

#undef BUFFER_NAME
#undef KEYWORD_NAME
#undef KEYWORD_ID

#else /* NO RUST */
void DetectSmbNamedPipeRegister(void) {}
#endif

#ifdef HAVE_RUST
#define BUFFER_NAME "smb_share"
#define KEYWORD_NAME BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_SHARE

static int g_smb_share_buffer_id = 0;

/** \brief SMB SHARE Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxSmbShare(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    uint8_t *buffer;
    uint32_t buffer_len;

    if (rs_smb_tx_get_share(txv, &buffer, &buffer_len) != 1) {
        return;
    }

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxSmbShareRequestRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxSmbShare,
        ALPROTO_SMB, 0,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
}

static int InspectEngineSmbShare(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    uint32_t buffer_len = 0;
    uint8_t *buffer = NULL;

    if (rs_smb_tx_get_share(tx, &buffer, &buffer_len) != 1)
        goto end;
    if (buffer == NULL ||buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0, DETECT_CI_FLAGS_SINGLE,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE,
                                          NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

end:
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectSmbShareSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_smb_share_buffer_id;
    return 0;
}

void DetectSmbShareRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbShareSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxSmbShareRequestRegister);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            InspectEngineSmbShare);

    g_smb_share_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
#else
void DetectSmbShareRegister(void) {}
#endif
