/* Copyright (C) 2007-2021 Open Information Security Foundation
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

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"

#include "detect-filestore.h"

#include "detect-engine-dcepayload.h"
#include "detect-engine-file.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"
#include "util-validate.h"


/**
 *  \brief Inspect the file inspecting keywords.
 *
 *  \param tv thread vars
 *  \param det_ctx detection engine thread ctx
 *  \param f flow
 *  \param s signature to inspect
 *
 *  \retval 0 no match
 *  \retval 1 match
 *  \retval 2 can't match
 *  \retval 3 can't match filestore signature
 */
static uint8_t DetectFileInspect(DetectEngineThreadCtx *det_ctx, Flow *f, const Signature *s,
        const SigMatchData *smd, uint8_t flags, FileContainer *ffc)
{
    uint8_t r = 0;
    int match = 0;
    int store_r = 0;

    SCLogDebug("file inspection... %p", ffc);

    for (File *file = ffc->head; file != NULL; file = file->next) {
        SCLogDebug("file");

        if (file->state == FILE_STATE_NONE) {
            SCLogDebug("file state FILE_STATE_NONE");
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_FILENAME) && file->name == NULL) {
            SCLogDebug("sig needs filename, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        uint64_t file_size = FileDataSize(file);
        if ((s->file_flags & FILE_SIG_NEED_MAGIC) && file_size == 0) {
            SCLogDebug("sig needs file content, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_FILECONTENT) && file_size == 0) {
            SCLogDebug("sig needs file content, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_MD5) && (!(file->flags & FILE_MD5))) {
            SCLogDebug("sig needs file md5, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_SHA1) && (!(file->flags & FILE_SHA1))) {
            SCLogDebug("sig needs file sha1, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_SHA256) && (!(file->flags & FILE_SHA256))) {
            SCLogDebug("sig needs file sha256, but we don't have any");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        if ((s->file_flags & FILE_SIG_NEED_SIZE) && file->state < FILE_STATE_CLOSED) {
            SCLogDebug("sig needs filesize, but state < FILE_STATE_CLOSED");
            r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            continue;
        }

        /* run the file match functions. */
        while (1) {
            SCLogDebug("smd %p", smd);

            if (sigmatch_table[smd->type].FileMatch != NULL) {
                KEYWORD_PROFILING_START;
                match = sigmatch_table[smd->type].FileMatch(det_ctx, f, flags, file, s, smd->ctx);
                KEYWORD_PROFILING_END(det_ctx, smd->type, (match > 0));
                if (match == 0) {
                    r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
                    break;
                } else if (smd->is_last) {
                    r = DETECT_ENGINE_INSPECT_SIG_MATCH;
                    break;
                }
            }
            if (smd->is_last)
                break;
            smd++;
        }

        /* continue inspection for other files as we may want to store
         * those as well. We'll return 1 (match) regardless of their
         * results though */
        if (r == DETECT_ENGINE_INSPECT_SIG_MATCH)
            store_r = DETECT_ENGINE_INSPECT_SIG_MATCH;

        /* continue, this file may (or may not) be unable to match
         * maybe we have more that can :) */
    }

    if (r == DETECT_ENGINE_INSPECT_SIG_NO_MATCH && store_r == DETECT_ENGINE_INSPECT_SIG_MATCH) {
        SCLogDebug("stored MATCH, current file NOMATCH");
        SCReturnInt(DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES);
    }

    if (store_r == DETECT_ENGINE_INSPECT_SIG_MATCH)
        r = DETECT_ENGINE_INSPECT_SIG_MATCH;
    SCReturnInt(r);
}

/**
 *  \brief Inspect the file inspecting keywords against the state
 *
 *  \param det_ctx detection engine thread ctx
 *  \param f flow
 *  \param s signature to inspect
 *  \param alstate state
 *  \param flags direction flag
 *
 *  \retval 0 no match
 *  \retval 1 match
 *  \retval 2 can't match
 *  \retval 3 can't match filestore signature
 *
 *  \note flow is not locked at this time
 */
uint8_t DetectFileInspectGeneric(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *_alstate, void *tx, uint64_t tx_id)
{
    SCEnter();
    DEBUG_VALIDATE_BUG_ON(f->alstate != _alstate);

    const uint8_t direction = flags & (STREAM_TOSERVER|STREAM_TOCLIENT);
    FileContainer *ffc = AppLayerParserGetTxFiles(f, tx, direction);
    SCLogDebug("tx %p tx_id %" PRIu64 " ffc %p ffc->head %p sid %u", tx, tx_id, ffc,
            ffc ? ffc->head : NULL, s->id);
    if (ffc == NULL) {
        SCReturnInt(DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES);
    } else if (ffc->head == NULL) {
        SCReturnInt(DETECT_ENGINE_INSPECT_SIG_NO_MATCH);
    }

    uint8_t r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    uint8_t match = DetectFileInspect(det_ctx, f, s, engine->smd, flags, ffc);
    if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
        r = DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
        SCLogDebug("sid %u can't match on this transaction", s->id);
        r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES) {
        SCLogDebug("sid %u can't match on this transaction (file sig)", s->id);
        r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES) {
        SCLogDebug("match with more files ahead");
        r = match;
    }

    SCReturnInt(r);
}
