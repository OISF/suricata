/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#include "detect-engine-uri.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-file.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"
#include "app-layer-smtp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"


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
static int DetectFileInspect(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Flow *f, const Signature *s, const SigMatchData *smd,
        uint8_t flags, FileContainer *ffc)
{
    int r = 0;
    int match = 0;
    int store_r = 0;

    SCLogDebug("file inspection... %p", ffc);

    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            SCLogDebug("file");

            if (file->state == FILE_STATE_NONE) {
                SCLogDebug("file state FILE_STATE_NONE");
                continue;
            }

            if (file->txid < det_ctx->tx_id) {
                SCLogDebug("file->txid < det_ctx->tx_id == %"PRIu64" < %"PRIu64, file->txid, det_ctx->tx_id);
                continue;
            }

            if (file->txid > det_ctx->tx_id) {
                SCLogDebug("file->txid > det_ctx->tx_id == %"PRIu64" > %"PRIu64, file->txid, det_ctx->tx_id);
                break;
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
                    match = sigmatch_table[smd->type].
                        FileMatch(tv, det_ctx, f, flags, file, s, smd->ctx);
                    KEYWORD_PROFILING_END(det_ctx, smd->type, (match > 0));
                    if (match == 0) {
                        r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
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

            /* if this is a filestore sig, and the sig can't match
             * return 3 so we can distinguish */
            if ((s->flags & SIG_FLAG_FILESTORE) && r == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH)
                r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE;

            /* continue, this file may (or may not) be unable to match
             * maybe we have more that can :) */
        }
    } else {
        /* if we have a filestore sm with a scope > file (so tx, ssn) we
         * run it here */
        if (smd != NULL && smd->is_last && smd->type == DETECT_FILESTORE &&
                smd->ctx != NULL)
        {
            DetectFilestoreData *fd = (DetectFilestoreData *)smd->ctx;
            if (fd->scope > FILESTORE_SCOPE_DEFAULT) {
                KEYWORD_PROFILING_START;
                match = sigmatch_table[smd->type].
                    FileMatch(tv, det_ctx, f, flags, /* no file */NULL, s, smd->ctx);
                KEYWORD_PROFILING_END(det_ctx, smd->type, (match > 0));

                if (match == 1) {
                    r = DETECT_ENGINE_INSPECT_SIG_MATCH;
                }
            }
        }
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
 *  \param tv thread vars
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
int DetectFileInspectGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    SCEnter();

    if (alstate == NULL) {
        SCReturnInt(DETECT_ENGINE_INSPECT_SIG_NO_MATCH);
    }

    const uint8_t direction = flags & (STREAM_TOSERVER|STREAM_TOCLIENT);
    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, alstate, direction);
    if (ffc == NULL || ffc->head == NULL) {
        SCReturnInt(DETECT_ENGINE_INSPECT_SIG_NO_MATCH);
    }

    int r = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    int match = DetectFileInspect(tv, det_ctx, f, s, smd, flags, ffc);
    if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
        r = DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
        SCLogDebug("sid %u can't match on this transaction", s->id);
        r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE) {
        SCLogDebug("sid %u can't match on this transaction (filestore sig)", s->id);
        r = DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE;
    } else if (match == DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES) {
        SCLogDebug("match with more files ahead");
        r = match;
    }

    SCReturnInt(r);
}
